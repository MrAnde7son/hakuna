"""
Authentication & authorization utilities.
JWT token handling, password hashing, and FastAPI dependency injection.
"""
import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
from models import User, Organization, MSSPOrgAccess

# ── Config ────────────────────────────────────────────────

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production-use-a-real-secret")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


# ── Password helpers ──────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT helpers ───────────────────────────────────────────

def create_access_token(user_id: int, org_id: int, role: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": str(user_id),
        "org_id": org_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate JWT. Returns payload dict or raises."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ── FastAPI Dependencies ──────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Extract and validate the current user from the Authorization header.
    Returns None if no token is present (allows optional auth during migration).
    """
    if credentials is None:
        return None

    payload = decode_access_token(credentials.credentials)
    user_id = int(payload["sub"])
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


async def require_auth(
    user: Optional[User] = Depends(get_current_user),
) -> User:
    """Require a valid authenticated user. Use this on protected endpoints."""
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_role(*roles: str):
    """Dependency factory: require the authenticated user to have one of the given roles."""
    async def _check(user: User = Depends(require_auth)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(roles)}")
        return user
    return _check


async def get_accessible_org_ids(
    user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
) -> Optional[List[int]]:
    """Return the list of org IDs the current user can access.

    - No auth token → 401
    - superadmin → None (sees everything)
    - MSSP user → own org + all linked client orgs
    - Standard user → [own org_id]

    If X-Org-Context header is set, narrows to just that org (must be in accessible set).
    """
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    if user.role == "superadmin":
        if x_org_context:
            return [int(x_org_context)]
        return None  # No filter

    # Base: own org
    accessible = {user.org_id}

    # MSSP: add linked client orgs
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if org and org.org_type == "mssp":
        links = db.query(MSSPOrgAccess.client_org_id).filter(
            MSSPOrgAccess.mssp_org_id == user.org_id,
            MSSPOrgAccess.is_active == True,
        ).all()
        accessible.update(row[0] for row in links)

    # X-Org-Context: narrow down
    if x_org_context:
        ctx_id = int(x_org_context)
        if ctx_id not in accessible:
            raise HTTPException(status_code=403, detail="No access to requested organization")
        return [ctx_id]

    return list(accessible)


def apply_org_filter(query, model, org_ids: Optional[List[int]]):
    """Apply tenant filtering to a SQLAlchemy query.

    If org_ids is None (superadmin or no auth), returns query unchanged.
    Otherwise filters model.org_id IN org_ids.
    """
    if org_ids is None:
        return query
    if hasattr(model, "org_id"):
        return query.filter(model.org_id.in_(org_ids))
    return query


def apply_scan_org_filter(query, org_ids: Optional[List[int]]):
    """Apply tenant filtering via Scan.org_id for models that chain through scan_id.
    Requires the query to already have Scan joined or to be on the Scan model itself.
    """
    from models import Scan
    if org_ids is None:
        return query
    return query.filter(Scan.org_id.in_(org_ids))

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

from core.database import get_db
from models.models import User, Organization, MSSPOrgAccess, CustomRole, TagPermission, UserCustomRole, Tag

# ── Permission keys ──────────────────────────────────────
# All recognized permission keys for base_permissions / deny_permissions on CustomRole.

ALL_PERMISSION_KEYS = [
    # Data access
    "read_scans", "write_scans",
    "read_assets", "write_assets",
    "read_findings", "write_findings",
    # Actions
    "upload_scan", "delete_scan", "export_report",
    "manage_tags", "manage_campaigns", "manage_exceptions",
    "manage_workflows", "manage_users", "manage_integrations",
    "view_reports",
    # Pages
    "page_dashboard", "page_assets", "page_findings", "page_reports",
    "page_inventory", "page_campaigns", "page_remediation", "page_agents",
    "page_tags", "page_upload", "page_settings", "page_threat_intel",
    "page_workflows",
]

# Built-in role defaults — what each role gets out of the box.
_ALL_TRUE = {k: True for k in ALL_PERMISSION_KEYS}

BUILTIN_ROLE_DEFAULTS = {
    "superadmin": {**_ALL_TRUE, "manage_users": True},
    "org_admin":  {**_ALL_TRUE},
    "analyst": {
        # Data
        "read_scans": True, "write_scans": True,
        "read_assets": True, "write_assets": True,
        "read_findings": True, "write_findings": True,
        # Actions
        "upload_scan": True, "export_report": True,
        "manage_tags": True, "manage_campaigns": True,
        "manage_exceptions": True, "manage_workflows": True,
        "view_reports": True,
        # Pages
        "page_dashboard": True, "page_assets": True, "page_findings": True,
        "page_reports": True, "page_inventory": True, "page_campaigns": True,
        "page_remediation": True, "page_agents": True, "page_tags": True,
        "page_upload": True, "page_threat_intel": True, "page_workflows": True,
        "page_settings": True,
    },
    "viewer": {
        "read_scans": True, "read_assets": True, "read_findings": True,
        "view_reports": True, "export_report": True,
        "page_dashboard": True, "page_assets": True, "page_findings": True,
        "page_reports": True, "page_inventory": True, "page_threat_intel": True,
        "page_settings": True,
    },
    "custom": {},  # everything comes from custom roles
}

# ── Config ────────────────────────────────────────────────

_DEFAULT_JWT_SECRET = "change-me-in-production-use-a-real-secret"
JWT_SECRET = os.environ.get("JWT_SECRET", _DEFAULT_JWT_SECRET)
if JWT_SECRET == _DEFAULT_JWT_SECRET and not os.environ.get("DATABASE_URL", "sqlite://").startswith("sqlite"):
    raise RuntimeError(
        "JWT_SECRET must be set to a strong random value in production. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
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


def resolve_effective_permissions(user: User, db: Session) -> dict:
    """Compute the user's effective permissions by merging built-in role defaults
    with all assigned custom roles. Deny always wins over allow.

    Returns a dict of {permission_key: bool}.
    """
    # 1. Start with built-in role defaults
    base = dict(BUILTIN_ROLE_DEFAULTS.get(user.role, {}))

    # 2. Merge all custom role base_permissions (union — any True wins)
    assignments = (
        db.query(UserCustomRole)
        .filter(UserCustomRole.user_id == user.id)
        .all()
    )
    deny_set = set()
    for ucr in assignments:
        role = ucr.role
        if not role or not role.is_active:
            continue
        for k, v in (role.base_permissions or {}).items():
            if v and k in ALL_PERMISSION_KEYS:
                base[k] = True
        for k, v in (role.deny_permissions or {}).items():
            if v and k in ALL_PERMISSION_KEYS:
                deny_set.add(k)

    # 3. Apply deny — deny always wins
    for k in deny_set:
        base[k] = False

    return base


def require_permission(*permissions: str):
    """Dependency factory: require the user to have ALL of the given effective permissions."""
    async def _check(user: User = Depends(require_auth), db: Session = Depends(get_db)):
        effective = resolve_effective_permissions(user, db)
        missing = [p for p in permissions if not effective.get(p)]
        if missing:
            raise HTTPException(status_code=403, detail=f"Missing permission: {', '.join(missing)}")
        return user
    return _check


def has_tag_permission(user: User, tag_id: int, permission: str, db: Session) -> bool:
    """Check if a user has the given permission ('read' or 'write') on a tag via custom roles.

    - superadmin and org_admin: auto-grant unless an explicit deny exists via custom roles.
    - analyst/viewer/custom: checks UserCustomRole → TagPermission for grants and denies.
    - Deny always wins over allow.
    - 'write' requires an explicit write grant; 'read' is satisfied by read or write.
    """
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        return False

    allowed = ["write"] if permission == "write" else ["read", "write"]

    role_ids_subq = (
        db.query(UserCustomRole.role_id)
        .filter(UserCustomRole.user_id == user.id)
        .subquery()
    )

    # Check for deny first — deny always wins
    # Tag-level deny
    if db.query(TagPermission).filter(
        TagPermission.role_id.in_(role_ids_subq),
        TagPermission.target_type == "tag",
        TagPermission.target_id == tag_id,
        TagPermission.permission.in_(allowed),
        TagPermission.effect == "deny",
    ).first():
        return False

    # Category-level deny
    if db.query(TagPermission).filter(
        TagPermission.role_id.in_(role_ids_subq),
        TagPermission.target_type == "category",
        TagPermission.target_category == tag.category,
        TagPermission.permission.in_(allowed),
        TagPermission.effect == "deny",
    ).first():
        return False

    # superadmin / org_admin: auto-grant (after deny check)
    if user.role in ("superadmin", "org_admin"):
        return True

    # Tag-level allow grant
    if db.query(TagPermission).filter(
        TagPermission.role_id.in_(role_ids_subq),
        TagPermission.target_type == "tag",
        TagPermission.target_id == tag_id,
        TagPermission.permission.in_(allowed),
        TagPermission.effect == "allow",
    ).first():
        return True

    # Category-level allow grant
    if db.query(TagPermission).filter(
        TagPermission.role_id.in_(role_ids_subq),
        TagPermission.target_type == "category",
        TagPermission.target_category == tag.category,
        TagPermission.permission.in_(allowed),
        TagPermission.effect == "allow",
    ).first():
        return True

    return False


def get_user_custom_roles(user_id: int, db: Session) -> list:
    """Return all active custom roles assigned to a user."""
    assignments = (
        db.query(UserCustomRole)
        .filter(UserCustomRole.user_id == user_id)
        .all()
    )
    return [a.role for a in assignments if a.role and a.role.is_active]


def apply_scan_org_filter(query, org_ids: Optional[List[int]]):
    """Apply tenant filtering via Scan.org_id for models that chain through scan_id.
    Requires the query to already have Scan joined or to be on the Scan model itself.
    """
    from models.models import Scan
    if org_ids is None:
        return query
    return query.filter(Scan.org_id.in_(org_ids))

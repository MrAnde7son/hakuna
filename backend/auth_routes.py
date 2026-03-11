"""
Authentication & organization management routes.
Prefix: /api/auth
"""
import re
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db
from models import Organization, User, MSSPOrgAccess, Scan
from auth import (
    hash_password, verify_password, create_access_token,
    require_auth, require_role, get_current_user, get_accessible_org_ids,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── Pydantic schemas ─────────────────────────────────────

class RegisterRequest(BaseModel):
    org_name: str
    email: str
    password: str
    display_name: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

class InviteRequest(BaseModel):
    email: str
    display_name: Optional[str] = None
    role: str = "analyst"  # org_admin | analyst | viewer
    password: str  # Initial password (in prod, use invite token + email flow)

class CreateOrgRequest(BaseModel):
    name: str
    org_type: str = "standard"  # standard | mssp
    parent_org_id: Optional[int] = None

class MSSPLinkRequest(BaseModel):
    mssp_org_id: int
    client_org_id: int

class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

class UpdateOrgRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    org_type: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Helpers ───────────────────────────────────────────────

def _slugify(name: str) -> str:
    """Convert org name to a URL-safe slug."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


def _user_response(user: User, org: Organization) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "org_type": org.org_type,
            "parent_org_id": org.parent_org_id,
        },
    }


def _org_response(org: Organization) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "org_type": org.org_type,
        "parent_org_id": org.parent_org_id,
        "is_active": org.is_active,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


# ── Public routes ─────────────────────────────────────────

@router.post("/register")
async def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new organization and its first admin user.
    Also serves as the bootstrap route for the first superadmin.
    """
    # Check if email already exists
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")

    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    # Create org
    slug = _slugify(body.org_name)
    # Ensure slug uniqueness
    base_slug = slug
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    org = Organization(name=body.org_name, slug=slug)
    db.add(org)
    db.flush()

    # First user in the entire system becomes superadmin
    user_count = db.query(func.count(User.id)).scalar()
    role = "superadmin" if user_count == 0 else "org_admin"

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        display_name=body.display_name or body.email.split("@")[0],
        org_id=org.id,
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(org)

    token = create_access_token(user.id, org.id, user.role)
    logger.info(f"New registration: {body.email} → org '{org.name}' (role={role})")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


@router.post("/login")
async def login(body: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate with email + password, returns JWT."""
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Account is deactivated")

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or not org.is_active:
        raise HTTPException(403, "Organization is deactivated")

    # Update last login
    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(user.id, org.id, user.role)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


# ── Authenticated routes ─────────────────────────────────

@router.get("/me")
async def get_me(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return current authenticated user info."""
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    result = _user_response(user, org)

    # If MSSP, include accessible client orgs
    if org.org_type == "mssp":
        links = db.query(MSSPOrgAccess).filter(
            MSSPOrgAccess.mssp_org_id == org.id, MSSPOrgAccess.is_active == True
        ).all()
        client_orgs = []
        for link in links:
            client = db.query(Organization).filter(Organization.id == link.client_org_id).first()
            if client:
                client_orgs.append(_org_response(client))
        result["accessible_orgs"] = [_org_response(org)] + client_orgs
    elif user.role == "superadmin":
        all_orgs = db.query(Organization).filter(Organization.is_active == True).all()
        result["accessible_orgs"] = [_org_response(o) for o in all_orgs]

    return result


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    user.hashed_password = hash_password(body.new_password)
    db.commit()
    return {"status": "ok"}


# ── User management (org_admin+) ─────────────────────────

@router.post("/invite")
async def invite_user(
    body: InviteRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Invite a new user to the current user's organization."""
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")

    if body.role not in ("org_admin", "analyst", "viewer"):
        raise HTTPException(400, "Invalid role. Use: org_admin, analyst, viewer")

    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    new_user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        display_name=body.display_name or body.email.split("@")[0],
        org_id=user.org_id,
        role=body.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    return _user_response(new_user, org)


@router.get("/users")
async def list_users(
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """List all users in the current org (or all for superadmin)."""
    q = db.query(User)
    if user.role != "superadmin":
        q = q.filter(User.org_id == user.org_id)
    users = q.order_by(User.created_at.desc()).all()

    results = []
    for u in users:
        org = db.query(Organization).filter(Organization.id == u.org_id).first()
        results.append(_user_response(u, org))
    return results


@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    body: UpdateUserRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Update a user's role, name, or active status."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    # org_admin can only manage users in their own org
    if user.role != "superadmin" and target.org_id != user.org_id:
        raise HTTPException(403, "Cannot manage users outside your organization")

    # Cannot demote yourself
    if target.id == user.id and body.role and body.role != user.role:
        raise HTTPException(400, "Cannot change your own role")

    if body.display_name is not None:
        target.display_name = body.display_name
    if body.role is not None:
        if body.role not in ("superadmin", "org_admin", "analyst", "viewer"):
            raise HTTPException(400, "Invalid role")
        if body.role == "superadmin" and user.role != "superadmin":
            raise HTTPException(403, "Only superadmin can grant superadmin role")
        target.role = body.role
    if body.is_active is not None:
        if target.id == user.id:
            raise HTTPException(400, "Cannot deactivate yourself")
        target.is_active = body.is_active

    db.commit()
    db.refresh(target)
    org = db.query(Organization).filter(Organization.id == target.org_id).first()
    return _user_response(target, org)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Delete a user permanently."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == user.id:
        raise HTTPException(400, "Cannot delete yourself")
    if user.role != "superadmin" and target.org_id != user.org_id:
        raise HTTPException(403, "Cannot manage users outside your organization")
    if target.role == "superadmin" and user.role != "superadmin":
        raise HTTPException(403, "Cannot delete a superadmin")

    db.delete(target)
    db.commit()
    return {"status": "deleted", "id": user_id}


# ── Organization management (superadmin) ─────────────────

@router.get("/orgs")
async def list_orgs(
    user: User = Depends(require_auth),
    org_ids: Optional[list] = Depends(get_accessible_org_ids),
    db: Session = Depends(get_db),
):
    """List organizations accessible to the current user."""
    q = db.query(Organization)
    if org_ids is not None:
        q = q.filter(Organization.id.in_(org_ids))
    orgs = q.order_by(Organization.created_at.desc()).all()
    return [_org_response(o) for o in orgs]


@router.post("/orgs")
async def create_org(
    body: CreateOrgRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Create a new organization. Superadmin can create any; org_admin of MSSP can create client orgs."""
    # org_admin can only create if they're MSSP
    if user.role != "superadmin":
        org = db.query(Organization).filter(Organization.id == user.org_id).first()
        if org.org_type != "mssp":
            raise HTTPException(403, "Only MSSP organizations can create client orgs")
        # Force parent to their MSSP org
        body.parent_org_id = user.org_id

    slug = _slugify(body.name)
    base_slug = slug
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    new_org = Organization(
        name=body.name,
        slug=slug,
        org_type=body.org_type,
        parent_org_id=body.parent_org_id,
    )
    db.add(new_org)
    db.flush()

    # If created by MSSP org_admin, auto-create access link
    if user.role != "superadmin" and body.parent_org_id:
        link = MSSPOrgAccess(mssp_org_id=body.parent_org_id, client_org_id=new_org.id)
        db.add(link)

    db.commit()
    db.refresh(new_org)
    return _org_response(new_org)


@router.patch("/orgs/{org_id}")
async def update_org(
    org_id: int,
    body: UpdateOrgRequest,
    user: User = Depends(require_role("superadmin")),
    db: Session = Depends(get_db),
):
    """Update organization details (superadmin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    if body.name is not None:
        org.name = body.name
    if body.is_active is not None:
        org.is_active = body.is_active
    if body.org_type is not None:
        org.org_type = body.org_type
    db.commit()
    db.refresh(org)
    return _org_response(org)


@router.delete("/orgs/{org_id}")
async def delete_org(
    org_id: int,
    user: User = Depends(require_role("superadmin")),
    db: Session = Depends(get_db),
):
    """Delete an organization and all its users (superadmin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    # Prevent deleting the org the superadmin belongs to
    if org_id == user.org_id:
        raise HTTPException(400, "Cannot delete your own organization")

    # Delete all users in this org
    db.query(User).filter(User.org_id == org_id).delete()
    # Delete MSSP links
    db.query(MSSPOrgAccess).filter(
        (MSSPOrgAccess.mssp_org_id == org_id) | (MSSPOrgAccess.client_org_id == org_id)
    ).delete(synchronize_session=False)
    db.delete(org)
    db.commit()
    return {"status": "deleted", "id": org_id}


# ── MSSP management ──────────────────────────────────────

@router.post("/mssp-link")
async def create_mssp_link(
    body: MSSPLinkRequest,
    user: User = Depends(require_role("superadmin")),
    db: Session = Depends(get_db),
):
    """Link an MSSP org to a client org."""
    mssp = db.query(Organization).filter(Organization.id == body.mssp_org_id).first()
    client = db.query(Organization).filter(Organization.id == body.client_org_id).first()
    if not mssp or not client:
        raise HTTPException(404, "Organization not found")
    if mssp.org_type != "mssp":
        raise HTTPException(400, "Source organization is not an MSSP")

    existing = db.query(MSSPOrgAccess).filter(
        MSSPOrgAccess.mssp_org_id == body.mssp_org_id,
        MSSPOrgAccess.client_org_id == body.client_org_id,
    ).first()
    if existing:
        existing.is_active = True
        db.commit()
        return {"status": "reactivated", "id": existing.id}

    link = MSSPOrgAccess(mssp_org_id=body.mssp_org_id, client_org_id=body.client_org_id)
    db.add(link)
    db.commit()
    db.refresh(link)
    return {"status": "created", "id": link.id}


@router.delete("/mssp-link/{link_id}")
async def delete_mssp_link(
    link_id: int,
    user: User = Depends(require_role("superadmin")),
    db: Session = Depends(get_db),
):
    """Deactivate an MSSP-client link."""
    link = db.query(MSSPOrgAccess).filter(MSSPOrgAccess.id == link_id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    link.is_active = False
    db.commit()
    return {"status": "deactivated"}


@router.get("/mssp/clients")
async def list_mssp_clients(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """List client orgs for the current user's MSSP org."""
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or org.org_type != "mssp":
        raise HTTPException(400, "Not an MSSP organization")

    links = db.query(MSSPOrgAccess).filter(
        MSSPOrgAccess.mssp_org_id == user.org_id,
        MSSPOrgAccess.is_active == True,
    ).all()

    clients = []
    for link in links:
        client = db.query(Organization).filter(Organization.id == link.client_org_id).first()
        if client:
            info = _org_response(client)
            # Add stats
            info["scan_count"] = db.query(func.count(Scan.id)).filter(Scan.org_id == client.id).scalar()
            info["user_count"] = db.query(func.count(User.id)).filter(User.org_id == client.id).scalar()
            clients.append(info)

    return clients

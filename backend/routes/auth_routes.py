"""
Authentication & organization management routes.
Prefix: /api/auth
"""
import re
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from core.database import get_db
from models.models import Organization, User, MSSPOrgAccess, Scan, CustomRole, TagPermission, UserCustomRole, Tag
from core.auth import (
    hash_password, verify_password, create_access_token,
    require_auth, require_role, get_current_user, get_accessible_org_ids,
    get_user_custom_roles, resolve_effective_permissions, ALL_PERMISSION_KEYS,
)
from core.audit import log_audit, diff as _diff
from core.i18n import get_locale_from_request, t as translate
from core.subscription import check_user_invite_limit
from services.easm import trigger_easm_for_new_org

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

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class GoogleAuthRequest(BaseModel):
    credential: str  # Google ID token from Google Identity Services


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
        "locale": user.locale or "en",
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "org_type": org.org_type,
            "parent_org_id": org.parent_org_id,
            "subscription_tier": org.subscription_tier or "free",
            "subscription_status": org.subscription_status,
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
async def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new organization and its first admin user.
    Also serves as the bootstrap route for the first superadmin.
    """
    locale = get_locale_from_request(request)
    # Check if email already exists
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, translate("email_exists", locale))

    if len(body.password) < 8:
        raise HTTPException(400, translate("password_too_short", locale))

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

    # Trigger EASM discovery for corporate email domains (non-blocking)
    try:
        await trigger_easm_for_new_org(db, org, body.email)
    except Exception as e:
        logger.warning(f"EASM trigger failed (non-fatal): {e}")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


@router.post("/login")
async def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate with email + password, returns JWT."""
    locale = get_locale_from_request(request)
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not user.hashed_password or not verify_password(body.password, user.hashed_password):
        raise HTTPException(401, translate("invalid_credentials", locale))
    if not user.is_active:
        raise HTTPException(403, translate("account_deactivated", locale))

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or not org.is_active:
        raise HTTPException(403, translate("org_deactivated", locale))

    # Update last login
    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(user.id, org.id, user.role)

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


# ── Google OAuth (public) ────────────────────────────────

@router.post("/google")
async def google_auth(body: GoogleAuthRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate or register via Google ID token (from Google Identity Services)."""
    import os
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    locale = get_locale_from_request(request)
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        raise HTTPException(500, "Google OAuth is not configured")

    # Verify the Google ID token
    try:
        idinfo = google_id_token.verify_oauth2_token(
            body.credential, google_requests.Request(), client_id
        )
    except ValueError:
        raise HTTPException(401, translate("invalid_credentials", locale))

    google_sub = idinfo["sub"]
    email = idinfo.get("email")
    if not email or not idinfo.get("email_verified"):
        raise HTTPException(400, "Google account email is not verified")

    # Try to find existing user by google_id or email
    user = db.query(User).filter(User.google_id == google_sub).first()
    if not user:
        user = db.query(User).filter(User.email == email).first()

    if user:
        # ── Existing user: log in ──
        if not user.is_active:
            raise HTTPException(403, translate("account_deactivated", locale))
        org = db.query(Organization).filter(Organization.id == user.org_id).first()
        if not org or not org.is_active:
            raise HTTPException(403, translate("org_deactivated", locale))

        # Link Google ID if not yet linked
        if not user.google_id:
            user.google_id = google_sub
        user.last_login_at = datetime.utcnow()
        db.commit()

        token = create_access_token(user.id, org.id, user.role)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": _user_response(user, org),
        }
    else:
        # ── New user: register ──
        display_name = idinfo.get("name") or email.split("@")[0]

        # Create org from email domain
        domain = email.split("@")[1]
        org_name = domain.split(".")[0].title()
        slug = _slugify(org_name)
        base_slug = slug
        counter = 1
        while db.query(Organization).filter(Organization.slug == slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        org = Organization(name=org_name, slug=slug)
        db.add(org)
        db.flush()

        # First user in the system becomes superadmin
        user_count = db.query(func.count(User.id)).scalar()
        role = "superadmin" if user_count == 0 else "org_admin"

        user = User(
            email=email,
            hashed_password=None,
            display_name=display_name,
            org_id=org.id,
            role=role,
            google_id=google_sub,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        db.refresh(org)

        token = create_access_token(user.id, org.id, user.role)
        logger.info(f"Google registration: {email} → org '{org.name}' (role={role})")

        # Trigger EASM discovery for corporate email domains (non-blocking)
        try:
            await trigger_easm_for_new_org(db, org, email)
        except Exception as e:
            logger.warning(f"EASM trigger failed (non-fatal): {e}")

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": _user_response(user, org),
        }


# ── Password reset (public) ───────────────────────────────

@router.post("/forgot-password")
async def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Request a password reset email. Always returns 200 to prevent email enumeration."""
    from services.brevo import send_password_reset, is_configured as brevo_configured
    user = db.query(User).filter(User.email == body.email).first()
    if user and user.is_active and brevo_configured():
        token = secrets.token_urlsafe(32)
        user.password_reset_token = token
        user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        try:
            send_password_reset(user.email, user.display_name or user.email, token)
        except Exception as e:
            logger.error(f"Failed to send password reset email to {body.email}: {e}")
    return {"status": "ok", "message": "If that email is registered, a reset link has been sent."}


@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using a valid token from a reset email."""
    if len(body.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    user = db.query(User).filter(User.password_reset_token == body.token).first()
    if not user or not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
        raise HTTPException(400, "Invalid or expired reset token")

    user.hashed_password = hash_password(body.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    log_audit(db, "update", "user", user.id, entity_name=user.email,
              changes={"password": "reset via email"})
    db.commit()
    return {"status": "ok", "message": "Password reset successfully. You can now log in."}


# ── Authenticated routes ─────────────────────────────────

@router.get("/me")
async def get_me(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Return current authenticated user info."""
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    result = _user_response(user, org)

    # Include effective permissions
    result["effective_permissions"] = resolve_effective_permissions(user, db)

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
    log_audit(db, "update", "user", user.id, entity_name=user.email,
              changes={"password": "changed"}, actor=user)
    db.commit()
    return {"status": "ok"}


class UpdateLocaleRequest(BaseModel):
    locale: str


@router.put("/locale")
async def update_locale(body: UpdateLocaleRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Update the authenticated user's preferred locale."""
    supported = {"en", "ja", "fr", "de", "he", "ru", "zh", "es", "pt", "nl", "ar", "it"}
    if body.locale not in supported:
        raise HTTPException(400, f"Unsupported locale. Supported: {', '.join(sorted(supported))}")
    user.locale = body.locale
    db.commit()
    return {"status": "ok", "locale": user.locale}


# ── User management (org_admin+) ─────────────────────────

@router.post("/invite", dependencies=[Depends(check_user_invite_limit)])
async def invite_user(
    body: InviteRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Invite a new user to the current user's organization."""
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")

    if body.role not in ("org_admin", "analyst", "viewer", "custom"):
        raise HTTPException(400, "Invalid role. Use: org_admin, analyst, viewer, custom")

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
    db.flush()
    log_audit(db, "create", "user", new_user.id,
              entity_name=new_user.email,
              changes={"email": new_user.email, "role": new_user.role, "display_name": new_user.display_name},
              actor=user)
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

    _old_u = {"display_name": target.display_name, "role": target.role, "is_active": target.is_active}
    if body.display_name is not None:
        target.display_name = body.display_name
    if body.role is not None:
        if body.role not in ("superadmin", "org_admin", "analyst", "viewer", "custom"):
            raise HTTPException(400, "Invalid role")
        if body.role == "superadmin" and user.role != "superadmin":
            raise HTTPException(403, "Only superadmin can grant superadmin role")
        target.role = body.role
    if body.is_active is not None:
        if target.id == user.id:
            raise HTTPException(400, "Cannot deactivate yourself")
        target.is_active = body.is_active

    _new_u = {"display_name": target.display_name, "role": target.role, "is_active": target.is_active}
    log_audit(db, "update", "user", target.id, entity_name=target.email,
              changes=_diff(_old_u, _new_u), actor=user)
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

    _del_email, _del_org = target.email, target.org_id
    db.delete(target)
    log_audit(db, "delete", "user", user_id, entity_name=_del_email, actor=user, org_id=_del_org)
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

    log_audit(db, "create", "organization", new_org.id,
              entity_name=new_org.name,
              changes={"name": new_org.name, "org_type": new_org.org_type},
              actor=user)
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
    _old_org = {"name": org.name, "is_active": org.is_active, "org_type": org.org_type}
    if body.name is not None:
        org.name = body.name
    if body.is_active is not None:
        org.is_active = body.is_active
    if body.org_type is not None:
        org.org_type = body.org_type
    _new_org = {"name": org.name, "is_active": org.is_active, "org_type": org.org_type}
    log_audit(db, "update", "organization", org_id, entity_name=org.name,
              changes=_diff(_old_org, _new_org), actor=user)
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

    _org_name = org.name
    # Delete all users in this org
    db.query(User).filter(User.org_id == org_id).delete()
    # Delete MSSP links
    db.query(MSSPOrgAccess).filter(
        (MSSPOrgAccess.mssp_org_id == org_id) | (MSSPOrgAccess.client_org_id == org_id)
    ).delete(synchronize_session=False)
    db.delete(org)
    log_audit(db, "delete", "organization", org_id, entity_name=_org_name, actor=user)
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


# ── Custom Role Management ────────────────────────────────

BASE_PERMISSION_KEYS = ALL_PERMISSION_KEYS


class CreateRoleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    base_permissions: Optional[dict] = None
    deny_permissions: Optional[dict] = None


class UpdateRoleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    base_permissions: Optional[dict] = None
    deny_permissions: Optional[dict] = None
    is_active: Optional[bool] = None


class TagPermissionRequest(BaseModel):
    target_type: str          # "tag" | "category"
    target_id: Optional[int] = None        # tag ID when target_type="tag"
    target_category: Optional[str] = None  # category name when target_type="category"
    permission: str           # "read" | "write"
    effect: str = "allow"     # "allow" | "deny"


def _role_response(role: CustomRole, db: Session) -> dict:
    perms = []
    for tp in role.tag_permissions:
        entry = {
            "id": tp.id,
            "target_type": tp.target_type,
            "permission": tp.permission,
            "effect": tp.effect or "allow",
        }
        if tp.target_type == "tag":
            entry["target_id"] = tp.target_id
            entry["target_label"] = f"{tp.tag.category}:{tp.tag.value}" if tp.tag else str(tp.target_id)
        else:
            entry["target_category"] = tp.target_category
            entry["target_label"] = f"category:{tp.target_category}"
        perms.append(entry)

    member_count = db.query(func.count(UserCustomRole.id)).filter(
        UserCustomRole.role_id == role.id
    ).scalar()

    return {
        "id": role.id,
        "org_id": role.org_id,
        "name": role.name,
        "description": role.description,
        "base_permissions": role.base_permissions or {},
        "deny_permissions": role.deny_permissions or {},
        "is_active": role.is_active,
        "created_at": role.created_at.isoformat() if role.created_at else None,
        "tag_permissions": perms,
        "member_count": member_count,
    }


@router.post("/roles")
async def create_role(
    body: CreateRoleRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Create a custom role for the current org."""
    if db.query(CustomRole).filter(
        CustomRole.org_id == user.org_id,
        CustomRole.name == body.name,
    ).first():
        raise HTTPException(400, "A role with this name already exists in your organization")

    perms = {k: bool(v) for k, v in (body.base_permissions or {}).items() if k in BASE_PERMISSION_KEYS}
    deny = {k: bool(v) for k, v in (body.deny_permissions or {}).items() if k in BASE_PERMISSION_KEYS}
    role = CustomRole(
        org_id=user.org_id,
        name=body.name,
        description=body.description,
        base_permissions=perms,
        deny_permissions=deny,
        created_by_id=user.id,
    )
    db.add(role)
    db.flush()
    log_audit(db, "create", "role", role.id,
              entity_name=role.name,
              changes={"name": role.name, "description": role.description, "base_permissions": perms},
              actor=user)
    db.commit()
    db.refresh(role)
    return _role_response(role, db)


@router.get("/roles")
async def list_roles(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """List all custom roles in the current org."""
    roles = db.query(CustomRole).filter(
        CustomRole.org_id == user.org_id,
    ).order_by(CustomRole.name).all()
    return [_role_response(r, db) for r in roles]


@router.get("/roles/{role_id}")
async def get_role(
    role_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(404, "Role not found")
    return _role_response(role, db)


@router.patch("/roles/{role_id}")
async def update_role(
    role_id: int,
    body: UpdateRoleRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(404, "Role not found")

    _old_r = {"name": role.name, "description": role.description, "base_permissions": role.base_permissions, "deny_permissions": role.deny_permissions, "is_active": role.is_active}
    if body.name is not None:
        # Check uniqueness
        conflict = db.query(CustomRole).filter(
            CustomRole.org_id == user.org_id,
            CustomRole.name == body.name,
            CustomRole.id != role_id,
        ).first()
        if conflict:
            raise HTTPException(400, "A role with this name already exists")
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.base_permissions is not None:
        role.base_permissions = {k: bool(v) for k, v in body.base_permissions.items() if k in BASE_PERMISSION_KEYS}
    if body.deny_permissions is not None:
        role.deny_permissions = {k: bool(v) for k, v in body.deny_permissions.items() if k in BASE_PERMISSION_KEYS}
    if body.is_active is not None:
        role.is_active = body.is_active

    _new_r = {"name": role.name, "description": role.description, "base_permissions": role.base_permissions, "deny_permissions": role.deny_permissions, "is_active": role.is_active}
    log_audit(db, "update", "role", role_id, entity_name=role.name,
              changes=_diff(_old_r, _new_r), actor=user)
    db.commit()
    db.refresh(role)
    return _role_response(role, db)


@router.delete("/roles/{role_id}")
async def delete_role(
    role_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(404, "Role not found")
    _role_name = role.name
    db.delete(role)
    log_audit(db, "delete", "role", role_id, entity_name=_role_name, actor=user)
    db.commit()
    return {"status": "deleted", "id": role_id}


# ── Tag permissions on a role ─────────────────────────────

@router.post("/roles/{role_id}/permissions")
async def add_tag_permission(
    role_id: int,
    body: TagPermissionRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(404, "Role not found")

    if body.target_type not in ("tag", "category"):
        raise HTTPException(400, "target_type must be 'tag' or 'category'")
    if body.permission not in ("read", "write"):
        raise HTTPException(400, "permission must be 'read' or 'write'")
    if body.effect not in ("allow", "deny"):
        raise HTTPException(400, "effect must be 'allow' or 'deny'")

    if body.target_type == "tag":
        if not body.target_id:
            raise HTTPException(400, "target_id required when target_type is 'tag'")
        tag = db.query(Tag).filter(Tag.id == body.target_id).first()
        if not tag:
            raise HTTPException(404, "Tag not found")
        # Check duplicate
        existing = db.query(TagPermission).filter(
            TagPermission.role_id == role_id,
            TagPermission.target_type == "tag",
            TagPermission.target_id == body.target_id,
            TagPermission.permission == body.permission,
            TagPermission.effect == body.effect,
        ).first()
    else:
        if not body.target_category:
            raise HTTPException(400, "target_category required when target_type is 'category'")
        existing = db.query(TagPermission).filter(
            TagPermission.role_id == role_id,
            TagPermission.target_type == "category",
            TagPermission.target_category == body.target_category,
            TagPermission.permission == body.permission,
            TagPermission.effect == body.effect,
        ).first()

    if existing:
        raise HTTPException(409, "Permission already exists")

    tp = TagPermission(
        role_id=role_id,
        target_type=body.target_type,
        target_id=body.target_id if body.target_type == "tag" else None,
        target_category=body.target_category if body.target_type == "category" else None,
        permission=body.permission,
        effect=body.effect,
    )
    db.add(tp)
    log_audit(db, "update", "role", role_id, entity_name=role.name,
              changes={"added_tag_permission": {"target_type": body.target_type,
                        "target": body.target_id or body.target_category,
                        "permission": body.permission}},
              actor=user)
    db.commit()
    db.refresh(role)
    return _role_response(role, db)


@router.delete("/roles/{role_id}/permissions/{perm_id}")
async def remove_tag_permission(
    role_id: int,
    perm_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    tp = db.query(TagPermission).filter(
        TagPermission.id == perm_id,
        TagPermission.role_id == role_id,
    ).first()
    if not tp:
        raise HTTPException(404, "Permission not found")
    # Ensure role belongs to user's org
    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(403, "Access denied")
    db.delete(tp)
    log_audit(db, "update", "role", role_id, entity_name=role.name,
              changes={"removed_tag_permission": {"target_type": tp.target_type,
                        "target": tp.target_id or tp.target_category,
                        "permission": tp.permission}},
              actor=user)
    db.commit()
    db.refresh(role)
    return _role_response(role, db)


# ── Assign / unassign custom roles to users ───────────────

@router.get("/users/{user_id}/custom-roles")
async def get_user_custom_role_list(
    user_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Get custom roles assigned to a user."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    # Users can see their own; admins can see any in their org
    if user.id != user_id and user.role not in ("superadmin", "org_admin"):
        raise HTTPException(403, "Access denied")
    if user.role not in ("superadmin",) and target.org_id != user.org_id:
        raise HTTPException(403, "Access denied")
    roles = get_user_custom_roles(user_id, db)
    return [_role_response(r, db) for r in roles]


@router.post("/users/{user_id}/custom-roles/{role_id}")
async def assign_custom_role(
    user_id: int,
    role_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Assign a custom role to a user."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if user.role != "superadmin" and target.org_id != user.org_id:
        raise HTTPException(403, "Cannot manage users outside your organization")

    role = db.query(CustomRole).filter(
        CustomRole.id == role_id, CustomRole.org_id == user.org_id
    ).first()
    if not role:
        raise HTTPException(404, "Role not found")

    existing = db.query(UserCustomRole).filter(
        UserCustomRole.user_id == user_id,
        UserCustomRole.role_id == role_id,
    ).first()
    if existing:
        raise HTTPException(409, "Role already assigned to this user")

    db.add(UserCustomRole(user_id=user_id, role_id=role_id, assigned_by_id=user.id))
    log_audit(db, "create", "role_assignment", None,
              entity_name=f"{target.email} → {role.name}",
              changes={"user_id": user_id, "user_email": target.email, "role_id": role_id, "role_name": role.name},
              actor=user)
    db.commit()
    return {"status": "assigned", "user_id": user_id, "role_id": role_id}


@router.delete("/users/{user_id}/custom-roles/{role_id}")
async def unassign_custom_role(
    user_id: int,
    role_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Remove a custom role from a user."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if user.role != "superadmin" and target.org_id != user.org_id:
        raise HTTPException(403, "Cannot manage users outside your organization")

    ucr = db.query(UserCustomRole).filter(
        UserCustomRole.user_id == user_id,
        UserCustomRole.role_id == role_id,
    ).first()
    if not ucr:
        raise HTTPException(404, "Assignment not found")
    role_obj = db.query(CustomRole).filter(CustomRole.id == role_id).first()
    db.delete(ucr)
    log_audit(db, "delete", "role_assignment", None,
              entity_name=f"{target.email} → {role_obj.name if role_obj else role_id}",
              changes={"user_id": user_id, "user_email": target.email, "role_id": role_id},
              actor=user)
    db.commit()
    return {"status": "unassigned", "user_id": user_id, "role_id": role_id}

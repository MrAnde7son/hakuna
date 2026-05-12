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
from sqlalchemy import func, text

from core.database import get_db
from core.limiter import limiter
from models.models import Organization, User, MSSPOrgAccess, OrgInvite, OrgJoinRequest, Scan, CustomRole, TagPermission, UserCustomRole, Tag
from core.public_email_domains import extract_domain, is_public_email_domain
from core.auth import (
    hash_password, verify_password, create_access_token, decode_access_token,
    require_auth, require_role, get_current_user, get_accessible_org_ids,
    get_user_custom_roles, resolve_effective_permissions, ALL_PERMISSION_KEYS,
    ACCESS_TOKEN_EXPIRE_MINUTES, validate_password_strength,
    LOGIN_FAILURE_THRESHOLD, LOGIN_LOCKOUT_MINUTES, enforce_page_consistency,
)
from core.audit import log_audit, diff as _diff
from core.i18n import get_locale_from_request, t as translate
from core.time_utils import iso_utc
from core.subscription import check_user_invite_limit
from core.builtin_team_roles import seed_builtin_team_roles
from services.easm import trigger_easm_for_new_org
from services.brevo import APP_URL
from services import posthog_client as analytics

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


def _track_auth(user: User, org: Organization, event: str) -> None:
    """Identify the user + org and fire a lifecycle event to PostHog."""
    analytics.identify(user.id, {
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "org_id": org.id,
        "org_name": org.name,
        "email_verified": bool(user.email_verified),
    })
    analytics.group_identify("company", org.id, {
        "name": org.name,
        "slug": org.slug,
        "org_type": org.org_type,
        "subscription_tier": org.subscription_tier or "free",
        "subscription_status": org.subscription_status,
    })
    analytics.capture(user.id, event, {"role": user.role}, org_id=org.id)


# ── Pydantic schemas ─────────────────────────────────────

class RegisterRequest(BaseModel):
    # ``org_name`` is required for ``intent='create'`` and ignored otherwise.
    # Default kept Optional so the join path doesn't force callers to invent
    # one — the org they're joining already has a name.
    org_name: Optional[str] = None
    email: str
    password: str
    display_name: Optional[str] = None
    intent: Optional[str] = "create"  # create | join

class LoginRequest(BaseModel):
    email: str
    password: str

class InviteRequest(BaseModel):
    email: str
    display_name: Optional[str] = None
    role: str = "analyst"  # org_admin | analyst | viewer
    password: Optional[str] = None  # If omitted, sends activation email instead

class CreateOrgRequest(BaseModel):
    name: str
    org_type: str = "standard"  # standard | mssp
    parent_org_id: Optional[int] = None
    admin_email: Optional[str] = None  # If set, creates an org_admin user and sends activation email

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
    current_password: Optional[str] = None
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
        "email_verified": bool(user.email_verified),
        "has_password": bool(user.hashed_password),
        "created_at": iso_utc(user.created_at),
        "last_login_at": iso_utc(user.last_login_at),
        "org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "org_type": org.org_type,
            "parent_org_id": org.parent_org_id,
            "subscription_tier": org.subscription_tier or "free",
            "subscription_status": org.subscription_status,
            "easm_domain": org.easm_domain,
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
        "subscription_tier": org.subscription_tier or "free",
        "subscription_status": org.subscription_status,
        "created_at": iso_utc(org.created_at),
    }


# ── Public routes ─────────────────────────────────────────

@router.post("/register")
@limiter.limit("3/minute")
async def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new organization (intent='create') or request to join an
    existing one matched by email domain (intent='join').

    Also serves as the bootstrap route for the first superadmin.
    """
    locale = get_locale_from_request(request)
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, translate("email_exists", locale))

    pw_error = validate_password_strength(body.password)
    if pw_error:
        raise HTTPException(400, pw_error)

    domain = extract_domain(body.email)
    if not domain:
        raise HTTPException(400, "Invalid email address")

    intent = (body.intent or "create").lower()
    if intent not in ("create", "join"):
        raise HTTPException(400, "intent must be 'create' or 'join'")

    matched_org = None
    if not is_public_email_domain(domain):
        matched_org = db.query(Organization).filter(
            Organization.claimed_domain == domain,
            Organization.is_active == True,
        ).first()

    # ── Join an existing org by domain ──────────────────────
    if intent == "join":
        if not matched_org:
            raise HTTPException(404, "No organization claims that email domain")
        if matched_org.domain_join_mode == "disabled":
            # Don't leak that the org exists if its admin has turned join off.
            raise HTTPException(404, "No organization claims that email domain")
        return await _register_join_existing_org(db, body, matched_org)

    # ── Create a new org (default path) ─────────────────────
    if not body.org_name:
        raise HTTPException(400, "org_name is required when creating a new organization")

    slug = _slugify(body.org_name)
    base_slug = slug
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    # Auto-claim the email domain for the new org if it's a corporate domain
    # and no other org has claimed it yet. The unique index guards against a
    # race so this is a soft check.
    auto_claim = (
        not is_public_email_domain(domain)
        and matched_org is None
    )

    org = Organization(
        name=body.org_name,
        slug=slug,
        claimed_domain=domain if auto_claim else None,
        domain_join_mode="auto" if auto_claim else "disabled",
    )
    db.add(org)
    db.flush()

    seed_builtin_team_roles(db, org.id)

    user_count = db.query(func.count(User.id)).scalar()
    role = "superadmin" if user_count == 0 else "org_admin"
    is_first_user = role == "superadmin"
    verify_token = None if is_first_user else secrets.token_urlsafe(32)

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        display_name=body.display_name or body.email.split("@")[0],
        org_id=org.id,
        role=role,
        email_verified=is_first_user,
        email_verify_token=verify_token,
        email_verify_expires=None if is_first_user else datetime.utcnow() + timedelta(hours=24),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.refresh(org)

    token = create_access_token(user.id, org.id, user.role)
    logger.info(
        f"New registration: {body.email} → org '{org.name}' (role={role}"
        f"{', claimed_domain=' + domain if auto_claim else ''})"
    )

    if not is_first_user:
        try:
            from services.brevo import send_email_verification, is_configured as brevo_configured
            if brevo_configured():
                send_email_verification(body.email, user.display_name, verify_token)
                logger.info(f"Verification email sent to {body.email}")
            else:
                logger.warning("Brevo not configured — skipping verification email")
        except Exception as e:
            logger.warning(f"Failed to send verification email (non-fatal): {e}")

    try:
        await trigger_easm_for_new_org(db, org, body.email)
    except Exception as e:
        logger.warning(f"EASM trigger failed (non-fatal): {e}")

    _track_auth(user, org, "user_registered")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


async def _register_join_existing_org(db: Session, body: RegisterRequest, org: Organization) -> dict:
    """Handle ``intent='join'``. Branches on the org's ``domain_join_mode``:
      * ``auto``    — create the User immediately (email_verified=False, no
                      access token issued); they verify, then log in.
      * ``request`` — store an OrgJoinRequest, notify org admins. No User
                      is created until an admin approves.
    """
    from services.brevo import (
        send_email_verification,
        send_domain_join_request_to_admin,
        is_configured as brevo_configured,
    )

    if org.domain_join_mode == "auto":
        verify_token = secrets.token_urlsafe(32)
        user = User(
            email=body.email,
            hashed_password=hash_password(body.password),
            display_name=body.display_name or body.email.split("@")[0],
            org_id=org.id,
            role=org.domain_join_default_role or "viewer",
            email_verified=False,
            email_verify_token=verify_token,
            email_verify_expires=datetime.utcnow() + timedelta(hours=24),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Domain auto-join: {body.email} → org '{org.name}' (pending email verification)")

        if brevo_configured():
            try:
                send_email_verification(body.email, user.display_name, verify_token)
            except Exception as e:
                logger.warning(f"Failed to send verification email (non-fatal): {e}")

        # Auto-join requires the user to verify their inbox before they get a
        # session — otherwise anyone could spoof an `@acme.com` address and
        # walk into ACME's tenant.
        return {
            "status": "verification_required",
            "joined_org_name": org.name,
            "email": body.email,
            "message": (
                "Account created. Please check your email to verify your "
                "address before signing in."
            ),
        }

    # mode == 'request'
    # Replace any existing pending request for this email+org so users can
    # retry without admin intervention. Old denied/approved rows are kept
    # for audit.
    existing = db.query(OrgJoinRequest).filter(
        OrgJoinRequest.org_id == org.id,
        OrgJoinRequest.email == body.email,
        OrgJoinRequest.status == "pending",
    ).first()
    if existing:
        existing.hashed_password = hash_password(body.password)
        existing.display_name = body.display_name or existing.display_name
        existing.created_at = datetime.utcnow()
        existing.expires_at = datetime.utcnow() + timedelta(days=30)
    else:
        jr = OrgJoinRequest(
            org_id=org.id,
            email=body.email,
            hashed_password=hash_password(body.password),
            display_name=body.display_name or body.email.split("@")[0],
            requested_role=org.domain_join_default_role or "viewer",
            status="pending",
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db.add(jr)
    db.commit()
    logger.info(f"Domain join request: {body.email} → org '{org.name}' (pending admin approval)")

    if brevo_configured():
        admins = db.query(User).filter(
            User.org_id == org.id,
            User.role.in_(("org_admin", "superadmin")),
            User.is_active == True,
        ).all()
        for admin in admins:
            try:
                send_domain_join_request_to_admin(
                    to=admin.email,
                    admin_display_name=admin.display_name or admin.email,
                    org_name=org.name,
                    requester_email=body.email,
                    requester_display_name=body.display_name or body.email.split("@")[0],
                )
            except Exception as e:
                logger.warning(f"Failed to notify admin {admin.email} (non-fatal): {e}")

    return {
        "status": "pending_approval",
        "joined_org_name": org.name,
        "email": body.email,
        "message": (
            f"Your request to join {org.name} has been sent to its administrators. "
            f"You'll get an email when it's approved."
        ),
    }


class VerifyEmailRequest(BaseModel):
    token: str


@router.post("/verify-email")
@limiter.limit("10/minute")
async def verify_email(body: VerifyEmailRequest, request: Request, db: Session = Depends(get_db)):
    """Verify a user's email address using the token from the verification email."""
    user = db.query(User).filter(User.email_verify_token == body.token).first()
    if not user or not user.email_verify_expires or user.email_verify_expires < datetime.utcnow():
        raise HTTPException(400, "Invalid or expired verification link")

    user.email_verified = True
    user.email_verify_token = None
    user.email_verify_expires = None
    db.commit()

    logger.info(f"Email verified: {user.email}")
    return {"status": "ok", "message": "Email verified successfully"}


@router.post("/resend-verification")
@limiter.limit("3/minute")
async def resend_verification(request: Request, db: Session = Depends(get_db), current_user: User = Depends(require_auth)):
    """Resend the email verification link to the current user."""
    if current_user.email_verified:
        return {"status": "ok", "message": "Email already verified"}

    verify_token = secrets.token_urlsafe(32)
    current_user.email_verify_token = verify_token
    current_user.email_verify_expires = datetime.utcnow() + timedelta(hours=24)
    db.commit()

    try:
        from services.brevo import send_email_verification, is_configured as brevo_configured
        if brevo_configured():
            send_email_verification(current_user.email, current_user.display_name, verify_token)
            return {"status": "ok", "message": "Verification email sent"}
        else:
            raise HTTPException(503, "Email service is not configured")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        raise HTTPException(500, "Failed to send verification email")


@router.post("/login")
@limiter.limit("5/minute")
async def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate with email + password, returns JWT."""
    locale = get_locale_from_request(request)
    user = db.query(User).filter(User.email == body.email).first()

    now = datetime.utcnow()
    if user and user.locked_until and user.locked_until > now:
        minutes_remaining = max(1, int((user.locked_until - now).total_seconds() // 60) + 1)
        raise HTTPException(
            423,
            translate("account_locked", locale, minutes=minutes_remaining),
        )

    # Account exists but has no password → was created via Google SSO.
    if user and not user.hashed_password:
        raise HTTPException(401, translate("use_google_signin", locale))

    if not user or not verify_password(body.password, user.hashed_password):
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= LOGIN_FAILURE_THRESHOLD:
                user.locked_until = now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
                logger.warning(
                    f"Account locked due to repeated failures: {user.email}"
                )
            db.commit()
        raise HTTPException(401, translate("invalid_credentials", locale))
    if not user.is_active:
        raise HTTPException(403, translate("account_deactivated", locale))

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or not org.is_active:
        raise HTTPException(403, translate("org_deactivated", locale))

    # Successful login — clear counters and update last_login_at.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now

    # Backfill any missing built-in team roles, tags, and auto-tag rules.
    seed_builtin_team_roles(db, org.id)

    db.commit()

    token = create_access_token(user.id, org.id, user.role)

    _track_auth(user, org, "user_logged_in")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(user, org),
    }


# ── Google OAuth (public) ────────────────────────────────

@router.post("/google")
@limiter.limit("5/minute")
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
        # Google-verified email → mark as verified
        if not user.email_verified:
            user.email_verified = True
        user.last_login_at = datetime.utcnow()

        # Backfill any missing built-in team roles, tags, and auto-tag rules.
        seed_builtin_team_roles(db, org.id)

        db.commit()

        token = create_access_token(user.id, org.id, user.role)
        _track_auth(user, org, "user_logged_in")
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": _user_response(user, org),
        }
    else:
        # ── New user: register ──
        display_name = idinfo.get("name") or email.split("@")[0]
        domain = extract_domain(email)

        # If another org already claims this domain and has domain auto-join
        # enabled, drop the new user into it. Google guarantees email
        # verification, so this is safe without an extra round-trip.
        claimed_org = None
        if not is_public_email_domain(domain):
            claimed_org = db.query(Organization).filter(
                Organization.claimed_domain == domain,
                Organization.is_active == True,
            ).first()

        if claimed_org and claimed_org.domain_join_mode == "auto":
            org = claimed_org
            new_org_created = False
        else:
            # Create a new org from the email domain. Auto-claim the domain
            # iff it's a corporate (non-public) domain not already claimed.
            org_name = domain.split(".")[0].title() if domain else "My Org"
            slug = _slugify(org_name)
            base_slug = slug
            counter = 1
            while db.query(Organization).filter(Organization.slug == slug).first():
                slug = f"{base_slug}-{counter}"
                counter += 1

            auto_claim = (
                not is_public_email_domain(domain)
                and claimed_org is None
            )
            org = Organization(
                name=org_name,
                slug=slug,
                claimed_domain=domain if auto_claim else None,
                domain_join_mode="auto" if auto_claim else "disabled",
            )
            db.add(org)
            db.flush()
            new_org_created = True

        # Seed built-in team-scoped roles only when we created the org —
        # otherwise we'd reseed the existing org on every domain auto-join.
        if new_org_created:
            seed_builtin_team_roles(db, org.id)

        if not new_org_created:
            # Joining a claimed org via Google: assume the org's configured
            # default role for new domain joiners, never admin.
            role = org.domain_join_default_role or "viewer"
        else:
            user_count = db.query(func.count(User.id)).scalar()
            role = "superadmin" if user_count == 0 else "org_admin"

        user = User(
            email=email,
            hashed_password=None,
            display_name=display_name,
            org_id=org.id,
            role=role,
            google_id=google_sub,
            email_verified=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        db.refresh(org)

        token = create_access_token(user.id, org.id, user.role)
        logger.info(
            f"Google registration: {email} → org '{org.name}' "
            f"(role={role}, {'joined existing' if not new_org_created else 'new org'})"
        )

        # Trigger EASM discovery for newly-created corporate email orgs only —
        # the existing org already had its EASM trigger fired at signup.
        if new_org_created:
            try:
                await trigger_easm_for_new_org(db, org, email)
            except Exception as e:
                logger.warning(f"EASM trigger failed (non-fatal): {e}")

        _track_auth(user, org, "user_registered")

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": _user_response(user, org),
        }


# ── Password reset (public) ───────────────────────────────

@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(body: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
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
@limiter.limit("5/minute")
async def reset_password(body: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Reset password using a valid token from a reset email."""
    pw_error = validate_password_strength(body.new_password)
    if pw_error:
        raise HTTPException(400, pw_error)

    user = db.query(User).filter(User.password_reset_token == body.token).first()
    if not user or not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
        raise HTTPException(400, "Invalid or expired reset token")

    user.hashed_password = hash_password(body.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    # Reset lockout on successful password change.
    user.failed_login_count = 0
    user.locked_until = None
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


@router.post("/refresh")
async def refresh_token(user: User = Depends(require_auth), db: Session = Depends(get_db)):
    """Issue a fresh JWT for an authenticated user whose token is still valid.
    This allows mobile clients to silently extend sessions without re-login.
    """
    if not user.is_active:
        raise HTTPException(403, "Account deactivated")
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or not org.is_active:
        raise HTTPException(403, "Organization deactivated")
    token = create_access_token(user.id, org.id, user.role)
    return {"access_token": token, "token_type": "bearer"}


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, user: User = Depends(require_auth), db: Session = Depends(get_db)):
    # SSO-only accounts (Google) start with hashed_password = NULL; allow setting one
    # without a current password. Otherwise require and verify the current password.
    is_setting_initial = not user.hashed_password
    if not is_setting_initial:
        if not body.current_password or not verify_password(body.current_password, user.hashed_password):
            raise HTTPException(400, "Current password is incorrect")
    pw_error = validate_password_strength(body.new_password)
    if pw_error:
        raise HTTPException(400, pw_error)
    user.hashed_password = hash_password(body.new_password)
    log_audit(db, "update", "user", user.id, entity_name=user.email,
              changes={"password": "set" if is_setting_initial else "changed"}, actor=user)
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
    """Invite a new user to the current user's organization.

    If password is provided, user is created with that password.
    If password is omitted, an activation email is sent so the user can set their own password.
    """
    from services.brevo import send_user_invite, is_configured as brevo_configured

    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")

    if body.role not in ("org_admin", "analyst", "viewer", "custom"):
        raise HTTPException(400, "Invalid role. Use: org_admin, analyst, viewer, custom")

    if body.password and len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    if not body.password and not brevo_configured():
        raise HTTPException(400, "Email service not configured. Please provide an initial password.")

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    display_name = body.display_name or body.email.split("@")[0]

    user_kwargs = dict(
        email=body.email,
        display_name=display_name,
        org_id=user.org_id,
        role=body.role,
    )

    email_sent = False
    if body.password:
        user_kwargs["hashed_password"] = hash_password(body.password)
    else:
        # Generate unusable placeholder password and activation token
        token = secrets.token_urlsafe(32)
        user_kwargs["hashed_password"] = hash_password(secrets.token_hex(32))
        user_kwargs["password_reset_token"] = token
        user_kwargs["password_reset_expires"] = datetime.utcnow() + timedelta(hours=24)

    new_user = User(**user_kwargs)
    db.add(new_user)
    db.flush()
    log_audit(db, "create", "user", new_user.id,
              entity_name=new_user.email,
              changes={"email": new_user.email, "role": new_user.role, "display_name": new_user.display_name},
              actor=user)

    if not body.password:
        try:
            send_user_invite(body.email, display_name, org.name if org else "your organization", token)
            email_sent = True
        except Exception as e:
            logger.error(f"Failed to send invite email to {body.email}: {e}")

    db.commit()
    db.refresh(new_user)

    result = _user_response(new_user, org)
    result["invite_email_sent"] = email_sent
    return result


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

    # Seed built-in team roles so the new org has team-scoped RBAC out of the box.
    seed_builtin_team_roles(db, new_org.id)

    # If created by MSSP org_admin, auto-create access link
    if user.role != "superadmin" and body.parent_org_id:
        link = MSSPOrgAccess(mssp_org_id=body.parent_org_id, client_org_id=new_org.id)
        db.add(link)

    log_audit(db, "create", "organization", new_org.id,
              entity_name=new_org.name,
              changes={"name": new_org.name, "org_type": new_org.org_type},
              actor=user)

    activation_link = None
    email_sent = False
    if body.admin_email:
        from services.brevo import send_org_admin_activation, is_configured as brevo_configured
        if db.query(User).filter(User.email == body.admin_email).first():
            raise HTTPException(400, f"Email {body.admin_email} is already registered")
        token = secrets.token_urlsafe(32)
        admin_user = User(
            email=body.admin_email,
            hashed_password=hash_password(secrets.token_hex(32)),  # unusable placeholder — user must activate via link
            display_name=body.admin_email.split("@")[0],
            org_id=new_org.id,
            role="org_admin",
            password_reset_token=token,
            password_reset_expires=datetime.utcnow() + timedelta(hours=24),
        )
        db.add(admin_user)
        activation_link = f"{APP_URL}/reset-password?token={token}"
        if brevo_configured():
            try:
                send_org_admin_activation(body.admin_email, new_org.name, token)
                email_sent = True
            except Exception as e:
                logger.error(f"Failed to send org admin activation email: {e}")

    db.commit()
    db.refresh(new_org)
    result = _org_response(new_org)
    if body.admin_email:
        result["admin_activation_link"] = activation_link
        result["admin_email_sent"] = email_sent
    return result


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

    # Every FK from a tenant-scoped row up to its parent is ``ON DELETE
    # CASCADE`` (see migration 073_cascade_org_delete), so deleting the
    # organization prunes the full subtree in one transaction. We issue a
    # raw DELETE instead of ``db.delete(org)`` because the ORM unit-of-work
    # eagerly nulls out children before the DB-level CASCADE fires, which
    # fails on NOT NULL columns like ``users.org_id``.
    log_audit(db, "delete", "organization", org_id, entity_name=_org_name, actor=user)
    db.execute(text("DELETE FROM organizations WHERE id = :oid"), {"oid": org_id})
    db.commit()
    return {"status": "deleted", "id": org_id}


# ── Domain claim & auto-join ──────────────────────────────

class DomainSettingsRequest(BaseModel):
    claimed_domain: Optional[str] = None  # "" or null clears the claim
    domain_join_mode: Optional[str] = None  # disabled | request | auto
    domain_join_default_role: Optional[str] = None  # viewer | analyst | org_admin


def _domain_settings_response(org: Organization) -> dict:
    return {
        "org_id": org.id,
        "org_name": org.name,
        "claimed_domain": org.claimed_domain,
        "domain_join_mode": org.domain_join_mode or "disabled",
        "domain_join_default_role": org.domain_join_default_role or "viewer",
    }


@router.get("/org-by-domain")
@limiter.limit("30/minute")
async def lookup_org_by_domain(
    request: Request,
    email: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Public lookup. Given an email or domain, return the org that has
    claimed it — but only when its admin has opened domain-based join.
    Returns 200 with ``{"matched": false}`` if no joinable match (so we
    don't expose orgs that have join disabled)."""
    raw = (domain or extract_domain(email or "")).lower().strip()
    if not raw or is_public_email_domain(raw):
        return {"matched": False}

    org = db.query(Organization).filter(
        Organization.claimed_domain == raw,
        Organization.is_active == True,
    ).first()
    if not org or org.domain_join_mode == "disabled":
        return {"matched": False}
    return {
        "matched": True,
        "org_name": org.name,
        "domain": raw,
        "join_mode": org.domain_join_mode,  # 'request' or 'auto'
    }


@router.get("/domain-settings")
async def get_domain_settings(
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Return the current org's domain-claim and auto-join configuration."""
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return _domain_settings_response(org)


@router.patch("/domain-settings")
async def update_domain_settings(
    body: DomainSettingsRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Update domain claim & auto-join settings for the current org.

    A domain can only be claimed if (a) it's not on the public-email
    blocklist, and (b) no other org has already claimed it. The admin's
    own email domain is always considered a valid claim — they
    self-served the org so they implicitly own it.
    """
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    _old = {
        "claimed_domain": org.claimed_domain,
        "domain_join_mode": org.domain_join_mode,
        "domain_join_default_role": org.domain_join_default_role,
    }

    if body.claimed_domain is not None:
        new_domain = body.claimed_domain.strip().lower() or None
        if new_domain and new_domain != org.claimed_domain:
            if is_public_email_domain(new_domain):
                raise HTTPException(400, (
                    "Public email domains (gmail.com, outlook.com, etc.) "
                    "cannot be claimed."
                ))
            # Basic shape check; matches the email-extraction rules.
            if "." not in new_domain or " " in new_domain:
                raise HTTPException(400, "Invalid domain")
            # Require the admin's own email to be on the domain unless
            # they're a superadmin overriding the rule.
            if user.role != "superadmin":
                admin_domain = extract_domain(user.email)
                if admin_domain != new_domain:
                    raise HTTPException(403, (
                        f"You can only claim a domain matching your own "
                        f"email ({admin_domain}). Ask a superadmin if you "
                        f"need to claim a different domain."
                    ))
            existing = db.query(Organization).filter(
                Organization.claimed_domain == new_domain,
                Organization.id != org.id,
            ).first()
            if existing:
                raise HTTPException(409, (
                    f"That domain is already claimed by another organization."
                ))
        org.claimed_domain = new_domain

    if body.domain_join_mode is not None:
        if body.domain_join_mode not in ("disabled", "request", "auto"):
            raise HTTPException(400, "domain_join_mode must be disabled, request, or auto")
        if body.domain_join_mode != "disabled" and not org.claimed_domain and body.claimed_domain in (None, ""):
            raise HTTPException(400, "Claim a domain before enabling auto-join")
        org.domain_join_mode = body.domain_join_mode

    if body.domain_join_default_role is not None:
        if body.domain_join_default_role not in ("viewer", "analyst", "org_admin"):
            raise HTTPException(400, "domain_join_default_role must be viewer, analyst, or org_admin")
        if body.domain_join_default_role == "org_admin" and user.role != "superadmin":
            raise HTTPException(403, "Only superadmin can default new joiners to org_admin")
        org.domain_join_default_role = body.domain_join_default_role

    _new = {
        "claimed_domain": org.claimed_domain,
        "domain_join_mode": org.domain_join_mode,
        "domain_join_default_role": org.domain_join_default_role,
    }
    log_audit(db, "update", "organization", org.id, entity_name=org.name,
              changes=_diff(_old, _new), actor=user)
    db.commit()
    db.refresh(org)
    return _domain_settings_response(org)


def _join_request_response(jr: OrgJoinRequest) -> dict:
    return {
        "id": jr.id,
        "org_id": jr.org_id,
        "email": jr.email,
        "display_name": jr.display_name,
        "requested_role": jr.requested_role,
        "status": jr.status,
        "denial_reason": jr.denial_reason,
        "created_at": iso_utc(jr.created_at),
        "expires_at": iso_utc(jr.expires_at),
        "decided_at": iso_utc(jr.decided_at),
        "decided_by_user_id": jr.decided_by_user_id,
    }


@router.get("/join-requests")
async def list_join_requests(
    status_filter: Optional[str] = Query(None, alias="status"),
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """List join requests targeting the current admin's org. Defaults to
    ``pending`` only; pass ``?status=all`` to include decided ones."""
    q = db.query(OrgJoinRequest).filter(OrgJoinRequest.org_id == user.org_id)
    if status_filter and status_filter != "all":
        q = q.filter(OrgJoinRequest.status == status_filter)
    elif not status_filter:
        q = q.filter(OrgJoinRequest.status == "pending")
    return [_join_request_response(jr) for jr in q.order_by(OrgJoinRequest.created_at.desc()).all()]


class JoinRequestDecisionRequest(BaseModel):
    reason: Optional[str] = None  # only used on deny


@router.post("/join-requests/{request_id}/approve")
async def approve_join_request(
    request_id: int,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Approve a pending join request. Creates the User in the admin's org
    using the password the requester chose at signup. Their email_verified
    flag is set to True — the admin's approval acts as the vouch."""
    from services.brevo import send_domain_join_approved, is_configured as brevo_configured

    jr = db.query(OrgJoinRequest).filter(OrgJoinRequest.id == request_id).first()
    if not jr:
        raise HTTPException(404, "Join request not found")
    if jr.org_id != user.org_id and user.role != "superadmin":
        raise HTTPException(403, "Cannot manage join requests for another organization")
    if jr.status != "pending":
        raise HTTPException(400, f"Request is already {jr.status}")
    if jr.expires_at and jr.expires_at < datetime.utcnow():
        jr.status = "expired"
        db.commit()
        raise HTTPException(400, "Request has expired")

    if db.query(User).filter(User.email == jr.email).first():
        raise HTTPException(409, "A user with that email already exists")

    new_user = User(
        email=jr.email,
        hashed_password=jr.hashed_password,
        display_name=jr.display_name or jr.email.split("@")[0],
        org_id=jr.org_id,
        role=jr.requested_role or "viewer",
        email_verified=True,
    )
    db.add(new_user)
    jr.status = "approved"
    jr.decided_at = datetime.utcnow()
    jr.decided_by_user_id = user.id
    db.flush()

    org = db.query(Organization).filter(Organization.id == jr.org_id).first()
    log_audit(db, "create", "user", new_user.id,
              entity_name=new_user.email,
              changes={"email": new_user.email, "role": new_user.role, "via": "domain_join_request"},
              actor=user)
    db.commit()
    db.refresh(new_user)

    if brevo_configured():
        try:
            send_domain_join_approved(new_user.email, new_user.display_name, org.name)
        except Exception as e:
            logger.warning(f"Failed to send approval email (non-fatal): {e}")

    return {"status": "approved", "user": _user_response(new_user, org)}


@router.post("/join-requests/{request_id}/deny")
async def deny_join_request(
    request_id: int,
    body: JoinRequestDecisionRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Deny a pending join request. The requester gets an email notice."""
    from services.brevo import send_domain_join_denied, is_configured as brevo_configured

    jr = db.query(OrgJoinRequest).filter(OrgJoinRequest.id == request_id).first()
    if not jr:
        raise HTTPException(404, "Join request not found")
    if jr.org_id != user.org_id and user.role != "superadmin":
        raise HTTPException(403, "Cannot manage join requests for another organization")
    if jr.status != "pending":
        raise HTTPException(400, f"Request is already {jr.status}")

    jr.status = "denied"
    jr.denial_reason = body.reason
    jr.decided_at = datetime.utcnow()
    jr.decided_by_user_id = user.id
    org = db.query(Organization).filter(Organization.id == jr.org_id).first()
    log_audit(db, "deny", "join_request", jr.id, entity_name=jr.email,
              changes={"reason": body.reason or ""}, actor=user)
    db.commit()

    if brevo_configured():
        try:
            send_domain_join_denied(
                jr.email,
                jr.display_name or jr.email.split("@")[0],
                org.name,
                body.reason,
            )
        except Exception as e:
            logger.warning(f"Failed to send denial email (non-fatal): {e}")

    return {"status": "denied", "id": jr.id}


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


# ── MSSP Self-Serve Client Invites ───────────────────────

class MSSPInviteClientRequest(BaseModel):
    invited_email: Optional[str] = None
    client_org_name: Optional[str] = None


class AcceptInviteRequest(BaseModel):
    token: str
    org_name: str
    admin_name: str
    admin_email: str
    password: str


@router.post("/mssp/invite-client")
async def mssp_invite_client(
    body: MSSPInviteClientRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Generate a self-serve invite link for a new MSSP client org.

    Returns the invite link always. If Brevo is configured and invited_email
    is provided, also sends an invite email.
    """
    from services.brevo import send_client_invite, is_configured as brevo_configured

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org or org.org_type != "mssp":
        raise HTTPException(400, "Not an MSSP organization")
    if user.role not in ("superadmin", "org_admin"):
        raise HTTPException(403, "Insufficient permissions")

    token = secrets.token_urlsafe(32)
    invite = OrgInvite(
        token=token,
        mssp_org_id=user.org_id,
        invited_email=body.invited_email or None,
        client_org_name=body.client_org_name or None,
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db.add(invite)
    db.commit()

    invite_url = f"{APP_URL}/accept-invite?token={token}"

    email_sent = False
    if body.invited_email and brevo_configured():
        try:
            send_client_invite(body.invited_email, org.name, invite_url, body.client_org_name)
            email_sent = True
        except Exception as e:
            logger.error(f"Failed to send client invite email: {e}")

    return {
        "invite_url": invite_url,
        "token": token,
        "email_sent": email_sent,
        "expires_at": iso_utc(invite.expires_at),
    }


@router.get("/invite/{token}")
async def get_invite_info(token: str, db: Session = Depends(get_db)):
    """Return public invite metadata for a token. Used to pre-fill the registration form."""
    invite = db.query(OrgInvite).filter(OrgInvite.token == token).first()
    if not invite:
        raise HTTPException(404, "Invite not found")
    if invite.accepted_at:
        raise HTTPException(410, "This invite has already been used")
    if invite.expires_at < datetime.utcnow():
        raise HTTPException(410, "This invite has expired")

    mssp = db.query(Organization).filter(Organization.id == invite.mssp_org_id).first()
    return {
        "mssp_org_name": mssp.name if mssp else "",
        "invited_email": invite.invited_email,
        "client_org_name": invite.client_org_name,
        "expires_at": iso_utc(invite.expires_at),
    }


@router.post("/accept-invite")
@limiter.limit("10/minute")
async def accept_invite(body: AcceptInviteRequest, request: Request, db: Session = Depends(get_db)):
    """Accept an MSSP client invite — creates the new org, admin user, and MSSP access link."""
    invite = db.query(OrgInvite).filter(OrgInvite.token == body.token).first()
    if not invite:
        raise HTTPException(404, "Invite not found")
    if invite.accepted_at:
        raise HTTPException(410, "This invite has already been used")
    if invite.expires_at < datetime.utcnow():
        raise HTTPException(410, "This invite has expired")

    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if db.query(User).filter(User.email == body.admin_email).first():
        raise HTTPException(400, "Email already registered")

    mssp_org = db.query(Organization).filter(Organization.id == invite.mssp_org_id).first()
    if not mssp_org:
        raise HTTPException(400, "MSSP organization not found")

    # Create client org
    slug = _slugify(body.org_name)
    base_slug = slug
    counter = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    client_org = Organization(
        name=body.org_name,
        slug=slug,
        org_type="standard",
        parent_org_id=mssp_org.id,
    )
    db.add(client_org)
    db.flush()

    # Seed built-in team roles for the newly provisioned client org.
    seed_builtin_team_roles(db, client_org.id)

    # Create admin user
    admin = User(
        email=body.admin_email,
        hashed_password=hash_password(body.password),
        display_name=body.admin_name or body.admin_email.split("@")[0],
        org_id=client_org.id,
        role="org_admin",
    )
    db.add(admin)
    db.flush()

    # Grant MSSP access to the new client org
    link = MSSPOrgAccess(mssp_org_id=mssp_org.id, client_org_id=client_org.id)
    db.add(link)

    # Mark invite as used
    invite.accepted_at = datetime.utcnow()

    log_audit(db, "create", "organization", client_org.id,
              entity_name=client_org.name,
              changes={"name": client_org.name, "via": "mssp_invite", "mssp_org": mssp_org.name})
    db.commit()
    db.refresh(admin)

    token = create_access_token(admin.id, client_org.id, admin.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_response(admin, client_org),
    }


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
        "created_at": iso_utc(role.created_at),
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
    perms = enforce_page_consistency(perms)
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
        role.base_permissions = enforce_page_consistency(
            {k: bool(v) for k, v in body.base_permissions.items() if k in BASE_PERMISSION_KEYS}
        )
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

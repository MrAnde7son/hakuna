"""AuthProfile routes — CRUD + test-login for authenticated VM scans.

An AuthProfile pairs a login flow (URL + selectors + success condition)
with an IntegrationCredential for secrets. The session broker drives
Playwright against the flow at scan dispatch time; see
services.session_broker for the runtime.

Prefix: /api/auth-profiles
"""

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter, require_auth
from core.audit import log_audit, diff as _diff
from core.database import get_db
from models.models import AuthProfile, IntegrationCredential, User
from services import session_broker, auth_flow_detector


router = APIRouter(prefix="/api/auth-profiles", tags=["auth-profiles"])


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

SUPPORTED_TYPES = {"static", "form_login"}


class AuthProfileCreate(BaseModel):
    name: str
    profile_type: str = "form_login"
    credential_id: str
    login_url: Optional[str] = None
    login_flow: List[dict] = Field(default_factory=list)
    success_condition: dict = Field(default_factory=dict)
    session_ttl_seconds: int = 900


class AuthProfileUpdate(BaseModel):
    name: Optional[str] = None
    profile_type: Optional[str] = None
    credential_id: Optional[str] = None
    login_url: Optional[str] = None
    login_flow: Optional[List[dict]] = None
    success_condition: Optional[dict] = None
    session_ttl_seconds: Optional[int] = None


def _validate_for_type(ptype: str, login_url: Optional[str], login_flow: List[dict], success_condition: dict) -> None:
    """form_login needs url+flow+condition; static needs none of them."""
    if ptype not in SUPPORTED_TYPES:
        raise HTTPException(400, f"Unsupported profile_type: {ptype!r}. Supported: {sorted(SUPPORTED_TYPES)}")
    if ptype == "form_login":
        if not login_url:
            raise HTTPException(400, "login_url is required for form_login profiles")
        if not login_flow:
            raise HTTPException(400, "login_flow must have at least one step for form_login profiles")
        if not success_condition or not success_condition.get("type"):
            raise HTTPException(400, "success_condition with a type is required for form_login profiles")


def _to_dict(profile: AuthProfile) -> dict[str, Any]:
    return {
        "id": profile.id,
        "org_id": profile.org_id,
        "name": profile.name,
        "profile_type": profile.profile_type or "form_login",
        "credential_id": profile.credential_id,
        "login_url": profile.login_url,
        "login_flow": profile.login_flow or [],
        "success_condition": profile.success_condition or {},
        "session_ttl_seconds": profile.session_ttl_seconds,
        "session_cached": bool(profile.cached_session_blob),
        "session_expires_at": profile.session_expires_at.isoformat() if profile.session_expires_at else None,
        "created_at": profile.created_at.isoformat() if profile.created_at else None,
        "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
    }


def _require_credential(db: Session, credential_id: str, org_ids: Optional[List[int]]) -> IntegrationCredential:
    q = db.query(IntegrationCredential).filter(IntegrationCredential.id == credential_id)
    if org_ids is not None:
        # org_id can be nullable on legacy credentials; tolerate that here.
        q = q.filter(
            (IntegrationCredential.org_id.in_(org_ids))
            | (IntegrationCredential.org_id.is_(None))
        )
    cred = q.first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    return cred


# ─────────────────────────────────────────────
# CRUD
# ─────────────────────────────────────────────

@router.get("")
async def list_profiles(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(AuthProfile), AuthProfile, org_ids)
    profiles = q.order_by(AuthProfile.created_at.desc()).all()
    return [_to_dict(p) for p in profiles]


@router.get("/{profile_id}")
async def get_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(AuthProfile), AuthProfile, org_ids)
    profile = q.filter(AuthProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "AuthProfile not found")
    return _to_dict(profile)


@router.post("")
async def create_profile(
    body: AuthProfileCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    _require_credential(db, body.credential_id, org_ids)
    _validate_for_type(body.profile_type, body.login_url, body.login_flow, body.success_condition)

    existing = db.query(AuthProfile).filter(
        AuthProfile.org_id == user.org_id,
        AuthProfile.name == body.name,
    ).first()
    if existing:
        raise HTTPException(409, f"AuthProfile '{body.name}' already exists")

    profile = AuthProfile(
        org_id=user.org_id,
        name=body.name,
        profile_type=body.profile_type,
        credential_id=body.credential_id,
        login_url=body.login_url,
        login_flow=body.login_flow or [],
        success_condition=body.success_condition or {},
        session_ttl_seconds=body.session_ttl_seconds or 900,
        created_by_user_id=user.id,
    )
    db.add(profile)
    db.flush()
    log_audit(
        db, "create", "auth_profile", entity_id=None, entity_name=profile.name,
        changes={"name": profile.name, "login_url": profile.login_url}, actor=user,
    )
    db.commit()
    db.refresh(profile)
    return _to_dict(profile)


@router.patch("/{profile_id}")
async def update_profile(
    profile_id: str,
    body: AuthProfileUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(AuthProfile), AuthProfile, org_ids)
    profile = q.filter(AuthProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "AuthProfile not found")

    before = {
        "name": profile.name,
        "credential_id": profile.credential_id,
        "login_url": profile.login_url,
        "session_ttl_seconds": profile.session_ttl_seconds,
    }

    if body.credential_id and body.credential_id != profile.credential_id:
        _require_credential(db, body.credential_id, org_ids)
        profile.credential_id = body.credential_id
    if body.name is not None:
        profile.name = body.name
    if body.profile_type is not None:
        profile.profile_type = body.profile_type
    if body.login_url is not None:
        profile.login_url = body.login_url
    if body.login_flow is not None:
        profile.login_flow = body.login_flow
    if body.success_condition is not None:
        profile.success_condition = body.success_condition
    if body.session_ttl_seconds is not None:
        profile.session_ttl_seconds = body.session_ttl_seconds

    # Re-validate with the post-edit shape (mix old + new values as needed).
    _validate_for_type(
        profile.profile_type or "form_login",
        profile.login_url,
        profile.login_flow or [],
        profile.success_condition or {},
    )

    # Any edit invalidates the cached session — selectors or URL may have
    # changed. Broker will re-login on next get_or_create_session call.
    profile.cached_session_blob = None
    profile.session_expires_at = None
    profile.session_credential_hash = None

    after = {
        "name": profile.name,
        "credential_id": profile.credential_id,
        "login_url": profile.login_url,
        "session_ttl_seconds": profile.session_ttl_seconds,
    }
    log_audit(
        db, "update", "auth_profile", entity_id=None, entity_name=profile.name,
        changes=_diff(before, after), actor=user,
    )
    db.commit()
    db.refresh(profile)
    return _to_dict(profile)


@router.delete("/{profile_id}")
async def delete_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(AuthProfile), AuthProfile, org_ids)
    profile = q.filter(AuthProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "AuthProfile not found")
    name = profile.name
    db.delete(profile)
    log_audit(
        db, "delete", "auth_profile", entity_id=None, entity_name=name,
        actor=user, org_id=profile.org_id,
    )
    db.commit()
    return {"message": "AuthProfile deleted"}


# ─────────────────────────────────────────────
# Test login
# ─────────────────────────────────────────────

@router.post("/{profile_id}/test")
async def test_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Validate the profile can produce a usable auth payload.

    - form_login: drive Playwright and report captured cookie/header names
    - static: decrypt the credential and report the scheme + any header
      names we'd emit. Values are never echoed either way.
    """
    from services import credential_manager
    q = apply_org_filter(db.query(AuthProfile), AuthProfile, org_ids)
    profile = q.filter(AuthProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(404, "AuthProfile not found")

    ptype = (profile.profile_type or "form_login").lower()

    if ptype == "static":
        values = await credential_manager.load_credentials(db, profile.credential_id, profile.org_id)
        if not values:
            return {"success": False, "error": "credential not found or empty"}
        return {
            "success": True,
            "auth_type": values.get("_auth_type"),
            "captured_fields": [k for k in values.keys() if not k.startswith("_")],
        }

    # form_login — force a fresh login so the user sees the result of their
    # current config, not a stale cached one.
    session_broker.invalidate(db, profile_id)
    return await session_broker.test_login(db, profile.org_id, profile_id)


# ─────────────────────────────────────────────
# Auto-detect login flow (LLM)
# ─────────────────────────────────────────────

class DetectFlowRequest(BaseModel):
    login_url: str


@router.post("/detect-flow")
async def detect_flow(
    body: DetectFlowRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Fetch the login page and ask the LLM (same provider as the rest of
    the system — Vertex AI when configured) to propose a login_flow + success
    condition. The user reviews and edits before saving."""
    if not body.login_url or not body.login_url.strip():
        raise HTTPException(400, "login_url is required")

    result = await auth_flow_detector.detect_login_flow(
        login_url=body.login_url.strip(),
        db=db,
        org_id=user.org_id,
    )
    return result

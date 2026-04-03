"""
SAML 2.0 SSO routes.
Prefix: /api/saml

Provides:
  - SP metadata endpoint (public)
  - SSO login initiation (public)
  - ACS (Assertion Consumer Service) callback (public, POST from IdP)
  - SLO (Single Logout) endpoint (public, POST from IdP)
  - SAML config CRUD for org admins (authenticated)
"""
import os
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import (
    create_access_token, require_auth, require_role,
    get_accessible_org_ids, ACCESS_TOKEN_EXPIRE_MINUTES,
)
from core.audit import log_audit
from models.models import Organization, User, SAMLConfig

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/saml", tags=["saml"])

APP_URL = os.environ.get("APP_URL", "http://localhost:5173").rstrip("/")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")


# ── Pydantic schemas ─────────────────────────────────────

class SAMLConfigCreate(BaseModel):
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: Optional[str] = None
    idp_x509_cert: str
    sp_entity_id: Optional[str] = None
    default_role: str = "analyst"
    auto_provision: bool = True
    force_sso: bool = False
    attribute_mapping: Optional[dict] = None

class SAMLConfigUpdate(BaseModel):
    idp_entity_id: Optional[str] = None
    idp_sso_url: Optional[str] = None
    idp_slo_url: Optional[str] = None
    idp_x509_cert: Optional[str] = None
    sp_entity_id: Optional[str] = None
    default_role: Optional[str] = None
    auto_provision: Optional[bool] = None
    force_sso: Optional[bool] = None
    is_enabled: Optional[bool] = None
    attribute_mapping: Optional[dict] = None

class SAMLConfigResponse(BaseModel):
    id: int
    org_id: int
    is_enabled: bool
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: Optional[str]
    sp_entity_id: Optional[str]
    default_role: str
    auto_provision: bool
    force_sso: bool
    attribute_mapping: Optional[dict]
    created_at: Optional[str]
    updated_at: Optional[str]
    # Computed SP fields for IdP setup
    sp_acs_url: str
    sp_metadata_url: str


# ── Helpers ───────────────────────────────────────────────

def _get_saml_config_for_org(org_id: int, db: Session) -> Optional[SAMLConfig]:
    return db.query(SAMLConfig).filter(SAMLConfig.org_id == org_id).first()


def _sp_entity_id(config: SAMLConfig) -> str:
    """Return the SP Entity ID — custom or auto-generated from backend URL."""
    if config.sp_entity_id:
        return config.sp_entity_id
    return f"{BACKEND_URL}/api/saml/metadata/{config.org_id}"


def _prepare_saml_auth(request: Request, config: SAMLConfig):
    """Create a OneLogin SAML Auth object from org config and request."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    # Build the request dict that python3-saml expects
    url_data = urlparse(str(request.url))
    saml_request = {
        "https": "on" if url_data.scheme == "https" else "off",
        "http_host": request.headers.get("host", url_data.netloc),
        "script_name": url_data.path,
        "server_port": url_data.port or (443 if url_data.scheme == "https" else 80),
        "get_data": dict(request.query_params),
        "post_data": {},
    }

    sp_eid = _sp_entity_id(config)
    acs_url = f"{BACKEND_URL}/api/saml/acs/{config.org_id}"
    sls_url = f"{BACKEND_URL}/api/saml/slo/{config.org_id}"

    settings = {
        "strict": True,
        "debug": os.environ.get("SAML_DEBUG", "").lower() in ("1", "true"),
        "sp": {
            "entityId": sp_eid,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": config.idp_x509_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantNameIdEncrypted": False,
        },
    }

    if config.idp_slo_url:
        settings["idp"]["singleLogoutService"] = {
            "url": config.idp_slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    return OneLogin_Saml2_Auth(saml_request, settings)


def _config_response(config: SAMLConfig) -> dict:
    return {
        "id": config.id,
        "org_id": config.org_id,
        "is_enabled": config.is_enabled,
        "idp_entity_id": config.idp_entity_id,
        "idp_sso_url": config.idp_sso_url,
        "idp_slo_url": config.idp_slo_url,
        "sp_entity_id": _sp_entity_id(config),
        "default_role": config.default_role,
        "auto_provision": config.auto_provision,
        "force_sso": config.force_sso,
        "attribute_mapping": config.attribute_mapping or {},
        "created_at": config.created_at.isoformat() if config.created_at else None,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
        "sp_acs_url": f"{BACKEND_URL}/api/saml/acs/{config.org_id}",
        "sp_metadata_url": f"{BACKEND_URL}/api/saml/metadata/{config.org_id}",
    }


# ── Public SAML endpoints ────────────────────────────────

@router.get("/metadata/{org_id}")
async def saml_metadata(org_id: int, request: Request, db: Session = Depends(get_db)):
    """Return SP metadata XML for the given org. Used by IdP admins to configure the integration."""
    config = _get_saml_config_for_org(org_id, db)
    if not config:
        raise HTTPException(404, "SAML is not configured for this organization")

    auth = _prepare_saml_auth(request, config)
    metadata = auth.get_settings().get_sp_metadata()
    errors = auth.get_settings().validate_metadata(metadata)
    if errors:
        raise HTTPException(500, f"SP metadata validation errors: {', '.join(errors)}")

    return Response(content=metadata, media_type="application/xml")


@router.get("/login/{org_id}")
async def saml_login(org_id: int, request: Request, db: Session = Depends(get_db)):
    """Initiate SAML SSO login — redirects user to IdP."""
    config = _get_saml_config_for_org(org_id, db)
    if not config or not config.is_enabled:
        raise HTTPException(404, "SAML SSO is not enabled for this organization")

    auth = _prepare_saml_auth(request, config)
    redirect_url = auth.login(return_to=f"{APP_URL}/sso/callback")
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/acs/{org_id}")
async def saml_acs(org_id: int, request: Request, db: Session = Depends(get_db)):
    """Assertion Consumer Service — receives SAML response from IdP after authentication."""
    config = _get_saml_config_for_org(org_id, db)
    if not config or not config.is_enabled:
        raise HTTPException(404, "SAML SSO is not enabled for this organization")

    # Parse form data from IdP POST
    form_data = await request.form()
    post_data = dict(form_data)

    # Build SAML auth with POST data
    url_data = urlparse(str(request.url))
    saml_request = {
        "https": "on" if url_data.scheme == "https" else "off",
        "http_host": request.headers.get("host", url_data.netloc),
        "script_name": url_data.path,
        "server_port": url_data.port or (443 if url_data.scheme == "https" else 80),
        "get_data": dict(request.query_params),
        "post_data": post_data,
    }

    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    sp_eid = _sp_entity_id(config)
    acs_url = f"{BACKEND_URL}/api/saml/acs/{config.org_id}"
    sls_url = f"{BACKEND_URL}/api/saml/slo/{config.org_id}"

    settings = {
        "strict": True,
        "debug": os.environ.get("SAML_DEBUG", "").lower() in ("1", "true"),
        "sp": {
            "entityId": sp_eid,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": config.idp_x509_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantNameIdEncrypted": False,
        },
    }

    if config.idp_slo_url:
        settings["idp"]["singleLogoutService"] = {
            "url": config.idp_slo_url,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    auth = OneLogin_Saml2_Auth(saml_request, settings)
    auth.process_response()
    errors = auth.get_errors()

    if errors:
        logger.error("SAML ACS errors for org %d: %s (reason: %s)", org_id, errors, auth.get_last_error_reason())
        return RedirectResponse(
            url=f"{APP_URL}/login?sso_error=saml_validation_failed",
            status_code=302,
        )

    if not auth.is_authenticated():
        return RedirectResponse(
            url=f"{APP_URL}/login?sso_error=not_authenticated",
            status_code=302,
        )

    # Extract user attributes from SAML assertion
    attributes = auth.get_attributes()
    name_id = auth.get_nameid()
    attr_map = config.attribute_mapping or {}

    # Resolve email: from attribute mapping, or NameID
    email = None
    email_attr = attr_map.get("email")
    if email_attr and email_attr in attributes:
        email = attributes[email_attr][0]
    if not email:
        # Try common SAML attribute names
        for attr_name in [
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "email", "mail", "Email", "emailAddress",
        ]:
            if attr_name in attributes:
                email = attributes[attr_name][0]
                break
    if not email:
        email = name_id  # Fall back to NameID (often email for emailAddress format)

    if not email:
        return RedirectResponse(
            url=f"{APP_URL}/login?sso_error=no_email_in_assertion",
            status_code=302,
        )

    email = email.lower().strip()

    # Resolve display name
    display_name = None
    dn_attr = attr_map.get("display_name")
    if dn_attr and dn_attr in attributes:
        display_name = attributes[dn_attr][0]
    if not display_name:
        for attr_name in [
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "displayName", "display_name", "name", "cn",
        ]:
            if attr_name in attributes:
                display_name = attributes[attr_name][0]
                break

    # Find or create user
    user = db.query(User).filter(User.email == email, User.org_id == org_id).first()

    if not user:
        # Try matching by saml_subject_id
        user = db.query(User).filter(User.saml_subject_id == name_id, User.org_id == org_id).first()

    if user:
        # Existing user — update SAML link and login timestamp
        if not user.saml_subject_id:
            user.saml_subject_id = name_id
        if not user.is_active:
            return RedirectResponse(
                url=f"{APP_URL}/login?sso_error=account_deactivated",
                status_code=302,
            )
        user.last_login_at = datetime.utcnow()
        if not user.email_verified:
            user.email_verified = True  # IdP-verified email
        db.commit()
    elif config.auto_provision:
        # JIT provisioning: create new user
        org = db.query(Organization).filter(Organization.id == org_id, Organization.is_active == True).first()
        if not org:
            return RedirectResponse(
                url=f"{APP_URL}/login?sso_error=org_not_found",
                status_code=302,
            )

        # Resolve role from attribute mapping or default
        role = config.default_role
        role_attr = attr_map.get("role")
        if role_attr and role_attr in attributes:
            mapped_role = attributes[role_attr][0].lower()
            if mapped_role in ("org_admin", "analyst", "viewer"):
                role = mapped_role

        user = User(
            email=email,
            display_name=display_name or email.split("@")[0],
            org_id=org_id,
            role=role,
            saml_subject_id=name_id,
            email_verified=True,
            last_login_at=datetime.utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("SAML JIT provisioned user %s for org %d", email, org_id)
    else:
        return RedirectResponse(
            url=f"{APP_URL}/login?sso_error=user_not_found",
            status_code=302,
        )

    # Issue JWT token and redirect to frontend
    token = create_access_token(user.id, user.org_id, user.role)
    return RedirectResponse(
        url=f"{APP_URL}/sso/callback?token={token}",
        status_code=302,
    )


@router.post("/slo/{org_id}")
async def saml_slo(org_id: int, request: Request, db: Session = Depends(get_db)):
    """Single Logout Service — processes logout request from IdP."""
    config = _get_saml_config_for_org(org_id, db)
    if not config:
        raise HTTPException(404, "SAML is not configured for this organization")

    # For now, redirect to frontend logout
    return RedirectResponse(url=f"{APP_URL}/login?slo=1", status_code=302)


# ── SSO discovery (public) ────────────────────────────────

@router.get("/discover")
async def saml_discover(email: str = Query(...), db: Session = Depends(get_db)):
    """Check if an email domain has SAML SSO configured. Used by the login page."""
    domain = email.strip().lower().split("@")[-1] if "@" in email else None
    if not domain:
        return {"sso_enabled": False}

    # Find orgs with SAML enabled whose domain matches
    configs = db.query(SAMLConfig).filter(SAMLConfig.is_enabled == True).all()
    for config in configs:
        org = db.query(Organization).filter(Organization.id == config.org_id).first()
        if not org:
            continue
        # Match by org's EASM domain or by checking existing users with same domain
        if org.easm_domain and org.easm_domain.lower() == domain:
            return {
                "sso_enabled": True,
                "org_id": config.org_id,
                "org_name": org.name,
                "login_url": f"{BACKEND_URL}/api/saml/login/{config.org_id}",
                "force_sso": config.force_sso,
            }

    return {"sso_enabled": False}


# ── Config CRUD (org_admin+) ─────────────────────────────

@router.get("/config")
async def get_saml_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "org_admin")),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get SAML config for the current user's org."""
    config = db.query(SAMLConfig).filter(SAMLConfig.org_id == current_user.org_id).first()
    if not config:
        return {"configured": False}
    return {"configured": True, **_config_response(config)}


@router.post("/config")
async def create_saml_config(
    body: SAMLConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "org_admin")),
):
    """Create SAML configuration for the current user's org."""
    existing = db.query(SAMLConfig).filter(SAMLConfig.org_id == current_user.org_id).first()
    if existing:
        raise HTTPException(409, "SAML configuration already exists. Use PATCH to update.")

    valid_roles = ("org_admin", "analyst", "viewer")
    if body.default_role not in valid_roles:
        raise HTTPException(400, f"default_role must be one of: {', '.join(valid_roles)}")

    config = SAMLConfig(
        org_id=current_user.org_id,
        is_enabled=False,  # Must be explicitly enabled after creation
        idp_entity_id=body.idp_entity_id,
        idp_sso_url=body.idp_sso_url,
        idp_slo_url=body.idp_slo_url,
        idp_x509_cert=body.idp_x509_cert,
        sp_entity_id=body.sp_entity_id,
        default_role=body.default_role,
        auto_provision=body.auto_provision,
        force_sso=body.force_sso,
        attribute_mapping=body.attribute_mapping or {},
    )
    db.add(config)
    db.commit()
    db.refresh(config)

    log_audit(db, current_user.id, current_user.org_id, "saml_config_created", "saml_config", config.id)
    return _config_response(config)


@router.patch("/config")
async def update_saml_config(
    body: SAMLConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "org_admin")),
):
    """Update SAML configuration for the current user's org."""
    config = db.query(SAMLConfig).filter(SAMLConfig.org_id == current_user.org_id).first()
    if not config:
        raise HTTPException(404, "No SAML configuration found. Create one first.")

    updates = body.model_dump(exclude_unset=True)

    if "default_role" in updates:
        valid_roles = ("org_admin", "analyst", "viewer")
        if updates["default_role"] not in valid_roles:
            raise HTTPException(400, f"default_role must be one of: {', '.join(valid_roles)}")

    for key, value in updates.items():
        setattr(config, key, value)

    config.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(config)

    log_audit(db, current_user.id, current_user.org_id, "saml_config_updated", "saml_config", config.id)
    return _config_response(config)


@router.delete("/config")
async def delete_saml_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("superadmin", "org_admin")),
):
    """Delete SAML configuration for the current user's org."""
    config = db.query(SAMLConfig).filter(SAMLConfig.org_id == current_user.org_id).first()
    if not config:
        raise HTTPException(404, "No SAML configuration found.")

    db.delete(config)
    db.commit()

    log_audit(db, current_user.id, current_user.org_id, "saml_config_deleted", "saml_config", None)
    return {"detail": "SAML configuration deleted"}

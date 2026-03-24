"""
API Discovery + OAuth2 + File Upload + Auto-Provision routes.
Prefix: /api/integration-builder
"""
import os
import json
import logging
import secrets
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import require_auth
from models.models import User, DiscoveredSpec, IntegrationCredential
from services import credential_vault

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/integration-builder", tags=["integration-builder-discovery"])


# ─────────────────────────────────────────────────────────
# Discovery
# ─────────────────────────────────────────────────────────

class DiscoverRequest(BaseModel):
    url: str


@router.post("/discovery/discover")
async def discover_api(body: DiscoverRequest, user: User = Depends(require_auth)):
    """Discover API spec at a URL. Returns SSE-style JSON events."""
    from services.spec_discovery import discover

    events = []

    def progress(event_type, **kwargs):
        events.append({"type": event_type, **kwargs})

    result = await discover(body.url, progress_callback=progress)

    # Cache if found
    if result.spec_source != "none" and result.raw_spec:
        from urllib.parse import urlparse
        hostname = urlparse(body.url).hostname or body.url
        db = next(get_db())
        try:
            existing = db.query(DiscoveredSpec).filter(DiscoveredSpec.hostname == hostname).first()
            if existing:
                existing.spec_source = result.spec_source
                existing.raw_spec = result.raw_spec
                existing.parsed_spec = {
                    "tool_name": result.tool_name,
                    "endpoints": result.endpoints,
                    "auth_schemes": result.auth_schemes,
                }
                from datetime import datetime
                existing.refreshed_at = datetime.utcnow()
            else:
                spec = DiscoveredSpec(
                    hostname=hostname,
                    spec_source=result.spec_source,
                    raw_spec=result.raw_spec,
                    parsed_spec={
                        "tool_name": result.tool_name,
                        "endpoints": result.endpoints,
                        "auth_schemes": result.auth_schemes,
                    },
                )
                db.add(spec)
            db.commit()
        except Exception as e:
            logger.error("Failed to cache spec: %s", e)
        finally:
            db.close()

    return {
        "events": events,
        "spec_source": result.spec_source,
        "tool_name": result.tool_name,
        "base_url": result.base_url,
        "auth_schemes": result.auth_schemes,
        "endpoints": result.endpoints,
        "endpoint_count": result.endpoint_count,
        "error": result.error,
    }


class ParseDocsRequest(BaseModel):
    url: Optional[str] = None
    content: Optional[str] = None


@router.post("/discovery/parse-docs")
async def parse_docs(body: ParseDocsRequest = None, file: UploadFile = File(None),
                      user: User = Depends(require_auth)):
    """LLM-assisted doc parsing from URL, pasted content, or file upload."""
    from services.spec_discovery import parse_docs_with_llm
    import httpx

    content = ""
    base_url = ""

    if file:
        raw = await file.read()
        content = raw.decode("utf-8", errors="replace")
    elif body and body.url:
        base_url = body.url
        async with httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(body.url)
            content = resp.text
    elif body and body.content:
        content = body.content
    else:
        raise HTTPException(400, "Provide a URL, content, or file upload")

    if not content.strip():
        raise HTTPException(400, "Empty content")

    result = await parse_docs_with_llm(content, base_url)

    return {
        "spec_source": result.spec_source,
        "tool_name": result.tool_name,
        "base_url": result.base_url,
        "auth_schemes": result.auth_schemes,
        "endpoints": result.endpoints,
        "endpoint_count": result.endpoint_count,
        "error": result.error,
        "ai_generated": True,
    }


@router.get("/discovery/cache/{hostname}")
def get_cached_spec(hostname: str, db: Session = Depends(get_db),
                     user: User = Depends(require_auth)):
    """Return cached ParsedSpec if exists."""
    spec = db.query(DiscoveredSpec).filter(DiscoveredSpec.hostname == hostname).first()
    if not spec:
        raise HTTPException(404, "No cached spec for this hostname")
    return {
        "id": spec.id,
        "hostname": spec.hostname,
        "spec_source": spec.spec_source,
        "parsed_spec": spec.parsed_spec,
        "discovered_at": spec.discovered_at,
        "refreshed_at": spec.refreshed_at,
    }


@router.delete("/discovery/cache/{hostname}")
def delete_cached_spec(hostname: str, db: Session = Depends(get_db),
                        user: User = Depends(require_auth)):
    """Invalidate cached spec."""
    spec = db.query(DiscoveredSpec).filter(DiscoveredSpec.hostname == hostname).first()
    if spec:
        db.delete(spec)
        db.commit()
    return {"deleted": True}


# ─────────────────────────────────────────────────────────
# MCP Tool Discovery
# ─────────────────────────────────────────────────────────

class McpDiscoverRequest(BaseModel):
    server_url: str
    credentials_id: Optional[str] = None


@router.post("/discovery/mcp-tools")
async def discover_mcp_tools(body: McpDiscoverRequest, db: Session = Depends(get_db),
                              user: User = Depends(require_auth)):
    """Discover available tools on an MCP server via tools/list."""
    from services.transports.mcp_transport import discover_tools, McpAuthRequired

    credentials = {}
    if body.credentials_id:
        cred = db.query(IntegrationCredential).filter(
            IntegrationCredential.id == body.credentials_id,
            IntegrationCredential.org_id == user.org_id,
        ).first()
        if cred:
            credentials = credential_vault.decrypt(cred.encrypted_values)
            credentials["_auth_type"] = cred.auth_type

    try:
        result = await discover_tools(body.server_url, credentials)
        return result
    except McpAuthRequired as e:
        return {
            "auth_required": True,
            "error": str(e),
            "oauth_info": e.oauth_info,
            "oauth_metadata": e.oauth_metadata,
            "protected_resource_url": e.protected_resource_url,
        }
    except Exception as e:
        raise HTTPException(400, f"MCP discovery failed: {e}")


class McpOAuthStartRequest(BaseModel):
    server_url: str
    oauth_metadata: dict  # from the discovery response


@router.post("/oauth/mcp-start")
async def mcp_oauth_start(body: McpOAuthStartRequest, user: User = Depends(require_auth)):
    """Start OAuth 2.1 flow for an MCP server using discovered metadata."""
    import hashlib
    import base64

    auth_endpoint = body.oauth_metadata.get("authorization_endpoint")
    token_endpoint = body.oauth_metadata.get("token_endpoint")
    registration_endpoint = body.oauth_metadata.get("registration_endpoint")

    if not auth_endpoint or not token_endpoint:
        raise HTTPException(400, "OAuth metadata missing authorization_endpoint or token_endpoint")

    scopes = body.oauth_metadata.get("scopes_supported", [])
    redirect_uri = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8000/api/integration-builder/oauth/callback")

    # Dynamic client registration if supported and no static client_id configured
    client_id = os.environ.get("MCP_OAUTH_CLIENT_ID", "")
    if not client_id and registration_endpoint:
        import httpx as _httpx
        try:
            async with _httpx.AsyncClient(timeout=10.0, verify=False) as client:
                reg_resp = await client.post(registration_endpoint, json={
                    "client_name": "Hakuna Integration Builder",
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                })
                if reg_resp.status_code < 400:
                    reg_data = reg_resp.json()
                    client_id = reg_data.get("client_id", "")
        except Exception as e:
            logger.warning("Dynamic client registration failed: %s", e)

    if not client_id:
        # Use the redirect_uri as client_id per MCP spec (Client ID Metadata Document)
        client_id = redirect_uri

    # PKCE
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": " ".join(scopes) if scopes else "",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "resource": body.server_url,  # RFC 8707 resource indicator
    }
    query = "&".join(f"{k}={v}" for k, v in params.items() if v)
    authorization_url = f"{auth_endpoint}?{query}"

    # Store state for callback
    _oauth_states[state] = {
        "connector_id": "mcp",
        "code_verifier": code_verifier,
        "instance_url": body.server_url,
        "user_id": user.id,
        "org_id": user.org_id,
        "redirect_uri": redirect_uri,
        "token_url": token_endpoint,
        "client_id": client_id,
        "validation_request": None,  # MCP doesn't have a separate validation step
    }

    return {"authorization_url": authorization_url, "state": state}


# ─────────────────────────────────────────────────────────
# OAuth2 Server-Side Flow
# ─────────────────────────────────────────────────────────

# In-memory state store for OAuth flows (use Redis in production)
_oauth_states = {}


class OAuthStartRequest(BaseModel):
    instance_url: Optional[str] = None


@router.post("/oauth/start/{connector_id}")
async def oauth_start(connector_id: str, body: OAuthStartRequest = None,
                       user: User = Depends(require_auth)):
    """Start OAuth2 flow: generate auth URL + PKCE challenge."""
    from integrations.connector_loader import get_connector
    connector = get_connector(connector_id)
    if not connector:
        raise HTTPException(404, f"Connector '{connector_id}' not found")

    acq = connector.get("credential_acquisition", {})
    if acq.get("pattern") != "oauth2":
        raise HTTPException(400, "This connector does not use OAuth2")

    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)

    # PKCE challenge
    import hashlib
    import base64
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    instance_url = (body.instance_url if body else None) or ""
    redirect_uri = os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8000/api/integration-builder/oauth/callback")

    # Resolve all {{env.VAR}} placeholders in client_id generically
    import re
    raw_client_id = acq.get("client_id", "")
    client_id = re.sub(r'\{\{env\.(\w+)\}\}', lambda m: os.environ.get(m.group(1), ""), raw_client_id)

    scopes = " ".join(acq.get("scopes", []))
    auth_url = acq.get("authorization_url", "")

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scopes,
    }
    if acq.get("pkce"):
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"

    # Merge any connector-specific extra params (e.g. audience for Atlassian)
    params.update(acq.get("extra_params", {}))

    from urllib.parse import urlencode
    authorization_url = f"{auth_url}?{urlencode({k: v for k, v in params.items() if v})}"

    # Store state for callback verification
    _oauth_states[state] = {
        "connector_id": connector_id,
        "code_verifier": code_verifier,
        "instance_url": instance_url,
        "user_id": user.id,
        "org_id": user.org_id,
        "redirect_uri": redirect_uri,
        "token_url": acq.get("token_url", ""),
        "token_request_format": acq.get("token_request_format", "form"),
        "client_id": client_id,
        "validation_request": acq.get("validation_request"),
    }

    return {"authorization_url": authorization_url, "state": state}


@router.get("/oauth/callback")
async def oauth_callback(code: str = Query(...), state: str = Query(...),
                          db: Session = Depends(get_db)):
    """OAuth2 callback: exchange code for tokens, store credentials."""
    import httpx

    flow = _oauth_states.pop(state, None)
    if not flow:
        return _oauth_html_response(False, "Invalid or expired OAuth state")

    try:
        # Exchange code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": flow["redirect_uri"],
            "client_id": flow["client_id"],
        }
        if flow.get("code_verifier"):
            token_data["code_verifier"] = flow["code_verifier"]

        client_secret = os.environ.get("OAUTH_CLIENT_SECRET", "")
        if client_secret:
            token_data["client_secret"] = client_secret

        async with httpx.AsyncClient(timeout=15.0) as client:
            if flow.get("token_request_format") == "json":
                resp = await client.post(flow["token_url"], json=token_data)
            else:
                resp = await client.post(flow["token_url"], data=token_data)

        if resp.status_code >= 400:
            return _oauth_html_response(False, f"Token exchange failed: {resp.text[:200]}")

        tokens = resp.json()
        access_token = tokens.get("access_token", "")
        refresh_token = tokens.get("refresh_token")
        expires_in = tokens.get("expires_in")

        # Validate + extract user info
        connected_user = None
        val_req = flow.get("validation_request")
        if val_req and access_token:
            instance_url = flow.get("instance_url", "").rstrip("/")
            val_url = f"{instance_url}{val_req['path']}" if instance_url else val_req["path"]
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                val_resp = await client.get(val_url, headers={"Authorization": f"Bearer {access_token}"})
                if val_resp.status_code < 400:
                    val_data = val_resp.json()
                    for key, path in val_req.get("success_extracts", {}).items():
                        parts = path.replace("response.", "").split(".")
                        val = val_data
                        for p in parts:
                            val = val.get(p) if isinstance(val, dict) else None
                        if key == "connected_user":
                            connected_user = val

        # Store credentials
        from datetime import datetime, timedelta
        cred = IntegrationCredential(
            org_id=flow["org_id"],
            name=f"OAuth2 — {flow['connector_id']}",
            connector_id=flow["connector_id"],
            auth_type="oauth2",
            encrypted_values=credential_vault.encrypt({"access_token": access_token}),
            instance_url=flow.get("instance_url"),
            connected_user=connected_user,
            expires_at=datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None,
            encrypted_refresh_token=credential_vault.encrypt_string(refresh_token) if refresh_token else None,
        )
        db.add(cred)
        db.commit()
        db.refresh(cred)

        return _oauth_html_response(True, connected_user=connected_user, credentials_id=cred.id)

    except Exception as e:
        logger.exception("OAuth callback failed")
        return _oauth_html_response(False, str(e))


def _oauth_html_response(success: bool, error: str = None, connected_user: str = None, credentials_id: str = None):
    """Return HTML that posts message to opener and closes."""
    from fastapi.responses import HTMLResponse
    payload = json.dumps({
        "success": success,
        "error": error,
        "connected_user": connected_user,
        "credentials_id": credentials_id,
    })
    html = f"""<!DOCTYPE html><html><body><script>
    window.opener && window.opener.postMessage({payload}, window.location.origin);
    window.close();
    </script><p>{'Connected!' if success else 'Error: ' + (error or '')}</p></body></html>"""
    return HTMLResponse(html)


# ─────────────────────────────────────────────────────────
# OAuth2 Client Credentials — for machine-to-machine APIs
# ─────────────────────────────────────────────────────────

class ClientCredentialsRequest(BaseModel):
    instance_url: str
    token_url: str  # discovered token endpoint
    client_id: str
    client_secret: str
    scopes: list = []
    connector_id: str = "custom"


@router.post("/oauth/client-credentials")
async def oauth_client_credentials(body: ClientCredentialsRequest, db: Session = Depends(get_db),
                                    user: User = Depends(require_auth)):
    """Exchange client_id + client_secret for an access token (client_credentials grant).

    Used for machine-to-machine APIs like CrowdStrike, where there is no user popup —
    the app authenticates directly with its own credentials.
    """
    import httpx

    token_data = {
        "grant_type": "client_credentials",
        "client_id": body.client_id,
        "client_secret": body.client_secret,
    }
    if body.scopes:
        token_data["scope"] = " ".join(body.scopes)

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.post(body.token_url, data=token_data)
    except httpx.RequestError as e:
        raise HTTPException(400, f"Connection error: {e}")

    if resp.status_code >= 400:
        raise HTTPException(400, f"Token request failed (HTTP {resp.status_code}): {resp.text[:300]}")

    tokens = resp.json()
    access_token = tokens.get("access_token", "")
    if not access_token:
        raise HTTPException(400, "Token response did not include an access_token")

    expires_in = tokens.get("expires_in")
    # client_credentials rarely return refresh tokens, but handle it if present
    refresh_token = tokens.get("refresh_token")

    from datetime import datetime, timedelta
    cred = IntegrationCredential(
        org_id=user.org_id,
        name=f"OAuth2 (client credentials) — {body.connector_id}",
        connector_id=body.connector_id,
        auth_type="oauth2",
        encrypted_values=credential_vault.encrypt({"access_token": access_token}),
        instance_url=body.instance_url,
        connected_user=body.client_id,
        expires_at=datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None,
        encrypted_refresh_token=credential_vault.encrypt_string(refresh_token) if refresh_token else None,
    )
    # Store client_id/secret so we can re-issue when expired (no refresh token)
    # We re-encrypt together with the access token so refresh logic can use them
    cred.encrypted_values = credential_vault.encrypt({
        "access_token": access_token,
        "_client_id": body.client_id,
        "_client_secret": body.client_secret,
        "_token_url": body.token_url,
        "_scopes": body.scopes,
    })
    db.add(cred)
    db.commit()
    db.refresh(cred)

    return {
        "success": True,
        "credentials_id": cred.id,
        "connected_user": body.client_id,
        "expires_at": str(cred.expires_at) if cred.expires_at else None,
    }


# ─────────────────────────────────────────────────────────
# Auto-Provision
# ─────────────────────────────────────────────────────────

class ProvisionRequest(BaseModel):
    instance_url: str
    values: dict  # admin credentials


@router.post("/connectors/{connector_id}/provision")
async def provision_service_account(connector_id: str, body: ProvisionRequest,
                                     db: Session = Depends(get_db),
                                     user: User = Depends(require_auth)):
    """Auto-provision a service account using admin credentials."""
    from integrations.connector_loader import get_connector
    import httpx

    connector = get_connector(connector_id)
    if not connector:
        raise HTTPException(404, f"Connector '{connector_id}' not found")

    acq = connector.get("credential_acquisition", {})
    if acq.get("pattern") != "auto_provision":
        raise HTTPException(400, "This connector does not support auto-provisioning")

    instance_url = body.instance_url.rstrip("/")
    admin_values = dict(body.values)  # copy — will be wiped
    extracted = {}

    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            for step in acq.get("provision_steps", []):
                req = step.get("request", {})
                method = req.get("method", "POST").upper()
                path = req.get("path", "")

                # Substitute extracted values in path
                for k, v in extracted.items():
                    path = path.replace("{{" + k + "}}", str(v))

                url = f"{instance_url}{path}"

                # Build auth headers
                headers = {"Content-Type": "application/json"}
                auth = req.get("auth", "")
                if auth == "basic":
                    import base64
                    encoded = base64.b64encode(
                        f"{admin_values.get('admin_username', '')}:{admin_values.get('admin_password', '')}".encode()
                    ).decode()
                    headers["Authorization"] = f"Basic {encoded}"

                # Build body with substitution
                req_body = req.get("body", {})
                body_str = json.dumps(req_body)
                for k, v in extracted.items():
                    body_str = body_str.replace("{{" + k + "}}", str(v))
                req_body = json.loads(body_str)

                resp = await client.request(method, url, headers=headers, json=req_body)

                if resp.status_code >= 400:
                    raise RuntimeError(f"Provision step failed: {step.get('description', '')} — HTTP {resp.status_code}: {resp.text[:200]}")

                resp_data = resp.json()

                # Extract values from response
                for key, path in step.get("extract", {}).items():
                    parts = path.replace("response.", "").split(".")
                    val = resp_data
                    for p in parts:
                        val = val.get(p) if isinstance(val, dict) else None
                    extracted[key] = val

        # Discard admin credentials
        for field in acq.get("discard_after_provision", []):
            admin_values.pop(field, None)
        admin_values.clear()

        # Validate provisioned credentials
        connected_user = None
        val_req = acq.get("validation_request")
        if val_req:
            val_path = val_req.get("path", "")
            for k, v in extracted.items():
                val_path = val_path.replace("{{" + k + "}}", str(v))

            val_headers = {}
            if val_req.get("auth_header"):
                header_str = val_req["auth_header"]
                for k, v in extracted.items():
                    header_str = header_str.replace("{{" + k + "}}", str(v))
                h_name, h_val = header_str.split(":", 1)
                val_headers[h_name.strip()] = h_val.strip()

            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                val_resp = await client.request(val_req.get("method", "GET"), f"{instance_url}{val_path}", headers=val_headers)
                if val_resp.status_code < 400:
                    val_data = val_resp.json()
                    for key, path in val_req.get("success_extracts", {}).items():
                        parts = path.replace("response.", "").split(".")
                        val = val_data
                        for p in parts:
                            val = val.get(p) if isinstance(val, dict) else None
                        if key == "connected_user":
                            connected_user = val

        # Store provisioned credentials (not admin credentials)
        cred = IntegrationCredential(
            org_id=user.org_id,
            name=f"Auto-provisioned — {connector_id}",
            connector_id=connector_id,
            auth_type="api_key",
            encrypted_values=credential_vault.encrypt(extracted),
            instance_url=instance_url,
            connected_user=connected_user,
        )
        db.add(cred)
        db.commit()
        db.refresh(cred)

        return {"success": True, "connected_user": connected_user, "credentials_id": cred.id}

    except Exception as e:
        admin_values.clear()  # always wipe
        logger.exception("Auto-provision failed for %s", connector_id)
        raise HTTPException(400, f"Provisioning failed: {e}")


# ─────────────────────────────────────────────────────────
# File Upload (temp file for FileTransport)
# ─────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_file(file: UploadFile = File(...), user: User = Depends(require_auth)):
    """Upload a file for FileTransport. Returns temp path."""
    upload_dir = os.path.join(tempfile.gettempdir(), "hakuna_uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # Sanitize filename
    safe_name = file.filename.replace("/", "_").replace("\\", "_")
    dest = os.path.join(upload_dir, f"{secrets.token_hex(8)}_{safe_name}")

    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    return {
        "path": dest,
        "filename": file.filename,
        "size": len(content),
        "format": _detect_format(file.filename),
    }


def _detect_format(filename: str) -> str:
    fn = filename.lower()
    if fn.endswith(".nessus"):
        return "nessus"
    if fn.endswith(".csv"):
        return "csv"
    if fn.endswith(".json"):
        return "json"
    if fn.endswith(".xml"):
        return "xml"
    if fn.endswith((".yaml", ".yml")):
        return "yaml"
    return "auto"


# ─────────────────────────────────────────────────────────
# OAuth2 Discovery — probe a URL for OAuth2 support
# ─────────────────────────────────────────────────────────

class OAuthDiscoverRequest(BaseModel):
    url: str


@router.post("/discovery/oauth")
async def discover_oauth(body: OAuthDiscoverRequest, user: User = Depends(require_auth)):
    """Probe a base URL for OAuth2/OIDC support.

    Checks (in order):
      1. /.well-known/openid-configuration  (OIDC)
      2. /.well-known/oauth-authorization-server  (RFC 8414)
      3. WWW-Authenticate header on a bare request to /

    Returns discovered endpoints and grant types so the frontend
    can present the right auth flow without a pre-built connector.
    """
    import httpx
    from urllib.parse import urlparse, urljoin

    url = body.url.rstrip("/")
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base = f"{parsed.scheme}://{parsed.netloc}"

    result = {
        "oauth_supported": False,
        "grant_types": [],
        "authorization_endpoint": None,
        "token_endpoint": None,
        "scopes_supported": [],
        "pkce_required": False,
        "client_credentials_supported": False,
        "authorization_code_supported": False,
        "source": None,
    }

    well_known_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
        # 1 & 2 — well-known discovery docs
        for path in well_known_paths:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    data = resp.json()
                    grant_types = data.get("grant_types_supported", ["authorization_code"])
                    result.update({
                        "oauth_supported": True,
                        "grant_types": grant_types,
                        "authorization_endpoint": data.get("authorization_endpoint"),
                        "token_endpoint": data.get("token_endpoint"),
                        "scopes_supported": data.get("scopes_supported", []),
                        "pkce_required": "S256" in data.get("code_challenge_methods_supported", []),
                        "client_credentials_supported": "client_credentials" in grant_types,
                        "authorization_code_supported": "authorization_code" in grant_types,
                        "source": path,
                    })
                    return result
            except Exception:
                continue

        # 3 — probe for WWW-Authenticate header
        try:
            resp = await client.get(f"{url}/")
            www_auth = resp.headers.get("www-authenticate", "")
            if "bearer" in www_auth.lower() or "oauth" in www_auth.lower():
                result["oauth_supported"] = True
                result["source"] = "www-authenticate"
                result["authorization_code_supported"] = True
                # Try to extract realm/scope hints
                import re
                scope_match = re.search(r'scope="([^"]+)"', www_auth, re.IGNORECASE)
                if scope_match:
                    result["scopes_supported"] = scope_match.group(1).split()
        except Exception:
            pass

    return result


# ─────────────────────────────────────────────────────────
# OAuth Token Refresh
# ─────────────────────────────────────────────────────────

@router.post("/credentials/{credential_id}/refresh")
async def refresh_token(credential_id: str, db: Session = Depends(get_db),
                         user: User = Depends(require_auth)):
    """Refresh an OAuth2 access token."""
    import httpx

    cred = db.query(IntegrationCredential).filter(
        IntegrationCredential.id == credential_id,
        IntegrationCredential.org_id == user.org_id,
    ).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    if cred.auth_type != "oauth2":
        raise HTTPException(400, "This credential does not use OAuth2")

    from datetime import datetime, timedelta
    import re

    current_values = credential_vault.decrypt(cred.encrypted_values)

    if cred.encrypted_refresh_token:
        # Standard refresh_token flow
        refresh_token_val = credential_vault.decrypt_string(cred.encrypted_refresh_token)
        from integrations.connector_loader import get_connector
        connector = get_connector(cred.connector_id)
        acq = (connector or {}).get("credential_acquisition", {}) if connector else {}
        token_url = acq.get("token_url", current_values.get("_token_url", ""))
        client_id = acq.get("client_id", current_values.get("_client_id", ""))
        client_id = re.sub(r'\{\{env\.(\w+)\}\}', lambda m: os.environ.get(m.group(1), ""), client_id)

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(token_url, data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_val,
                "client_id": client_id,
            })

        if resp.status_code >= 400:
            raise HTTPException(400, f"Token refresh failed: {resp.text[:200]}")

        tokens = resp.json()
        new_access = tokens.get("access_token", "")
        new_refresh = tokens.get("refresh_token", refresh_token_val)
        expires_in = tokens.get("expires_in")

        current_values["access_token"] = new_access
        cred.encrypted_values = credential_vault.encrypt(current_values)
        cred.encrypted_refresh_token = credential_vault.encrypt_string(new_refresh)
        if expires_in:
            cred.expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    elif current_values.get("_client_id") and current_values.get("_client_secret"):
        # Client credentials re-issue
        token_url = current_values.get("_token_url", "")
        token_data = {
            "grant_type": "client_credentials",
            "client_id": current_values["_client_id"],
            "client_secret": current_values["_client_secret"],
        }
        if current_values.get("_scopes"):
            token_data["scope"] = " ".join(current_values["_scopes"])

        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.post(token_url, data=token_data)

        if resp.status_code >= 400:
            raise HTTPException(400, f"Token re-issue failed: {resp.text[:200]}")

        tokens = resp.json()
        new_access = tokens.get("access_token", "")
        expires_in = tokens.get("expires_in")

        current_values["access_token"] = new_access
        cred.encrypted_values = credential_vault.encrypt(current_values)
        if expires_in:
            cred.expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    else:
        raise HTTPException(400, "No refresh token or client credentials available for re-issue")

    db.commit()
    return {"success": True, "expires_at": str(cred.expires_at) if cred.expires_at else None}

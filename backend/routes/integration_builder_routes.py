"""
Integration Builder routes.
Prefix: /api/integration-builder
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, require_auth
from models.models import (
    User, Integration, IntegrationCredential, IntegrationRun, DiscoveredSpec,
)
from integrations.schema import get_schema
from integrations.connector_loader import get_all_connectors, get_connector
from services import credential_vault
from services.field_mapper import detect_paths, map_record, auto_suggest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/integration-builder", tags=["integration-builder"])


# ─────────────────────────────────────────────────────────
# Schema & Connectors (Phase 1)
# ─────────────────────────────────────────────────────────

@router.get("/schema")
def integration_schema(entity: Optional[str] = Query(None)):
    """Return the Hakuna normalized schema for field mapping."""
    return get_schema(entity)


@router.get("/connectors")
def list_connectors():
    """Return all OOTB connector templates (summary)."""
    return get_all_connectors()


@router.get("/connectors/{connector_id}")
def get_connector_detail(connector_id: str):
    """Return full connector template including acquisition flow."""
    c = get_connector(connector_id)
    if not c:
        raise HTTPException(404, f"Connector '{connector_id}' not found")
    return c


@router.get("/connectors/{connector_id}/acquisition-flow")
def get_acquisition_flow(connector_id: str):
    """Return just the credential acquisition config for a connector."""
    c = get_connector(connector_id)
    if not c:
        raise HTTPException(404, f"Connector '{connector_id}' not found")
    acq = c.get("credential_acquisition")
    if not acq:
        return {"pattern": "none", "message": "This connector does not require authentication"}
    return acq


# ─────────────────────────────────────────────────────────
# Credentials
# ─────────────────────────────────────────────────────────

class CredentialCreate(BaseModel):
    name: str
    connector_id: str
    auth_type: str
    values: dict
    instance_url: Optional[str] = None
    connected_user: Optional[str] = None


@router.post("/credentials")
def create_credential(body: CredentialCreate, db: Session = Depends(get_db),
                       user: User = Depends(require_auth)):
    try:
        encrypted = credential_vault.encrypt(body.values)
    except Exception as e:
        raise HTTPException(500, f"Failed to encrypt credentials: {e}")
    cred = IntegrationCredential(
        org_id=user.org_id,
        name=body.name,
        connector_id=body.connector_id,
        auth_type=body.auth_type,
        encrypted_values=encrypted,
        instance_url=body.instance_url,
        connected_user=body.connected_user,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return {"id": cred.id, "name": cred.name, "connected_user": cred.connected_user}


@router.get("/credentials")
def list_credentials(db: Session = Depends(get_db), user: User = Depends(require_auth)):
    """List credentials — metadata only, never return encrypted values."""
    creds = db.query(IntegrationCredential).filter(
        IntegrationCredential.org_id == user.org_id
    ).all()
    return [
        {
            "id": c.id, "name": c.name, "connector_id": c.connector_id,
            "auth_type": c.auth_type, "instance_url": c.instance_url,
            "connected_user": c.connected_user, "created_at": c.created_at,
            "expires_at": c.expires_at,
        }
        for c in creds
    ]


@router.delete("/credentials/{credential_id}")
def delete_credential(credential_id: str, db: Session = Depends(get_db),
                       user: User = Depends(require_auth)):
    cred = db.query(IntegrationCredential).filter(
        IntegrationCredential.id == credential_id,
        IntegrationCredential.org_id == user.org_id,
    ).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    db.delete(cred)
    db.commit()
    return {"deleted": True}


# ─────────────────────────────────────────────────────────
# Validate credentials (connector-specific)
# ─────────────────────────────────────────────────────────

class ValidateCredentialRequest(BaseModel):
    instance_url: Optional[str] = None
    values: dict


@router.post("/connectors/{connector_id}/validate-credentials")
async def validate_credentials(connector_id: str, body: ValidateCredentialRequest):
    """Validate credentials against a connector's validation_request spec."""
    c = get_connector(connector_id)
    if not c:
        raise HTTPException(404, f"Connector '{connector_id}' not found")

    acq = c.get("credential_acquisition")
    if not acq or not acq.get("validation_request"):
        return {"success": True, "message": "No validation configured for this connector"}

    import httpx
    val_req = acq["validation_request"]
    instance_url = (body.instance_url or "").rstrip("/")
    method = val_req.get("method", "GET").upper()

    # Build URL
    path = val_req.get("path", "")
    # Substitute credential values in path
    for k, v in body.values.items():
        path = path.replace("{{" + k + "}}", str(v))
    url = f"{instance_url}{path}" if instance_url else path

    # Build headers
    headers = {}
    if val_req.get("auth_header"):
        header_str = val_req["auth_header"]
        for k, v in body.values.items():
            header_str = header_str.replace("{{" + k + "}}", str(v))
        h_name, h_val = header_str.split(":", 1)
        headers[h_name.strip()] = h_val.strip()

    if val_req.get("auth") == "basic":
        import base64
        encoded = base64.b64encode(
            f"{body.values.get('username', '')}:{body.values.get('password', '')}".encode()
        ).decode()
        headers["Authorization"] = f"Basic {encoded}"

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.request(method, url, headers=headers)

        if resp.status_code < 400:
            extracts = {}
            if val_req.get("success_extracts"):
                try:
                    resp_json = resp.json()
                    for key, path in val_req["success_extracts"].items():
                        parts = path.replace("response.", "").split(".")
                        val = resp_json
                        for p in parts:
                            val = val.get(p) if isinstance(val, dict) else None
                        extracts[key] = val
                except Exception:
                    pass
            return {"success": True, **extracts}
        else:
            return {"success": False, "error": val_req.get("error_message", f"HTTP {resp.status_code}")}
    except httpx.RequestError as e:
        return {"success": False, "error": f"Connection error: {e}"}


# ─────────────────────────────────────────────────────────
# Live Connect & Preview
# ─────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    transport_type: str
    transport_config: dict
    credentials_id: Optional[str] = None
    records_path: Optional[str] = None


@router.post("/connect")
async def live_connect(body: ConnectRequest, db: Session = Depends(get_db),
                        user: User = Depends(require_auth)):
    """Make a live call and return raw response + detected paths. No DB write."""
    from services.transports.api_transport import ApiTransport
    from services.transports.file_transport import FileTransport
    from services.transports.sql_transport import SqlTransport
    from services.transports.mcp_transport import McpTransport

    transport_map = {"api": ApiTransport, "file": FileTransport, "sql": SqlTransport, "mcp": McpTransport}
    transport_cls = transport_map.get(body.transport_type)
    if not transport_cls:
        raise HTTPException(400, f"Unsupported transport: {body.transport_type}")

    credentials = {}
    if body.credentials_id:
        cred = db.query(IntegrationCredential).filter(
            IntegrationCredential.id == body.credentials_id,
            IntegrationCredential.org_id == user.org_id,
        ).first()
        if cred:
            credentials = credential_vault.decrypt(cred.encrypted_values)
            credentials["_auth_type"] = cred.auth_type
            credentials["instance_url"] = cred.instance_url or ""

    config = body.transport_config
    if body.records_path:
        config["records_path"] = body.records_path

    transport = transport_cls()
    result = await transport.connect(config, credentials)

    if not result.success:
        raise HTTPException(400, result.error)

    detected = []
    if result.sample_records:
        detected = detect_paths(result.sample_records[0])

    return {
        "raw_response": result.raw_response,
        "sample_records": result.sample_records,
        "detected_paths": detected,
        "detected_records_path": result.detected_records_path,
    }


class PreviewRequest(BaseModel):
    transport_type: str
    transport_config: dict
    credentials_id: Optional[str] = None
    records_path: Optional[str] = None
    field_map: list = []
    auto_suggest_flag: bool = False


@router.post("/preview")
async def preview_mapping(body: PreviewRequest, db: Session = Depends(get_db),
                           user: User = Depends(require_auth)):
    """Preview mapped records without writing to DB."""
    from services.transports.api_transport import ApiTransport
    from services.transports.file_transport import FileTransport
    from services.transports.sql_transport import SqlTransport
    from services.transports.mcp_transport import McpTransport
    from integrations.schema import get_schema

    transport_map = {"api": ApiTransport, "file": FileTransport, "sql": SqlTransport, "mcp": McpTransport}
    transport_cls = transport_map.get(body.transport_type)
    if not transport_cls:
        raise HTTPException(400, f"Unsupported transport: {body.transport_type}")

    credentials = {}
    if body.credentials_id:
        cred = db.query(IntegrationCredential).filter(
            IntegrationCredential.id == body.credentials_id,
            IntegrationCredential.org_id == user.org_id,
        ).first()
        if cred:
            credentials = credential_vault.decrypt(cred.encrypted_values)
            credentials["_auth_type"] = cred.auth_type
            credentials["instance_url"] = cred.instance_url or ""

    config = body.transport_config
    if body.records_path:
        config["records_path"] = body.records_path

    transport = transport_cls()
    result = await transport.connect(config, credentials)
    if not result.success:
        raise HTTPException(400, result.error)

    # If auto-suggest requested, generate suggestions
    suggestions = None
    if body.auto_suggest_flag and result.sample_records:
        paths = detect_paths(result.sample_records[0])
        schema = get_schema("finding")  # default to finding
        suggestions = auto_suggest(paths, schema)

    field_map = body.field_map or (suggestions if suggestions else [])

    # Map up to 5 sample records
    preview_records = []
    for raw in result.sample_records[:5]:
        mapped_result = map_record(raw, field_map)
        preview_records.append({
            "raw": raw,
            "mapped": mapped_result["mapped"],
            "errors": mapped_result["errors"],
        })

    return {
        "records": preview_records,
        "suggestions": suggestions,
        "total_sample": len(result.sample_records),
    }


# ─────────────────────────────────────────────────────────
# Integration CRUD
# ─────────────────────────────────────────────────────────

class IntegrationCreate(BaseModel):
    name: str
    direction: str
    entity: str
    transport_type: str
    transport_config: dict = {}
    credentials_id: Optional[str] = None
    records_path: Optional[str] = None
    field_map: list = []
    dedup_key: list = []
    params: dict = {}
    schedule: Optional[str] = None
    enabled: bool = False
    template_id: Optional[str] = None


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    transport_config: Optional[dict] = None
    credentials_id: Optional[str] = None
    records_path: Optional[str] = None
    field_map: Optional[list] = None
    dedup_key: Optional[list] = None
    params: Optional[dict] = None
    schedule: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/integrations")
def list_integrations(db: Session = Depends(get_db), user: User = Depends(require_auth)):
    integrations = db.query(Integration).filter(
        Integration.org_id == user.org_id
    ).order_by(Integration.created_at.desc()).all()
    return [_integration_summary(i) for i in integrations]


@router.post("/integrations")
def create_integration(body: IntegrationCreate, db: Session = Depends(get_db),
                        user: User = Depends(require_auth)):
    if body.direction not in ("pull", "push"):
        raise HTTPException(400, "direction must be 'pull' or 'push'")
    if body.entity not in ("asset", "finding", "action"):
        raise HTTPException(400, "entity must be 'asset', 'finding', or 'action'")
    if body.transport_type not in ("api", "sql", "file", "mcp"):
        raise HTTPException(400, "transport_type must be 'api', 'sql', 'file', or 'mcp'")

    integration = Integration(
        org_id=user.org_id,
        name=body.name,
        direction=body.direction,
        entity=body.entity,
        transport_type=body.transport_type,
        transport_config=body.transport_config,
        credentials_id=body.credentials_id,
        records_path=body.records_path,
        field_map=body.field_map,
        dedup_key=body.dedup_key,
        params=body.params,
        schedule=body.schedule,
        enabled=body.enabled,
        template_id=body.template_id,
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    # Register schedule if enabled
    if integration.enabled and integration.schedule:
        from services.integration_scheduler import register_integration
        register_integration(integration.id, integration.schedule)
    return _integration_summary(integration)


@router.get("/integrations/{integration_id}")
def get_integration(integration_id: str, db: Session = Depends(get_db),
                     user: User = Depends(require_auth)):
    i = _get_integration_or_404(db, integration_id, user.org_id)
    return _integration_detail(i)


@router.put("/integrations/{integration_id}")
def update_integration(integration_id: str, body: IntegrationUpdate,
                        db: Session = Depends(get_db), user: User = Depends(require_auth)):
    i = _get_integration_or_404(db, integration_id, user.org_id)
    for field in ["name", "transport_config", "credentials_id", "records_path",
                   "field_map", "dedup_key", "params", "schedule", "enabled"]:
        val = getattr(body, field)
        if val is not None:
            setattr(i, field, val)
    db.commit()
    db.refresh(i)
    # Update schedule
    from services.integration_scheduler import register_integration, deregister_integration
    if i.enabled and i.schedule:
        register_integration(i.id, i.schedule)
    else:
        deregister_integration(i.id)
    return _integration_detail(i)


@router.delete("/integrations/{integration_id}")
def delete_integration(integration_id: str, db: Session = Depends(get_db),
                        user: User = Depends(require_auth)):
    i = _get_integration_or_404(db, integration_id, user.org_id)
    from services.integration_scheduler import deregister_integration
    deregister_integration(i.id)
    db.delete(i)
    db.commit()
    return {"deleted": True}


@router.post("/integrations/{integration_id}/enable")
def enable_integration(integration_id: str, db: Session = Depends(get_db),
                        user: User = Depends(require_auth)):
    i = _get_integration_or_404(db, integration_id, user.org_id)
    i.enabled = True
    db.commit()
    if i.schedule:
        from services.integration_scheduler import register_integration
        register_integration(i.id, i.schedule)
    return {"enabled": True}


@router.post("/integrations/{integration_id}/disable")
def disable_integration(integration_id: str, db: Session = Depends(get_db),
                         user: User = Depends(require_auth)):
    i = _get_integration_or_404(db, integration_id, user.org_id)
    i.enabled = False
    db.commit()
    from services.integration_scheduler import deregister_integration
    deregister_integration(i.id)
    return {"enabled": False}


# ─────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────

@router.post("/integrations/{integration_id}/run")
async def run_integration(integration_id: str, db: Session = Depends(get_db),
                           user: User = Depends(require_auth)):
    """Trigger an integration run."""
    i = _get_integration_or_404(db, integration_id, user.org_id)
    from services.run_engine import execute
    run_id = await execute(db, integration_id, triggered_by="manual")
    run = db.query(IntegrationRun).filter(IntegrationRun.id == run_id).first()
    return {
        "run_id": run_id,
        "status": run.status if run else "unknown",
        "records_fetched": run.records_fetched if run else 0,
        "records_inserted": run.records_inserted if run else 0,
    }


@router.get("/integrations/{integration_id}/runs")
def list_runs(integration_id: str, limit: int = Query(50, le=100),
              db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_integration_or_404(db, integration_id, user.org_id)
    runs = db.query(IntegrationRun).filter(
        IntegrationRun.integration_id == integration_id
    ).order_by(IntegrationRun.started_at.desc()).limit(limit).all()
    return [_run_summary(r) for r in runs]


@router.get("/integrations/{integration_id}/runs/{run_id}")
def get_run(integration_id: str, run_id: str, db: Session = Depends(get_db),
             user: User = Depends(require_auth)):
    _get_integration_or_404(db, integration_id, user.org_id)
    run = db.query(IntegrationRun).filter(IntegrationRun.id == run_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    return _run_detail(run)


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _get_integration_or_404(db, integration_id, org_id):
    i = db.query(Integration).filter(
        Integration.id == integration_id,
        Integration.org_id == org_id,
    ).first()
    if not i:
        raise HTTPException(404, "Integration not found")
    return i


def _integration_summary(i):
    return {
        "id": i.id, "name": i.name, "direction": i.direction, "entity": i.entity,
        "transport_type": i.transport_type, "enabled": i.enabled,
        "template_id": i.template_id, "schedule": i.schedule,
        "last_run_at": i.last_run_at, "last_run_status": i.last_run_status,
        "last_run_records": i.last_run_records, "created_at": i.created_at,
    }


def _integration_detail(i):
    return {
        **_integration_summary(i),
        "transport_config": i.transport_config,
        "credentials_id": i.credentials_id,
        "records_path": i.records_path,
        "field_map": i.field_map,
        "dedup_key": i.dedup_key,
        "params": i.params,
        "updated_at": i.updated_at,
    }


def _run_summary(r):
    return {
        "id": r.id, "started_at": r.started_at, "finished_at": r.finished_at,
        "status": r.status, "records_fetched": r.records_fetched,
        "records_inserted": r.records_inserted, "records_updated": r.records_updated,
        "records_skipped": r.records_skipped,
    }


def _run_detail(r):
    return {**_run_summary(r), "errors": r.errors, "step_log": r.step_log}

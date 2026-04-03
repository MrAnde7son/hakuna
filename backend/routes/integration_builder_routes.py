"""
Integration Builder routes.
Prefix: /api/integration-builder
"""
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, require_auth
from models.models import (
    User, Integration, IntegrationCredential, IntegrationRun, DiscoveredSpec,
)
from integrations.schema import get_schema
from integrations.connector_loader import get_all_connectors, get_connector
from integrations.model_registry import (
    get_registry, get_model_meta, get_target_schema, list_targets as list_registry_targets,
)
from services import credential_vault
from services.field_mapper import detect_paths, map_record, auto_suggest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/integration-builder", tags=["integration-builder"])


from services.credential_manager import load_credentials as _load_credentials


# ─────────────────────────────────────────────────────────
# Schema & Connectors (Phase 1)
# ─────────────────────────────────────────────────────────

@router.get("/schema")
def integration_schema(entity: Optional[str] = Query(None)):
    """Return the Hakuna normalized schema for field mapping.

    Falls back to the static schema for legacy entities (asset/finding/action)
    but dynamically returns introspected fields for registered model targets.
    """
    if entity:
        dynamic = get_target_schema(entity)
        if dynamic:
            return dynamic
        return get_schema(entity)
    # Return all: merge registry targets with static action schema
    result = {}
    for slug in get_registry():
        result[slug] = get_target_schema(slug)
    # Keep 'action' from static schema (it has no DB model)
    result["action"] = get_schema("action")
    return result


@router.get("/targets")
def list_targets():
    """Return all importable model targets grouped by category."""
    return list_registry_targets()


@router.get("/targets/{slug}/schema")
def get_target_fields(slug: str):
    """Return introspected field schema for a target model."""
    schema = get_target_schema(slug)
    if schema is None:
        raise HTTPException(404, f"Target model '{slug}' not found")
    return schema


class AutoSuggestRequest(BaseModel):
    source_paths: list[dict]   # [{path, sample_value, inferred_type}, ...]
    entity: str = "finding"    # target model slug


@router.post("/auto-suggest")
def auto_suggest_fields(body: AutoSuggestRequest, user: User = Depends(require_auth)):
    """Lightweight auto-suggest — no transport re-run, just string matching."""
    schema = get_target_schema(body.entity) or get_schema(body.entity)
    if not schema:
        raise HTTPException(404, f"Unknown target entity '{body.entity}'")
    return auto_suggest(body.source_paths, schema)


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
        u_field = val_req.get("basic_username_field", "username")
        p_field = val_req.get("basic_password_field", "password")
        encoded = base64.b64encode(
            f"{body.values.get(u_field, '')}:{body.values.get(p_field, '')}".encode()
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


def _trim_raw_response(raw, max_items=20):
    """Trim large arrays in a raw API response to keep it under size limits."""
    if isinstance(raw, list):
        return raw[:max_items]
    if isinstance(raw, dict):
        trimmed = {}
        for k, v in raw.items():
            if isinstance(v, list) and len(v) > max_items:
                trimmed[k] = v[:max_items]
                trimmed[f"_{k}_total"] = len(v)
            else:
                trimmed[k] = v
        return trimmed
    return raw


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

    try:
        credentials = await _load_credentials(db, body.credentials_id, user.org_id) if body.credentials_id else {}

        config = body.transport_config
        if body.records_path:
            config["records_path"] = body.records_path

        transport = transport_cls(db=db) if body.transport_type == "file" else transport_cls()
        result = await transport.connect(config, credentials)

        if not result.success:
            raise HTTPException(400, result.error)

        detected = []
        if result.sample_records:
            detected = detect_paths(result.sample_records[0])

        # Limit raw_response size to avoid serialization/timeout issues with large APIs
        raw = result.raw_response
        if isinstance(raw, (dict, list)):
            import json
            try:
                raw_str = json.dumps(raw, default=str)
                if len(raw_str) > 2_000_000:  # >2MB — trim large arrays
                    raw = _trim_raw_response(raw)
            except (TypeError, ValueError):
                raw = {"_error": "Response could not be serialized for preview"}

        return {
            "raw_response": raw,
            "sample_records": result.sample_records[:20],
            "detected_paths": detected,
            "detected_records_path": result.detected_records_path,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("live_connect failed")
        raise HTTPException(500, f"Connect failed: {e}")


class PreviewRequest(BaseModel):
    transport_type: str
    transport_config: dict
    credentials_id: Optional[str] = None
    records_path: Optional[str] = None
    field_map: list = []
    auto_suggest_flag: bool = False
    entity: Optional[str] = None  # target model slug for auto-suggest
    sample_records: list[dict] | None = None  # Pass cached records to skip transport re-run


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

    try:
        # Use cached sample records if provided, otherwise re-run transport
        if body.sample_records:
            samples = body.sample_records
        else:
            credentials = await _load_credentials(db, body.credentials_id, user.org_id) if body.credentials_id else {}

            config = body.transport_config
            if body.records_path:
                config["records_path"] = body.records_path

            transport = transport_cls(db=db) if body.transport_type == "file" else transport_cls()
            result = await transport.connect(config, credentials)
            if not result.success:
                raise HTTPException(400, result.error)
            samples = result.sample_records

        # If auto-suggest requested, generate suggestions
        suggestions = None
        if body.auto_suggest_flag and samples:
            paths = detect_paths(samples[0])
            target_slug = body.entity or "finding"
            schema = get_target_schema(target_slug) or get_schema("finding")
            suggestions = auto_suggest(paths, schema)

        field_map = body.field_map or (suggestions if suggestions else [])

        # Map up to 5 sample records
        preview_records = []
        for raw in samples[:5]:
            mapped_result = map_record(raw, field_map)
            preview_records.append({
                "raw": raw,
                "mapped": mapped_result["mapped"],
                "errors": mapped_result["errors"],
            })

        return {
            "records": preview_records,
            "suggestions": suggestions,
            "total_sample": len(samples),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("preview_mapping failed")
        raise HTTPException(500, f"Preview failed: {e}")


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
    logo_url: Optional[str] = None


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
    logo_url: Optional[str] = None


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
    valid_entities = set(get_registry().keys()) | {"action"}
    if body.entity not in valid_entities:
        raise HTTPException(400, f"entity must be one of: {sorted(valid_entities)}")
    if body.transport_type not in ("api", "sql", "file", "mcp"):
        raise HTTPException(400, "transport_type must be 'api', 'sql', 'file', or 'mcp'")

    # Auto-resolve logo from connector template if not provided
    logo_url = body.logo_url
    if not logo_url and body.template_id:
        try:
            tpl = get_connector(body.template_id)
            if tpl:
                logo_url = tpl.get("logo")
        except Exception:
            pass
    # Auto-fetch favicon if we have an instance URL and no logo
    if not logo_url and body.credentials_id:
        try:
            cred = db.query(IntegrationCredential).filter(
                IntegrationCredential.id == body.credentials_id
            ).first()
            if cred and cred.instance_url:
                logo_url = _favicon_url(cred.instance_url)
        except Exception:
            pass

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
        logo_url=logo_url,
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
                   "field_map", "dedup_key", "params", "schedule", "enabled", "logo_url"]:
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
async def run_integration(integration_id: str, background_tasks: BackgroundTasks = None,
                           db: Session = Depends(get_db),
                           user: User = Depends(require_auth)):
    """Trigger an integration run (executes in background)."""
    import asyncio
    from services.run_engine import execute

    i = _get_integration_or_404(db, integration_id, user.org_id)

    # Create a pending run record so we can return the run_id immediately
    run = IntegrationRun(
        integration_id=integration_id,
        status="running",
        triggered_by="manual",
        records_fetched=0, records_inserted=0, records_updated=0, records_skipped=0,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id

    # Execute in background with its own DB session.
    # Wrapped in create_task (preferred over ensure_future) with error logging.
    async def _bg_execute(bg_integration_id, bg_run_id):
        from core.database import SessionLocal
        bg_db = SessionLocal()
        try:
            await execute(bg_db, bg_integration_id, triggered_by="manual", run_id=bg_run_id)
        except Exception as e:
            logger.exception(f"Background run {bg_run_id} failed: {e}")
            try:
                bg_run = bg_db.query(IntegrationRun).filter(IntegrationRun.id == bg_run_id).first()
                if bg_run and bg_run.status == "running":
                    bg_run.status = "error"
                    bg_run.error_message = str(e)[:2000]
                    bg_db.commit()
            except Exception:
                logger.exception(f"Failed to record error for run {bg_run_id}")
        finally:
            bg_db.close()

    asyncio.get_running_loop().create_task(_bg_execute(integration_id, run_id))

    return {
        "run_id": run_id,
        "status": "running",
        "records_fetched": 0,
        "records_inserted": 0,
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
    # Resolve logo: use custom logo_url, or fall back to connector template logo
    logo = getattr(i, "logo_url", None)
    if not logo and i.template_id:
        try:
            tpl = get_connector(i.template_id)
            if tpl:
                logo = tpl.get("logo")
        except Exception:
            pass
    return {
        "id": i.id, "name": i.name, "direction": i.direction, "entity": i.entity,
        "transport_type": i.transport_type, "enabled": i.enabled,
        "template_id": i.template_id, "schedule": i.schedule,
        "logo_url": logo,
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
        "status": r.status, "triggered_by": getattr(r, "triggered_by", "manual"),
        "duration_ms": getattr(r, "duration_ms", None),
        "error_message": getattr(r, "error_message", None),
        "records_fetched": r.records_fetched,
        "records_inserted": r.records_inserted, "records_updated": r.records_updated,
        "records_skipped": r.records_skipped,
        "error_count": len(r.errors) if r.errors else 0,
    }


def _run_detail(r):
    return {**_run_summary(r), "errors": r.errors, "step_log": r.step_log}


def _favicon_url(instance_url: str) -> str | None:
    """Derive a favicon URL from an instance URL using Google's favicon service."""
    if not instance_url:
        return None
    try:
        from urllib.parse import urlparse
        parsed = urlparse(instance_url if "://" in instance_url else f"https://{instance_url}")
        hostname = parsed.hostname
        if not hostname:
            return None
        return f"https://www.google.com/s2/favicons?domain={hostname}&sz=64"
    except Exception:
        return None


@router.post("/integrations/{integration_id}/logo")
def update_integration_logo(integration_id: str, body: dict,
                            db: Session = Depends(get_db), user: User = Depends(require_auth)):
    """Update the logo URL for an integration. Pass {"logo_url": "..."} or {"auto": true}."""
    i = _get_integration_or_404(db, integration_id, user.org_id)
    if body.get("auto"):
        # Auto-fetch from instance URL
        if i.credentials_id:
            cred = db.query(IntegrationCredential).filter(
                IntegrationCredential.id == i.credentials_id
            ).first()
            if cred and cred.instance_url:
                i.logo_url = _favicon_url(cred.instance_url)
        # Or from connector template
        if not i.logo_url and i.template_id:
            try:
                tpl = get_connector(i.template_id)
                if tpl:
                    i.logo_url = tpl.get("logo")
            except Exception:
                pass
    else:
        i.logo_url = body.get("logo_url")
    db.commit()
    return {"logo_url": i.logo_url}

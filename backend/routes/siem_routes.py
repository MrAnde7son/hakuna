"""SIEM event routes — /api/siem/*

Hot-tier ingest, search, and management for security events.
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text, or_
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from core.audit import log_audit
from models.models import SIEMEvent, IngestEndpoint, Integration, Asset
from services.event_store import get_event_store, EventFilter
from services.vector_config import generate_config, generate_install_script, list_templates, AVAILABLE_TEMPLATES

router = APIRouter()


# ── Pydantic schemas ────────────────────────────────────

class EventCreate(BaseModel):
    event_time: datetime
    source_system: str
    source_id: Optional[str] = None
    event_type: str
    event_category: Optional[str] = None
    severity: str = "info"
    action: Optional[str] = None
    outcome: Optional[str] = None
    asset_id: Optional[int] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    host_name: Optional[str] = None
    message: Optional[str] = None
    raw: Optional[dict] = None
    normalized: Optional[dict] = None
    integration_id: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "event_time": "2026-04-14T10:30:00Z",
                "source_system": "palo_alto",
                "event_type": "network",
                "severity": "medium",
                "source_ip": "10.0.0.5",
                "dest_ip": "203.0.113.50",
                "message": "Outbound connection to suspicious IP blocked",
            }
        }


class EventBatchCreate(BaseModel):
    events: List[EventCreate] = Field(..., max_length=5000)


class EventUpdate(BaseModel):
    severity: Optional[str] = None
    event_category: Optional[str] = None
    asset_id: Optional[int] = None


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


# ── Helpers ─────────────────────────────────────────────

def _resolve_event_asset(db: Session, org_id: int, source_ip: str = None, host_name: str = None) -> Optional[int]:
    """Resolve an asset_id from event source_ip or host_name at ingest time."""
    from models.models import Scan
    if source_ip:
        asset = db.query(Asset.id).join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == org_id, Asset.ip == source_ip).first()
        if asset:
            return asset[0]
    if host_name:
        asset = db.query(Asset.id).join(Scan, Asset.scan_id == Scan.id).filter(
            Scan.org_id == org_id,
            (Asset.hostname == host_name) | (Asset.fqdn == host_name),
        ).first()
        if asset:
            return asset[0]
    return None


def _compute_dedup_hash(org_id: int, event: EventCreate) -> str:
    """Deterministic hash for dedup: org + source_system + source_id + event_time + message."""
    key_parts = [
        str(org_id),
        event.source_system,
        event.source_id or "",
        event.event_time.isoformat(),
        event.event_type,
        event.message or "",
    ]
    raw = "|".join(key_parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _event_to_dict(ev: SIEMEvent) -> dict:
    return {
        "id": ev.id,
        "org_id": ev.org_id,
        "event_time": ev.event_time.isoformat() if ev.event_time else None,
        "ingested_at": ev.ingested_at.isoformat() if ev.ingested_at else None,
        "source_system": ev.source_system,
        "source_id": ev.source_id,
        "event_type": ev.event_type,
        "event_category": ev.event_category,
        "severity": ev.severity,
        "action": ev.action,
        "outcome": ev.outcome,
        "asset_id": ev.asset_id,
        "user_name": ev.user_name,
        "source_ip": ev.source_ip,
        "dest_ip": ev.dest_ip,
        "host_name": ev.host_name,
        "message": ev.message,
        "raw": ev.raw,
        "normalized": ev.normalized,
        "dedup_hash": ev.dedup_hash,
        "integration_id": ev.integration_id,
    }


def _validate_severity(severity: str):
    if severity not in VALID_SEVERITIES:
        raise HTTPException(400, f"Invalid severity '{severity}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}")


# ── Single event ingest ─────────────────────────────────

@router.post("/api/siem/events")
async def ingest_event(
    body: EventCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Ingest a single SIEM event."""
    _validate_severity(body.severity)
    org_id = org_ids[0] if org_ids else current_user.org_id
    dedup_hash = _compute_dedup_hash(org_id, body)

    existing = db.query(SIEMEvent).filter(
        SIEMEvent.org_id == org_id,
        SIEMEvent.dedup_hash == dedup_hash,
    ).first()
    if existing:
        return {"id": existing.id, "status": "duplicate", "dedup_hash": dedup_hash}

    # Resolve asset from IP/hostname if not explicitly provided
    asset_id = body.asset_id
    if not asset_id:
        asset_id = _resolve_event_asset(db, org_id, body.source_ip, body.host_name)

    ev = SIEMEvent(
        org_id=org_id,
        event_time=body.event_time,
        source_system=body.source_system,
        source_id=body.source_id,
        event_type=body.event_type,
        event_category=body.event_category,
        severity=body.severity,
        action=body.action,
        outcome=body.outcome,
        asset_id=asset_id,
        user_name=body.user_name,
        source_ip=body.source_ip,
        dest_ip=body.dest_ip,
        host_name=body.host_name,
        message=body.message,
        raw=body.raw,
        normalized=body.normalized,
        dedup_hash=dedup_hash,
        integration_id=body.integration_id,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return {"id": ev.id, "status": "created", "dedup_hash": dedup_hash}


# ── Batch ingest ────────────────────────────────────────

@router.post("/api/siem/events/batch")
async def ingest_events_batch(
    body: EventBatchCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Bulk ingest up to 5000 SIEM events."""
    org_id = org_ids[0] if org_ids else current_user.org_id
    created = 0
    duplicates = 0
    errors = []

    # Pre-compute hashes and check existing in bulk
    hash_map = {}
    for i, event in enumerate(body.events):
        if event.severity not in VALID_SEVERITIES:
            errors.append({"index": i, "error": f"Invalid severity: {event.severity}"})
            continue
        h = _compute_dedup_hash(org_id, event)
        hash_map[h] = (i, event)

    existing_hashes = set()
    if hash_map:
        hashes = list(hash_map.keys())
        # Query in batches of 500
        for batch_start in range(0, len(hashes), 500):
            batch = hashes[batch_start:batch_start + 500]
            rows = db.query(SIEMEvent.dedup_hash).filter(
                SIEMEvent.org_id == org_id,
                SIEMEvent.dedup_hash.in_(batch),
            ).all()
            existing_hashes.update(r[0] for r in rows)

    new_events = []
    for h, (i, event) in hash_map.items():
        if h in existing_hashes:
            duplicates += 1
            continue
        asset_id = event.asset_id or _resolve_event_asset(db, org_id, event.source_ip, event.host_name)
        new_events.append(SIEMEvent(
            org_id=org_id,
            event_time=event.event_time,
            source_system=event.source_system,
            source_id=event.source_id,
            event_type=event.event_type,
            event_category=event.event_category,
            severity=event.severity,
            action=event.action,
            outcome=event.outcome,
            asset_id=asset_id,
            user_name=event.user_name,
            source_ip=event.source_ip,
            dest_ip=event.dest_ip,
            host_name=event.host_name,
            message=event.message,
            raw=event.raw,
            normalized=event.normalized,
            dedup_hash=h,
            integration_id=event.integration_id,
        ))

    if new_events:
        db.bulk_save_objects(new_events)
        db.commit()
        created = len(new_events)

    return {
        "created": created,
        "duplicates": duplicates,
        "errors": errors,
        "total": len(body.events),
    }


# ── Facets ─────────────────────────────────────────────

@router.get("/api/siem/events/source-systems")
async def list_source_systems(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Return distinct source_system values for the tenant."""
    q = db.query(SIEMEvent.source_system)
    if org_ids is not None:
        q = q.filter(SIEMEvent.org_id.in_(list(org_ids)))
    rows = q.distinct().order_by(SIEMEvent.source_system).all()
    return [r[0] for r in rows if r[0]]


# ── Search ──────────────────────────────────────────────

@router.get("/api/siem/events/search")
async def search_events(
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    source_system: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    asset_id: Optional[int] = None,
    host_name: Optional[str] = None,
    user_name: Optional[str] = None,
    source_ip: Optional[str] = None,
    q: Optional[str] = None,
    sort_by: str = "event_time",
    order: str = "desc",
    page: int = 1,
    page_size: int = Query(default=50, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Search SIEM events with filters and pagination.

    Uses RoutedEventStore to query hot (Postgres) or lake (Iceberg) tier
    based on the requested time range.
    """
    store = get_event_store(db)
    filters = EventFilter(
        org_ids=list(org_ids) if org_ids is not None else [],
        time_from=time_from,
        time_to=time_to,
        source_system=source_system,
        severity=severity,
        event_type=event_type,
        asset_id=asset_id,
        host_name=host_name,
        user_name=user_name,
        source_ip=source_ip,
        q=q,
        sort_by=sort_by,
        order=order,
    )

    total = store.count(filters)
    offset = (page - 1) * page_size
    records = store.query(filters, limit=page_size, offset=offset)

    return {
        "items": [r.to_dict() for r in records],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 1,
    }


# ── Single event detail ────────────────────────────────

@router.get("/api/siem/events/{event_id}")
async def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get a single SIEM event by ID (checks hot tier, then lake)."""
    store = get_event_store(db)
    record = store.get_by_id(event_id, list(org_ids) if org_ids is not None else [])
    if not record:
        raise HTTPException(404, "Event not found")
    return record.to_dict()


# ── Retention cleanup (admin-only) ─────────────────────

@router.delete("/api/siem/events/retention")
async def cleanup_retention(
    hours: int = Query(default=72, ge=1, description="Delete events older than this many hours"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Delete hot-tier events older than the retention window. Admin only."""
    if current_user.role not in ("org_admin", "super_admin"):
        raise HTTPException(403, "Admin access required")

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(SIEMEvent).filter(SIEMEvent.event_time < cutoff)
    if org_ids is not None:
        q = q.filter(SIEMEvent.org_id.in_(org_ids))
    deleted = q.delete(synchronize_session=False)
    db.commit()

    log_audit(db, "delete", "siem_event", None,
              entity_name="retention_cleanup",
              changes={"hours": hours, "deleted_count": deleted, "cutoff": cutoff.isoformat()},
              actor=current_user)

    return {"deleted": deleted, "cutoff": cutoff.isoformat()}


# ── Ingest Endpoint Management ─────────────────────────

class EndpointCreate(BaseModel):
    name: str
    parser_type: str = "json"
    integration_id: Optional[str] = None


VALID_PARSER_TYPES = {"json", "hec", "cef", "leef", "syslog_rfc5424"}


@router.post("/api/siem/endpoints")
async def create_ingest_endpoint(
    body: EndpointCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Create an ingest endpoint. Returns plaintext token + HMAC secret ONCE."""
    if current_user.role not in ("org_admin", "super_admin"):
        raise HTTPException(403, "Admin access required")
    if body.parser_type not in VALID_PARSER_TYPES:
        raise HTTPException(400, f"Invalid parser_type. Must be one of: {', '.join(sorted(VALID_PARSER_TYPES))}")

    import secrets
    from passlib.hash import bcrypt

    org_id = org_ids[0] if org_ids else current_user.org_id
    token = f"hki_{secrets.token_urlsafe(32)}"
    hmac_secret = secrets.token_urlsafe(32)

    ep = IngestEndpoint(
        org_id=org_id,
        integration_id=body.integration_id,
        name=body.name,
        token_hash=bcrypt.hash(token),
        token_prefix=token[:12],
        hmac_secret_hash=bcrypt.hash(hmac_secret),
        parser_type=body.parser_type,
    )
    db.add(ep)
    db.commit()
    db.refresh(ep)

    log_audit(db, "create", "ingest_endpoint", ep.id,
              entity_name=ep.name,
              changes={"parser_type": ep.parser_type},
              actor=current_user)

    return {
        "id": ep.id,
        "name": ep.name,
        "parser_type": ep.parser_type,
        "token": token,
        "hmac_secret": hmac_secret,
        "token_prefix": ep.token_prefix,
        "warning": "Save token and HMAC secret now — they will not be shown again.",
    }


@router.get("/api/siem/endpoints")
async def list_ingest_endpoints(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List all ingest endpoints for the org."""
    q = db.query(IngestEndpoint)
    if org_ids is not None:
        q = q.filter(IngestEndpoint.org_id.in_(org_ids))
    endpoints = q.order_by(IngestEndpoint.created_at.desc()).all()

    return [
        {
            "id": ep.id,
            "name": ep.name,
            "parser_type": ep.parser_type,
            "token_prefix": ep.token_prefix,
            "is_active": ep.is_active,
            "last_used_at": ep.last_used_at.isoformat() if ep.last_used_at else None,
            "request_count": ep.request_count or 0,
            "created_at": ep.created_at.isoformat() if ep.created_at else None,
        }
        for ep in endpoints
    ]


@router.delete("/api/siem/endpoints/{endpoint_id}")
async def delete_ingest_endpoint(
    endpoint_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Delete an ingest endpoint."""
    if current_user.role not in ("org_admin", "super_admin"):
        raise HTTPException(403, "Admin access required")

    q = db.query(IngestEndpoint).filter(IngestEndpoint.id == endpoint_id)
    if org_ids is not None:
        q = q.filter(IngestEndpoint.org_id.in_(org_ids))
    ep = q.first()
    if not ep:
        raise HTTPException(404, "Endpoint not found")

    db.delete(ep)
    db.commit()

    log_audit(db, "delete", "ingest_endpoint", endpoint_id,
              entity_name=ep.name,
              actor=current_user)

    return {"deleted": True}


# ── Vector Config Generation ───────────────────────────

@router.get("/api/siem/vector-templates")
async def get_vector_templates(
    current_user=Depends(get_current_user),
):
    """List available Vector source templates."""
    return list_templates()


class VectorConfigRequest(BaseModel):
    template_id: str = "linux_syslog"
    endpoint_id: str
    token: str
    hakuna_url: str = "http://localhost:8000"
    listen_port: Optional[int] = None
    custom_vrl: Optional[str] = None


@router.post("/api/siem/vector-config")
async def generate_vector_config(
    body: VectorConfigRequest,
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
    db: Session = Depends(get_db),
):
    """Generate a Vector config YAML for a given template + endpoint."""
    # Verify the endpoint belongs to this org
    eq = db.query(IngestEndpoint).filter(IngestEndpoint.id == body.endpoint_id)
    if org_ids is not None:
        eq = eq.filter(IngestEndpoint.org_id.in_(org_ids))
    ep = eq.first()
    if not ep:
        raise HTTPException(404, "Ingest endpoint not found")

    config_yaml = generate_config(
        integration_name=ep.name,
        template_id=body.template_id,
        endpoint_id=body.endpoint_id,
        token=body.token,
        hakuna_url=body.hakuna_url,
        listen_port=body.listen_port,
        custom_vrl=body.custom_vrl,
    )
    return {"config": config_yaml, "template_id": body.template_id, "endpoint_id": body.endpoint_id}


@router.post("/api/siem/vector-config/install-script")
async def generate_vector_install_script(
    body: VectorConfigRequest,
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
    db: Session = Depends(get_db),
):
    """Generate a bootstrap shell script for Vector installation."""
    eq = db.query(IngestEndpoint).filter(IngestEndpoint.id == body.endpoint_id)
    if org_ids is not None:
        eq = eq.filter(IngestEndpoint.org_id.in_(org_ids))
    ep = eq.first()
    if not ep:
        raise HTTPException(404, "Ingest endpoint not found")

    script = generate_install_script(
        endpoint_id=body.endpoint_id,
        token=body.token,
        template_id=body.template_id,
        hakuna_url=body.hakuna_url,
        listen_port=body.listen_port,
    )
    return {"script": script, "template_id": body.template_id}


@router.get("/api/siem/integrations/{integration_id}/vector-config")
async def get_integration_vector_config(
    integration_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get the Vector config for a stream-type integration."""
    iq = db.query(Integration).filter(Integration.id == integration_id)
    if org_ids is not None:
        iq = iq.filter(Integration.org_id.in_(org_ids))
    integration = iq.first()
    if not integration:
        raise HTTPException(404, "Integration not found")
    if integration.transport_type != "stream":
        raise HTTPException(400, "Integration is not a stream transport type")

    stream_cfg = integration.stream_config or {}
    template_id = stream_cfg.get("template_id", "linux_syslog")

    # Find linked ingest endpoint
    eq = db.query(IngestEndpoint).filter(IngestEndpoint.integration_id == integration_id)
    if org_ids is not None:
        eq = eq.filter(IngestEndpoint.org_id.in_(org_ids))
    ep = eq.first()
    if not ep:
        raise HTTPException(400, "No ingest endpoint linked to this integration. Create one first.")

    hakuna_url = stream_cfg.get("hakuna_url", "http://localhost:8000")
    listen_port = stream_cfg.get("listen_port")

    config_yaml = generate_config(
        integration_name=integration.name,
        template_id=template_id,
        endpoint_id=ep.id,
        token="<YOUR_TOKEN>",  # Token is one-time — user must supply
        hakuna_url=hakuna_url,
        listen_port=listen_port,
        custom_vrl=stream_cfg.get("vrl_transform"),
    )
    return {"config": config_yaml, "template_id": template_id, "endpoint_id": ep.id}

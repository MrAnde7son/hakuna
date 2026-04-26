"""Auto-dispatch unauthenticated SMB / SNMP audits when hakuna-scanner
reports newly opened ports on an asset.

Wired into ``services.scanner_event_bridge``: after each ``port_change``
event is forwarded to the workflow engine, this also checks whether any
of the *newly added* ports map to a protocol we can audit anonymously
(SMB on 445/139, SNMP on 161). If so — and the org has opted in via
``Organization.settings["auto_audit_anon"]`` — we kick off an audit run
through the standard ``services.audit_runner.dispatch_audit_run``
pipeline with ``credential_id=None``.

A 24h per-(asset, protocol) cooldown is stored on
``Asset.easm_data["_auto_audit_last"]`` so a flapping port doesn't fan
out a fresh audit on every poll cycle.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.models import Asset, Organization, RelayAgent, Scan
from services.audit_runner import AuditDispatchError, dispatch_audit_run

logger = logging.getLogger(__name__)


# Newly-opened port → (protocol, mission) for protocols whose tools support
# unauthenticated operation. Aligned with
# ``audit_runner._ANON_CAPABLE_PROTOCOLS`` plus the specific mission whose
# checklist is meaningful without credentials.
_PORT_TO_ANON_AUDIT: dict[int, tuple[str, str]] = {
    445: ("smb", "null_session"),
    139: ("smb", "null_session"),
    161: ("snmp", "device_posture"),
}

_COOLDOWN = timedelta(hours=24)


def _is_enabled(org: Organization) -> bool:
    """Per-org opt-in. Default OFF so this never spends LLM budget without
    explicit consent — the org admin flips it on under settings."""
    return bool((org.settings or {}).get("auto_audit_anon"))


def _resolve_backend_asset(
    db: Session, org_id: int, scanner_asset_id: Optional[str], hostname: Optional[str],
) -> Optional[Asset]:
    """Map the scanner-side UUID back to a backend ``Asset`` in this org.

    The scanner emits its own UUID; backend assets store it in
    ``easm_data["easm_asset_id"]``. Filtering JSON across SQLite (tests)
    and Postgres (prod) is dialect-specific, so narrow with ``hostname``
    when available and finish the match in Python — the candidate set is
    small (one asset per fqdn per org).
    """
    if not scanner_asset_id:
        return None
    q = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Scan.org_id == org_id, Asset.easm_data.isnot(None))
    )
    if hostname:
        q = q.filter(or_(Asset.hostname == hostname, Asset.fqdn == hostname))
    for asset in q.limit(50).all():
        if (asset.easm_data or {}).get("easm_asset_id") == scanner_asset_id:
            return asset
    return None


def _pick_relay(db: Session, org_id: int) -> Optional[RelayAgent]:
    """Most-recently-seen connected relay for the org. Audits run over the
    relay; without one we have nowhere to send the request."""
    return (
        db.query(RelayAgent)
        .filter(RelayAgent.org_id == org_id, RelayAgent.status == "connected")
        .order_by(RelayAgent.last_seen_at.desc().nullslast())
        .first()
    )


def _within_cooldown(asset: Asset, protocol: str, now: datetime) -> bool:
    last_map = (asset.easm_data or {}).get("_auto_audit_last") or {}
    raw = last_map.get(protocol)
    if not raw:
        return False
    try:
        last = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) < _COOLDOWN


def _stamp_cooldown(asset: Asset, protocol: str, now: datetime) -> None:
    easm = dict(asset.easm_data or {})
    last_map = dict(easm.get("_auto_audit_last") or {})
    last_map[protocol] = now.isoformat()
    easm["_auto_audit_last"] = last_map
    asset.easm_data = easm


def maybe_auto_trigger_anon_audits(
    db: Session, org: Organization, event: dict,
) -> int:
    """Inspect a scanner ``port_change`` event and dispatch matching anon audits.

    Returns the number of audits actually dispatched. No-op (returns 0) if
    the org hasn't opted in, the event isn't a ``port_change``, no added
    port matches an anon-capable protocol, the asset can't be resolved, no
    relay is connected, or the per-(asset,protocol) cooldown is in effect.
    """
    if event.get("event_type") != "port_change":
        return 0
    if not _is_enabled(org):
        return 0

    payload = event.get("payload") or {}
    new_ports: set[int] = set()
    for p in payload.get("new_ports") or []:
        try:
            new_ports.add(int(p))
        except (TypeError, ValueError):
            continue
    matched: dict[str, str] = {}
    for port in new_ports:
        if port in _PORT_TO_ANON_AUDIT:
            proto, mission = _PORT_TO_ANON_AUDIT[port]
            # First port wins per protocol — 445 and 139 both map to smb;
            # we only need one audit run.
            matched.setdefault(proto, mission)
    if not matched:
        return 0

    asset = _resolve_backend_asset(
        db, org.id,
        scanner_asset_id=event.get("asset_id"),
        hostname=payload.get("hostname"),
    )
    if not asset:
        logger.info(
            "auto-audit: org=%d skipped — scanner asset %s not yet linked to backend",
            org.id, event.get("asset_id"),
        )
        return 0

    relay = _pick_relay(db, org.id)
    if not relay:
        logger.info(
            "auto-audit: org=%d skipped — no connected relay for asset %d",
            org.id, asset.id,
        )
        return 0

    now = datetime.now(timezone.utc)
    dispatched = 0
    for protocol, mission in matched.items():
        if _within_cooldown(asset, protocol, now):
            logger.debug(
                "auto-audit: org=%d asset=%d protocol=%s suppressed by cooldown",
                org.id, asset.id, protocol,
            )
            continue
        try:
            result = dispatch_audit_run(
                db, org,
                protocol=protocol,
                mission=mission,
                relay_agent_id=relay.id,
                credential_id=None,
                asset_ids=[asset.id],
            )
        except AuditDispatchError as e:
            logger.warning(
                "auto-audit: org=%d asset=%d protocol=%s dispatch failed: %s",
                org.id, asset.id, protocol, e,
            )
            continue
        _stamp_cooldown(asset, protocol, now)
        dispatched += 1
        logger.info(
            "auto-audit: org=%d asset=%d protocol=%s mission=%s scan=%s dispatched on port_change",
            org.id, asset.id, protocol, mission, result.get("scan_id"),
        )
    if dispatched:
        db.commit()
    return dispatched

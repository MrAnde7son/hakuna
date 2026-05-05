"""Scanner event bridge — polls hakuna-scanner /events endpoint and fires
workflow triggers in the backend.

The scanner already writes events durably to its Postgres (`asset_events`
table). This bridge polls every 60s via `/orgs/{org_id}/events?since=<cursor>`,
advances a per-org cursor, and maps each event type to the appropriate
workflow trigger type:

    new_asset        → on_new_asset        (already wired; de-duped with cursor)
    tech_change      → on_tech_changed     (NEW)
    port_change      → on_port_changed     (NEW)
    ip_change        → on_ip_changed       (NEW)
    cert_expiring    → on_cert_expiring    (NEW)
    asset_gone       → on_asset_gone       (NEW)

Each scanner event becomes a separate backend event with normalized payload.
Cursor advancement is per-org so one org's failure doesn't block others.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.models import Organization, ScannerEventCursor
from services import workflow_engine
from services.audit_auto_trigger import maybe_auto_trigger_anon_audits
from services.easm import get_easm_events

logger = logging.getLogger(__name__)


# Scanner event type → backend workflow trigger type
EVENT_TYPE_MAP = {
    "new_asset": "on_new_asset",
    "tech_change": "on_tech_changed",
    "port_change": "on_port_changed",
    "ip_change": "on_ip_changed",
    "cert_expiring": "on_cert_expiring",
    "asset_gone": "on_asset_gone",
}


def _get_or_create_cursor(db: Session, org_id: int) -> ScannerEventCursor:
    """Load or create the per-org event cursor."""
    cursor = db.query(ScannerEventCursor).filter_by(org_id=org_id).first()
    if cursor:
        return cursor
    cursor = ScannerEventCursor(org_id=org_id, last_event_at=None, last_event_id=None)
    db.add(cursor)
    db.commit()
    db.refresh(cursor)
    return cursor


def _normalize_payload(event: dict) -> dict:
    """Normalize a scanner event into a workflow-engine-compatible payload."""
    payload = event.get("payload") or {}
    return {
        "asset_id": event.get("asset_id"),
        "event_type": event.get("event_type"),
        "event_at": event.get("created_at"),
        **payload,
    }


async def _poll_org_once(db: Session, org: Organization) -> dict:
    """Poll a single org for new scanner events and fire workflow triggers.

    Returns stats: {"events": int, "fired": int, "skipped": int}.
    """
    if not org.easm_org_id:
        return {"events": 0, "fired": 0, "skipped": 0, "reason": "no_easm_org_id"}

    cursor = _get_or_create_cursor(db, org.id)
    since = cursor.last_event_at.isoformat() if cursor.last_event_at else None

    try:
        events = await get_easm_events(org.easm_org_id, since=since, limit=500)
    except Exception as e:
        logger.warning("org=%d scanner events fetch failed: %s", org.id, e)
        return {"events": 0, "fired": 0, "skipped": 0, "error": str(e)}

    if not events:
        return {"events": 0, "fired": 0, "skipped": 0}

    fired_total = 0
    skipped = 0
    max_event_at: datetime | None = cursor.last_event_at
    max_event_id: str | None = cursor.last_event_id

    for event in events:
        scanner_event_type = event.get("event_type")
        trigger_type = EVENT_TYPE_MAP.get(scanner_event_type)
        event_id = event.get("id")
        event_created_at = event.get("created_at")

        # Skip events we've already processed (defensive dedup using id)
        if event_id and event_id == cursor.last_event_id:
            skipped += 1
            continue

        if not trigger_type:
            skipped += 1
        else:
            payload = _normalize_payload(event)
            try:
                fired = workflow_engine.fire_event_workflows(db, trigger_type, payload)
                fired_total += fired or 0
            except Exception as e:
                logger.warning(
                    "org=%d failed to fire trigger %s: %s", org.id, trigger_type, e,
                )

            # Out-of-the-box auto-audit on port_change for anon-capable
            # protocols (SMB null session, SNMP default community). Gated
            # per-org by Organization.settings["auto_audit_anon"]; failure
            # here is non-fatal and must not interrupt cursor advancement.
            if scanner_event_type == "port_change":
                try:
                    maybe_auto_trigger_anon_audits(db, org, event)
                except Exception as e:
                    logger.warning(
                        "org=%d auto-audit trigger failed: %s", org.id, e,
                    )

        # Advance cursor
        if event_created_at:
            try:
                event_dt = datetime.fromisoformat(event_created_at.replace("Z", "+00:00"))
                # Ensure both sides are tz-aware for comparison (legacy rows may be naive)
                if max_event_at is not None and max_event_at.tzinfo is None:
                    max_event_at = max_event_at.replace(tzinfo=timezone.utc)
                if max_event_at is None or event_dt > max_event_at:
                    max_event_at = event_dt
                    max_event_id = event_id
            except (ValueError, AttributeError):
                pass

    # Persist cursor advance
    if max_event_at and max_event_at != cursor.last_event_at:
        cursor.last_event_at = max_event_at
        cursor.last_event_id = max_event_id
        cursor.updated_at = datetime.now(timezone.utc)
        db.commit()

    return {"events": len(events), "fired": fired_total, "skipped": skipped}


async def _poll_all_orgs() -> dict:
    """Poll all orgs linked to the hakuna-scanner."""
    db: Session = SessionLocal()
    try:
        orgs = db.query(Organization).filter(Organization.easm_org_id.isnot(None)).all()
        stats = {"orgs": len(orgs), "events": 0, "fired": 0}
        for org in orgs:
            try:
                result = await _poll_org_once(db, org)
                stats["events"] += result.get("events", 0)
                stats["fired"] += result.get("fired", 0)
            except Exception as e:
                logger.exception("org=%d scanner event bridge error: %s", org.id, e)
        if stats["events"]:
            logger.info(
                "Scanner event bridge: orgs=%d events=%d fired=%d workflows",
                stats["orgs"], stats["events"], stats["fired"],
            )
        return stats
    finally:
        db.close()


def _run_poll_cycle():
    """APScheduler entry point — sync wrapper around async poll."""
    try:
        asyncio.run(_poll_all_orgs())
    except Exception as e:
        logger.exception("Scanner event bridge cycle failed: %s", e)


def start_event_bridge_scheduler():
    """Register the event bridge with APScheduler (every 60s).

    Follows the same pattern as start_detection_scheduler.
    Safe to call multiple times — replace_existing=True.
    """
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        _run_poll_cycle,
        IntervalTrigger(seconds=60),
        id="scanner_event_bridge",
        replace_existing=True,
        misfire_grace_time=60,
        coalesce=True,
    )
    scheduler.start()
    logger.info("Scanner event bridge scheduler started (every 60 seconds)")

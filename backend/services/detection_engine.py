"""Detection engine — runs windowed threshold rules against SIEM events.

Each DetectionRule specifies:
- query: filters (source_system, severity, event_type, message patterns)
- window_seconds: time window to count events
- threshold: fire if count >= threshold within window
- group_by: group events by fields (e.g. source_ip) for per-group alerts
- schedule_minutes: how often to check
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models.models import DetectionRule, Alert, SIEMEvent

logger = logging.getLogger(__name__)


def _apply_rule_filters(query, rule: DetectionRule):
    """Apply rule.query filters to a SIEMEvent query."""
    filters = rule.query or {}

    if filters.get("source_system"):
        query = query.filter(SIEMEvent.source_system == filters["source_system"])
    if filters.get("severity"):
        if isinstance(filters["severity"], list):
            query = query.filter(SIEMEvent.severity.in_(filters["severity"]))
        else:
            query = query.filter(SIEMEvent.severity == filters["severity"])
    if filters.get("event_type"):
        query = query.filter(SIEMEvent.event_type == filters["event_type"])
    if filters.get("message_contains"):
        query = query.filter(SIEMEvent.message.ilike(f"%{filters['message_contains']}%"))
    if filters.get("source_ip"):
        query = query.filter(SIEMEvent.source_ip == filters["source_ip"])
    if filters.get("user_name"):
        query = query.filter(SIEMEvent.user_name.ilike(f"%{filters['user_name']}%"))
    if filters.get("action"):
        query = query.filter(SIEMEvent.action == filters["action"])
    if filters.get("outcome"):
        query = query.filter(SIEMEvent.outcome == filters["outcome"])

    return query


def run_rule(db: Session, rule: DetectionRule) -> list[Alert]:
    """Execute a single detection rule. Returns list of newly created alerts."""
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=rule.window_seconds)

    base_query = db.query(SIEMEvent).filter(
        SIEMEvent.org_id == rule.org_id,
        SIEMEvent.event_time >= window_start,
        SIEMEvent.event_time <= now,
    )
    base_query = _apply_rule_filters(base_query, rule)

    group_by_fields = rule.group_by or []
    new_alerts = []

    if group_by_fields:
        # Group events by the specified fields
        events = base_query.all()
        groups: dict[str, list] = {}
        for ev in events:
            key_parts = [str(getattr(ev, f, "") or "") for f in group_by_fields]
            group_key = "|".join(key_parts)
            groups.setdefault(group_key, []).append(ev)

        for group_key, group_events in groups.items():
            if len(group_events) >= rule.threshold:
                alert = _create_alert(db, rule, group_events, group_key)
                if alert:
                    new_alerts.append(alert)
    else:
        events = base_query.all()
        if len(events) >= rule.threshold:
            alert = _create_alert(db, rule, events, None)
            if alert:
                new_alerts.append(alert)

    rule.last_run_at = now
    if new_alerts:
        rule.last_alert_at = now
    db.flush()

    return new_alerts


def _create_alert(db: Session, rule: DetectionRule, events: list, group_key: Optional[str]) -> Optional[Alert]:
    """Create an alert from matching events, if not already alerted recently."""
    # Dedup: don't re-alert for the same group within the window
    recent_cutoff = datetime.utcnow() - timedelta(seconds=rule.window_seconds)
    existing = db.query(Alert).filter(
        Alert.rule_id == rule.id,
        Alert.org_id == rule.org_id,
        Alert.fired_at >= recent_cutoff,
    )
    if group_key is not None:
        existing = existing.filter(Alert.group_key == group_key)
    if existing.first():
        return None

    # Build context: sample of matching events
    sample = []
    for ev in events[:10]:
        sample.append({
            "id": ev.id,
            "event_time": ev.event_time.isoformat() if ev.event_time else None,
            "source_system": ev.source_system,
            "severity": ev.severity,
            "message": (ev.message or "")[:200],
            "source_ip": ev.source_ip,
            "user_name": ev.user_name,
            "host_name": ev.host_name,
        })

    # Try to resolve asset_id if events share one
    asset_ids = {ev.asset_id for ev in events if ev.asset_id}
    asset_id = asset_ids.pop() if len(asset_ids) == 1 else None

    alert = Alert(
        org_id=rule.org_id,
        rule_id=rule.id,
        severity=rule.severity,
        event_count=len(events),
        group_key=group_key,
        first_event_id=events[0].id if events else None,
        last_event_id=events[-1].id if events else None,
        context={"events_sample": sample, "group_by": rule.group_by or [], "group_key": group_key},
        asset_id=asset_id,
    )
    db.add(alert)
    db.flush()

    # Fire workflow trigger
    _fire_alert_trigger(db, alert, rule)

    return alert


def _fire_alert_trigger(db: Session, alert: Alert, rule: DetectionRule):
    """Fire on_alert_created workflow trigger."""
    try:
        import services.workflow_engine as we
        we.fire_event_workflows(db, "on_alert_created", {
            "alert_id": alert.id,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": alert.severity,
            "event_count": alert.event_count,
            "group_key": alert.group_key,
            "org_id": alert.org_id,
        })
    except Exception as e:
        logger.warning("Failed to fire on_alert_created workflow: %s", e)


def run_all_due_rules(db: Session = None) -> dict:
    """Run all enabled rules that are due for execution. Called by scheduler."""
    from core.database import SessionLocal

    own_session = db is None
    if own_session:
        db = SessionLocal()

    result = {"rules_checked": 0, "alerts_created": 0, "errors": []}

    try:
        now = datetime.utcnow()
        rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).all()

        for rule in rules:
            try:
                # Check if rule is due
                if rule.last_run_at:
                    next_run = rule.last_run_at + timedelta(minutes=rule.schedule_minutes)
                    if now < next_run:
                        continue

                result["rules_checked"] += 1
                new_alerts = run_rule(db, rule)
                result["alerts_created"] += len(new_alerts)
            except Exception as e:
                result["errors"].append({"rule_id": rule.id, "error": str(e)})
                logger.error("Rule %s (%s) failed: %s", rule.id, rule.name, e)

        db.commit()
    except Exception as e:
        result["errors"].append({"error": str(e)})
        logger.error("Detection engine run failed: %s", e)
    finally:
        if own_session:
            db.close()

    return result


def start_detection_scheduler():
    """Register the detection engine with APScheduler (every minute)."""
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_all_due_rules,
        IntervalTrigger(minutes=1),
        id="siem_detection_engine",
        replace_existing=True,
        misfire_grace_time=60,
        coalesce=True,
    )
    scheduler.start()
    logger.info("SIEM detection engine scheduler started (every 1 minute)")

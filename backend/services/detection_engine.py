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

from sqlalchemy import text
from sqlalchemy.orm import Session

from models.models import DetectionRule, Alert, SIEMEvent, SuppressionRule, Asset

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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
        # Apply asset context filter if set
        if rule.asset_filter:
            events = _check_asset_filter(db, rule, events)
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
        if rule.asset_filter:
            events = _check_asset_filter(db, rule, events)
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

    # Determine primary entity from events
    entity_type, entity_value = _extract_primary_entity(events, group_key, rule.group_by or [])

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
        entity_type=entity_type,
        entity_value=entity_value,
    )

    # Check suppression before persisting
    suppression = _check_suppression(db, rule, events, sample)
    if suppression:
        alert.suppressed = True
        alert.suppression_rule_id = suppression.id
        suppression.suppressed_count = (suppression.suppressed_count or 0) + 1

    db.add(alert)
    db.flush()

    # Enrich with exposure context from asset graph (best-effort)
    try:
        _enrich_with_exposure(db, alert, events)
    except Exception as e:
        logger.warning("Alert enrichment failed (alert %s): %s", alert.id, e)

    # LLM triage (best-effort, gated by ALERT_TRIAGE_ENABLED).
    # Runs after exposure enrichment so the model sees asset context, and
    # before trigger/notification so auto-suppressed FPs don't page a human.
    try:
        from services.alert_triage import triage_alert
        triage_alert(db, alert, rule, events)
    except Exception as e:
        logger.warning("Alert triage failed (alert %s): %s", alert.id, e)

    # Fire workflow trigger and notification for non-suppressed alerts
    if not alert.suppressed:
        _fire_alert_trigger(db, alert, rule)
        _fire_alert_notification(db, alert, rule)

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


def _fire_alert_notification(db: Session, alert: Alert, rule: DetectionRule):
    """Create an in-app notification for a new alert."""
    try:
        from services.notifications import create_notification
        sev = (alert.severity or "medium").capitalize()
        body = f"{sev} severity \u00b7 {alert.event_count} event{'s' if alert.event_count != 1 else ''}"
        if alert.entity_value:
            body += f" \u00b7 {alert.entity_value}"
        create_notification(
            db=db,
            org_id=alert.org_id,
            category="security_alert",
            title=f"Alert: {rule.name}",
            body=body,
            link=f"/siem/alerts?alert_id={alert.id}",
            entity_type="alert",
            entity_id=alert.id,
            metadata={"rule_id": rule.id, "severity": alert.severity, "event_count": alert.event_count},
        )
    except Exception as e:
        logger.warning("Failed to create alert notification: %s", e)


def _extract_primary_entity(events: list, group_key: Optional[str], group_by: list) -> tuple[Optional[str], Optional[str]]:
    """Determine the primary entity (type, value) from events or group key."""
    # If group_by includes a known entity field, use it
    field_to_type = {"source_ip": "ip", "dest_ip": "ip", "host_name": "hostname", "user_name": "user"}
    if group_key and group_by:
        parts = group_key.split("|")
        for i, field in enumerate(group_by):
            if field in field_to_type and i < len(parts) and parts[i]:
                return field_to_type[field], parts[i]

    # Fallback: pick from first event, prefer source_ip > host_name > user_name
    if events:
        ev = events[0]
        if ev.source_ip:
            return "ip", ev.source_ip
        if ev.host_name:
            return "hostname", ev.host_name
        if ev.user_name:
            return "user", ev.user_name

    return None, None


def _check_suppression(db: Session, rule: DetectionRule, events: list, sample: list) -> Optional[SuppressionRule]:
    """Check if any active suppression rule matches this alert's events."""
    now = datetime.utcnow()
    suppressions = db.query(SuppressionRule).filter(
        SuppressionRule.org_id == rule.org_id,
        SuppressionRule.enabled == True,
        (SuppressionRule.expires_at.is_(None)) | (SuppressionRule.expires_at > now),
        (SuppressionRule.rule_id.is_(None)) | (SuppressionRule.rule_id == rule.id),
    ).all()

    if not suppressions:
        return None

    # Build a representative event dict from the first event for matching
    ev = events[0] if events else None
    if not ev:
        return None

    ev_dict = {
        "source_system": ev.source_system,
        "severity": ev.severity,
        "event_type": ev.event_type,
        "source_ip": ev.source_ip,
        "dest_ip": ev.dest_ip,
        "host_name": ev.host_name,
        "user_name": ev.user_name,
        "action": ev.action,
        "outcome": ev.outcome,
        "message": ev.message or "",
    }

    for supp in suppressions:
        conditions = supp.conditions or []
        if not conditions:
            continue

        logic = (supp.conditions_logic or "AND").upper()
        matches = []

        for cond in conditions:
            field = cond.get("field", "")
            op = cond.get("op", "eq")
            value = cond.get("value", "")
            actual = ev_dict.get(field, "")

            if actual is None:
                actual = ""

            matched = False
            actual_lower = str(actual).lower()
            value_lower = str(value).lower()

            if op == "eq":
                matched = actual_lower == value_lower
            elif op == "neq":
                matched = actual_lower != value_lower
            elif op == "contains":
                matched = value_lower in actual_lower
            elif op == "startswith":
                matched = actual_lower.startswith(value_lower)
            elif op == "regex":
                import re
                try:
                    matched = bool(re.search(value, str(actual), re.IGNORECASE))
                except re.error:
                    matched = False
            else:
                matched = actual_lower == value_lower

            matches.append(matched)

        if logic == "AND" and all(matches):
            return supp
        elif logic == "OR" and any(matches):
            return supp

    return None


def _resolve_asset(db: Session, org_id: int, entity_type: str, entity_value: str) -> Optional[Asset]:
    """Resolve an asset from entity type/value."""
    if not entity_value:
        return None
    # org_id is an ALTER TABLE column not in the ORM mapper — use text filter
    q = db.query(Asset).filter(text("assets.org_id = :org_id")).params(org_id=org_id)
    if entity_type == "ip":
        q = q.filter(Asset.ip == entity_value)
    elif entity_type == "hostname":
        q = q.filter((Asset.hostname == entity_value) | (Asset.fqdn == entity_value))
    else:
        return None
    return q.order_by(Asset.last_seen.desc()).first()


def _enrich_with_exposure(db: Session, alert: Alert, events: list):
    """Enrich alert with exposure context from the asset/vulnerability graph."""
    # Resolve asset if not already set
    if not alert.asset_id and alert.entity_type and alert.entity_value:
        asset = _resolve_asset(db, alert.org_id, alert.entity_type, alert.entity_value)
        if asset:
            alert.asset_id = asset.id

    if not alert.asset_id:
        return

    asset = db.query(Asset).filter(Asset.id == alert.asset_id).first()
    if not asset:
        return

    alert.asset_criticality = asset.criticality
    alert.open_vulnerabilities = (asset.critical_count or 0) + (asset.high_count or 0)
    alert.internet_facing = asset.is_internet_facing

    alert.exposure_context = {
        "asset_name": asset.hostname or asset.ip or asset.fqdn,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "risk_score": asset.risk_score,
        "is_internet_facing": asset.is_internet_facing,
        "critical_vulns": asset.critical_count or 0,
        "high_vulns": asset.high_count or 0,
        "medium_vulns": asset.medium_count or 0,
        "environment": asset.environment_tag,
    }
    db.flush()


def _check_asset_filter(db: Session, rule: DetectionRule, events: list) -> list:
    """Filter events by asset context if rule has asset_filter set.
    Returns only events whose linked asset matches the filter criteria."""
    af = rule.asset_filter or {}
    if not af:
        return events

    # Collect unique asset_ids from events
    asset_ids = {ev.asset_id for ev in events if ev.asset_id}
    if not asset_ids:
        return []  # No events have linked assets — nothing matches an asset filter

    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()}
    passing = []

    for ev in events:
        asset = assets.get(ev.asset_id)
        if not asset:
            continue
        # Evaluate each filter condition
        ok = True
        if "min_criticality" in af and (asset.criticality or 0) < af["min_criticality"]:
            ok = False
        if "internet_facing" in af and af["internet_facing"] and not asset.is_internet_facing:
            ok = False
        if "has_critical_vulns" in af and af["has_critical_vulns"] and not (asset.critical_count or 0) > 0:
            ok = False
        if "has_high_vulns" in af and af["has_high_vulns"] and not ((asset.critical_count or 0) + (asset.high_count or 0)) > 0:
            ok = False
        if "environment" in af and (asset.environment_tag or "").lower() != af["environment"].lower():
            ok = False
        if "asset_type" in af and (asset.asset_type or "").lower() != af["asset_type"].lower():
            ok = False
        if ok:
            passing.append(ev)

    return passing


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
                db.rollback()
                result["errors"].append({"rule_id": rule.id, "error": str(e)})
                logger.error("Rule %s (%s) failed: %s", rule.id, rule.name, e, exc_info=True)

        db.commit()
        logger.info("Detection engine tick: %d rules checked, %d alerts created, %d errors",
                     result["rules_checked"], result["alerts_created"], len(result["errors"]))
    except Exception as e:
        db.rollback()
        result["errors"].append({"error": str(e)})
        logger.error("Detection engine run failed: %s", e, exc_info=True)
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

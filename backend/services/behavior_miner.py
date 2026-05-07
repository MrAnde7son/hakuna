"""Behavior miner — turns repeated user actions in `audit_logs` into low-confidence
suggestions inside `org_memory_facts` under namespace `behavior_suggestions`.

Why a separate namespace: agents are opt-in to namespaces (see
`agents/agent_context.py:_build_org_memory_section`). `behavior_suggestions`
is intentionally NOT a namespace any agent is opted into — suggestions stay
out of the system prompt until an admin promotes them into a real namespace
(`priority_rules`, `owner_hints`, etc.) at higher confidence. This avoids
agents overfitting to one analyst's habits before a human signs off.

Design notes
------------
- Idempotent. Running twice produces one fact per pattern; the second run
  supersedes the first via `services.org_memory.remember`.
- Single signal class today: **dismissal patterns** — a plugin_id that the
  org has closed as won't_fix / false_positive / accepted_risk N+ times in
  the lookback window. The structure leaves room for `_mine_owner_hints` /
  `_mine_exception_templates` later without changing the call site.
- Read-only against `audit_logs` and `findings`. Writes only to
  `org_memory_facts`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.models import AuditLog, Finding, Organization
from services import org_memory

logger = logging.getLogger(__name__)

# A status update that effectively closes the finding without a fix. Distinct
# from `resolved`, which is the legitimate "fixed" outcome.
DISMISSAL_STATUSES = {"won't_fix", "wont_fix", "false_positive", "accepted_risk"}

DEFAULT_LOOKBACK_DAYS = 14
DEFAULT_DISMISSAL_THRESHOLD = 5  # at least N closures across the window
SUGGESTION_NAMESPACE = "behavior_suggestions"
SUGGESTION_CONFIDENCE = 0.35       # below typical opt-in threshold; analyst must promote


def _new_status_value(changes: dict | None) -> str | None:
    """Pull the new workflow_status out of an audit-log diff blob.

    `log_audit` writes `changes` as `{field: {old, new}}`. Be permissive about
    shape — older rows may differ.
    """
    if not isinstance(changes, dict):
        return None
    raw = changes.get("status") or changes.get("workflow_status")
    if isinstance(raw, dict):
        new = raw.get("new")
    else:
        new = raw
    if isinstance(new, str):
        return new.strip().lower().replace(" ", "_")
    return None


def _mine_dismissal_patterns(
    db: Session,
    org_id: int,
    since: datetime,
    threshold: int,
) -> list[dict]:
    """Find plugin_ids the org repeatedly closes without fixing.

    Joins audit_logs (action=update, entity_type=finding_status) → findings
    so we can group by plugin_id. Filters in-Python rather than SQL because
    the dismissal check has to read the JSON `changes` blob, which is
    cross-dialect awkward in SQL.
    """
    rows = (
        db.query(AuditLog, Finding)
        .join(Finding, Finding.id == AuditLog.entity_id)
        .filter(
            AuditLog.org_id == org_id,
            AuditLog.entity_type == "finding_status",
            AuditLog.action == "update",
            AuditLog.created_at >= since,
        )
        .all()
    )

    counts: dict[str, dict] = {}
    for log, finding in rows:
        status = _new_status_value(log.changes)
        if status not in DISMISSAL_STATUSES:
            continue
        plugin_id = finding.plugin_id
        if not plugin_id:
            continue
        bucket = counts.setdefault(plugin_id, {
            "plugin_id": plugin_id,
            "plugin_name": finding.plugin_name,
            "plugin_family": finding.plugin_family,
            "count": 0,
            "actor_user_ids": set(),
            "last_seen": log.created_at,
        })
        bucket["count"] += 1
        if log.actor_user_id:
            bucket["actor_user_ids"].add(log.actor_user_id)
        if log.created_at and (not bucket["last_seen"] or log.created_at > bucket["last_seen"]):
            bucket["last_seen"] = log.created_at

    suggestions: list[dict] = []
    for plugin_id, bucket in counts.items():
        if bucket["count"] < threshold:
            continue
        suggestions.append({
            "key": f"dismissal:{plugin_id}",
            "value": {
                "kind": "frequent_dismissal",
                "plugin_id": plugin_id,
                "plugin_name": bucket["plugin_name"],
                "plugin_family": bucket["plugin_family"],
                "dismissal_count": bucket["count"],
                "distinct_actors": len(bucket["actor_user_ids"]),
                "suggestion": (
                    f"Org has dismissed {bucket['count']} findings of plugin "
                    f"{plugin_id} ({bucket['plugin_name']}) as won't-fix / "
                    f"false-positive / accepted-risk. Consider auto-suppressing "
                    f"or de-prioritizing this plugin."
                ),
            },
            "evidence": {
                "lookback_start": since.isoformat(),
                "last_seen": bucket["last_seen"].isoformat() if bucket["last_seen"] else None,
                "distinct_actors": len(bucket["actor_user_ids"]),
                "miner": "dismissal_patterns",
            },
        })
    return suggestions


def mine_org(
    db: Session,
    org_id: int,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    dismissal_threshold: int = DEFAULT_DISMISSAL_THRESHOLD,
) -> int:
    """Mine one org and write suggestions into `org_memory_facts`.

    Returns the count of suggestions written this run. Each suggestion key
    is stable, so re-running supersedes the previous version (history
    chain still preserved).
    """
    since = datetime.utcnow() - timedelta(days=lookback_days)
    written = 0

    for sig in _mine_dismissal_patterns(db, org_id, since, dismissal_threshold):
        org_memory.remember(
            db,
            org_id=org_id,
            namespace=SUGGESTION_NAMESPACE,
            key=sig["key"],
            value=sig["value"],
            evidence=sig["evidence"],
            confidence=SUGGESTION_CONFIDENCE,
            ttl_days=lookback_days * 2,  # auto-expire if no longer reinforced
        )
        written += 1

    if written:
        logger.info("behavior_miner: org=%s wrote %d suggestion(s)", org_id, written)
    return written


def mine_all_orgs(
    db_factory,
    lookback_days: int = DEFAULT_LOOKBACK_DAYS,
    dismissal_threshold: int = DEFAULT_DISMISSAL_THRESHOLD,
) -> dict:
    """Iterate all orgs and run `mine_org`. `db_factory` is a callable that
    returns a fresh `Session` (typically `core.database.SessionLocal`).

    Designed to be called from a scheduler. Failures in one org don't stop
    the others; per-org exceptions are logged and the count is reported in
    the return dict.
    """
    summary: dict[str, int] = {}
    db = db_factory()
    try:
        org_ids = [o for (o,) in db.query(Organization.id).all()]
    finally:
        db.close()

    for org_id in org_ids:
        db = db_factory()
        try:
            written = mine_org(db, org_id, lookback_days, dismissal_threshold)
            db.commit()
            summary[str(org_id)] = written
        except Exception:
            logger.exception("behavior_miner: org=%s failed", org_id)
            db.rollback()
            summary[str(org_id)] = -1
        finally:
            db.close()
    return summary

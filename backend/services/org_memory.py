"""Org-scoped, agent-shared memory layer.

Captures HOW each customer triages — priority rules, owner conventions,
business context — so every agent in the org benefits across runs. This is
distinct from the per-agent scratchpad in agents/agent_context.py (file
based, per-agent) and Agent.memory (per-agent column).

Append-only: `remember` never UPDATEs an existing row's value. It inserts a
new row, then points the predecessor's `superseded_by` at the new id so the
full chain is preserved. `recall` only returns active rows — those that are
not superseded and not yet expired.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from models.models import OrgMemoryFact

logger = logging.getLogger(__name__)


def _serialize(fact: OrgMemoryFact) -> dict:
    return {
        "id": fact.id,
        "org_id": fact.org_id,
        "namespace": fact.namespace,
        "key": fact.key,
        "value": fact.value,
        "confidence": fact.confidence,
        "source_agent_id": fact.source_agent_id,
        "source_run_id": fact.source_run_id,
        "evidence": fact.evidence,
        "created_at": fact.created_at.isoformat() if fact.created_at else None,
        "updated_at": fact.updated_at.isoformat() if fact.updated_at else None,
        "expires_at": fact.expires_at.isoformat() if fact.expires_at else None,
        "superseded_by": fact.superseded_by,
    }


def _active_filter(now: datetime):
    """Predicates that select active facts (not superseded, not expired)."""
    return and_(
        OrgMemoryFact.superseded_by.is_(None),
        or_(OrgMemoryFact.expires_at.is_(None), OrgMemoryFact.expires_at > now),
    )


def recall(
    db: Session,
    org_id: int,
    namespace: str,
    key: Optional[str] = None,
    limit: int = 20,
) -> list[dict]:
    """Return active (not superseded, not expired) facts for the org.

    If `key` is given, exact match on (org_id, namespace, key). Otherwise
    return the whole namespace, newest first.
    """
    now = datetime.utcnow()
    q = db.query(OrgMemoryFact).filter(
        OrgMemoryFact.org_id == org_id,
        OrgMemoryFact.namespace == namespace,
        _active_filter(now),
    )
    if key is not None:
        q = q.filter(OrgMemoryFact.key == key)
    q = q.order_by(OrgMemoryFact.created_at.desc()).limit(limit)
    return [_serialize(f) for f in q.all()]


def remember(
    db: Session,
    org_id: int,
    namespace: str,
    key: str,
    value: Any,
    evidence: Optional[dict] = None,
    confidence: float = 0.8,
    source_agent_id: Optional[int] = None,
    source_run_id: Optional[int] = None,
    ttl_days: Optional[int] = None,
) -> OrgMemoryFact:
    """Insert a new fact. If a key already exists active, supersede it.

    Append-only: the predecessor row is left intact; we only set its
    `superseded_by` to the new row's id.
    """
    now = datetime.utcnow()
    expires_at = now + timedelta(days=ttl_days) if ttl_days else None

    new_fact = OrgMemoryFact(
        org_id=org_id,
        namespace=namespace,
        key=key,
        value=value,
        confidence=confidence,
        source_agent_id=source_agent_id,
        source_run_id=source_run_id,
        evidence=evidence,
        created_at=now,
        updated_at=now,
        expires_at=expires_at,
    )
    db.add(new_fact)
    db.flush()

    # Supersede any active predecessors with the same (org, namespace, key).
    predecessors = db.query(OrgMemoryFact).filter(
        OrgMemoryFact.org_id == org_id,
        OrgMemoryFact.namespace == namespace,
        OrgMemoryFact.key == key,
        OrgMemoryFact.id != new_fact.id,
        OrgMemoryFact.superseded_by.is_(None),
    ).all()
    for p in predecessors:
        p.superseded_by = new_fact.id
        p.updated_at = now

    db.flush()
    logger.info(
        "org_memory.remember: org=%s namespace=%s key=%s id=%s superseded=%d",
        org_id, namespace, key, new_fact.id, len(predecessors),
    )
    return new_fact


def forget(db: Session, org_id: int, namespace: str, key: str) -> int:
    """Mark all active rows for (org, namespace, key) as superseded.

    Returns the number of rows marked. Append-only: rows are not deleted; a
    sentinel row is inserted with value=null and the predecessors point at
    it via `superseded_by`.
    """
    now = datetime.utcnow()
    actives = db.query(OrgMemoryFact).filter(
        OrgMemoryFact.org_id == org_id,
        OrgMemoryFact.namespace == namespace,
        OrgMemoryFact.key == key,
        _active_filter(now),
    ).all()
    if not actives:
        return 0

    sentinel = OrgMemoryFact(
        org_id=org_id,
        namespace=namespace,
        key=key,
        value=None,
        confidence=0.0,
        evidence={"forgotten": True, "forgotten_at": now.isoformat()},
        created_at=now,
        updated_at=now,
        expires_at=now,  # immediately inactive — `forgotten` rows never recall
    )
    db.add(sentinel)
    db.flush()

    for a in actives:
        a.superseded_by = sentinel.id
        a.updated_at = now
    db.flush()
    logger.info(
        "org_memory.forget: org=%s namespace=%s key=%s superseded=%d",
        org_id, namespace, key, len(actives),
    )
    return len(actives)


def history(db: Session, org_id: int, namespace: str, key: str) -> list[dict]:
    """Return the full supersede chain for a key, oldest first."""
    rows = db.query(OrgMemoryFact).filter(
        OrgMemoryFact.org_id == org_id,
        OrgMemoryFact.namespace == namespace,
        OrgMemoryFact.key == key,
    ).order_by(OrgMemoryFact.created_at.asc()).all()
    return [_serialize(r) for r in rows]


ORG_PROFILE_NAMESPACE = "org_profile"

# Map of (settings.onboarding field path → memory key). Each entry becomes a
# fact in `org_profile` so an agent's prompt can read industry, team-shape,
# and stated objectives without wiring a custom tool. Confidence is high —
# the user typed these into the wizard.
_PROFILE_FIELDS: list[tuple[str, str]] = [
    ("profile.industry",       "industry"),
    ("profile.org_size",       "org_size"),
    ("profile.team_size",      "team_size"),
    ("profile.team_functions", "team_functions"),
    ("objectives",             "objectives"),
]


def _dig(obj: dict, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def sync_org_profile_to_memory(db: Session, org_id: int) -> int:
    """Mirror `Organization.settings.onboarding` into `org_profile` namespace.

    Idempotent — values that match the active fact are skipped, values that
    changed are superseded via `remember`. The wizard's settings blob remains
    the source-of-truth for "is onboarding complete?"; this is a one-way
    write so agents have a uniform read path.

    Returns the number of facts written (created or superseded) this call.
    """
    from models.models import Organization
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return 0
    onboarding = (org.settings or {}).get("onboarding") or {}
    if not onboarding:
        return 0

    written = 0
    for path, key in _PROFILE_FIELDS:
        new_value = _dig(onboarding, path)
        if new_value in (None, "", [], {}):
            continue
        existing = recall(db, org_id, ORG_PROFILE_NAMESPACE, key=key, limit=1)
        if existing and existing[0].get("value") == new_value:
            continue  # unchanged — don't churn the supersede chain
        remember(
            db,
            org_id=org_id,
            namespace=ORG_PROFILE_NAMESPACE,
            key=key,
            value=new_value,
            evidence={
                "source": "onboarding_wizard",
                "field": path,
            },
            confidence=0.95,
        )
        written += 1
    return written


def list_namespaces(db: Session, org_id: int) -> list[dict]:
    """Return distinct namespaces with active fact counts for the org."""
    now = datetime.utcnow()
    rows = db.query(OrgMemoryFact.namespace).filter(
        OrgMemoryFact.org_id == org_id,
        _active_filter(now),
    ).all()
    counts: dict[str, int] = {}
    for (ns,) in rows:
        counts[ns] = counts.get(ns, 0) + 1
    return [{"namespace": ns, "count": c} for ns, c in sorted(counts.items())]

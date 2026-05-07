"""Tests for the behavior miner and the promote endpoint."""
from datetime import datetime, timedelta

import pytest

from models.models import AuditLog, Finding
from services import behavior_miner, org_memory


def _seed_finding(db_session, test_org, test_scan, plugin_id="P-1234", name="Test Plugin"):
    from models.models import Asset
    from sqlalchemy import text
    a = Asset(scan_id=test_scan.id, ip="10.0.0.1", hostname="test-host")
    db_session.add(a)
    db_session.flush()
    db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :i"), {"o": test_org.id, "i": a.id})
    f = Finding(
        scan_id=test_scan.id,
        asset_id=a.id,
        plugin_id=plugin_id,
        plugin_name=name,
        plugin_family="Test Family",
        severity=2,
        severity_label="Medium",
    )
    db_session.add(f)
    db_session.flush()
    db_session.execute(text("UPDATE findings SET org_id = :o WHERE id = :i"), {"o": test_org.id, "i": f.id})
    db_session.flush()
    return f


def _seed_dismissals(db_session, test_org, finding, count, status="false_positive", actor_user_id=None):
    """Insert N audit_log rows recording closure of `finding` to `status`."""
    for _ in range(count):
        log = AuditLog(
            org_id=test_org.id,
            actor_user_id=actor_user_id,
            action="update",
            entity_type="finding_status",
            entity_id=finding.id,
            entity_name=finding.plugin_name,
            changes={"status": {"old": "open", "new": status}},
            created_at=datetime.utcnow() - timedelta(hours=1),
        )
        db_session.add(log)
    db_session.flush()


def test_miner_emits_suggestion_above_threshold(db_session, test_org, test_scan, test_user):
    f = _seed_finding(db_session, test_org, test_scan)
    _seed_dismissals(db_session, test_org, f, count=5, actor_user_id=test_user.id)

    written = behavior_miner.mine_org(db_session, test_org.id, dismissal_threshold=5)
    assert written == 1

    facts = org_memory.recall(db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE)
    assert len(facts) == 1
    assert facts[0]["key"] == "dismissal:P-1234"
    assert facts[0]["value"]["dismissal_count"] == 5
    assert facts[0]["value"]["kind"] == "frequent_dismissal"
    assert facts[0]["confidence"] == behavior_miner.SUGGESTION_CONFIDENCE


def test_miner_skips_below_threshold(db_session, test_org, test_scan, test_user):
    f = _seed_finding(db_session, test_org, test_scan)
    _seed_dismissals(db_session, test_org, f, count=3, actor_user_id=test_user.id)

    written = behavior_miner.mine_org(db_session, test_org.id, dismissal_threshold=5)
    assert written == 0
    assert org_memory.recall(db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE) == []


def test_miner_ignores_non_dismissal_status(db_session, test_org, test_scan, test_user):
    f = _seed_finding(db_session, test_org, test_scan)
    # `resolved` is a real fix, not a dismissal — should not be counted
    _seed_dismissals(db_session, test_org, f, count=10, status="resolved", actor_user_id=test_user.id)
    written = behavior_miner.mine_org(db_session, test_org.id, dismissal_threshold=5)
    assert written == 0


def test_miner_idempotent_supersedes_prior(db_session, test_org, test_scan, test_user):
    f = _seed_finding(db_session, test_org, test_scan)
    _seed_dismissals(db_session, test_org, f, count=5, actor_user_id=test_user.id)
    behavior_miner.mine_org(db_session, test_org.id, dismissal_threshold=5)
    behavior_miner.mine_org(db_session, test_org.id, dismissal_threshold=5)

    actives = org_memory.recall(
        db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE, key="dismissal:P-1234",
    )
    assert len(actives) == 1
    chain = org_memory.history(
        db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE, "dismissal:P-1234",
    )
    # 2 mine runs → 2 rows in chain (older one superseded)
    assert len(chain) == 2


def test_miner_respects_lookback(db_session, test_org, test_scan, test_user):
    f = _seed_finding(db_session, test_org, test_scan)
    # Old dismissals (30 days ago) should be ignored when lookback=14
    for _ in range(5):
        log = AuditLog(
            org_id=test_org.id,
            actor_user_id=test_user.id,
            action="update",
            entity_type="finding_status",
            entity_id=f.id,
            entity_name=f.plugin_name,
            changes={"status": {"old": "open", "new": "false_positive"}},
            created_at=datetime.utcnow() - timedelta(days=30),
        )
        db_session.add(log)
    db_session.flush()
    written = behavior_miner.mine_org(db_session, test_org.id, lookback_days=14, dismissal_threshold=5)
    assert written == 0


def test_promote_endpoint_creates_target_and_forgets_source(authed_client, db_session, test_org):
    org_memory.remember(
        db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE, "dismissal:P-1",
        value={"kind": "frequent_dismissal", "plugin_id": "P-1", "dismissal_count": 7},
        confidence=0.35,
    )
    db_session.commit()

    r = authed_client.post(
        f"/api/org-memory/{behavior_miner.SUGGESTION_NAMESPACE}/dismissal:P-1/promote",
        json={"target_namespace": "priority_rules", "confidence": 0.9},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["target_namespace"] == "priority_rules"
    assert body["status"] == "promoted"

    # Suggestion is gone from active list
    suggestions = org_memory.recall(
        db_session, test_org.id, behavior_miner.SUGGESTION_NAMESPACE,
    )
    assert suggestions == []

    # And the promoted fact is in the target namespace at the new confidence
    promoted = org_memory.recall(db_session, test_org.id, "priority_rules")
    assert len(promoted) == 1
    assert promoted[0]["confidence"] == 0.9
    assert promoted[0]["value"]["plugin_id"] == "P-1"
    assert promoted[0]["evidence"]["promoted_from"]["key"] == "dismissal:P-1"


def test_promote_404_when_source_missing(authed_client):
    r = authed_client.post(
        f"/api/org-memory/{behavior_miner.SUGGESTION_NAMESPACE}/nonexistent/promote",
        json={"target_namespace": "priority_rules"},
    )
    assert r.status_code == 404

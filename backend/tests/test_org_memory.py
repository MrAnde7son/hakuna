"""Tests for the org-shared memory layer (services/org_memory.py + routes)."""
from datetime import datetime, timedelta

import pytest

from models.models import Organization, OrgMemoryFact
from services import org_memory


@pytest.fixture
def org_b(db_session):
    """Second org used to assert tenant isolation."""
    org = Organization(name="Other Org", slug="other-org")
    db_session.add(org)
    db_session.flush()
    return org


def test_recall_returns_only_active(db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", {"priority": "high"})
    facts = org_memory.recall(db_session, test_org.id, "rules")
    assert len(facts) == 1
    assert facts[0]["key"] == "k1"
    assert facts[0]["value"] == {"priority": "high"}


def test_remember_supersedes_correctly(db_session, test_org):
    first = org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    second = org_memory.remember(db_session, test_org.id, "rules", "k1", "v2")

    db_session.refresh(first)
    assert first.superseded_by == second.id

    actives = org_memory.recall(db_session, test_org.id, "rules", key="k1")
    assert len(actives) == 1
    assert actives[0]["value"] == "v2"
    assert actives[0]["id"] == second.id


def test_org_isolation(db_session, test_org, org_b):
    org_memory.remember(db_session, test_org.id, "rules", "secret", {"a": 1})
    org_memory.remember(db_session, org_b.id, "rules", "secret", {"b": 2})

    a_facts = org_memory.recall(db_session, test_org.id, "rules")
    b_facts = org_memory.recall(db_session, org_b.id, "rules")

    assert len(a_facts) == 1 and a_facts[0]["value"] == {"a": 1}
    assert len(b_facts) == 1 and b_facts[0]["value"] == {"b": 2}


def test_history_walks_supersede_chain(db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v2")
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v3")

    chain = org_memory.history(db_session, test_org.id, "rules", "k1")
    values = [c["value"] for c in chain]
    assert values == ["v1", "v2", "v3"]


def test_ttl_expiration_honored(db_session, test_org):
    fact = org_memory.remember(
        db_session, test_org.id, "rules", "k1", "soon",
        ttl_days=1,
    )
    # Force the row to be expired by stamping expires_at into the past
    fact.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db_session.flush()

    actives = org_memory.recall(db_session, test_org.id, "rules")
    assert actives == []


def test_forget_marks_active_rows_superseded(db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    count = org_memory.forget(db_session, test_org.id, "rules", "k1")
    assert count == 1
    assert org_memory.recall(db_session, test_org.id, "rules", key="k1") == []


def test_list_namespaces_counts_active_only(db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    org_memory.remember(db_session, test_org.id, "rules", "k2", "v2")
    org_memory.remember(db_session, test_org.id, "owners", "k1", "v1")
    # Supersede one so it shouldn't be counted twice
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1b")

    ns = {n["namespace"]: n["count"] for n in org_memory.list_namespaces(db_session, test_org.id)}
    assert ns == {"rules": 2, "owners": 1}


# ── HTTP routes ─────────────────────────────────────────────────────

def test_route_namespaces_endpoint(authed_client, db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    db_session.commit()
    r = authed_client.get("/api/org-memory/namespaces")
    assert r.status_code == 200
    body = r.json()
    assert any(n["namespace"] == "rules" and n["count"] == 1 for n in body["namespaces"])


def test_route_list_facts_endpoint(authed_client, db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", {"priority": "high"})
    db_session.commit()
    r = authed_client.get("/api/org-memory/rules")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["facts"][0]["value"] == {"priority": "high"}


def test_route_history_endpoint(authed_client, db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v2")
    db_session.commit()
    r = authed_client.get("/api/org-memory/rules/k1/history")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert [h["value"] for h in body["history"]] == ["v1", "v2"]


def test_route_forget_endpoint(authed_client, db_session, test_org):
    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    db_session.commit()
    r = authed_client.delete("/api/org-memory/rules/k1")
    assert r.status_code == 200
    assert r.json()["forgotten"] == 1
    # And gone from active list
    r2 = authed_client.get("/api/org-memory/rules")
    assert r2.json()["count"] == 0


def test_route_remember_creates_fact(authed_client, db_session, test_org):
    r = authed_client.post("/api/org-memory", json={
        "namespace": "priority_rules",
        "key": "pci_assets",
        "value": {"priority": "critical"},
        "confidence": 0.9,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "remembered"
    assert body["namespace"] == "priority_rules"

    facts = org_memory.recall(db_session, test_org.id, "priority_rules")
    assert len(facts) == 1
    assert facts[0]["value"] == {"priority": "critical"}
    assert facts[0]["confidence"] == 0.9


def test_route_remember_supersedes_via_same_key(authed_client, db_session, test_org):
    authed_client.post("/api/org-memory", json={
        "namespace": "priority_rules", "key": "k1", "value": "v1",
    })
    authed_client.post("/api/org-memory", json={
        "namespace": "priority_rules", "key": "k1", "value": "v2",
    })
    actives = org_memory.recall(db_session, test_org.id, "priority_rules", key="k1")
    assert len(actives) == 1
    assert actives[0]["value"] == "v2"


def test_route_remember_blocks_viewer(client, db_session, test_org):
    """Viewer must not be able to add facts (analyst+ gate)."""
    from tests.conftest import create_user
    from core.auth import create_access_token
    viewer = create_user(db_session, test_org, email="viewer@test.com", role="viewer")
    db_session.flush()
    token = create_access_token(viewer.id, test_org.id, viewer.role)
    headers = {"Authorization": f"Bearer {token}", "X-Org-Context": str(test_org.id)}

    r = client.post(
        "/api/org-memory",
        json={"namespace": "priority_rules", "key": "k1", "value": "v1"},
        headers=headers,
    )
    assert r.status_code == 403


def test_route_forget_requires_admin(client, db_session, test_org, auth_headers):
    """Non-admin (analyst) must not be able to call DELETE."""
    from tests.conftest import create_user
    from core.auth import create_access_token
    analyst = create_user(db_session, test_org, email="analyst@test.com", role="analyst")
    db_session.flush()
    token = create_access_token(analyst.id, test_org.id, analyst.role)
    headers = {"Authorization": f"Bearer {token}", "X-Org-Context": str(test_org.id)}

    org_memory.remember(db_session, test_org.id, "rules", "k1", "v1")
    db_session.commit()

    r = client.delete("/api/org-memory/rules/k1", headers=headers)
    assert r.status_code == 403

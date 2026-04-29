"""Tests for the user-facing /api/relay-agents endpoints.

Covers the auto-provisioning of the managed cloud_scanner row and the guards
that prevent customers from mutating it.
"""

from models.models import RelayAgent


def test_list_agents_auto_provisions_cloud_scanner(authed_client, db_session, test_org):
    """First call to GET /api/relay-agents should create the managed cloud_scanner
    row even in environments where the GCP cloud-relay container isn't polling.
    Without this, customers in self-hosted/dev envs see an empty list and have
    no way to know external scans are supposed to be possible."""
    pre = db_session.query(RelayAgent).filter(
        RelayAgent.org_id == test_org.id,
        RelayAgent.relay_type == "cloud_scanner",
    ).count()
    assert pre == 0

    resp = authed_client.get("/api/relay-agents")
    assert resp.status_code == 200
    rows = resp.json()
    cloud_rows = [r for r in rows if r.get("relay_type") == "cloud_scanner"]
    assert len(cloud_rows) == 1
    assert cloud_rows[0]["name"] == "Hakuna Cloud Scanner"
    assert cloud_rows[0]["credentials_mode"] == "cloud_managed"

    # Second call must be idempotent — no duplicate row created.
    db_session.expire_all()
    resp2 = authed_client.get("/api/relay-agents")
    assert resp2.status_code == 200
    cloud_rows2 = [r for r in resp2.json() if r.get("relay_type") == "cloud_scanner"]
    assert len(cloud_rows2) == 1
    assert cloud_rows2[0]["id"] == cloud_rows[0]["id"]


def test_delete_cloud_scanner_rejected(authed_client, db_session, test_org):
    """Cloud scanner is Hakuna-managed — customers can't delete it."""
    authed_client.get("/api/relay-agents")  # provision
    db_session.expire_all()
    cloud = db_session.query(RelayAgent).filter(
        RelayAgent.org_id == test_org.id,
        RelayAgent.relay_type == "cloud_scanner",
    ).first()
    assert cloud is not None

    resp = authed_client.delete(f"/api/relay-agents/{cloud.id}")
    assert resp.status_code == 400
    assert "managed" in resp.json()["detail"].lower()

    # Row still present.
    db_session.expire_all()
    still_there = db_session.query(RelayAgent).filter(RelayAgent.id == cloud.id).first()
    assert still_there is not None


def test_rotate_token_rejected_for_cloud_scanner(authed_client, db_session, test_org):
    """Cloud scanner authenticates via INTERNAL_SHARED_SECRET, not a per-row
    token, so token rotation is meaningless and would just stomp the sentinel
    that signals 'this is a managed row' to the WS handler."""
    authed_client.get("/api/relay-agents")
    db_session.expire_all()
    cloud = db_session.query(RelayAgent).filter(
        RelayAgent.org_id == test_org.id,
        RelayAgent.relay_type == "cloud_scanner",
    ).first()

    resp = authed_client.post(f"/api/relay-agents/{cloud.id}/rotate-token")
    assert resp.status_code == 400


def test_update_rejected_for_cloud_scanner(authed_client, db_session, test_org):
    """Renaming/relabeling the managed row would let customers spoof the UI."""
    authed_client.get("/api/relay-agents")
    db_session.expire_all()
    cloud = db_session.query(RelayAgent).filter(
        RelayAgent.org_id == test_org.id,
        RelayAgent.relay_type == "cloud_scanner",
    ).first()

    resp = authed_client.put(f"/api/relay-agents/{cloud.id}", json={"name": "Pwned"})
    assert resp.status_code == 400


def test_setup_instructions_rejected_for_cloud_scanner(authed_client, db_session, test_org):
    """Setup instructions describe how to deploy a customer-managed agent —
    they don't apply to the managed cloud scanner."""
    authed_client.get("/api/relay-agents")
    db_session.expire_all()
    cloud = db_session.query(RelayAgent).filter(
        RelayAgent.org_id == test_org.id,
        RelayAgent.relay_type == "cloud_scanner",
    ).first()

    resp = authed_client.get(f"/api/relay-agents/{cloud.id}/setup")
    assert resp.status_code == 400


def test_regular_agent_unaffected(authed_client, db_session, test_org):
    """Sanity check — provisioning the cloud_scanner row doesn't break the
    create flow for regular on-prem agents."""
    resp = authed_client.post("/api/relay-agents", json={"name": "NYC Office"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "NYC Office"
    assert body["relay_type"] == "agent"
    assert "token" in body  # one-time token

    list_resp = authed_client.get("/api/relay-agents")
    rows = list_resp.json()
    types = sorted(r["relay_type"] for r in rows)
    assert types == ["agent", "cloud_scanner"]

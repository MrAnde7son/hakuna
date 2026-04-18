"""Tests for /api/integration-builder/integrations/{id}/webhook and /webhook/rotate."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))


IB = "/api/integration-builder"


def _create_webhook_integration(authed_client, name="Test Webhook"):
    resp = authed_client.post(f"{IB}/integrations", json={
        "name": name,
        "direction": "push",
        "entity": "siem_event",
        "transport_type": "webhook",
        "transport_config": {"parser_type": "json"},
        "field_map": [],
        "enabled": True,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_create_webhook_returns_credentials_once(authed_client):
    data = _create_webhook_integration(authed_client)
    assert "ingest_endpoint" in data
    creds = data["ingest_endpoint"]
    assert creds["token"].startswith("hki_")
    assert creds["hmac_secret"]
    assert creds["endpoint_id"]
    assert creds["parser_type"] == "json"


def test_get_webhook_info_returns_url_without_secrets(authed_client):
    created = _create_webhook_integration(authed_client)
    integration_id = created["id"]

    resp = authed_client.get(f"{IB}/integrations/{integration_id}/webhook")
    assert resp.status_code == 200
    info = resp.json()
    assert info["endpoint_id"] == created["ingest_endpoint"]["endpoint_id"]
    assert info["parser_type"] == "json"
    assert info["token_prefix"]
    assert "token" not in info
    assert "hmac_secret" not in info


def test_get_webhook_info_rejects_non_webhook_integration(authed_client):
    resp = authed_client.post(f"{IB}/integrations", json={
        "name": "API integration",
        "direction": "pull",
        "entity": "finding",
        "transport_type": "api",
        "transport_config": {"base_url": "https://example.com"},
        "field_map": [],
        "enabled": False,
    })
    assert resp.status_code == 200
    iid = resp.json()["id"]

    resp = authed_client.get(f"{IB}/integrations/{iid}/webhook")
    assert resp.status_code == 400


def test_rotate_webhook_credentials_returns_new_secrets(authed_client):
    created = _create_webhook_integration(authed_client)
    integration_id = created["id"]
    original_prefix = created["ingest_endpoint"]["token_prefix"]

    resp = authed_client.post(f"{IB}/integrations/{integration_id}/webhook/rotate")
    assert resp.status_code == 200
    rotated = resp.json()
    assert rotated["token"].startswith("hki_")
    assert rotated["token_prefix"] != original_prefix
    assert rotated["hmac_secret"]
    assert rotated["endpoint_id"] == created["ingest_endpoint"]["endpoint_id"]

    info = authed_client.get(f"{IB}/integrations/{integration_id}/webhook").json()
    assert info["token_prefix"] == rotated["token_prefix"]


def test_rotate_invalidates_old_token(authed_client, client):
    import json
    created = _create_webhook_integration(authed_client)
    ep_id = created["ingest_endpoint"]["endpoint_id"]
    old_token = created["ingest_endpoint"]["token"]

    authed_client.post(f"{IB}/integrations/{created['id']}/webhook/rotate")

    resp = client.post(
        f"/api/ingest/events/{ep_id}",
        content=json.dumps({"timestamp": "2026-04-14T10:00:00Z", "source": "s", "type": "t"}),
        headers={"Authorization": f"Bearer {old_token}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_rotate_new_token_works(authed_client, client):
    import json
    created = _create_webhook_integration(authed_client)
    ep_id = created["ingest_endpoint"]["endpoint_id"]

    rotated = authed_client.post(f"{IB}/integrations/{created['id']}/webhook/rotate").json()

    resp = client.post(
        f"/api/ingest/events/{ep_id}",
        content=json.dumps({"timestamp": "2026-04-14T10:00:00Z", "source": "s", "type": "t"}),
        headers={"Authorization": f"Bearer {rotated['token']}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 200

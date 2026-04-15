"""Tests for SIEM push ingest: parsers, HMAC, HEC, CEF, LEEF, org isolation, rate limiting."""
import os
import sys
import json
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from datetime import datetime
from conftest import create_user, make_auth_headers


# ── Parser unit tests ──────────────────────────────────

def test_parse_json_single():
    from services.event_parsers import parse_json
    body = json.dumps({
        "timestamp": "2026-04-14T10:30:00Z",
        "source": "firewall",
        "type": "network",
        "severity": "high",
        "src_ip": "10.0.0.1",
        "message": "blocked connection"
    })
    results = parse_json(body)
    assert len(results) == 1
    assert results[0]["source_system"] == "firewall"
    assert results[0]["severity"] == "high"
    assert results[0]["source_ip"] == "10.0.0.1"


def test_parse_json_array():
    from services.event_parsers import parse_json
    body = json.dumps([
        {"timestamp": "2026-04-14T10:00:00Z", "source": "ids", "type": "alert", "message": "event 1"},
        {"timestamp": "2026-04-14T10:01:00Z", "source": "ids", "type": "alert", "message": "event 2"},
    ])
    results = parse_json(body)
    assert len(results) == 2


def test_parse_hec_single():
    from services.event_parsers import parse_hec
    body = json.dumps({
        "time": 1776000000,
        "host": "web-01",
        "source": "access_log",
        "sourcetype": "apache:access",
        "event": {"message": "GET /index.html", "status": 200}
    })
    results = parse_hec(body)
    assert len(results) == 1
    assert results[0]["host_name"] == "web-01"
    assert results[0]["source_system"] == "access_log"


def test_parse_hec_ndjson():
    from services.event_parsers import parse_hec
    body = '\n'.join([
        json.dumps({"time": 1776000000, "host": "h1", "source": "s1", "event": "line 1"}),
        json.dumps({"time": 1776000001, "host": "h2", "source": "s2", "event": "line 2"}),
    ])
    results = parse_hec(body)
    assert len(results) == 2


def test_parse_cef():
    from services.event_parsers import parse_cef
    body = "CEF:0|Security|IDS|1.0|100|Intrusion Detected|8|src=10.0.0.1 dst=10.0.0.2 act=blocked suser=admin msg=SQL injection attempt"
    results = parse_cef(body)
    assert len(results) == 1
    ev = results[0]
    assert ev["source_system"] == "security_ids"
    assert ev["severity"] == "high"  # CEF 8 maps to high
    assert ev["source_ip"] == "10.0.0.1"
    assert ev["dest_ip"] == "10.0.0.2"
    assert ev["user_name"] == "admin"
    assert ev["action"] == "blocked"


def test_parse_cef_invalid():
    from services.event_parsers import parse_cef
    results = parse_cef("not a cef line")
    assert len(results) == 0


def test_parse_leef():
    from services.event_parsers import parse_leef
    body = "LEEF:1.0|Microsoft|MSExchange|4.0|15345|src=10.0.0.1\tdst=10.0.0.2\tsev=high\tusrName=jdoe\tmsg=Auth failure"
    results = parse_leef(body)
    assert len(results) == 1
    ev = results[0]
    assert ev["source_system"] == "microsoft_msexchange"
    assert ev["severity"] == "high"
    assert ev["source_ip"] == "10.0.0.1"
    assert ev["user_name"] == "jdoe"


def test_parse_leef_invalid():
    from services.event_parsers import parse_leef
    results = parse_leef("not a leef line")
    assert len(results) == 0


def test_severity_normalization():
    from services.event_parsers import _normalize_severity
    assert _normalize_severity("critical") == "critical"
    assert _normalize_severity("CRITICAL") == "critical"
    assert _normalize_severity("warn") == "medium"
    assert _normalize_severity("error") == "high"
    assert _normalize_severity("fatal") == "critical"
    assert _normalize_severity("") == "info"
    assert _normalize_severity("unknown_value") == "info"


def test_cef_severity_mapping():
    from services.event_parsers import _normalize_cef_severity
    assert _normalize_cef_severity("0") == "low"
    assert _normalize_cef_severity("3") == "low"
    assert _normalize_cef_severity("5") == "medium"
    assert _normalize_cef_severity("8") == "high"
    assert _normalize_cef_severity("10") == "critical"


# ── Endpoint management API tests ──────────────────────

def test_create_endpoint(authed_client):
    resp = authed_client.post("/api/siem/endpoints", json={
        "name": "Test Endpoint",
        "parser_type": "json",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert "hmac_secret" in data
    assert data["token"].startswith("hki_")
    assert data["name"] == "Test Endpoint"
    assert "warning" in data


def test_create_endpoint_invalid_parser(authed_client):
    resp = authed_client.post("/api/siem/endpoints", json={
        "name": "Bad Parser",
        "parser_type": "invalid",
    })
    assert resp.status_code == 400


def test_list_endpoints(authed_client):
    # Create one first
    authed_client.post("/api/siem/endpoints", json={"name": "List Test", "parser_type": "hec"})

    resp = authed_client.get("/api/siem/endpoints")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert any(ep["name"] == "List Test" for ep in data)


def test_delete_endpoint(authed_client):
    resp = authed_client.post("/api/siem/endpoints", json={"name": "To Delete"})
    ep_id = resp.json()["id"]

    resp = authed_client.delete(f"/api/siem/endpoints/{ep_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    # Verify it's gone
    resp = authed_client.get("/api/siem/endpoints")
    ids = [ep["id"] for ep in resp.json()]
    assert ep_id not in ids


# ── Push ingest tests ──────────────────────────────────

def _create_endpoint_and_get_creds(authed_client, parser_type="json"):
    """Helper: create an endpoint and return (endpoint_id, token)."""
    resp = authed_client.post("/api/siem/endpoints", json={
        "name": f"Ingest Test {parser_type}",
        "parser_type": parser_type,
    })
    data = resp.json()
    return data["id"], data["token"]


def test_ingest_json_via_push(authed_client, client):
    ep_id, token = _create_endpoint_and_get_creds(authed_client)

    body = json.dumps([
        {"timestamp": "2026-04-14T10:00:00Z", "source": "test_push", "type": "network",
         "message": "push event 1"},
        {"timestamp": "2026-04-14T10:01:00Z", "source": "test_push", "type": "network",
         "message": "push event 2"},
    ])

    resp = client.post(
        f"/api/ingest/events/{ep_id}",
        content=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["created"] == 2


def test_ingest_hec_via_push(authed_client, client):
    ep_id, token = _create_endpoint_and_get_creds(authed_client, "hec")

    body = json.dumps({
        "time": 1776000000,
        "host": "web-01",
        "source": "test_hec_push",
        "event": {"message": "HEC push test"}
    })

    resp = client.post(
        f"/api/ingest/hec/{ep_id}",
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["text"] == "Success"
    assert data["code"] == 0
    assert data["created"] >= 1


def test_ingest_webhook(authed_client, client):
    ep_id, token = _create_endpoint_and_get_creds(authed_client, "json")

    body = json.dumps({"timestamp": "2026-04-14T10:00:00Z", "source": "webhook_test",
                        "type": "alert", "message": "webhook event"})

    resp = client.post(
        f"/api/ingest/webhook/{ep_id}",
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "accepted"


def test_ingest_invalid_token(authed_client, client):
    ep_id, _ = _create_endpoint_and_get_creds(authed_client)

    resp = client.post(
        f"/api/ingest/events/{ep_id}",
        content=json.dumps({"timestamp": "2026-04-14T10:00:00Z", "source": "s", "type": "t"}),
        headers={"Authorization": "Bearer bad-token"},
    )
    assert resp.status_code == 401


def test_ingest_no_token(client):
    resp = client.post(
        "/api/ingest/events/nonexistent",
        content=json.dumps({"timestamp": "2026-04-14T10:00:00Z"}),
    )
    assert resp.status_code in (401, 404)


def test_ingest_nonexistent_endpoint(client):
    resp = client.post(
        "/api/ingest/events/does-not-exist",
        content=json.dumps({"source": "x"}),
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 404


# ── Org isolation via endpoint ─────────────────────────

def test_org_isolation_via_endpoint(authed_client, client, db_session, test_org):
    """Events ingested via an endpoint are scoped to the endpoint's org."""
    ep_id, token = _create_endpoint_and_get_creds(authed_client)

    # Ingest event
    body = json.dumps({"timestamp": "2026-04-14T10:00:00Z", "source": "org_iso_test",
                        "type": "auth", "message": "org isolation test"})
    resp = client.post(
        f"/api/ingest/events/{ep_id}",
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["created"] == 1

    # Verify event is visible to the same org
    resp = authed_client.get("/api/siem/events/search", params={"q": "org isolation test"})
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1


# ── Rate limit test ────────────────────────────────────

def test_rate_limit_token_bucket():
    from routes.siem_ingest_routes import _TokenBucket

    # Very low rate for testing
    bucket = _TokenBucket(rate=2, capacity=2)
    ep_id = "test-rate-limit"

    # First 2 should be allowed
    assert bucket.allow(ep_id) is True
    assert bucket.allow(ep_id) is True
    # Third should be denied (bucket depleted)
    assert bucket.allow(ep_id) is False


# ── CEF ingest end-to-end ──────────────────────────────

def test_ingest_cef_via_webhook(authed_client, client):
    ep_id, token = _create_endpoint_and_get_creds(authed_client, "cef")

    body = "CEF:0|Security|Firewall|1.0|200|Connection Blocked|7|src=192.168.1.1 dst=10.0.0.1 act=deny"

    resp = client.post(
        f"/api/ingest/webhook/{ep_id}",
        content=body.encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    assert resp.json()["created"] == 1


# ── LEEF ingest end-to-end ─────────────────────────────

def test_ingest_leef_via_webhook(authed_client, client):
    ep_id, token = _create_endpoint_and_get_creds(authed_client, "leef")

    body = "LEEF:1.0|Vendor|Product|1.0|EVT001|src=10.0.0.5\tdst=10.0.0.6\tsev=medium\tmsg=Test LEEF"

    resp = client.post(
        f"/api/ingest/webhook/{ep_id}",
        content=body.encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
    )
    assert resp.status_code == 200
    assert resp.json()["created"] == 1

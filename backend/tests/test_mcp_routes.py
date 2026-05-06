"""Tests for the MCP (Model Context Protocol) server endpoint."""


def _rpc(client, method, params=None, req_id=1):
    return client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}},
    )


def test_initialize_handshake(authed_client):
    r = _rpc(authed_client, "initialize", {"protocolVersion": "2025-06-18"})
    assert r.status_code == 200
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert body["result"]["capabilities"]["tools"] == {"listChanged": False}
    assert body["result"]["serverInfo"]["name"] == "hakuna-mcp"


def test_initialize_negotiates_unsupported_version_to_default(authed_client):
    r = _rpc(authed_client, "initialize", {"protocolVersion": "1900-01-01"})
    assert r.status_code == 200
    assert r.json()["result"]["protocolVersion"] == "2025-06-18"


def test_tools_list_returns_expected_tools(authed_client):
    r = _rpc(authed_client, "tools/list")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == {
        "list_findings",
        "get_finding",
        "list_assets",
        "get_asset",
        "list_campaigns",
    }


def test_unauthenticated_request_is_rejected(client):
    r = client.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


def test_list_findings_returns_seeded_data(authed_client, test_findings):
    r = _rpc(authed_client, "tools/call", {"name": "list_findings", "arguments": {"limit": 100}})
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured["count"] == len(test_findings)
    # Ordered by priority_score desc — first row should have the highest score.
    assert structured["findings"][0]["priority_score"] >= structured["findings"][-1]["priority_score"]


def test_list_findings_filter_by_severity(authed_client, test_findings):
    r = _rpc(authed_client, "tools/call",
             {"name": "list_findings", "arguments": {"severity": "critical"}})
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    assert structured["count"] >= 1
    for f in structured["findings"]:
        assert f["severity"] == 4


def test_get_finding_returns_full_detail(authed_client, test_findings):
    target = test_findings[0]
    r = _rpc(authed_client, "tools/call",
             {"name": "get_finding", "arguments": {"finding_id": target.id}})
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    assert structured["id"] == target.id
    assert structured["description"] == target.description
    assert structured["solution"] == target.solution


def test_get_finding_not_found_returns_tool_error(authed_client):
    r = _rpc(authed_client, "tools/call",
             {"name": "get_finding", "arguments": {"finding_id": 999999}})
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is True
    assert "not found" in result["content"][0]["text"].lower()


def test_list_assets_returns_seeded_data(authed_client, test_assets):
    r = _rpc(authed_client, "tools/call", {"name": "list_assets", "arguments": {}})
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    assert structured["count"] == len(test_assets)
    hostnames = {a["hostname"] for a in structured["assets"]}
    assert hostnames == {a.hostname for a in test_assets}


def test_list_campaigns_returns_seeded_data(authed_client, test_campaign):
    r = _rpc(authed_client, "tools/call", {"name": "list_campaigns", "arguments": {}})
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    assert structured["count"] == 1
    assert structured["campaigns"][0]["name"] == test_campaign.name


def test_unknown_tool_returns_tool_error(authed_client):
    r = _rpc(authed_client, "tools/call", {"name": "does_not_exist", "arguments": {}})
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is True


def test_unknown_method_returns_jsonrpc_error(authed_client):
    r = _rpc(authed_client, "frobnicate")
    assert r.status_code == 200
    body = r.json()
    assert body["error"]["code"] == -32601


def test_initialized_notification_returns_202(authed_client):
    r = authed_client.post(
        "/api/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert r.status_code == 202


def test_get_returns_server_info(authed_client):
    r = authed_client.get("/api/mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["server"] == "hakuna-mcp"
    assert "list_findings" in body["tools"]

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
        # read-only
        "list_findings", "get_finding",
        "list_assets", "get_asset",
        "list_campaigns",
        # write
        "update_finding_status", "create_campaign", "assign_owner",
        "request_exception", "trigger_scan", "add_finding_comment",
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


# ── Write tools — auto-execute path (SOFT_WRITE) ──────────────────────


def test_update_finding_status_executes_at_standard(authed_client, test_findings, db_session):
    """SOFT_WRITE tool — at the MCP default 'standard' autonomy, no approval
    is needed and the change lands directly."""
    target = test_findings[0]
    r = _rpc(authed_client, "tools/call", {
        "name": "update_finding_status",
        "arguments": {"finding_id": target.id, "status": "resolved", "comment": "fixed by patch"},
    })
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured == {"finding_id": target.id, "before": "open", "after": "resolved"}
    db_session.expire_all()
    from models.models import Finding
    refreshed = db_session.query(Finding).filter(Finding.id == target.id).first()
    assert refreshed.workflow_status == "resolved"
    assert "fixed by patch" in (refreshed.workflow_notes or "")


def test_add_finding_comment_executes_and_attributes_principal(authed_client, test_findings, test_user, db_session):
    target = test_findings[0]
    r = _rpc(authed_client, "tools/call", {
        "name": "add_finding_comment",
        "arguments": {"finding_id": target.id, "comment": "investigation kicked off"},
    })
    assert r.status_code == 200
    assert r.json()["result"]["isError"] is False
    db_session.expire_all()
    from models.models import Finding
    f = db_session.query(Finding).filter(Finding.id == target.id).first()
    assert "investigation kicked off" in f.workflow_notes
    assert "mcp_external" in f.workflow_notes
    assert test_user.email in f.workflow_notes


def test_assign_owner_executes_at_standard(authed_client, test_assets, test_user, db_session):
    a = test_assets[0]
    r = _rpc(authed_client, "tools/call", {
        "name": "assign_owner",
        "arguments": {"asset_id": a.id, "owner_email": test_user.email},
    })
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["matched_user_id"] == test_user.id


# ── Write tools — approval-required path (HARD_WRITE / EXTERNAL) ──────


def test_create_campaign_returns_pending_approval(authed_client, test_findings, test_org, db_session):
    """HARD_WRITE tool — at standard autonomy the MCP gate creates an
    AgentApproval row instead of executing."""
    finding_ids = [f.id for f in test_findings[:2]]
    r = _rpc(authed_client, "tools/call", {
        "name": "create_campaign",
        "arguments": {
            "name": "Patch Critical Web Hosts",
            "finding_ids": finding_ids,
        },
    })
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured["status"] == "pending_approval"
    assert structured["tool"] == "create_campaign"
    approval_id = structured["approval_id"]

    from models.models import AgentApproval, Campaign
    db_session.expire_all()
    approval = db_session.query(AgentApproval).filter(AgentApproval.id == approval_id).first()
    assert approval is not None
    assert approval.source == "mcp_external"
    assert approval.agent_id is None
    assert approval.agent_run_id is None
    assert approval.status == "pending"
    assert approval.org_id == test_org.id
    assert approval.tool_name == "create_campaign"
    assert approval.tool_input["name"] == "Patch Critical Web Hosts"
    assert approval.tool_input["_principal_email"]  # principal stamped

    # And no campaign was actually created.
    assert db_session.query(Campaign).filter(Campaign.name == "Patch Critical Web Hosts").first() is None


def test_request_exception_returns_pending_approval(authed_client, test_findings, db_session):
    target = test_findings[0]
    r = _rpc(authed_client, "tools/call", {
        "name": "request_exception",
        "arguments": {
            "finding_id": target.id,
            "justification": "Compensating WAF rule in place; revisit at quarter end.",
            "expires_at": "2099-01-01",
        },
    })
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    assert structured["status"] == "pending_approval"

    from models.models import AgentApproval, FindingException
    db_session.expire_all()
    approval = db_session.query(AgentApproval).filter(AgentApproval.id == structured["approval_id"]).first()
    assert approval.tool_name == "request_exception"
    assert approval.source == "mcp_external"
    # Nothing executed yet.
    assert db_session.query(FindingException).count() == 0


def test_trigger_scan_returns_pending_approval(authed_client, test_assets, db_session):
    asset_ids = [a.id for a in test_assets[:2]]
    r = _rpc(authed_client, "tools/call", {
        "name": "trigger_scan",
        "arguments": {"asset_ids": asset_ids, "scan_type": "nuclei"},
    })
    structured = r.json()["result"]["structuredContent"]
    assert structured["status"] == "pending_approval"
    from models.models import AgentApproval
    approval = db_session.query(AgentApproval).filter(AgentApproval.id == structured["approval_id"]).first()
    assert approval.source == "mcp_external"
    assert approval.tool_input["asset_ids"] == asset_ids


# ── Org-wide 24h grant short-circuits the gate ────────────────────────


def test_org_grant_skips_approval_for_create_campaign(authed_client, test_findings, test_org, test_user, db_session):
    """When an OrgActionGrant exists the gate auto-approves and the tool
    executes directly."""
    from datetime import datetime, timedelta
    from models.models import OrgActionGrant, Campaign
    grant = OrgActionGrant(
        org_id=test_org.id,
        action_name="create_campaign",
        expires_at=datetime.utcnow() + timedelta(hours=24),
        granted_by=test_user.id,
    )
    db_session.add(grant)
    db_session.commit()

    r = _rpc(authed_client, "tools/call", {
        "name": "create_campaign",
        "arguments": {"name": "Grant Bypass Campaign", "finding_ids": [test_findings[0].id]},
    })
    assert r.status_code == 200
    structured = r.json()["result"]["structuredContent"]
    # Skipped the approval gate — no pending status, real campaign id back.
    assert "status" not in structured or structured.get("status") == "draft"
    assert "campaign_id" in structured
    db_session.expire_all()
    assert db_session.query(Campaign).filter(Campaign.name == "Grant Bypass Campaign").first() is not None


# ── Write-tool errors ─────────────────────────────────────────────────


def test_update_finding_status_nonexistent_finding(authed_client):
    r = _rpc(authed_client, "tools/call", {
        "name": "update_finding_status",
        "arguments": {"finding_id": 999999, "status": "resolved"},
    })
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["isError"] is True
    assert "not found" in result["content"][0]["text"].lower()


def test_request_exception_invalid_date(authed_client, test_findings):
    r = _rpc(authed_client, "tools/call", {
        "name": "request_exception",
        "arguments": {
            "finding_id": test_findings[0].id,
            "justification": "x" * 20,
            "expires_at": "not-a-date",
        },
    })
    # The shape: HARD_WRITE → returns pending_approval before date validation
    # runs. The bad value lives on the AgentApproval.tool_input until the
    # human approves and the executor unpacks it. Verify the approval row
    # was created so the gate is exercised.
    structured = r.json()["result"]["structuredContent"]
    assert structured["status"] == "pending_approval"

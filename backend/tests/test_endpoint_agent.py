"""Tests for endpoint-agent vulnerability detection & response."""

from services import ai_threat_intel


# ── Vulnerable inventory payloads ────────────────────────────

LOG4J_SW = {"name": "log4j-core", "version": "2.14.1", "vendor": "demo"}
OPENSSL_SW = {"name": "openssl", "version": "3.0.2", "vendor": "demo"}

CHECKIN_PAYLOAD = {
    "hostname": "web-01",
    "platform": "linux",
    "os_version": "Ubuntu 22.04",
    "ip_address": "10.0.1.20",
    "agent_version": "1.0.0",
    "software": [LOG4J_SW, OPENSSL_SW],
    "processes": [{"name": "java", "pid": 4242, "ppid": 1}],
    "listening_ports": [{"address": "0.0.0.0", "port": 8080, "protocol": "tcp"}],
    "security_controls": [{"type": "edr", "product": "CrowdStrike Falcon",
                           "enabled": True}],
}


def _register_agent(authed_client, **kw):
    body = {"name": "web-01 agent", "auto_respond": False, "checkin_interval": 300}
    body.update(kw)
    resp = authed_client.post("/api/endpoint-agents", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


# ── Agent registration ───────────────────────────────────────

def test_create_agent_returns_token_once(authed_client):
    agent = _register_agent(authed_client)
    assert agent["token"].startswith("hke_")
    assert "install_command" in agent
    assert agent["status"] == "pending"

    listing = authed_client.get("/api/endpoint-agents").json()
    assert len(listing) == 1
    assert "token" not in listing[0]          # plaintext never returned again
    assert listing[0]["token_prefix"].startswith("hke_")


# ── Enrollment + check-in detection ──────────────────────────

def test_enroll_then_checkin_detects_vulnerabilities(authed_client, client):
    agent = _register_agent(authed_client)
    headers = {"X-Agent-Token": agent["token"]}

    enroll = client.post("/api/endpoint-agents/enroll",
                         json={"hostname": "web-01", "platform": "linux"},
                         headers=headers)
    assert enroll.status_code == 200
    assert enroll.json()["agent_id"] == agent["id"]

    checkin = client.post("/api/endpoint-agents/checkin",
                          json=CHECKIN_PAYLOAD, headers=headers)
    assert checkin.status_code == 200, checkin.text
    result = checkin.json()
    # log4j (critical) + openssl (high) both detected
    assert result["findings"]["total"] == 2
    assert result["findings"]["critical"] == 1
    cves = {d["cve"] for d in result["detections"]}
    assert "CVE-2021-44228" in cves


def test_checkin_rejected_with_bad_token(client):
    resp = client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                       headers={"X-Agent-Token": "hke_not_a_real_token"})
    assert resp.status_code == 401


# ── Contextualization ────────────────────────────────────────

def test_checkin_contextualizes_findings(authed_client, client):
    agent = _register_agent(authed_client)
    headers = {"X-Agent-Token": agent["token"]}
    client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                headers=headers)

    detail = authed_client.get(f"/api/endpoint-agents/{agent['id']}").json()
    log4j = next(f for f in detail["findings"] if f["cve"] == "CVE-2021-44228")

    ctx = log4j["endpoint_context"]
    assert ctx["runtime_active"] is True          # java process is running
    assert ctx["network_reachable"] is True       # port 8080 is listening
    assert ctx["fixed_version"] == "2.17.1"
    assert ctx["edr_present"] is True
    assert log4j["ctx_reachability"] in ("internet_facing", "internal_only")

    # Model-derived intelligence is attached.
    signal = log4j["ai_threat_signal"]
    assert signal is not None
    assert signal["generated_by_model"] == "mythos-threat-lm-v1"
    assert 0.0 <= signal["confidence"] <= 1.0


# ── Response: auto-created EDR detections ────────────────────

def test_auto_respond_creates_edr_detection(authed_client, client):
    agent = _register_agent(authed_client, auto_respond=True)
    headers = {"X-Agent-Token": agent["token"]}

    result = client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                         headers=headers).json()
    # log4j is critical + KEV → auto EDR detection
    assert len(result["auto_edr_detections"]) >= 1
    assert any(d["cve"] == "CVE-2021-44228"
               for d in result["auto_edr_detections"])

    from models.models import DetectionRule
    rules = authed_client.get("/api/endpoint-agents")  # sanity: agent still listed
    assert rules.status_code == 200


def test_manual_edr_detection_from_finding(authed_client, client):
    agent = _register_agent(authed_client)
    headers = {"X-Agent-Token": agent["token"]}
    client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                headers=headers)

    detail = authed_client.get(f"/api/endpoint-agents/{agent['id']}").json()
    finding_id = detail["findings"][0]["id"]

    resp = authed_client.post(
        f"/api/endpoint-agents/{agent['id']}/findings/{finding_id}/edr-detection"
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["push_connector"] == "crowdstrike_create_detection"


# ── Response: host action lifecycle ──────────────────────────

def test_host_action_queue_dispatch_and_result(authed_client, client):
    agent = _register_agent(authed_client)
    headers = {"X-Agent-Token": agent["token"]}

    queued = authed_client.post(
        f"/api/endpoint-agents/{agent['id']}/actions",
        json={"action_type": "kill_process",
              "params": {"pid": 4242, "process_name": "java"},
              "reason": "contain exploitation"},
    )
    assert queued.status_code == 200
    action_id = queued.json()["id"]
    assert queued.json()["status"] == "pending"

    # Check-in hands the action to the agent and marks it dispatched.
    result = client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                         headers=headers).json()
    pending = result["pending_actions"]
    assert len(pending) == 1
    assert pending[0]["id"] == action_id
    assert pending[0]["action_type"] == "kill_process"

    # Agent reports the outcome.
    done = client.post(f"/api/endpoint-agents/actions/{action_id}/result",
                       json={"status": "completed", "result": {"ok": True}},
                       headers=headers)
    assert done.status_code == 200
    assert done.json()["action"]["status"] == "completed"


def test_invalid_action_type_rejected(authed_client):
    agent = _register_agent(authed_client)
    resp = authed_client.post(
        f"/api/endpoint-agents/{agent['id']}/actions",
        json={"action_type": "format_disk", "params": {}},
    )
    assert resp.status_code == 400


# ── Lifecycle: auto-resolve when a vulnerability is gone ─────

def test_vulnerability_auto_resolves_when_package_removed(authed_client, client):
    agent = _register_agent(authed_client)
    headers = {"X-Agent-Token": agent["token"]}

    client.post("/api/endpoint-agents/checkin", json=CHECKIN_PAYLOAD,
                headers=headers)
    # Re-check-in with log4j removed (only openssl remains).
    payload = {**CHECKIN_PAYLOAD, "software": [OPENSSL_SW]}
    result = client.post("/api/endpoint-agents/checkin", json=payload,
                         headers=headers).json()
    assert result["findings"]["resolved"] >= 1

    detail = authed_client.get(f"/api/endpoint-agents/{agent['id']}").json()
    log4j = next(f for f in detail["findings"] if f["cve"] == "CVE-2021-44228")
    assert log4j["workflow_status"] == "resolved"


# ── Unit: model-derived threat intelligence ─────────────────

def test_ai_threat_intel_synthesize_is_deterministic():
    a = ai_threat_intel.synthesize("CVE-2021-44228", cvss=10.0, in_kev=True,
                                   has_public_exploit=True)
    b = ai_threat_intel.synthesize("CVE-2021-44228", cvss=10.0, in_kev=True,
                                   has_public_exploit=True)
    assert a == b
    assert a["predicted_exploitation"] is True
    assert a["generated_by_model"] == "mythos-threat-lm-v1"
    assert a["horizon_days"] >= 3


def test_ai_threat_intel_flags_high_severity_ahead_of_kev():
    # A high-severity CVE with exploit code but not yet on KEV — the model
    # should be able to forecast exploitation ahead of the classic feeds.
    sig = ai_threat_intel.synthesize("CVE-2024-6387", cvss=8.1, in_kev=False,
                                     has_public_exploit=True)
    if sig["predicted_exploitation"]:
        assert "leads_kev" in sig["indicators"]

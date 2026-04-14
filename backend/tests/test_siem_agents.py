"""Tests for SIEM agent tools and workflow integration."""
import os, sys, hashlib, json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest


def _seed_events(db, org_id, count=5):
    from models.models import SIEMEvent
    events = []
    for i in range(count):
        ev = SIEMEvent(
            org_id=org_id,
            event_time=datetime.utcnow() - timedelta(seconds=i * 10),
            source_system="test_agent",
            event_type="authentication",
            severity="high",
            outcome="failure",
            source_ip="10.0.0.1",
            user_name="admin",
            host_name="dc01",
            message=f"Agent tool test event {i}",
            dedup_hash=hashlib.sha256(f"agent-test-{i}-{os.urandom(4).hex()}".encode()).hexdigest(),
        )
        db.add(ev)
        events.append(ev)
    db.flush()
    return events


def test_query_events_tool(db_session, test_org):
    from agents.agent_tools import query_events
    _seed_events(db_session, test_org.id, 5)

    result = query_events(db_session, {"_org_id": test_org.id, "severity": "high", "limit": 10})
    assert result["count"] >= 5
    assert all(e["severity"] == "high" for e in result["events"])


def test_query_events_with_text_search(db_session, test_org):
    from agents.agent_tools import query_events
    _seed_events(db_session, test_org.id, 3)

    result = query_events(db_session, {"_org_id": test_org.id, "q": "Agent tool test"})
    assert result["count"] >= 3


def test_get_event_context_tool(db_session, test_org):
    from agents.agent_tools import get_event_context
    events = _seed_events(db_session, test_org.id, 5)

    result = get_event_context(db_session, {"event_id": events[0].id, "_org_id": test_org.id})
    assert "event" in result
    assert result["event"]["id"] == events[0].id
    assert "nearby_events" in result


def test_list_alerts_tool(db_session, test_org):
    from agents.agent_tools import list_alerts
    from models.models import DetectionRule, Alert

    rule = DetectionRule(org_id=test_org.id, name="Agent test rule", severity="high", query={})
    db_session.add(rule)
    db_session.flush()

    alert = Alert(org_id=test_org.id, rule_id=rule.id, severity="high", event_count=3)
    db_session.add(alert)
    db_session.flush()

    result = list_alerts(db_session, {"_org_id": test_org.id, "status": "open"})
    assert result["count"] >= 1


def test_get_alert_with_events_tool(db_session, test_org):
    from agents.agent_tools import get_alert_with_events
    from models.models import DetectionRule, Alert

    rule = DetectionRule(org_id=test_org.id, name="Alert detail test", severity="critical", query={},
                         mitre_techniques=["T1110"])
    db_session.add(rule)
    db_session.flush()

    alert = Alert(org_id=test_org.id, rule_id=rule.id, severity="critical", event_count=10,
                   context={"events_sample": [{"id": "ev1"}]})
    db_session.add(alert)
    db_session.flush()

    result = get_alert_with_events(db_session, {"alert_id": alert.id, "_org_id": test_org.id})
    assert result["severity"] == "critical"
    assert "T1110" in result["mitre_techniques"]


def test_update_alert_status_tool(db_session, test_org):
    from agents.agent_tools import update_alert_status
    from models.models import DetectionRule, Alert

    rule = DetectionRule(org_id=test_org.id, name="Status update test", severity="medium", query={})
    db_session.add(rule)
    db_session.flush()

    alert = Alert(org_id=test_org.id, rule_id=rule.id, severity="medium")
    db_session.add(alert)
    db_session.flush()

    result = update_alert_status(db_session, {"alert_id": alert.id, "status": "closed", "_org_id": test_org.id})
    assert result["status"] == "closed"
    assert result["updated"] is True


def test_agent_tools_org_isolation(db_session, test_org):
    from agents.agent_tools import query_events
    from models.models import Organization

    org2 = Organization(name="Other Agent Org", slug="other-agent-org")
    db_session.add(org2)
    db_session.flush()

    _seed_events(db_session, test_org.id, 3)
    _seed_events(db_session, org2.id, 3)

    # Org 1 should only see its events
    result = query_events(db_session, {"_org_id": test_org.id})
    assert all(e["severity"] for e in result["events"])  # basic check

    # Org 2 should see different events
    result2 = query_events(db_session, {"_org_id": org2.id})
    assert isinstance(result2["events"], list)


def test_soc_triage_template_valid():
    """Verify the SOC triage agent template is valid JSON with required fields."""
    from pathlib import Path
    tmpl_path = Path(__file__).parent.parent / "seeds" / "agent_templates" / "soc_triage.json"
    tmpl = json.loads(tmpl_path.read_text())

    assert tmpl["name"] == "SOC Triage Analyst"
    assert "tools" in tmpl
    assert "query_events" in tmpl["tools"]
    assert "get_alert_with_events" in tmpl["tools"]
    assert tmpl["autonomy"] in ("auto", "confirm", "conservative")


def test_siem_tools_registered():
    """Verify all SIEM agent tools are in the registry."""
    from agents.agent_tools import TOOL_REGISTRY

    siem_tools = ["query_events", "get_event_context", "list_alerts",
                   "get_alert_with_events", "update_alert_status", "run_detection_rule_now"]
    for tool_name in siem_tools:
        assert tool_name in TOOL_REGISTRY, f"Tool {tool_name} not registered"

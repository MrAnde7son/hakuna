"""Tests for pure evaluator functions in services/control_assessment.py."""

from types import SimpleNamespace

import pytest

from services.control_assessment import (
    _extract_techniques,
    evaluate_crowdstrike,
    evaluate_firewall,
    evaluate_defender,
)


def make_finding(**kwargs):
    defaults = dict(matched_ttps=None, port=None, protocol="tcp")
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def make_policy(settings=None):
    return SimpleNamespace(settings=settings or {})


# ── _extract_techniques ──────────────────────────────────────────────────────

def test_extract_techniques_list_of_dicts():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}, {"technique_id": "T1003"}])
    assert _extract_techniques(finding) == ["T1059", "T1003"]


def test_extract_techniques_list_of_strings():
    finding = make_finding(matched_ttps=["T1059", "T1486"])
    assert _extract_techniques(finding) == ["T1059", "T1486"]


def test_extract_techniques_none_returns_empty():
    finding = make_finding(matched_ttps=None)
    assert _extract_techniques(finding) == []


def test_extract_techniques_empty_list_returns_empty():
    finding = make_finding(matched_ttps=[])
    assert _extract_techniques(finding) == []


def test_extract_techniques_dicts_missing_technique_id_skipped():
    finding = make_finding(matched_ttps=[{"other_key": "T1059"}, {"technique_id": "T1003"}])
    assert _extract_techniques(finding) == ["T1003"]


def test_extract_techniques_mixed_types():
    # Dicts and strings can coexist
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}, "T1486"])
    result = _extract_techniques(finding)
    assert "T1059" in result
    assert "T1486" in result


# ── evaluate_crowdstrike ─────────────────────────────────────────────────────

def test_crowdstrike_no_techniques_returns_unknown():
    finding = make_finding(matched_ttps=[])
    policy = make_policy()
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "unknown"
    assert result["confidence"] == "low"


def test_crowdstrike_all_techniques_blocked_returns_mitigated():
    # T1059 maps to script_based_execution_monitoring
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "script_based_execution_monitoring": {"enabled": True, "mode": "block"},
    })
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "mitigated"
    assert result["confidence"] == "high"


def test_crowdstrike_some_blocked_some_detected_returns_partially_mitigated():
    # T1059 → script_based_execution_monitoring (block), T1003 → credential_dumping (detect)
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}, {"technique_id": "T1003"}])
    policy = make_policy(settings={
        "script_based_execution_monitoring": {"enabled": True, "mode": "block"},
        "credential_dumping": {"enabled": True, "mode": "detect"},
    })
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "partially_mitigated"
    assert result["confidence"] == "medium"


def test_crowdstrike_all_detect_returns_not_mitigated():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "script_based_execution_monitoring": {"enabled": True, "mode": "detect"},
    })
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_crowdstrike_cs_prevention_level_aggressive_treated_as_block():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "script_based_execution_monitoring": {"enabled": True, "mode": "AGGRESSIVE"},
    })
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "mitigated"


def test_crowdstrike_cs_prevention_level_disabled_treated_as_detect():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "script_based_execution_monitoring": {"enabled": True, "mode": "DISABLED"},
    })
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_crowdstrike_unmapped_technique_returns_unknown():
    finding = make_finding(matched_ttps=[{"technique_id": "T9999"}])
    policy = make_policy()
    result = evaluate_crowdstrike(finding, policy)
    assert result["verdict"] == "unknown"


# ── evaluate_firewall ────────────────────────────────────────────────────────

def test_firewall_no_port_returns_unknown():
    finding = make_finding(port=None, protocol="tcp")
    policy = make_policy(settings={"rules": []})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "unknown"
    assert result["confidence"] == "low"


def test_firewall_port_blocked_by_matching_rule():
    finding = make_finding(port=443, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "inbound", "ports": [443], "protocol": "tcp", "name": "Block HTTPS"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "mitigated"
    assert result["confidence"] == "high"
    assert "Block HTTPS" in result["explanation"]


def test_firewall_port_blocked_by_any_protocol_rule():
    finding = make_finding(port=8080, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "inbound", "ports": [8080], "protocol": "any"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "mitigated"


def test_firewall_port_not_in_rules_returns_not_mitigated():
    finding = make_finding(port=9999, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "inbound", "ports": [443], "protocol": "tcp"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_firewall_protocol_mismatch_returns_not_mitigated():
    finding = make_finding(port=53, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "inbound", "ports": [53], "protocol": "udp"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_firewall_allow_rule_does_not_count_as_block():
    finding = make_finding(port=80, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "allow", "direction": "inbound", "ports": [80], "protocol": "tcp"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_firewall_outbound_only_rule_does_not_mitigate():
    finding = make_finding(port=443, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "outbound", "ports": [443], "protocol": "tcp"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_firewall_any_port_wildcard_blocks_finding():
    finding = make_finding(port=12345, protocol="tcp")
    policy = make_policy(settings={"rules": [
        {"action": "block", "direction": "both", "ports": ["any"], "protocol": "any"},
    ]})
    result = evaluate_firewall(finding, policy)
    assert result["verdict"] == "mitigated"


# ── evaluate_defender ────────────────────────────────────────────────────────

def test_defender_no_techniques_rtp_enabled_returns_partially_mitigated():
    finding = make_finding(matched_ttps=[])
    policy = make_policy(settings={
        "real_time_protection": {"enabled": True},
    })
    result = evaluate_defender(finding, policy)
    assert result["verdict"] == "partially_mitigated"
    assert result["confidence"] == "low"


def test_defender_no_techniques_rtp_disabled_returns_not_mitigated():
    finding = make_finding(matched_ttps=[])
    policy = make_policy(settings={
        "real_time_protection": {"enabled": False},
    })
    result = evaluate_defender(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_defender_techniques_with_protections_returns_partially_mitigated():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "real_time_protection": {"enabled": True},
        "cloud_protection": {"enabled": True},
    })
    result = evaluate_defender(finding, policy)
    assert result["verdict"] == "partially_mitigated"
    assert "real-time protection" in result["explanation"]
    assert "cloud protection" in result["explanation"]
    assert len(result["matched_techniques"]) >= 1


def test_defender_techniques_all_protections_disabled_returns_not_mitigated():
    finding = make_finding(matched_ttps=[{"technique_id": "T1059"}])
    policy = make_policy(settings={
        "real_time_protection": {"enabled": False},
        "cloud_protection": {"enabled": False},
    })
    result = evaluate_defender(finding, policy)
    assert result["verdict"] == "not_mitigated"


def test_defender_no_techniques_no_settings_returns_not_mitigated():
    finding = make_finding(matched_ttps=[])
    policy = make_policy(settings={})
    result = evaluate_defender(finding, policy)
    assert result["verdict"] == "not_mitigated"

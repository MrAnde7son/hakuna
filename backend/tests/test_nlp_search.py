"""Unit tests for services/nlp_search.py — parse_nlp_query()."""

import pytest
from services.nlp_search import parse_nlp_query


# ── Severity ─────────────────────────────────────────────────────────────────

def test_single_severity_critical():
    r = parse_nlp_query("critical findings")
    assert r["finding_filters"]["severity"] == 4

def test_single_severity_high():
    r = parse_nlp_query("show high vulns")
    assert r["finding_filters"]["severity"] == 3

def test_single_severity_medium_alias():
    r = parse_nlp_query("med severity issues")
    assert r["finding_filters"]["severity"] == 2

def test_multiple_severities():
    r = parse_nlp_query("critical and high findings")
    assert sorted(r["finding_filters"]["severity_list"]) == [3, 4]
    assert "severity" not in r["finding_filters"]

def test_severity_sets_asset_min_counts():
    r = parse_nlp_query("critical vulnerabilities")
    assert r["asset_filters"].get("min_critical") == 1


# ── CVE ──────────────────────────────────────────────────────────────────────

def test_cve_reference():
    r = parse_nlp_query("CVE-2021-44228")
    assert r["finding_filters"]["cve"] == "CVE-2021-44228"

def test_cve_case_insensitive():
    r = parse_nlp_query("show me cve-2023-1234")
    assert r["finding_filters"]["cve"] == "CVE-2023-1234"


# ── Exploit / KEV / Ransomware / Trending ────────────────────────────────────

def test_exploit_keywords():
    for q in ["exploitable findings", "weaponized vulns", "poc available"]:
        r = parse_nlp_query(q)
        assert r["finding_filters"]["has_exploit"] is True, f"Failed for: {q}"

def test_kev():
    r = parse_nlp_query("known exploited vulnerabilities")
    assert r["finding_filters"]["is_kev"] is True

def test_cisa_kev():
    r = parse_nlp_query("CISA findings")
    assert r["finding_filters"]["is_kev"] is True

def test_ransomware():
    r = parse_nlp_query("ransomware-linked vulns")
    assert r["finding_filters"]["ransomware_linked"] is True

def test_trending():
    r = parse_nlp_query("trending vulnerabilities")
    assert r["finding_filters"]["trending_in_news"] is True


# ── Zero-day / Regression / Auto-resolved ────────────────────────────────────

def test_zero_day():
    r = parse_nlp_query("zero-day vulnerabilities")
    assert r["finding_filters"]["zero_day"] is True

def test_zero_day_variant():
    r = parse_nlp_query("0day exploits")
    assert r["finding_filters"]["zero_day"] is True

def test_regression():
    r = parse_nlp_query("regression findings")
    assert r["finding_filters"]["is_regression"] is True

def test_regression_came_back():
    r = parse_nlp_query("findings that came back")
    assert r["finding_filters"]["is_regression"] is True

def test_auto_resolved():
    r = parse_nlp_query("auto-resolved findings")
    assert r["finding_filters"]["auto_resolved"] is True


# ── Workflow status ──────────────────────────────────────────────────────────

def test_workflow_open_with_context():
    r = parse_nlp_query("open findings")
    assert r["finding_filters"]["workflow_status"] == "open"

def test_workflow_in_progress():
    r = parse_nlp_query("in progress vulnerabilities")
    assert r["finding_filters"]["workflow_status"] == "in_progress"

def test_workflow_accepted_risk():
    r = parse_nlp_query("accepted risk findings")
    assert r["finding_filters"]["workflow_status"] == "accepted_risk"

def test_workflow_false_positive():
    r = parse_nlp_query("false positive findings")
    assert r["finding_filters"]["workflow_status"] == "false_positive"

def test_workflow_excepted():
    r = parse_nlp_query("excepted vulnerabilities")
    assert r["finding_filters"]["workflow_status"] == "excepted"


# ── "open" false-positive avoidance ──────────────────────────────────────────

def test_openssl_not_open_workflow():
    r = parse_nlp_query("OpenSSL vulnerabilities")
    assert r["finding_filters"].get("workflow_status") != "open"

def test_open_port_not_open_workflow():
    r = parse_nlp_query("open port 443")
    assert r["finding_filters"].get("workflow_status") != "open"

def test_openvas_not_open_workflow():
    r = parse_nlp_query("findings from openvas")
    assert r["finding_filters"].get("workflow_status") != "open"


# ── MITRE ATT&CK ────────────────────────────────────────────────────────────

def test_has_ttps():
    r = parse_nlp_query("findings with TTPs")
    assert r["finding_filters"]["has_ttps"] is True

def test_tactic_lateral_movement():
    r = parse_nlp_query("lateral movement findings")
    assert "tactic" in r["finding_filters"]

def test_technique_id():
    r = parse_nlp_query("findings with T1021.001")
    assert r["finding_filters"]["technique_id"] == "T1021.001"


# ── Score thresholds ─────────────────────────────────────────────────────────

def test_cvss_above():
    r = parse_nlp_query("CVSS above 9")
    assert r["finding_filters"]["min_cvss"] == 9.0

def test_epss_percentage():
    r = parse_nlp_query("EPSS 50%")
    assert r["finding_filters"]["min_epss"] == 0.5

def test_epss_decimal():
    r = parse_nlp_query("EPSS 0.8")
    assert r["finding_filters"]["min_epss"] == 0.8

def test_vpr_above():
    r = parse_nlp_query("VPR above 7")
    assert r["finding_filters"]["min_vpr"] == 7.0

def test_priority_score():
    r = parse_nlp_query("priority above 8")
    assert r["finding_filters"]["min_priority"] == 8.0


# ── OS / Platform ────────────────────────────────────────────────────────────

def test_os_windows():
    r = parse_nlp_query("Windows servers")
    assert r["asset_filters"]["search"] == "Windows"

def test_os_linux():
    r = parse_nlp_query("Linux hosts")
    assert r["asset_filters"]["search"] == "Linux"

def test_os_rhel():
    r = parse_nlp_query("RHEL servers")
    assert r["asset_filters"]["search"] == "Red Hat"


# ── Environment ──────────────────────────────────────────────────────────────

def test_env_dmz():
    r = parse_nlp_query("findings in DMZ")
    assert r["asset_filters"]["environment"] == "dmz"

def test_env_production():
    r = parse_nlp_query("production assets")
    assert r["asset_filters"]["environment"] == "production"

def test_env_dev():
    r = parse_nlp_query("dev environment")
    assert r["asset_filters"]["environment"] == "development"


# ── Source / scanner ─────────────────────────────────────────────────────────

def test_source_nessus():
    r = parse_nlp_query("nessus findings")
    assert r["finding_filters"]["source"] == "nessus"
    assert r["asset_filters"]["source"] == "nessus"

def test_source_vm_scanner_alias():
    r = parse_nlp_query("vm scanner assets")
    assert r["asset_filters"]["source"] == "vm_scanner"

def test_source_exclusion():
    r = parse_nlp_query("assets not scanned by qualys")
    assert r["asset_filters"]["exclude_source"] == "qualys"

def test_source_easm():
    r = parse_nlp_query("easm assets")
    assert r["asset_filters"]["source"] == "easm"


# ── Multi-source assets ──────────────────────────────────────────────────────

def test_multiple_sources():
    r = parse_nlp_query("assets with multiple sources")
    assert r["asset_filters"]["min_sources"] == 2

def test_more_than_n_sources():
    r = parse_nlp_query("more than 3 sources")
    assert r["asset_filters"]["min_sources"] == 4

def test_at_least_n_sources():
    r = parse_nlp_query("at least 2 sources")
    assert r["asset_filters"]["min_sources"] == 2


# ── Asset properties ─────────────────────────────────────────────────────────

def test_internet_facing():
    r = parse_nlp_query("internet-facing assets")
    assert r["asset_filters"]["is_internet_facing"] is True

def test_stale_assets():
    r = parse_nlp_query("stale assets")
    assert r["asset_filters"]["asset_status"] == "stale"

def test_criticality_threshold():
    r = parse_nlp_query("criticality above 8")
    assert r["asset_filters"]["criticality"] == 8

def test_high_value_assets():
    r = parse_nlp_query("high-value assets")
    assert r["asset_filters"]["criticality"] == 8


# ── Effort / SLA ─────────────────────────────────────────────────────────────

def test_quick_wins():
    r = parse_nlp_query("quick wins")
    assert r["finding_filters"]["effort_level"] == "quick_win"

def test_complex_findings():
    r = parse_nlp_query("complex vulnerabilities")
    assert r["finding_filters"]["effort_level"] == "complex"

def test_sla_breached():
    r = parse_nlp_query("SLA breached findings")
    assert r["finding_filters"]["sla_status"] == "breached"

def test_sla_overdue():
    r = parse_nlp_query("overdue vulnerabilities")
    assert r["finding_filters"]["sla_status"] == "breached"


# ── Plugin family ────────────────────────────────────────────────────────────

def test_family_web():
    r = parse_nlp_query("web server vulnerabilities")
    assert r["finding_filters"]["plugin_family"] == "Web Servers"

def test_family_ssh():
    r = parse_nlp_query("SSH findings")
    assert r["finding_filters"]["plugin_family"] == "SSH"

def test_family_database():
    r = parse_nlp_query("database vulnerabilities")
    assert r["finding_filters"]["plugin_family"] == "Databases"


# ── Port / IP / Plugin ID ───────────────────────────────────────────────────

def test_port():
    r = parse_nlp_query("findings on port 443")
    assert r["finding_filters"]["port"] == "443"

def test_ip_address():
    r = parse_nlp_query("findings on 10.0.0.1")
    assert r["asset_filters"]["search"] == "10.0.0.1"

def test_plugin_id():
    r = parse_nlp_query("plugin 12345")
    assert r["finding_filters"]["search"] == "12345"


# ── Sort ─────────────────────────────────────────────────────────────────────

def test_sort_most_critical():
    r = parse_nlp_query("most critical findings")
    assert r["sort"]["sort_by"] == "priority_score"
    assert r["sort"]["order"] == "desc"

def test_sort_newest():
    r = parse_nlp_query("newest findings")
    assert r["sort"]["sort_by"] == "created_at"
    assert r["sort"]["order"] == "desc"

def test_sort_oldest():
    r = parse_nlp_query("oldest vulnerabilities")
    assert r["sort"]["sort_by"] == "created_at"
    assert r["sort"]["order"] == "asc"

def test_sort_highest_cvss():
    r = parse_nlp_query("highest CVSS findings")
    assert r["sort"]["sort_by"] == "cvss3_base_score"
    assert r["sort"]["order"] == "desc"


# ── Tags ─────────────────────────────────────────────────────────────────────

def test_tags():
    r = parse_nlp_query("tagged with PCI")
    assert r["asset_filters"]["tags"].lower() == "pci"
    assert r["finding_filters"]["tags"].lower() == "pci"


# ── Combined queries ─────────────────────────────────────────────────────────

def test_combined_severity_os_exploit():
    r = parse_nlp_query("critical Windows servers with exploits")
    assert r["finding_filters"]["severity"] == 4
    assert r["finding_filters"]["has_exploit"] is True
    assert r["asset_filters"]["search"] == "Windows"

def test_combined_sla_env():
    r = parse_nlp_query("SLA breached high risk assets in DMZ")
    assert r["finding_filters"]["sla_status"] == "breached"
    assert r["asset_filters"]["environment"] == "dmz"

def test_combined_quick_wins_kev():
    r = parse_nlp_query("quick wins with CVE in KEV")
    assert r["finding_filters"]["effort_level"] == "quick_win"
    assert r["finding_filters"]["is_kev"] is True


# ── Explanation chips ────────────────────────────────────────────────────────

def test_chips_present():
    r = parse_nlp_query("critical findings with exploits")
    labels = [c["label"] for c in r["explanation"]]
    assert "Severity" in labels
    assert "Has Exploit" in labels

def test_chips_have_color():
    r = parse_nlp_query("critical findings")
    for chip in r["explanation"]:
        assert "color" in chip
        assert chip["color"].startswith("#")


# ── Edge cases ───────────────────────────────────────────────────────────────

def test_empty_query():
    r = parse_nlp_query("")
    assert r["asset_filters"] == {}
    assert r["finding_filters"] == {}

def test_whitespace_only():
    r = parse_nlp_query("   ")
    assert r["asset_filters"] == {}
    assert r["finding_filters"] == {}

def test_original_query_preserved():
    r = parse_nlp_query("  critical findings  ")
    assert r["original_query"] == "critical findings"

def test_gibberish_becomes_text_search():
    r = parse_nlp_query("foobarqux something random")
    # residual text should become search
    search = r["asset_filters"].get("search") or r["finding_filters"].get("search")
    assert search is not None

def test_min_critical_count():
    r = parse_nlp_query("assets with more than 5 critical findings")
    assert r["asset_filters"]["min_critical"] == 5

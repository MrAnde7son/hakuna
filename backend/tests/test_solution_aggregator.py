"""Tests for pure functions in services/solution_aggregator.py."""

import pytest

from services.solution_aggregator import (
    VulnFingerprint,
    _normalize_component,
    _extract_target_version,
    _classify_vuln_class,
    _extract_audit_component,
    fingerprint_finding,
)


class _FakeFinding:
    """Minimal stand-in for a Finding ORM row."""

    def __init__(self, plugin_name="", plugin_family="", solution="",
                 severity=3, cwe_ids=None, cves=None):
        self.plugin_name = plugin_name
        self.plugin_family = plugin_family
        self.solution = solution
        self.severity = severity
        self.cwe_ids = cwe_ids or []
        self.cves = cves or []


# ── VulnFingerprint ──────────────────────────────────────────────────────────

def test_vulnfingerprint_stores_finding():
    finding = object()
    fp = VulnFingerprint(finding)
    assert fp.finding is finding


def test_vulnfingerprint_defaults_to_none():
    fp = VulnFingerprint(None)
    assert fp.component is None
    assert fp.root_cause_type is None
    assert fp.current_version is None
    assert fp.target_version is None
    assert fp.group_key is None


# ── _normalize_component ─────────────────────────────────────────────────────

def test_normalize_dotnet_framework_variants():
    assert _normalize_component("Microsoft .NET Framework") == ".NET"
    assert _normalize_component("Microsoft .NET Core") == ".NET"


def test_normalize_aspnet_core_preserved():
    # ASP.NET Core is kept as-is (canonical form)
    result = _normalize_component("ASP.NET Core")
    assert result == "ASP.NET Core"


def test_normalize_removes_security_updates_for_prefix():
    result = _normalize_component("Security Updates for Microsoft .NET Framework")
    assert result == ".NET"


def test_normalize_strips_parenthetical_noise():
    result = _normalize_component("Node.js (v18.x)")
    assert result == "Node.js"


def test_normalize_removes_trailing_vulnerabilities():
    result = _normalize_component("OpenSSL Multiple Vulnerabilities")
    assert result == "OpenSSL"


def test_normalize_removes_trailing_detection():
    result = _normalize_component("Apache Tomcat Detection")
    assert result == "Apache Tomcat"


def test_normalize_removes_trailing_deprecated_protocol():
    result = _normalize_component("TLS 1.0 Deprecated Protocol")
    assert result == "TLS 1.0"


def test_normalize_none_returns_none():
    assert _normalize_component(None) is None


def test_normalize_empty_string_returns_none():
    assert _normalize_component("") is None


def test_normalize_strips_surrounding_whitespace():
    result = _normalize_component("  OpenSSL  ")
    assert result == "OpenSSL"


# ── _extract_target_version ──────────────────────────────────────────────────

def test_extract_version_upgrade_pattern():
    solution = "Upgrade to OpenSSL version 3.0.7 or later."
    assert _extract_target_version(solution) == "3.0.7"


def test_extract_version_upgrade_pattern_without_version_word():
    solution = "Upgrade to Node.js 18.12.1 or later."
    assert _extract_target_version(solution) == "18.12.1"


def test_extract_version_update_pattern():
    solution = "Update the software to version 2.4.58 to remediate this issue."
    assert _extract_target_version(solution) == "2.4.58"


def test_extract_version_no_version_returns_none():
    solution = "Contact the vendor for a patch."
    assert _extract_target_version(solution) is None


def test_extract_version_none_solution_returns_none():
    assert _extract_target_version(None) is None


def test_extract_version_empty_solution_returns_none():
    assert _extract_target_version("") is None


# ── _classify_vuln_class ─────────────────────────────────────────────────────

def test_classify_by_cwe_id():
    f = _FakeFinding(cwe_ids=["CWE-89"])
    assert _classify_vuln_class(f) == "SQL Injection"


def test_classify_by_cwe_lowercase():
    f = _FakeFinding(cwe_ids=["cwe-79"])
    assert _classify_vuln_class(f) == "Cross-Site Scripting"


def test_classify_by_plugin_name_when_no_cwe():
    f = _FakeFinding(plugin_name="SQL Injection (UNION-based) via `id` parameter")
    assert _classify_vuln_class(f) == "SQL Injection"


def test_classify_returns_none_for_unrelated_finding():
    f = _FakeFinding(plugin_name="OpenSSH 7.4 Detection")
    assert _classify_vuln_class(f) is None


# ── fingerprint_finding: vuln_class fallback (Rule 9) ────────────────────────

def test_fingerprint_app_layer_finding_via_cwe():
    """Native/agent finding with no Nessus-shaped metadata still aggregates via CWE."""
    f = _FakeFinding(
        plugin_name="SQL Injection (UNION-based) via `id` parameter at /vulnerabilities/sqli/",
        plugin_family="Agent",
        cwe_ids=["CWE-89"],
        severity=4,
    )
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.component == "SQL Injection"
    assert fp.root_cause_type == "vuln_class"
    assert fp.group_key == ("SQL Injection", "vuln_class")


def test_fingerprint_app_layer_finding_via_name_only():
    """Falls back to plugin_name keyword match when cwe_ids is empty."""
    f = _FakeFinding(plugin_name="Reflected Cross-Site Scripting in search box",
                     plugin_family="Web Application")
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.component == "Cross-Site Scripting"
    assert fp.root_cause_type == "vuln_class"


# ── fingerprint_finding: audit-profile fallback (Rule 8.5) ───────────────────

def test_fingerprint_ldap_audit_finding():
    f = _FakeFinding(plugin_name="LDAP Anonymous Bind Allowed",
                     plugin_family="LDAP")
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.root_cause_type == "misconfiguration"


def test_fingerprint_generic_snmp_family_not_bucketed():
    """Generic SNMP findings without a specific misconfig regex match are
    left un-aggregated — each one carries its own remediation."""
    f = _FakeFinding(plugin_name="Some custom check",
                     plugin_family="SNMP")
    assert fingerprint_finding(f) is None


def test_fingerprint_smb_signing_misconfig():
    f = _FakeFinding(plugin_name="SMB Signing not required",
                     plugin_family="Windows")
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.component == "SMB Signing"
    assert fp.root_cause_type == "misconfiguration"


def test_fingerprint_returns_none_for_truly_unmatched():
    """Findings with no recognizable signal still return None."""
    f = _FakeFinding(plugin_name="Mysterious thing",
                     plugin_family="General")
    assert fingerprint_finding(f) is None


def test_fingerprint_skips_info_severity():
    f = _FakeFinding(plugin_name="SQL Injection somewhere",
                     cwe_ids=["CWE-89"],
                     severity=0)
    assert fingerprint_finding(f) is None


# ── _extract_audit_component (CVE Hunt title parser) ─────────────────────────

def test_audit_component_strips_outdated_prefix():
    assert _extract_audit_component("Outdated Google Chrome 119 — RCE") == "Google Chrome"


def test_audit_component_strips_vulnerable_prefix_and_cve_tail():
    assert _extract_audit_component("Vulnerable OpenSSH 8.2p1 (CVE-2023-1234)") == "OpenSSH"


def test_audit_component_handles_em_dash_separator():
    assert _extract_audit_component("Apache log4j 2.14 — Log4Shell") == "Apache log4j"


def test_audit_component_returns_none_for_bare_cve():
    assert _extract_audit_component("CVE-2024-1234") is None


def test_audit_component_returns_none_when_too_short():
    assert _extract_audit_component("X") is None


# ── fingerprint_finding: CVE Hunt (Rule 8.5 — audit family + CVEs) ──────────

def test_cve_hunt_groups_by_extracted_component():
    f = _FakeFinding(
        plugin_name="Outdated Google Chrome 119 — multiple RCE CVEs",
        plugin_family="Audit: Windows",
        solution="Update Chrome to the latest stable channel",
        cves=["CVE-2023-7024"],
        severity=3,
    )
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.component == "Google Chrome"
    assert fp.root_cause_type == "outdated_version"


def test_cve_hunt_falls_back_to_protocol_bucket():
    """When title is too generic to extract a component, group by protocol bucket."""
    f = _FakeFinding(
        plugin_name="X",  # too short to extract
        plugin_family="Audit: SSH",
        cves=["CVE-2024-1234"],
        severity=3,
    )
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.component == "Linux Packages"
    assert fp.root_cause_type == "outdated_version"


def test_cve_hunt_smb_with_cves_routes_to_outdated_not_misconfig():
    """Audit: SMB family with CVEs must go to outdated_version, not SMB Hardening."""
    f = _FakeFinding(
        plugin_name="Vulnerable Samba 4.13 — CVE-2024-XXXX",
        plugin_family="Audit: SMB",
        cves=["CVE-2024-XXXX"],
        severity=4,
    )
    fp = fingerprint_finding(f)
    assert fp is not None
    assert fp.root_cause_type == "outdated_version"
    assert fp.component == "Samba"


def test_audit_family_no_cves_is_not_bucketed():
    """Audit-profile findings without CVEs and without a specific misconfig
    match are left un-aggregated so their per-finding remediation surfaces."""
    f = _FakeFinding(
        plugin_name="Some custom Windows policy check",
        plugin_family="Audit: Windows",
        cves=[],
        severity=2,
    )
    assert fingerprint_finding(f) is None


def test_audit_kerberos_generic_not_bucketed():
    f = _FakeFinding(plugin_name="Generic Kerberos check",
                     plugin_family="Audit: Kerberos")
    assert fingerprint_finding(f) is None


def test_audit_cloud_aws_generic_not_bucketed():
    f = _FakeFinding(plugin_name="S3 bucket misconfiguration",
                     plugin_family="Audit: Cloud (AWS)")
    assert fingerprint_finding(f) is None

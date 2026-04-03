"""Tests for pure functions in services/solution_aggregator.py."""

import pytest

from services.solution_aggregator import (
    VulnFingerprint,
    _normalize_component,
    _extract_target_version,
)


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

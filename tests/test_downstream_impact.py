"""
Unit tests for downstream impact assessment logic.

Tests _compute_verdict(), _compute_severity_delta(), alternative version
sorting, efficiency_score penalty, and version comparison.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.downstream_impact import (
    _compute_verdict,
    _compute_severity_delta,
    _classify_severity,
    _version_lte,
    _version_in_range,
    _parse_version_tuple,
    _product_name_matches,
    _severity_label,
    VERDICT_MULTIPLIERS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cve(severity="low", cve_id="CVE-2024-0001"):
    return {"cve_id": cve_id, "severity": severity, "cvss3_score": None}


# ── _classify_severity ────────────────────────────────────────────────────────

class TestClassifySeverity:
    def test_critical(self):
        assert _classify_severity(9.8) == "critical"
        assert _classify_severity(9.0) == "critical"

    def test_high(self):
        assert _classify_severity(7.0) == "high"
        assert _classify_severity(8.9) == "high"

    def test_medium(self):
        assert _classify_severity(4.0) == "medium"
        assert _classify_severity(6.9) == "medium"

    def test_low(self):
        assert _classify_severity(3.9) == "low"
        assert _classify_severity(0.1) == "low"

    def test_none(self):
        assert _classify_severity(None) == "low"


class TestSeverityLabel:
    def test_all_levels(self):
        assert _severity_label(0) == "info"
        assert _severity_label(1) == "low"
        assert _severity_label(2) == "medium"
        assert _severity_label(3) == "high"
        assert _severity_label(4) == "critical"

    def test_unknown(self):
        assert _severity_label(99) == "low"


# ── _compute_severity_delta ───────────────────────────────────────────────────

class TestComputeSeverityDelta:
    def test_no_cves(self):
        assert _compute_severity_delta([], []) == 0.0

    def test_only_resolved(self):
        resolved = [_cve("critical"), _cve("high")]
        delta = _compute_severity_delta(resolved, [])
        assert delta == 15.0  # 10 + 5

    def test_only_introduced(self):
        introduced = [_cve("medium"), _cve("low")]
        delta = _compute_severity_delta([], introduced)
        assert delta == -2.5  # 0 - (2 + 0.5)

    def test_mixed(self):
        resolved = [_cve("critical")]  # weight 10
        introduced = [_cve("medium"), _cve("medium")]  # weight 2+2=4
        delta = _compute_severity_delta(resolved, introduced)
        assert delta == 6.0  # 10 - 4

    def test_weights_correct(self):
        for sev, weight in [("critical", 10), ("high", 5), ("medium", 2), ("low", 0.5)]:
            delta = _compute_severity_delta([_cve(sev)], [])
            assert delta == weight


# ── _compute_verdict ──────────────────────────────────────────────────────────

class TestComputeVerdict:
    def test_no_introduced_is_safe(self):
        resolved = [_cve("critical"), _cve("high")]
        assert _compute_verdict(resolved, [], 15.0) == "safe"

    def test_introduced_critical_is_high_risk(self):
        resolved = [_cve("critical")]
        introduced = [_cve("critical")]
        assert _compute_verdict(resolved, introduced, 0.0) == "high_risk"

    def test_introduced_high_ge_resolved_high_is_high_risk(self):
        resolved = [_cve("high")]
        introduced = [_cve("high"), _cve("high")]
        delta = _compute_severity_delta(resolved, introduced)
        assert _compute_verdict(resolved, introduced, delta) == "high_risk"

    def test_introduced_high_eq_resolved_high_is_high_risk(self):
        resolved = [_cve("high")]
        introduced = [_cve("high")]
        assert _compute_verdict(resolved, introduced, 0.0) == "high_risk"

    def test_introduced_medium_is_needs_review(self):
        resolved = [_cve("critical"), _cve("high")]
        introduced = [_cve("medium")]
        delta = _compute_severity_delta(resolved, introduced)
        assert _compute_verdict(resolved, introduced, delta) == "needs_review"

    def test_introduced_low_only_is_safe(self):
        resolved = [_cve("high")]
        introduced = [_cve("low"), _cve("low")]
        delta = _compute_severity_delta(resolved, introduced)
        assert _compute_verdict(resolved, introduced, delta) == "safe"

    def test_empty_introduced_is_safe(self):
        assert _compute_verdict([], [], 0.0) == "safe"

    def test_no_resolved_but_introduced_critical(self):
        introduced = [_cve("critical")]
        assert _compute_verdict([], introduced, -10.0) == "high_risk"

    def test_no_resolved_but_introduced_medium(self):
        introduced = [_cve("medium")]
        assert _compute_verdict([], introduced, -2.0) == "needs_review"


# ── Alternative version sorting ───────────────────────────────────────────────

class TestAlternativeVersionSorting:
    def test_sorted_by_net_severity_delta_descending(self):
        alternatives = [
            {"version": "1.0", "net_severity_delta": -5.0, "verdict": "high_risk"},
            {"version": "2.0", "net_severity_delta": 10.0, "verdict": "safe"},
            {"version": "3.0", "net_severity_delta": 3.0, "verdict": "needs_review"},
        ]
        sorted_alts = sorted(alternatives, key=lambda x: x["net_severity_delta"], reverse=True)
        assert sorted_alts[0]["version"] == "2.0"
        assert sorted_alts[1]["version"] == "3.0"
        assert sorted_alts[2]["version"] == "1.0"

    def test_top3_only(self):
        alternatives = [
            {"version": str(i), "net_severity_delta": float(i)}
            for i in range(10)
        ]
        sorted_alts = sorted(alternatives, key=lambda x: x["net_severity_delta"], reverse=True)[:3]
        assert len(sorted_alts) == 3
        assert sorted_alts[0]["version"] == "9"


# ── Efficiency score penalty ──────────────────────────────────────────────────

class TestEfficiencyScorePenalty:
    def test_safe_no_penalty(self):
        base_score = 12.5
        assert base_score * VERDICT_MULTIPLIERS["safe"] == 12.5

    def test_needs_review_penalty(self):
        base_score = 12.5
        assert base_score * VERDICT_MULTIPLIERS["needs_review"] == pytest.approx(9.375)

    def test_high_risk_penalty(self):
        base_score = 12.5
        assert base_score * VERDICT_MULTIPLIERS["high_risk"] == pytest.approx(3.75)

    def test_multiplier_values(self):
        assert VERDICT_MULTIPLIERS == {"safe": 1.0, "needs_review": 0.75, "high_risk": 0.3}


# ── Version comparison ────────────────────────────────────────────────────────

class TestVersionComparison:
    def test_equal_versions(self):
        assert _version_lte("6.0.13", "6.0.13") is True

    def test_target_below_ceiling(self):
        assert _version_lte("6.0.13", "6.0.25") is True

    def test_target_above_ceiling(self):
        assert _version_lte("6.0.26", "6.0.25") is False

    def test_major_version_below(self):
        assert _version_lte("5.0.0", "6.0.25") is True

    def test_major_version_above(self):
        assert _version_lte("7.0.0", "6.0.25") is False

    def test_minor_version_comparison(self):
        assert _version_lte("6.0.13", "6.1.0") is True
        assert _version_lte("6.2.0", "6.1.0") is False

    def test_two_segment_versions(self):
        assert _version_lte("14.17", "14.21") is True
        assert _version_lte("14.22", "14.21") is False

    def test_four_segment_versions(self):
        assert _version_lte("1.2.3.4", "1.2.3.5") is True
        assert _version_lte("1.2.3.6", "1.2.3.5") is False

    def test_parse_version_tuple(self):
        assert _parse_version_tuple("6.0.13") == (6, 0, 13)
        assert _parse_version_tuple("14.17.1") == (14, 17, 1)
        assert _parse_version_tuple("1.0") == (1, 0)


# ── NVD version range matching ────────────────────────────────────────────────

class TestVersionInRange:
    def test_end_including(self):
        prod = {"versionEndIncluding": "6.0.25"}
        assert _version_in_range("6.0.13", prod) is True
        assert _version_in_range("6.0.25", prod) is True
        assert _version_in_range("6.0.26", prod) is False

    def test_end_excluding(self):
        prod = {"versionEndExcluding": "6.0.25"}
        assert _version_in_range("6.0.24", prod) is True
        assert _version_in_range("6.0.25", prod) is False
        assert _version_in_range("6.0.26", prod) is False

    def test_start_including(self):
        prod = {"versionStartIncluding": "6.0.0", "versionEndExcluding": "6.0.25"}
        assert _version_in_range("5.9.0", prod) is False
        assert _version_in_range("6.0.0", prod) is True
        assert _version_in_range("6.0.13", prod) is True
        assert _version_in_range("6.0.25", prod) is False

    def test_start_excluding(self):
        prod = {"versionStartExcluding": "6.0.0", "versionEndIncluding": "6.0.25"}
        assert _version_in_range("6.0.0", prod) is False
        assert _version_in_range("6.0.1", prod) is True
        assert _version_in_range("6.0.25", prod) is True

    def test_exact_cpe_version(self):
        prod = {"cpe_version": "6.0.13"}
        assert _version_in_range("6.0.13", prod) is True
        assert _version_in_range("6.0.14", prod) is False

    def test_no_version_info(self):
        prod = {}
        assert _version_in_range("6.0.13", prod) is False

    def test_full_range(self):
        # Typical NVD entry: affects 6.0.0 <= v < 6.0.25
        prod = {"versionStartIncluding": "6.0.0", "versionEndExcluding": "6.0.25"}
        assert _version_in_range("6.0.13", prod) is True
        assert _version_in_range("6.0.24", prod) is True
        assert _version_in_range("6.0.25", prod) is False
        assert _version_in_range("7.0.0", prod) is False


# ── Product name matching ─────────────────────────────────────────────────────

class TestProductNameMatches:
    def test_exact(self):
        assert _product_name_matches(".net", ".NET") is True

    def test_substring(self):
        assert _product_name_matches("dotnet", ".NET") is True  # slug "net" matches
        assert _product_name_matches("node.js", "Node.js") is True

    def test_slug_normalization(self):
        # ".NET" slug = "net", ".net_framework" slug = "netframework"
        assert _product_name_matches(".net_framework", ".NET") is True

    def test_no_match(self):
        assert _product_name_matches("openssl", ".NET") is False

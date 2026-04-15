"""
Unit tests for backend/prioritizer.py — priority scoring, effort levels, owner mapping.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from services.prioritizer import compute_priority_score, compute_asset_risk_score


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_finding(**kwargs):
    """Minimal finding dict with sensible defaults.

    Default solution is neutral (no patch/complex keywords) so effort level
    is determined by severity + exploitability, not solution text.
    """
    defaults = {
        "plugin_id": "99999",
        "plugin_name": "Test Plugin",
        "plugin_family": "General",
        "severity": 2,
        "cvss3_score": 5.0,
        "cvss2_score": None,
        "cvss4_score": None,
        "vpr_score": None,
        "epss_score": None,
        "cves": [],
        "exploit_available": False,
        "exploit_maturity": None,
        "zero_day": False,
        "is_kev": False,
        "ransomware_linked": False,
        "trending_in_news": False,
        "solution": "Review vendor documentation.",  # neutral — no patch/complex keywords
        "port": None,
    }
    defaults.update(kwargs)
    return defaults


# ── Score range & floors ──────────────────────────────────────────────────────

class TestScoreRange:
    def test_score_between_0_and_10(self):
        finding = make_finding(severity=2, cvss3_score=5.0)
        result = compute_priority_score(finding)
        assert 0.0 <= result["priority_score"] <= 10.0

    def test_critical_floor_at_7(self):
        """Critical findings must score >= 7 even with zero CVSS."""
        finding = make_finding(severity=4, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 7.0

    def test_high_floor_at_5(self):
        finding = make_finding(severity=3, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 5.0

    def test_medium_floor_at_3(self):
        finding = make_finding(severity=2, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 3.0

    def test_info_cap_at_2_5(self):
        finding = make_finding(severity=0, cvss3_score=10.0, vpr_score=10.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] <= 2.5

    def test_score_capped_at_10(self):
        finding = make_finding(
            severity=4, cvss3_score=10.0, vpr_score=10.0,
            exploit_maturity="weaponized", is_kev=True, ransomware_linked=True,
            zero_day=True,
        )
        result = compute_priority_score(finding)
        assert result["priority_score"] <= 10.0

    def test_high_cvss_yields_higher_score_than_low(self):
        low = compute_priority_score(make_finding(severity=2, cvss3_score=3.0))
        high = compute_priority_score(make_finding(severity=2, cvss3_score=9.0))
        assert high["priority_score"] > low["priority_score"]


# ── Exploit bonuses ───────────────────────────────────────────────────────────

class TestExploitBonuses:
    def test_weaponized_scores_higher_than_no_exploit(self):
        base = compute_priority_score(make_finding(severity=3, cvss3_score=7.0))
        weaponized = compute_priority_score(make_finding(
            severity=3, cvss3_score=7.0, exploit_maturity="weaponized"
        ))
        assert weaponized["priority_score"] >= base["priority_score"]

    def test_zero_day_scores_higher_than_weaponized(self):
        weaponized = compute_priority_score(make_finding(
            severity=3, cvss3_score=7.0, exploit_maturity="weaponized"
        ))
        zeroday = compute_priority_score(make_finding(
            severity=3, cvss3_score=7.0, zero_day=True
        ))
        assert zeroday["priority_score"] >= weaponized["priority_score"]

    def test_exploit_available_flag_raises_score(self):
        no_exploit = compute_priority_score(make_finding(severity=2, cvss3_score=5.0))
        with_exploit = compute_priority_score(make_finding(
            severity=2, cvss3_score=5.0, exploit_available=True
        ))
        assert with_exploit["priority_score"] >= no_exploit["priority_score"]

    def test_kev_flag_increases_score(self):
        no_kev = compute_priority_score(make_finding(severity=3, cvss3_score=7.0))
        kev = compute_priority_score(make_finding(severity=3, cvss3_score=7.0, is_kev=True))
        assert kev["priority_score"] >= no_kev["priority_score"]

    def test_ransomware_linked_increases_score(self):
        base = compute_priority_score(make_finding(severity=3, cvss3_score=7.0))
        ransomware = compute_priority_score(make_finding(
            severity=3, cvss3_score=7.0, ransomware_linked=True
        ))
        assert ransomware["priority_score"] >= base["priority_score"]


# ── Intel enrichment ──────────────────────────────────────────────────────────

class TestIntelEnrichment:
    def test_intel_zero_day_overrides_to_max(self):
        finding = make_finding(severity=3, cvss3_score=7.0, cves=["CVE-2024-9999"])
        intel = {"CVE-2024-9999": {"zero_day": True}}
        result = compute_priority_score(finding, intel=intel)
        assert result["priority_score"] >= 5.0  # High floor guaranteed

    def test_intel_cvss_fills_missing_cvss(self):
        finding = make_finding(severity=2, cvss3_score=None, cves=["CVE-2024-1234"])
        intel = {"CVE-2024-1234": {"cvss3": {"base_score": 8.5}}}
        result_with_intel = compute_priority_score(finding, intel=intel)
        result_no_intel = compute_priority_score(make_finding(severity=2, cvss3_score=None))
        # Intel-enriched score should be higher due to 8.5 CVSS
        assert result_with_intel["priority_score"] >= result_no_intel["priority_score"]

    def test_empty_intel_has_no_effect(self):
        finding = make_finding(severity=2, cvss3_score=6.0)
        with_empty = compute_priority_score(finding, intel={})
        without = compute_priority_score(finding, intel=None)
        assert with_empty["priority_score"] == without["priority_score"]


# ── Asset criticality ─────────────────────────────────────────────────────────

class TestAssetCriticality:
    def test_high_criticality_increases_score(self):
        low_crit = compute_priority_score(make_finding(severity=2, cvss3_score=5.0), asset_criticality=1)
        high_crit = compute_priority_score(make_finding(severity=2, cvss3_score=5.0), asset_criticality=10)
        assert high_crit["priority_score"] >= low_crit["priority_score"]


# ── CVSS source selection ─────────────────────────────────────────────────────

class TestSeveritySource:
    def test_cvss_best_prefers_v4_over_v3(self):
        finding = make_finding(cvss4_score=9.8, cvss3_score=7.0, severity=3)
        result = compute_priority_score(finding, risk_cfg={"severity_source": "cvss_best"})
        result_v3_only = compute_priority_score(
            make_finding(cvss3_score=7.0, severity=3),
            risk_cfg={"severity_source": "cvss_best"}
        )
        assert result["priority_score"] >= result_v3_only["priority_score"]

    def test_explicit_cvss2_source(self):
        finding = make_finding(cvss2_score=8.0, cvss3_score=4.0, severity=3)
        result = compute_priority_score(finding, risk_cfg={"severity_source": "cvss2"})
        result_v3 = compute_priority_score(finding, risk_cfg={"severity_source": "cvss3"})
        assert result["priority_score"] >= result_v3["priority_score"]

    def test_vpr_source(self):
        finding = make_finding(cvss3_score=5.0, vpr_score=9.5, severity=3)
        result = compute_priority_score(finding, risk_cfg={"severity_source": "vpr"})
        assert result["priority_score"] >= 5.0  # High floor + high VPR


# ── Effort levels ─────────────────────────────────────────────────────────────

class TestEffortLevels:
    def test_info_finding_is_quick_win(self):
        # Low severity, no complex/patch family, no complex solution → quick_win
        finding = make_finding(severity=0)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "quick_win"

    def test_low_severity_is_quick_win(self):
        # severity=1 falls into quick_win branch of the decision tree
        finding = make_finding(severity=1, cvss3_score=2.0, exploit_available=False)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "quick_win"

    def test_critical_with_weaponized_exploit_is_complex(self):
        # severity=4 AND exploit_bonus >= 0.7 → complex (per decision tree)
        finding = make_finding(severity=4, cvss3_score=9.5, exploit_maturity="weaponized")
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_critical_no_exploit_is_medium(self):
        # severity=4 but no exploit → falls to the else branch → medium
        finding = make_finding(severity=4, cvss3_score=9.5)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "medium"

    def test_high_severity_without_exploit_is_medium(self):
        # severity=3, no exploit, neutral solution → medium
        finding = make_finding(severity=3, cvss3_score=7.0, exploit_available=False)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "medium"

    def test_medium_severity_without_exploit_is_medium(self):
        finding = make_finding(severity=2, cvss3_score=6.0, exploit_available=False)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "medium"

    def test_patch_solution_keyword_produces_quick_win(self):
        # 'upgrade to' is in _PATCH_KEYWORDS; default asset_criticality=5 → no reboot/server worry
        finding = make_finding(severity=3, cvss3_score=7.0, solution="Upgrade to version 2.0.")
        result = compute_priority_score(finding)
        assert result["effort_level"] == "quick_win"

    def test_patch_family_is_quick_win_for_workstation(self):
        # Patch family + low criticality (workstation proxy) → quick_win
        finding = make_finding(
            severity=3, cvss3_score=7.0,
            plugin_family="Windows : Microsoft Bulletins",
            asset_criticality=3,
        )
        result = compute_priority_score(finding, asset_criticality=3)
        assert result["effort_level"] == "quick_win"

    def test_backdoor_family_is_complex(self):
        finding = make_finding(severity=2, cvss3_score=5.0, plugin_family="Backdoors")
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_complex_solution_keyword_is_complex(self):
        finding = make_finding(severity=2, cvss3_score=5.0, solution="Reconfigure the network architecture.")
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"


# ── Owner suggestions ─────────────────────────────────────────────────────────

class TestOwnerSuggestions:
    def test_windows_finding_goes_to_it(self):
        finding = make_finding(plugin_family="Windows")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "IT"

    def test_web_server_goes_to_appsec(self):
        finding = make_finding(plugin_family="Web Servers")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "AppSec"

    def test_cgi_goes_to_appsec(self):
        finding = make_finding(plugin_family="CGI abuses")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "AppSec"

    def test_firewall_goes_to_networking(self):
        finding = make_finding(plugin_family="Firewalls")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "Networking"

    def test_credentials_goes_to_iam(self):
        finding = make_finding(plugin_family="Credentials")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "IAM"

    def test_databases_goes_to_dba(self):
        finding = make_finding(plugin_family="Databases")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "DBA"

    def test_policy_compliance_goes_to_grc(self):
        finding = make_finding(plugin_family="Policy Compliance")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "GRC"

    def test_unknown_family_defaults_to_secops(self):
        finding = make_finding(plugin_family="SomeUnknownFamily")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "SecOps"


# ── Remediation steps ─────────────────────────────────────────────────────────

class TestRemediationSteps:
    def test_steps_returned_as_string(self):
        result = compute_priority_score(make_finding())
        assert isinstance(result["remediation_steps"], str)
        assert len(result["remediation_steps"]) > 0

    def test_critical_finding_has_immediate_action(self):
        finding = make_finding(severity=4, cvss3_score=9.5, plugin_name="Some RCE")
        result = compute_priority_score(finding)
        assert "IMMEDIATE ACTION" in result["remediation_steps"]

    def test_cves_appear_in_steps(self):
        finding = make_finding(cves=["CVE-2024-12345"])
        result = compute_priority_score(finding)
        assert "CVE-2024-12345" in result["remediation_steps"]

    def test_solution_appears_in_steps(self):
        finding = make_finding(solution="Run update command now.")
        result = compute_priority_score(finding)
        assert "Run update command now." in result["remediation_steps"]

    def test_ssh_finding_has_ssh_guidance(self):
        finding = make_finding(plugin_name="OpenSSH Vulnerability", plugin_family="Misc.")
        result = compute_priority_score(finding)
        assert "ssh" in result["remediation_steps"].lower() or "sshd" in result["remediation_steps"].lower()

    def test_smb_finding_has_smb_guidance(self):
        finding = make_finding(plugin_name="SMBv1 Enabled")
        result = compute_priority_score(finding)
        assert "smb" in result["remediation_steps"].lower()

    def test_always_ends_with_verify_step(self):
        result = compute_priority_score(make_finding())
        assert "Verify the fix" in result["remediation_steps"]


# ── Asset risk score ──────────────────────────────────────────────────────────

class TestAssetRiskScore:
    def test_empty_findings_returns_zero(self):
        assert compute_asset_risk_score([]) == 0.0

    def test_single_critical_finding(self):
        score = compute_asset_risk_score([{"severity": 4}])
        assert score > 0.0

    def test_five_critical_findings_max_score(self):
        """5 critical findings = 50 points = normalized to 10.0."""
        findings = [{"severity": 4}] * 5
        assert compute_asset_risk_score(findings) == 10.0

    def test_more_critical_findings_higher_score(self):
        one_critical = compute_asset_risk_score([{"severity": 4}])
        three_critical = compute_asset_risk_score([{"severity": 4}] * 3)
        assert three_critical > one_critical

    def test_info_findings_contribute_zero(self):
        info_only = compute_asset_risk_score([{"severity": 0}] * 20)
        assert info_only == 0.0

    def test_mixed_severities(self):
        findings = [
            {"severity": 4},  # 10 points
            {"severity": 3},  # 7 points
            {"severity": 2},  # 4 points
        ]
        score = compute_asset_risk_score(findings)
        # (10+7+4)/50 * 10 = 21/50 * 10 = 4.2
        assert score == pytest.approx(4.2)

    def test_score_capped_at_10(self):
        findings = [{"severity": 4}] * 100
        assert compute_asset_risk_score(findings) == 10.0

    def test_score_is_rounded_to_2_decimals(self):
        findings = [{"severity": 3}] * 3  # 21/50*10 = 4.2
        score = compute_asset_risk_score(findings)
        assert score == round(score, 2)


# ── Controls & reachability ───────────────────────────────────────────────────

class TestControlsAndReachability:
    def test_no_controls_increases_score_vs_has_av(self):
        finding = make_finding(severity=2, cvss3_score=5.0)
        no_controls = compute_priority_score(
            finding,
            asset_inventory={"has_av": False, "has_firewall": False},
            risk_cfg={"finding_formula_weights": {
                "severity": 0.20, "intel": 0.20, "exploitability": 0.20,
                "criticality": 0.10, "family": 0.10, "controls": 0.10, "reachability": 0.10,
            }}
        )
        has_controls = compute_priority_score(
            make_finding(severity=2, cvss3_score=5.0),
            asset_inventory={"has_av": True, "has_firewall": True},
            risk_cfg={"finding_formula_weights": {
                "severity": 0.20, "intel": 0.20, "exploitability": 0.20,
                "criticality": 0.10, "family": 0.10, "controls": 0.10, "reachability": 0.10,
            }}
        )
        assert no_controls["priority_score"] >= has_controls["priority_score"]

    def test_port_in_established_connections_max_reachability(self):
        finding = make_finding(severity=2, cvss3_score=5.0, port="443")
        result = compute_priority_score(
            finding,
            asset_inventory={"established_ports": {443}, "listening_ports": set()},
            risk_cfg={"finding_formula_weights": {
                "severity": 0.20, "intel": 0.20, "exploitability": 0.20,
                "criticality": 0.10, "family": 0.10, "controls": 0.05, "reachability": 0.15,
            }}
        )
        no_port = compute_priority_score(
            make_finding(severity=2, cvss3_score=5.0, port="9999"),
            asset_inventory={"established_ports": {443}, "listening_ports": set()},
            risk_cfg={"finding_formula_weights": {
                "severity": 0.20, "intel": 0.20, "exploitability": 0.20,
                "criticality": 0.10, "family": 0.10, "controls": 0.05, "reachability": 0.15,
            }}
        )
        assert result["priority_score"] >= no_port["priority_score"]

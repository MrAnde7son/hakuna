"""
Tests for services/prioritizer.py

Pure-function tests — no database access required.
"""

import pytest
from services.prioritizer import compute_priority_score, compute_asset_risk_score


# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

def _finding(**kwargs) -> dict:
    """Return a minimal finding dict, overriding defaults with kwargs."""
    base = {
        "plugin_id": "12345",
        "plugin_name": "Test Plugin",
        "plugin_family": "General",
        "severity": 2,
        "cvss3_score": 5.0,
        "solution": "Apply the update.",
        "cves": [],
    }
    base.update(kwargs)
    return base


def _finding_with_risk_cfg(finding_overrides=None, weight_overrides=None):
    """Return (finding, risk_cfg) tuple for tests that need a risk_cfg."""
    finding = _finding(**(finding_overrides or {}))
    weights = {
        "severity":       0.25,
        "exploitability": 0.25,
        "intel":          0.20,
        "criticality":    0.10,
        "family":         0.10,
        "controls":       0.05,
        "reachability":   0.05,
    }
    if weight_overrides:
        weights.update(weight_overrides)
    risk_cfg = {"finding_formula_weights": weights}
    return finding, risk_cfg


# ---------------------------------------------------------------------------
# Class 1: compute_priority_score — basic scoring
# ---------------------------------------------------------------------------

class TestBasicScoring:

    def test_returns_expected_keys(self):
        result = compute_priority_score(_finding())
        assert set(result.keys()) == {"priority_score", "effort_level", "owner_suggestion", "remediation_steps"}

    def test_high_cvss3_gives_high_score(self):
        finding = _finding(cvss3_score=9.8, severity=4)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 7.0

    def test_score_clamped_at_10(self):
        finding = _finding(
            cvss3_score=10.0,
            severity=4,
            vpr_score=10.0,
            is_kev=True,
            ransomware_linked=True,
            zero_day=True,
        )
        result = compute_priority_score(finding)
        assert result["priority_score"] <= 10.0

    def test_score_is_float_rounded_to_2dp(self):
        result = compute_priority_score(_finding(cvss3_score=7.3))
        score = result["priority_score"]
        assert isinstance(score, float)
        assert score == round(score, 2)

    def test_zero_cvss_no_signals_gives_low_score(self):
        finding = _finding(cvss3_score=0.0, severity=1, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] <= 3.0


# ---------------------------------------------------------------------------
# Class 2: compute_priority_score — severity floors and caps
# ---------------------------------------------------------------------------

class TestSeverityFloors:

    def test_critical_severity_floor_7(self):
        # Even with no CVSS score, critical severity should floor at 7
        finding = _finding(severity=4, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 7.0

    def test_high_severity_floor_5(self):
        finding = _finding(severity=3, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 5.0

    def test_medium_severity_floor_3(self):
        finding = _finding(severity=2, cvss3_score=0.0, vpr_score=0.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 3.0

    def test_info_severity_capped_at_2_5(self):
        # Informational findings must never exceed 2.5
        finding = _finding(
            severity=0,
            cvss3_score=10.0,
            vpr_score=10.0,
            is_kev=True,
        )
        result = compute_priority_score(finding)
        assert result["priority_score"] <= 2.5


# ---------------------------------------------------------------------------
# Class 3: compute_priority_score — exploit maturity
# ---------------------------------------------------------------------------

class TestExploitMaturity:

    def test_weaponized_higher_than_poc(self):
        # Use risk_cfg so formula weights are applied; pass severity=1 to avoid floors
        # that would clamp scores to the same value.
        _, risk_cfg = _finding_with_risk_cfg()
        base = dict(severity=1, cvss3_score=7.0, plugin_family="General")
        r_weaponized = compute_priority_score(_finding(exploit_maturity="weaponized", **base), risk_cfg=risk_cfg)
        r_poc        = compute_priority_score(_finding(exploit_maturity="poc",        **base), risk_cfg=risk_cfg)
        assert r_weaponized["priority_score"] > r_poc["priority_score"]

    def test_functional_higher_than_unproven(self):
        _, risk_cfg = _finding_with_risk_cfg()
        base = dict(severity=1, cvss3_score=7.0, plugin_family="General")
        r_functional = compute_priority_score(_finding(exploit_maturity="functional", **base), risk_cfg=risk_cfg)
        r_unproven   = compute_priority_score(_finding(exploit_maturity="unproven",   **base), risk_cfg=risk_cfg)
        assert r_functional["priority_score"] > r_unproven["priority_score"]

    def test_zero_day_bonus(self):
        base = dict(severity=3, cvss3_score=7.0, plugin_family="General")
        r_zero_day = compute_priority_score(_finding(zero_day=True,  **base))
        r_normal   = compute_priority_score(_finding(zero_day=False, **base))
        assert r_zero_day["priority_score"] > r_normal["priority_score"]

    def test_exploit_available_flag(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_exploited = compute_priority_score(_finding(exploit_available=True,  **base))
        r_none      = compute_priority_score(_finding(exploit_available=False, **base))
        assert r_exploited["priority_score"] >= r_none["priority_score"]


# ---------------------------------------------------------------------------
# Class 4: compute_priority_score — threat intel signals
# ---------------------------------------------------------------------------

class TestIntelSignals:

    def test_kev_raises_score(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_kev    = compute_priority_score(_finding(is_kev=True,  **base))
        r_no_kev = compute_priority_score(_finding(is_kev=False, **base))
        assert r_kev["priority_score"] > r_no_kev["priority_score"]

    def test_ransomware_linked_raises_score(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_ransom = compute_priority_score(_finding(ransomware_linked=True,  **base))
        r_none   = compute_priority_score(_finding(ransomware_linked=False, **base))
        assert r_ransom["priority_score"] > r_none["priority_score"]

    def test_trending_in_news_raises_score(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_trending = compute_priority_score(_finding(trending_in_news=True,  **base))
        r_none     = compute_priority_score(_finding(trending_in_news=False, **base))
        assert r_trending["priority_score"] > r_none["priority_score"]

    def test_high_epss_raises_score(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_high_epss = compute_priority_score(_finding(epss_score=0.9, **base))
        r_zero_epss = compute_priority_score(_finding(epss_score=0.0, **base))
        assert r_high_epss["priority_score"] > r_zero_epss["priority_score"]

    def test_vpr_score_contribution(self):
        base = dict(severity=2, cvss3_score=5.0)
        r_high_vpr = compute_priority_score(_finding(vpr_score=9.0, **base))
        r_no_vpr   = compute_priority_score(_finding(vpr_score=0.0, **base))
        assert r_high_vpr["priority_score"] > r_no_vpr["priority_score"]

    def test_intel_dict_zero_day_raises_score(self):
        finding = _finding(severity=3, cvss3_score=6.0, cves=["CVE-2024-9999"])
        intel = {"CVE-2024-9999": {"zero_day": True}}
        r_intel  = compute_priority_score(finding, intel=intel)
        r_no_intel = compute_priority_score(_finding(severity=3, cvss3_score=6.0, cves=["CVE-2024-9999"]))
        assert r_intel["priority_score"] >= r_no_intel["priority_score"]

    def test_intel_dict_cvss_fallback(self):
        """When finding has no cvss3_score, intel dict supplies it."""
        finding = _finding(severity=3, cvss3_score=None, cvss2_score=None, cvss4_score=None, cves=["CVE-2025-0001"])
        intel = {"CVE-2025-0001": {"cvss3": {"base_score": 9.5}}}
        result = compute_priority_score(finding, intel=intel)
        # Score should reflect the high cvss from intel
        assert result["priority_score"] >= 5.0


# ---------------------------------------------------------------------------
# Class 5: compute_priority_score — asset criticality
# ---------------------------------------------------------------------------

class TestAssetCriticality:

    def test_high_criticality_raises_score(self):
        # Use risk_cfg so all weights including criticality are applied.
        # Use severity=1 to avoid severity floors clamping both scores to the same value.
        _, risk_cfg = _finding_with_risk_cfg()
        finding = _finding(severity=1, cvss3_score=5.0)
        r_high = compute_priority_score(finding, asset_criticality=10, risk_cfg=risk_cfg)
        r_low  = compute_priority_score(finding, asset_criticality=1,  risk_cfg=risk_cfg)
        assert r_high["priority_score"] > r_low["priority_score"]


# ---------------------------------------------------------------------------
# Class 6: compute_priority_score — plugin family weights
# ---------------------------------------------------------------------------

class TestPluginFamilyWeights:

    def test_shell_family_higher_than_service_detection(self):
        # Use risk_cfg and severity=1 so the family weight contribution isn't hidden by
        # the severity floor (severity=3 clamps both to the same floor value).
        _, risk_cfg = _finding_with_risk_cfg()
        base = dict(severity=1, cvss3_score=7.0)
        r_shell   = compute_priority_score(_finding(plugin_family="Gain a shell remotely", **base), risk_cfg=risk_cfg)
        r_service = compute_priority_score(_finding(plugin_family="Service detection",     **base), risk_cfg=risk_cfg)
        assert r_shell["priority_score"] > r_service["priority_score"]

    def test_backdoors_family_high_weight(self):
        finding = _finding(plugin_family="Backdoors", severity=3, cvss3_score=7.0)
        result = compute_priority_score(finding)
        assert result["priority_score"] >= 5.0

    def test_settings_family_low_weight(self):
        """Settings family (weight=0.5) should yield a low family bonus."""
        finding = _finding(plugin_family="Settings", severity=2, cvss3_score=4.0)
        result = compute_priority_score(finding)
        # family_bonus = (0.5 - 0.5)/1.0 = 0, shouldn't boost score
        assert result["priority_score"] < 6.0


# ---------------------------------------------------------------------------
# Class 7: compute_priority_score — controls & reachability
# ---------------------------------------------------------------------------

class TestControlsAndReachability:

    def test_has_av_reduces_controls_factor(self):
        # Use severity=1 to avoid severity floors clamping both scores equal.
        # Give controls a high weight to make the difference visible.
        finding = _finding(severity=1, cvss3_score=7.0)
        inv_cfg = {"finding_formula_weights": {
            "severity": 0.20, "exploitability": 0.15, "intel": 0.15,
            "criticality": 0.10, "family": 0.10, "controls": 0.15, "reachability": 0.15,
        }}
        r_av     = compute_priority_score(finding, risk_cfg=inv_cfg, asset_inventory={"has_av": True,  "has_firewall": False})
        r_no_av  = compute_priority_score(finding, risk_cfg=inv_cfg, asset_inventory={"has_av": False, "has_firewall": False})
        assert r_av["priority_score"] < r_no_av["priority_score"]

    def test_no_controls_increases_score(self):
        """has_av=False and has_firewall=False → controls_factor=1.0 (penalty applied)."""
        finding = _finding(severity=2, cvss3_score=5.0)
        _, risk_cfg = _finding_with_risk_cfg()
        r_none = compute_priority_score(finding, risk_cfg=risk_cfg,
                                        asset_inventory={"has_av": False, "has_firewall": False})
        r_both = compute_priority_score(finding, risk_cfg=risk_cfg,
                                        asset_inventory={"has_av": True,  "has_firewall": True})
        assert r_none["priority_score"] >= r_both["priority_score"]

    def test_internet_facing_sets_full_reachability(self):
        finding = _finding(severity=2, cvss3_score=5.0, port=443)
        _, risk_cfg = _finding_with_risk_cfg()
        r_facing  = compute_priority_score(finding, risk_cfg=risk_cfg,
                                           asset_inventory={"is_internet_facing": True})
        r_internal = compute_priority_score(finding, risk_cfg=risk_cfg,
                                            asset_inventory={"is_internet_facing": False, "listening_ports": set()})
        assert r_facing["priority_score"] >= r_internal["priority_score"]

    def test_port_in_listening_ports_raises_reachability(self):
        # severity=1 avoids the severity floor clamping both scores to the same value.
        # Give reachability a high enough weight to be visible in the final score.
        finding = _finding(severity=1, cvss3_score=5.0, port=8080)
        _, risk_cfg = _finding_with_risk_cfg(weight_overrides={"reachability": 0.20, "controls": 0.0})
        r_listening = compute_priority_score(finding, risk_cfg=risk_cfg,
                                             asset_inventory={"listening_ports": {8080}})
        r_not       = compute_priority_score(finding, risk_cfg=risk_cfg,
                                             asset_inventory={"listening_ports": set()})
        assert r_listening["priority_score"] > r_not["priority_score"]


# ---------------------------------------------------------------------------
# Class 8: compute_priority_score — severity source configuration
# ---------------------------------------------------------------------------

class TestSeveritySource:

    def test_cvss2_source(self):
        finding = _finding(cvss2_score=8.0, cvss3_score=4.0, severity=3)
        risk_cfg = {"severity_source": "cvss2"}
        result = compute_priority_score(finding, risk_cfg=risk_cfg)
        # cvss2=8.0 → sev_norm=0.8, should dominate; floor kicks in at 5 anyway
        assert result["priority_score"] >= 5.0

    def test_cvss3_source(self):
        finding = _finding(cvss3_score=9.0, cvss2_score=2.0, severity=4)
        risk_cfg = {"severity_source": "cvss3"}
        result = compute_priority_score(finding, risk_cfg=risk_cfg)
        assert result["priority_score"] >= 7.0

    def test_vpr_source(self):
        finding = _finding(vpr_score=8.5, cvss3_score=3.0, severity=3)
        risk_cfg = {"severity_source": "vpr"}
        result = compute_priority_score(finding, risk_cfg=risk_cfg)
        assert result["priority_score"] >= 5.0

    def test_epss_source(self):
        finding = _finding(epss_score=0.95, cvss3_score=3.0, severity=2)
        risk_cfg = {"severity_source": "epss"}
        result = compute_priority_score(finding, risk_cfg=risk_cfg)
        # epss=0.95 → sev_norm=0.95, high contribution; floor at 3 for medium
        assert result["priority_score"] >= 3.0

    def test_cvss_best_prefers_v4_over_v3(self):
        """cvss_best picks cvss4 > cvss3 > cvss2."""
        finding = _finding(cvss4_score=9.5, cvss3_score=4.0, cvss2_score=3.0, severity=4)
        risk_cfg = {"severity_source": "cvss_best"}
        result = compute_priority_score(finding, risk_cfg=risk_cfg)
        # cvss4=9.5 selected → high sev_norm
        assert result["priority_score"] >= 7.0

    def test_custom_weights_override_defaults(self):
        """risk_cfg.finding_formula_weights should override legacy defaults."""
        finding = _finding(severity=2, cvss3_score=5.0)
        # Give family weight of 0.9 — a "Service detection" family will drag score down
        risk_cfg = {
            "finding_formula_weights": {
                "severity": 0.05, "exploitability": 0.05, "intel": 0.05,
                "criticality": 0.05, "family": 0.75, "controls": 0.025, "reachability": 0.025,
            }
        }
        finding_low_family  = _finding(plugin_family="Settings",             severity=2, cvss3_score=5.0)
        finding_high_family = _finding(plugin_family="Gain a shell remotely", severity=2, cvss3_score=5.0)
        r_low  = compute_priority_score(finding_low_family,  risk_cfg=risk_cfg)
        r_high = compute_priority_score(finding_high_family, risk_cfg=risk_cfg)
        assert r_high["priority_score"] > r_low["priority_score"]


# ---------------------------------------------------------------------------
# Class 9: effort level
# ---------------------------------------------------------------------------

class TestEffortLevel:

    def test_eol_plugin_name_is_complex(self):
        finding = _finding(plugin_name="Windows Server 2008 End of Life", severity=3)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_unsupported_plugin_name_is_complex(self):
        finding = _finding(plugin_name="CentOS 6 Unsupported Version Detection", severity=2)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_patch_family_server_reboot_is_medium(self):
        finding = _finding(
            plugin_family="Ubuntu Local Security Checks",
            solution="Update to version 5.0. A system reboot is required.",
            asset_os="ubuntu linux server",
            severity=3,
        )
        result = compute_priority_score(finding, asset_criticality=7)
        assert result["effort_level"] == "medium"

    def test_patch_family_no_reboot_is_quick_win(self):
        finding = _finding(
            plugin_family="Ubuntu Local Security Checks",
            solution="Apply the update to fix this vulnerability.",
            asset_os="ubuntu linux server",
            severity=2,
        )
        result = compute_priority_score(finding, asset_criticality=5)
        assert result["effort_level"] == "quick_win"

    def test_windows_kb_patch_family_has_reboot(self):
        """Windows Microsoft Bulletins family always implies reboot → medium for servers."""
        finding = _finding(
            plugin_family="Windows : Microsoft Bulletins",
            solution="Apply KB4567890.",
            asset_os="windows server 2019",
            severity=3,
        )
        result = compute_priority_score(finding, asset_criticality=8)
        assert result["effort_level"] == "medium"

    def test_complex_family_is_complex(self):
        finding = _finding(plugin_family="Gain a shell remotely", severity=3)
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_critical_weaponized_is_complex(self):
        # Use a neutral solution (no patch/complex keywords) and a non-patch, non-complex
        # family so the decision falls through to the severity+exploit branch.
        finding = _finding(
            severity=4,
            exploit_maturity="weaponized",
            cvss3_score=9.5,
            plugin_family="General",
            solution="Contact the vendor for details.",
        )
        result = compute_priority_score(finding)
        assert result["effort_level"] == "complex"

    def test_low_severity_is_quick_win(self):
        finding = _finding(severity=1, cvss3_score=2.0, plugin_family="General")
        result = compute_priority_score(finding)
        assert result["effort_level"] == "quick_win"


# ---------------------------------------------------------------------------
# Class 10: owner suggestion
# ---------------------------------------------------------------------------

class TestOwnerSuggestion:

    def test_windows_family_mapped_to_it(self):
        finding = _finding(plugin_family="Windows")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "IT"

    def test_cgi_abuses_mapped_to_appsec(self):
        finding = _finding(plugin_family="CGI abuses")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "AppSec"

    def test_web_servers_mapped_to_appsec(self):
        finding = _finding(plugin_family="Web Servers")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "AppSec"

    def test_firewalls_mapped_to_networking(self):
        finding = _finding(plugin_family="Firewalls")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "Networking"

    def test_unknown_family_defaults_to_secops(self):
        finding = _finding(plugin_family="Unknown Exotic Family")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "SecOps"

    def test_credentials_mapped_to_iam(self):
        finding = _finding(plugin_family="Credentials")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "IAM"

    def test_databases_mapped_to_dba(self):
        finding = _finding(plugin_family="Databases")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "DBA"

    def test_backdoors_mapped_to_soc(self):
        finding = _finding(plugin_family="Backdoors")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "SOC"

    def test_policy_compliance_mapped_to_grc(self):
        finding = _finding(plugin_family="Policy Compliance")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "GRC"

    def test_nuclei_mapped_to_vm(self):
        finding = _finding(plugin_family="Nuclei")
        result = compute_priority_score(finding)
        assert result["owner_suggestion"] == "VM"


# ---------------------------------------------------------------------------
# Class 11: compute_asset_risk_score
# ---------------------------------------------------------------------------

class TestComputeAssetRiskScore:

    def test_empty_findings_returns_zero(self):
        assert compute_asset_risk_score([]) == 0.0

    def test_single_critical_finding(self):
        findings = [{"severity": 4}]
        score = compute_asset_risk_score(findings)
        # 10/50 * 10 = 2.0
        assert score == pytest.approx(2.0)

    def test_five_critical_findings_max_score(self):
        findings = [{"severity": 4}] * 5
        score = compute_asset_risk_score(findings)
        assert score == pytest.approx(10.0)

    def test_more_than_five_critical_clamped_at_10(self):
        findings = [{"severity": 4}] * 10
        score = compute_asset_risk_score(findings)
        assert score == 10.0

    def test_severity_weights_ordering(self):
        """Higher severity findings produce higher risk scores."""
        score_critical = compute_asset_risk_score([{"severity": 4}])
        score_high     = compute_asset_risk_score([{"severity": 3}])
        score_medium   = compute_asset_risk_score([{"severity": 2}])
        score_low      = compute_asset_risk_score([{"severity": 1}])
        score_info     = compute_asset_risk_score([{"severity": 0}])
        assert score_critical > score_high > score_medium > score_low
        assert score_info == 0.0

    def test_mixed_severities_sum_correctly(self):
        # 1 critical (10) + 1 high (7) = 17 → 17/50 * 10 = 3.4
        findings = [{"severity": 4}, {"severity": 3}]
        score = compute_asset_risk_score(findings)
        assert score == pytest.approx(3.4)

    def test_missing_severity_treated_as_info(self):
        findings = [{}]  # no severity key → defaults to 0 → weight 0
        score = compute_asset_risk_score(findings)
        assert score == 0.0

    def test_returns_float_rounded_to_2dp(self):
        findings = [{"severity": 3}]  # 7/50*10 = 1.4
        score = compute_asset_risk_score(findings)
        assert isinstance(score, float)
        assert score == round(score, 2)

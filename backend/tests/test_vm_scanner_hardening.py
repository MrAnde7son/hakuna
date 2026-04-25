"""PR 0b — VM scanner field coverage for compliance mapping.

Pins the normalization layer that feeds the compliance evaluator:
  - classification.cwe-id → Finding.cwe_ids
  - info.reference        → Finding.references["urls"]
  - template_id path / info.tags → Finding.plugin_family
  - severity_label set at insert time (not NULL)
  - ctx_* fields seeded from scan evidence
  - Nuclei tags reach the TTP matcher via custom_fields
"""

from services.vm_scanner import (
    _extract_nuclei_cwes,
    _extract_nuclei_references,
    _classify_nuclei_plugin_family,
    _seed_nuclei_context,
    _SEVERITY_LABEL_BY_STR,
)
from threat_intel.ttp_matcher import match_finding


# ─── CWE extraction ────────────────────────────────────────────

class TestExtractNucleiCwes:
    def test_cwe_list_in_classification(self):
        f = {"classification": {"cwe-id": ["CWE-79", "CWE-89"]}}
        assert _extract_nuclei_cwes(f) == ["CWE-79", "CWE-89"]

    def test_cwe_string_in_classification(self):
        f = {"classification": {"cwe-id": "CWE-79"}}
        assert _extract_nuclei_cwes(f) == ["CWE-79"]

    def test_empty_when_no_classification(self):
        assert _extract_nuclei_cwes({}) == []

    def test_empty_when_classification_not_a_dict(self):
        assert _extract_nuclei_cwes({"classification": "oops"}) == []

    def test_case_normalized_to_upper(self):
        f = {"classification": {"cwe-id": ["cwe-79"]}}
        assert _extract_nuclei_cwes(f) == ["CWE-79"]

    def test_dedupes_while_preserving_order(self):
        f = {"classification": {"cwe-id": ["CWE-79", "CWE-89", "CWE-79"]}}
        assert _extract_nuclei_cwes(f) == ["CWE-79", "CWE-89"]

    def test_null_cwe_id(self):
        f = {"classification": {"cwe-id": None}}
        assert _extract_nuclei_cwes(f) == []


# ─── References ────────────────────────────────────────────────

class TestExtractNucleiReferences:
    def test_list_wrapped_under_urls(self):
        f = {"reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]}
        assert _extract_nuclei_references(f) == {
            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        }

    def test_string_wrapped_as_single_url(self):
        f = {"reference": "https://example.com/advisory"}
        assert _extract_nuclei_references(f) == {
            "urls": ["https://example.com/advisory"]
        }

    def test_empty_dict_when_no_references(self):
        assert _extract_nuclei_references({}) == {}

    def test_empty_list_yields_empty_dict(self):
        assert _extract_nuclei_references({"reference": []}) == {}

    def test_drops_non_string_entries(self):
        f = {"reference": ["https://a.com", None, 42, "https://b.com"]}
        assert _extract_nuclei_references(f) == {
            "urls": ["https://a.com", "https://b.com"]
        }


# ─── plugin_family classifier ──────────────────────────────────

class TestClassifyNucleiPluginFamily:
    def test_cve_path_prefix(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "cves/2021/CVE-2021-44228"}
        ) == "CVE"

    def test_default_login_path(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "http/default-logins/apache-default-login"}
        ) == "DefaultLogin"

    def test_misconfiguration_path(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "http/misconfiguration/aws-bucket-takeover"}
        ) == "Misconfiguration"

    def test_exposed_panel_path(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "http/exposed-panels/grafana"}
        ) == "ExposedPanel"

    def test_takeover_path(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "http/takeovers/aws-takeover"}
        ) == "Takeover"

    def test_dns_path(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "dns/dangling-cname"}
        ) == "DNS"

    def test_tag_fallback_when_path_unknown(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "custom-template", "tags": ["cve", "rce"]}
        ) == "CVE"

    def test_tag_default_login(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "custom-something", "tags": ["default-login"]}
        ) == "DefaultLogin"

    def test_returns_nuclei_when_nothing_matches(self):
        assert _classify_nuclei_plugin_family(
            {"template_id": "opaque", "tags": []}
        ) == "Nuclei"


# ─── Context seeding ───────────────────────────────────────────

class TestSeedNucleiContext:
    class _FakeAsset:
        def __init__(self, is_internet_facing):
            self.is_internet_facing = is_internet_facing

    def test_internet_facing_authenticated(self):
        ctx = _seed_nuclei_context({}, self._FakeAsset(True), authenticated=True)
        assert ctx == {
            "ctx_reachability": "internet_facing",
            "ctx_accessibility": "authenticated_only",
            "ctx_exploitability": "easily_exploitable",
        }

    def test_internal_unauthenticated(self):
        ctx = _seed_nuclei_context({}, self._FakeAsset(False), authenticated=False)
        assert ctx == {
            "ctx_reachability": "internal_only",
            "ctx_accessibility": "public",
            "ctx_exploitability": "easily_exploitable",
        }


# ─── Severity label map is exhaustive ──────────────────────────

class TestSeverityLabelMap:
    def test_all_nuclei_severities_have_labels(self):
        # Every value in severity_map used at ingest time must have a label.
        for s in ("critical", "high", "medium", "low", "info"):
            assert s in _SEVERITY_LABEL_BY_STR


# ─── Nuclei tag → TTP ─────────────────────────────────────────

class TestTtpMatcherNucleiTags:
    def test_default_login_tag_maps_to_valid_accounts(self):
        ttps = match_finding(
            plugin_id="apache-default-login",
            plugin_name="Apache default credentials",
            plugin_family="DefaultLogin",
            synopsis="",
            description="",
            tags=["default-login"],
        )
        tids = [t["technique_id"] for t in ttps]
        assert "T1078" in tids
        reasons = {t["match_reason"] for t in ttps if t["technique_id"] == "T1078"}
        assert "nuclei_tag" in reasons

    def test_rce_tag_maps_to_t1190(self):
        ttps = match_finding(
            plugin_id="custom-rce-check",
            plugin_name="",
            plugin_family="Nuclei",
            synopsis="",
            description="",
            tags=["rce"],
        )
        assert any(t["technique_id"] == "T1190" for t in ttps)

    def test_takeover_tag_maps_to_t1583(self):
        ttps = match_finding(
            plugin_id="aws-takeover",
            plugin_name="",
            plugin_family="Takeover",
            synopsis="",
            description="",
            tags=["takeover"],
        )
        assert any(t["technique_id"] == "T1583.001" for t in ttps)

    def test_unknown_tag_contributes_nothing(self):
        ttps = match_finding(
            plugin_id="x",
            plugin_name="",
            plugin_family="Nuclei",
            synopsis="",
            description="",
            tags=["totally-unknown-tag"],
        )
        assert ttps == []

    def test_tag_match_dedupes_against_plugin_id_match(self):
        # If plugin_id already matched a TTP, tag mapping shouldn't dupe it.
        ttps = match_finding(
            plugin_id="69239",  # PLUGIN_ID_MAP → T1087.002
            plugin_name="",
            plugin_family="",
            synopsis="",
            description="",
            tags=["exposure"],  # would also add T1082
        )
        ids = [t["technique_id"] for t in ttps]
        assert len(ids) == len(set(ids)), f"duplicates in {ids}"

    def test_no_tags_argument_preserves_legacy_behavior(self):
        ttps = match_finding(
            plugin_id="",
            plugin_name="",
            plugin_family="",
            synopsis="",
            description="",
        )
        assert ttps == []

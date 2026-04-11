"""Unit tests for services/cpe_matcher.py.

The matcher has two halves:
  1. parse_cpe() — pure function, CPE 2.3 / 2.2 → (vendor, product, version)
  2. match_cves_for_cpes() — DB-backed, looks up matching CVEs via
     downstream_impact._query_threat_intel_cves

parse_cpe is tested directly.
match_cves_for_cpes is tested with the downstream helper monkey-patched so
we can drive it without a real ThreatCVE table.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.cpe_matcher import ParsedCpe, match_cves_for_cpes, parse_cpe


# ═══════════════════════════════════════════════════════════
# parse_cpe
# ═══════════════════════════════════════════════════════════


class TestParseCpe:
    def test_cpe_23_with_version(self):
        p = parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        assert p == ParsedCpe(vendor="nginx", product="nginx", version="1.18.0")

    def test_cpe_23_with_wildcard_version(self):
        p = parse_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        assert p is not None
        assert p.vendor == "nginx"
        assert p.product == "nginx"
        assert p.version == "*"
        assert p.has_version is False

    def test_cpe_23_empty_version_becomes_star(self):
        # Scanner fingerprinter sometimes emits "" instead of "*" on a field
        p = parse_cpe("cpe:2.3:a:apache:http_server::*:*:*:*:*:*:*")
        assert p is not None
        assert p.version == "*"
        assert p.has_version is False

    def test_cpe_23_case_normalized(self):
        p = parse_cpe("cpe:2.3:a:Apache:HTTP_SERVER:2.4.49:*:*:*:*:*:*:*")
        assert p.vendor == "apache"
        assert p.product == "http_server"
        assert p.version == "2.4.49"

    def test_cpe_22_format(self):
        p = parse_cpe("cpe:/a:jenkins:jenkins:2.387")
        assert p == ParsedCpe(vendor="jenkins", product="jenkins", version="2.387")

    def test_cpe_22_no_version(self):
        p = parse_cpe("cpe:/a:jenkins:jenkins")
        assert p is not None
        assert p.vendor == "jenkins"
        assert p.product == "jenkins"
        assert p.version == "*"

    def test_malformed_returns_none(self):
        assert parse_cpe("") is None
        assert parse_cpe("not a cpe") is None
        assert parse_cpe("cpe:2.3") is None
        assert parse_cpe("cpe:2.3:a") is None

    def test_none_input_returns_none(self):
        assert parse_cpe(None) is None  # type: ignore

    def test_non_string_input_returns_none(self):
        assert parse_cpe(12345) is None  # type: ignore
        assert parse_cpe(["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"]) is None  # type: ignore

    def test_has_version_property(self):
        assert ParsedCpe("nginx", "nginx", "1.18.0").has_version is True
        assert ParsedCpe("nginx", "nginx", "*").has_version is False
        assert ParsedCpe("nginx", "nginx", "").has_version is False

    def test_cpe_23_with_complex_version_string(self):
        # Real-world: Apache 2.4.49 with a distro suffix
        p = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49-ubuntu:*:*:*:*:*:*:*")
        assert p.version == "2.4.49-ubuntu"

    def test_empty_vendor_rejected(self):
        assert parse_cpe("cpe:2.3:a::nginx:1.18.0:*:*:*:*:*:*:*") is None

    def test_empty_product_rejected(self):
        assert parse_cpe("cpe:2.3:a:nginx::1.18.0:*:*:*:*:*:*:*") is None


# ═══════════════════════════════════════════════════════════
# match_cves_for_cpes
#
# We monkeypatch _query_threat_intel_cves so we don't need a real DB or
# ThreatCVE rows. The fake returns deterministic matches per (product, version).
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def fake_query(monkeypatch):
    """Patch _query_threat_intel_cves to return canned data per product."""
    calls: list[tuple[str, str, list[str]]] = []

    # Minimal fake threat intel database: product → list of (version, cve_dict)
    fake_db: dict[str, list[tuple[str, dict]]] = {
        "nginx": [
            ("1.18.0", {
                "cve_id": "CVE-2021-23017",
                "cvss3_score": 7.5,
                "severity": "high",
                "in_kev": False,
                "has_public_exploit": True,
                "description": "A security issue in nginx resolver was identified.",
            }),
        ],
        "http_server": [  # apache:http_server
            ("2.4.49", {
                "cve_id": "CVE-2021-41773",
                "cvss3_score": 9.8,
                "severity": "critical",
                "in_kev": True,
                "has_public_exploit": True,
                "description": "Path traversal in Apache httpd 2.4.49.",
            }),
        ],
        "jenkins": [
            ("2.387", {
                "cve_id": "CVE-2023-27898",
                "cvss3_score": 8.8,
                "severity": "high",
                "in_kev": False,
                "has_public_exploit": False,
                "description": "Jenkins XSS vulnerability.",
            }),
        ],
    }

    def _fake(db, component, version, exclude_cve_ids):
        calls.append((component, version, list(exclude_cve_ids)))
        matches = []
        for prod_key, entries in fake_db.items():
            if prod_key in component.lower() or component.lower() in prod_key:
                for ver, cve_dict in entries:
                    if ver == version and cve_dict["cve_id"] not in exclude_cve_ids:
                        matches.append(dict(cve_dict))
        return matches

    import services.cpe_matcher as mod
    import services.downstream_impact as di_mod

    monkeypatch.setattr(di_mod, "_query_threat_intel_cves", _fake)
    return calls


class TestMatchCves:
    def test_empty_input(self, fake_query):
        assert match_cves_for_cpes(None, None) == []
        assert match_cves_for_cpes(None, []) == []

    def test_versioned_cpe_matches(self, fake_query):
        result = match_cves_for_cpes(None, ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"])
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-23017"
        assert result[0]["matched_cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    def test_version_star_skipped(self, fake_query):
        # No concrete version → no CVE lookup, no calls to _query_threat_intel_cves
        result = match_cves_for_cpes(None, ["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"])
        assert result == []
        assert len(fake_query) == 0

    def test_mixed_versioned_and_star(self, fake_query):
        result = match_cves_for_cpes(None, [
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",         # skipped
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",    # matches
        ])
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-23017"
        # Only ONE call (the version=* was skipped before hitting the query)
        assert len(fake_query) == 1

    def test_kev_cve_surfaced(self, fake_query):
        result = match_cves_for_cpes(None, [
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        ])
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-41773"
        assert result[0]["in_kev"] is True

    def test_multiple_cpes_dedup_by_cve_id(self, fake_query):
        # Two CPEs that happen to match the same CVE — one result
        result = match_cves_for_cpes(None, [
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",  # duplicate input
        ])
        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2021-23017"

    def test_multiple_distinct_cves(self, fake_query):
        result = match_cves_for_cpes(None, [
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        ])
        cve_ids = {cve["cve_id"] for cve in result}
        assert cve_ids == {"CVE-2021-23017", "CVE-2021-41773"}

    def test_unparseable_cpe_skipped_not_fatal(self, fake_query):
        result = match_cves_for_cpes(None, [
            "garbage",
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        ])
        assert len(result) == 1

    def test_query_exception_is_non_fatal(self, monkeypatch):
        """If _query_threat_intel_cves raises, matcher logs and continues."""
        import services.downstream_impact as di_mod

        def _raise(db, component, version, exclude_cve_ids):
            raise RuntimeError("DB exploded")

        monkeypatch.setattr(di_mod, "_query_threat_intel_cves", _raise)
        # Should not raise; should return []
        result = match_cves_for_cpes(None, [
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
        ])
        assert result == []

    def test_exclude_list_passed_between_calls(self, fake_query):
        """After finding a CVE on CPE 1, CPE 2's lookup should exclude it."""
        match_cves_for_cpes(None, [
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        ])
        # Second call should have received the first call's CVE in exclude_cve_ids
        assert len(fake_query) == 2
        assert "CVE-2021-23017" in fake_query[1][2]

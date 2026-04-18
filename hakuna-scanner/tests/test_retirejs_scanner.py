"""Tests for retirejs_scanner.

Focuses on the matching/version-resolution logic. The DB is the bundled
seed; tests must remain robust as the seed is refreshed (assert on
behavior, not exact CVE counts).
"""
from app.ingest.retirejs_scanner import (
    RetireHit,
    _parse_version,
    _worst_applicable_vuln,
    reload_db,
    scan_js_file,
)

# Make sure we test against the bundled DB, not stale cache from another test.
reload_db()


# ── _parse_version ──────────────────────────────────────────────


class TestParseVersion:
    def test_simple_semver(self):
        assert _parse_version("3.1.1") == (3, 1, 1)

    def test_two_part_version(self):
        assert _parse_version("1.7") == (1, 7)

    def test_drops_pre_release_suffix(self):
        # We don't compare pre-releases — close enough for vuln-range work.
        assert _parse_version("3.0.0-rc.2") == (3, 0, 0)
        assert _parse_version("1.2.3+build.42") == (1, 2, 3)

    def test_non_numeric_returns_none(self):
        assert _parse_version("alpha") is None

    def test_empty_returns_none(self):
        assert _parse_version("") is None


# ── _worst_applicable_vuln ──────────────────────────────────────


class TestWorstApplicableVuln:
    def _vulns(self):
        return [
            {"below": "1.6.3", "severity": "medium", "identifiers": {"CVE": ["CVE-A"]}},
            {"below": "3.0.0", "severity": "medium", "identifiers": {"CVE": ["CVE-B"]}},
            {"below": "3.4.0", "severity": "high", "identifiers": {"CVE": ["CVE-C"]}},
        ]

    def test_picks_highest_severity_among_applicable(self):
        out = _worst_applicable_vuln(self._vulns(), "1.5.0")
        # 1.5.0 is below all three → picks the high-severity one
        assert out["severity"] == "high"
        assert "CVE-C" in out["cves"]

    def test_returns_none_when_no_vuln_applies(self):
        # 4.0.0 is above all "below" thresholds
        assert _worst_applicable_vuln(self._vulns(), "4.0.0") is None

    def test_at_or_above_lower_bound(self):
        vulns = [
            {"below": "3.0.0", "atOrAbove": "2.0.0", "severity": "medium",
             "identifiers": {"CVE": ["CVE-X"]}},
        ]
        assert _worst_applicable_vuln(vulns, "1.0.0") is None  # below atOrAbove
        assert _worst_applicable_vuln(vulns, "2.5.0") is not None  # in range
        assert _worst_applicable_vuln(vulns, "3.5.0") is None  # above below


# ── scan_js_file ─────────────────────────────────────────────────


class TestScanJsFile:
    def test_jquery_detected_by_url(self):
        # Vulnerable jQuery 1.5.0 — should match the seed DB's <1.6.3 range
        hits = scan_js_file(
            "https://example.com/static/jquery-1.5.0.min.js",
            js_content=None,
        )
        jquery_hits = [h for h in hits if h.library == "jquery"]
        assert len(jquery_hits) == 1
        assert jquery_hits[0].version == "1.5.0"
        assert jquery_hits[0].detection_method == "uri"

    def test_jquery_detected_by_filecontent(self):
        body = "/*! jQuery JavaScript Library v1.7.2 — minified */\nvar a = 1;"
        hits = scan_js_file("https://example.com/lib.js", js_content=body)
        jquery_hits = [h for h in hits if h.library == "jquery"]
        assert jquery_hits, "filecontent matcher should detect jquery 1.7.2"
        assert jquery_hits[0].version == "1.7.2"
        assert jquery_hits[0].detection_method == "filecontent"

    def test_safe_jquery_version_no_hit(self):
        """jQuery 3.6.0 is above all known ranges → no finding."""
        hits = scan_js_file(
            "https://example.com/static/jquery-3.6.0.min.js",
            js_content=None,
        )
        assert not any(h.library == "jquery" for h in hits)

    def test_lodash_old_version_detected(self):
        hits = scan_js_file(
            "https://example.com/lodash-4.17.0.min.js",
            js_content=None,
        )
        lodash_hits = [h for h in hits if h.library == "lodash"]
        assert lodash_hits, "lodash 4.17.0 is below 4.17.5 (CVE-2018-3721)"
        assert any("CVE-2018-3721" in h.cves for h in lodash_hits)

    def test_unknown_library_no_hit(self):
        hits = scan_js_file(
            "https://example.com/some-random-lib-1.0.0.min.js",
            js_content=None,
        )
        assert hits == []

    def test_file_sha256_recorded(self):
        body = "/*! jQuery JavaScript Library v1.5.0 */\n"
        hits = scan_js_file("https://example.com/lib.js", js_content=body)
        assert hits and len(hits[0].file_sha256) == 64

    def test_to_dict_serializable(self):
        hits = scan_js_file(
            "https://example.com/jquery-1.5.0.min.js", js_content=None,
        )
        for h in hits:
            d = h.to_dict()
            assert isinstance(d["cves"], list)
            assert isinstance(d["info"], list)

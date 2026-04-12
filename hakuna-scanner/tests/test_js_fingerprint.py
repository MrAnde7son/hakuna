"""Unit tests for the JavaScript library fingerprinting module."""

import pytest

from app.ingest.js_fingerprint import (
    _ScriptExtractor,
    _match_content,
    _match_url,
    _resolve_script_urls,
    reload_db,
)

# Ensure patterns are loaded fresh (in case module was cached with stale DB).
reload_db()


# ---------------------------------------------------------------------------
# Script extractor (HTML parsing)
# ---------------------------------------------------------------------------


class TestScriptExtractor:
    def test_extracts_script_src(self):
        html = '<html><head><script src="/js/jquery-3.1.1.min.js"></script></head></html>'
        parser = _ScriptExtractor()
        parser.feed(html)
        assert parser.script_srcs == ["/js/jquery-3.1.1.min.js"]
        assert parser.inline_scripts == []

    def test_extracts_inline_script(self):
        html = '<html><body><script>var x = 1;</script></body></html>'
        parser = _ScriptExtractor()
        parser.feed(html)
        assert parser.script_srcs == []
        assert parser.inline_scripts == ["var x = 1;"]

    def test_extracts_both(self):
        html = (
            '<script src="app.js"></script>'
            '<script>console.log("hi");</script>'
        )
        parser = _ScriptExtractor()
        parser.feed(html)
        assert parser.script_srcs == ["app.js"]
        assert parser.inline_scripts == ['console.log("hi");']

    def test_multiple_srcs(self):
        html = (
            '<script src="a.js"></script>'
            '<script src="b.js"></script>'
            '<script src="c.js"></script>'
        )
        parser = _ScriptExtractor()
        parser.feed(html)
        assert len(parser.script_srcs) == 3


# ---------------------------------------------------------------------------
# URL matching
# ---------------------------------------------------------------------------


class TestUrlMatching:
    def test_jquery_with_version(self):
        results = _match_url("https://cdn.example.com/js/jquery-3.1.1.min.js")
        assert len(results) >= 1
        jquery = [r for r in results if r["name"] == "jQuery"]
        assert len(jquery) == 1
        assert jquery[0]["version"] == "3.1.1"
        assert jquery[0]["cpe_vendor"] == "jquery"
        assert jquery[0]["cpe_product"] == "jquery"

    def test_jquery_dot_separator(self):
        results = _match_url("/assets/jquery.3.6.0.min.js")
        jquery = [r for r in results if r["name"] == "jQuery"]
        assert len(jquery) == 1
        assert jquery[0]["version"] == "3.6.0"

    def test_jquery_ui(self):
        results = _match_url("/js/jquery-ui-1.12.1.min.js")
        ui = [r for r in results if r["name"] == "jQuery UI"]
        assert len(ui) == 1
        assert ui[0]["version"] == "1.12.1"

    def test_moment_js(self):
        results = _match_url("/vendor/moment-2.29.1.min.js")
        moment = [r for r in results if r["name"] == "Moment.js"]
        assert len(moment) == 1
        assert moment[0]["version"] == "2.29.1"

    def test_bootstrap(self):
        results = _match_url("https://cdn.jsdelivr.net/npm/bootstrap-5.3.2/dist/js/bootstrap.min.js")
        bs = [r for r in results if r["name"] == "Bootstrap"]
        assert len(bs) == 1
        assert bs[0]["version"] == "5.3.2"

    def test_fancybox(self):
        results = _match_url("/js/fancybox-3.5.7.min.js")
        fb = [r for r in results if r["name"] == "FancyBox"]
        assert len(fb) == 1
        assert fb[0]["version"] == "3.5.7"

    def test_no_match(self):
        results = _match_url("https://example.com/app.js")
        assert results == []

    def test_mustache(self):
        results = _match_url("/vendor/mustache-2.3.0.js")
        m = [r for r in results if r["name"] == "Mustache.js"]
        assert len(m) == 1
        assert m[0]["version"] == "2.3.0"

    def test_mediaelement(self):
        results = _match_url("/js/mediaelement-and-player-4.2.10.min.js")
        me = [r for r in results if r["name"] == "MediaElement.js"]
        assert len(me) == 1
        assert me[0]["version"] == "4.2.10"


# ---------------------------------------------------------------------------
# Content matching
# ---------------------------------------------------------------------------


class TestContentMatching:
    def test_jquery_banner(self):
        content = "/*! jQuery JavaScript Library v3.1.1 - jquery.com */\n(function(){"
        results = _match_content(content)
        jquery = [r for r in results if r["name"] == "jQuery"]
        assert len(jquery) == 1
        assert jquery[0]["version"] == "3.1.1"

    def test_jquery_fn_jquery(self):
        content = 'jQuery.fn.jquery = "3.6.0"; something else'
        results = _match_content(content)
        jquery = [r for r in results if r["name"] == "jQuery"]
        assert len(jquery) == 1
        assert jquery[0]["version"] == "3.6.0"

    def test_moment_version(self):
        content = 'moment.version = "2.29.1"; // Moment.js library'
        results = _match_content(content)
        moment = [r for r in results if r["name"] == "Moment.js"]
        assert len(moment) == 1
        assert moment[0]["version"] == "2.29.1"

    def test_bootstrap_banner(self):
        content = "/*! Bootstrap v5.3.2 (https://getbootstrap.com/) */"
        results = _match_content(content)
        bs = [r for r in results if r["name"] == "Bootstrap"]
        assert len(bs) == 1
        assert bs[0]["version"] == "5.3.2"

    def test_jquery_ui_banner(self):
        content = "/*! jQuery UI - v1.12.1 - 2016-09-14 */"
        results = _match_content(content)
        ui = [r for r in results if r["name"] == "jQuery UI"]
        assert len(ui) == 1
        assert ui[0]["version"] == "1.12.1"

    def test_angular_version(self):
        content = "/* AngularJS v1.8.3 (angular.min.js) */"
        results = _match_content(content)
        ang = [r for r in results if r["name"] == "Angular"]
        assert len(ang) == 1
        assert ang[0]["version"] == "1.8.3"

    def test_fancybox_banner(self):
        content = "// fancyBox v3.5.7\n// Licensed GPLv3"
        results = _match_content(content)
        fb = [r for r in results if r["name"] == "FancyBox"]
        assert len(fb) == 1
        assert fb[0]["version"] == "3.5.7"

    def test_no_match(self):
        content = "function init() { console.log('hello'); }"
        results = _match_content(content)
        assert results == []


# ---------------------------------------------------------------------------
# URL resolution
# ---------------------------------------------------------------------------


class TestResolveUrls:
    def test_absolute_url(self):
        urls = _resolve_script_urls(
            "https://example.com/page",
            ["https://cdn.example.com/jquery.js"],
        )
        assert urls == ["https://cdn.example.com/jquery.js"]

    def test_relative_url(self):
        urls = _resolve_script_urls(
            "https://example.com/page/index.html",
            ["/js/app.js"],
        )
        assert urls == ["https://example.com/js/app.js"]

    def test_protocol_relative(self):
        urls = _resolve_script_urls(
            "https://example.com/",
            ["//cdn.example.com/lib.js"],
        )
        assert urls == ["https://cdn.example.com/lib.js"]

    def test_relative_path(self):
        urls = _resolve_script_urls(
            "https://example.com/app/page.html",
            ["../js/vendor.js"],
        )
        assert urls == ["https://example.com/js/vendor.js"]

    def test_empty_src_skipped(self):
        urls = _resolve_script_urls("https://example.com/", ["", "  "])
        assert urls == []


# ---------------------------------------------------------------------------
# Tenable comparison: exact CPEs from the user's test case
# ---------------------------------------------------------------------------


class TestTenableComparison:
    """Verify we'd detect the same libraries Tenable found on ir.bookingholdings.com."""

    def test_fancybox_3_5_7_url(self):
        results = _match_url("/js/fancybox-3.5.7.min.js")
        assert any(r["cpe_vendor"] == "fancybox_project" and r["version"] == "3.5.7" for r in results)

    def test_mediaelement_4_2_10_content(self):
        content = "/*! MediaElement.js 4.2.10 */"
        results = _match_content(content)
        assert any(r["cpe_vendor"] == "mediaelementjs" and r["version"] == "4.2.10" for r in results)

    def test_moment_2_29_1_content(self):
        content = '//! moment.js\n//! version : 2.29.1'
        results = _match_content(content)
        assert any(r["cpe_vendor"] == "momentjs" and r["version"] == "2.29.1" for r in results)

    def test_mustache_2_3_0_content(self):
        content = '/*! mustache.js - Logic-less {{mustache}} templates - 2.3.0 */'
        results = _match_content(content)
        assert any(r["cpe_vendor"] == "mustache.js_project" and r["version"] == "2.3.0" for r in results)

    def test_jquery_3_1_1_url(self):
        results = _match_url("/js/jquery-3.1.1.min.js")
        assert any(r["cpe_vendor"] == "jquery" and r["version"] == "3.1.1" for r in results)

    def test_jquery_ui_1_12_1_url(self):
        results = _match_url("/js/jquery-ui-1.12.1.min.js")
        assert any(r["cpe_vendor"] == "jquery" and r["version"] == "1.12.1" for r in results)

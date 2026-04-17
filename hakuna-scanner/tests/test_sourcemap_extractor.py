"""Tests for sourcemap_extractor — the pure parsing logic.

The HTTP path (httpx interactions) is exercised indirectly; here we
focus on:
  - reconstruct_sources correctly projects a parsed sourcemap
  - The trailing comment regex picks up the canonical and alternative forms
"""
from app.ingest.sourcemap_extractor import (
    _SMURL_RE,
    RecoveredSource,
    reconstruct_sources,
)


# ── reconstruct_sources ─────────────────────────────────────────


class TestReconstructSources:
    def test_pairs_sources_with_contents(self):
        smap = {
            "version": 3,
            "sources": ["app/auth.js", "app/router.js"],
            "sourcesContent": [
                "function login() { /* ... */ }",
                "const routes = ['/admin', '/users'];",
            ],
        }
        out = reconstruct_sources(smap)
        assert len(out) == 2
        assert out[0].path == "app/auth.js"
        assert out[0].content.startswith("function login")
        assert out[1].path == "app/router.js"

    def test_null_sources_content_yields_empty_body(self):
        """sourcesContent[i] of null means the bundler didn't inline that
        source. The path is still useful intel — we keep the entry but
        with empty content."""
        smap = {
            "version": 3,
            "sources": ["external.js", "inlined.js"],
            "sourcesContent": [None, "var x = 1;"],
        }
        out = reconstruct_sources(smap)
        assert len(out) == 2
        assert out[0].is_present is False
        assert out[1].is_present is True

    def test_missing_sources_content_yields_empty_bodies(self):
        """Some sourcemaps omit sourcesContent entirely (rare). Treat all
        sources as path-only entries."""
        smap = {"version": 3, "sources": ["a.js", "b.js"]}
        out = reconstruct_sources(smap)
        assert len(out) == 2
        assert all(not s.is_present for s in out)

    def test_empty_sources_returns_empty(self):
        assert reconstruct_sources({"version": 3, "sources": []}) == []

    def test_non_string_source_path_skipped(self):
        smap = {"version": 3, "sources": ["good.js", 42, None]}
        out = reconstruct_sources(smap)
        assert [s.path for s in out] == ["good.js"]


# ── _SMURL_RE — the trailing sourceMappingURL comment ───────────


class TestSourceMappingURLRegex:
    def test_canonical_form(self):
        body = "var x=1;\n//# sourceMappingURL=app.js.map"
        m = _SMURL_RE.search(body)
        assert m and m.group(1) == "app.js.map"

    def test_at_symbol_legacy_form(self):
        body = "var x=1;\n//@ sourceMappingURL=https://cdn.example.com/app.js.map"
        m = _SMURL_RE.search(body)
        assert m and m.group(1) == "https://cdn.example.com/app.js.map"

    def test_block_comment_form(self):
        body = "var x=1;\n/*# sourceMappingURL=app.js.map */"
        m = _SMURL_RE.search(body)
        assert m and m.group(1) == "app.js.map"

    def test_no_match_when_absent(self):
        assert _SMURL_RE.search("var x=1;") is None

    def test_extra_whitespace_tolerated(self):
        body = "//#  sourceMappingURL  =  app.js.map"
        m = _SMURL_RE.search(body)
        assert m and m.group(1) == "app.js.map"


# ── RecoveredSource ─────────────────────────────────────────────


class TestRecoveredSource:
    def test_is_present_with_content(self):
        assert RecoveredSource(path="x.js", content="var x = 1;").is_present is True

    def test_is_present_without_content(self):
        assert RecoveredSource(path="x.js", content="").is_present is False

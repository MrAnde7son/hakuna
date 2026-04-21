"""Unit tests for app.ingest.http_header_audit."""

import pytest

from app.ingest.http_header_audit import (
    _parse_set_cookie,
    _audit_hsts,
    audit_response,
)


# ── HSTS ───────────────────────────────────────────────────────────────────


class TestAuditHsts:
    def test_missing_on_https_is_flagged(self):
        result = _audit_hsts(None, is_https=True)
        assert result == {"present": False, "required": True}

    def test_missing_on_http_is_not_required(self):
        result = _audit_hsts(None, is_https=False)
        assert result["required"] is False

    def test_strong_max_age(self):
        result = _audit_hsts("max-age=31536000; includeSubDomains", is_https=True)
        assert result["strong"] is True
        assert result["max_age"] == 31_536_000
        assert result["include_subdomains"] is True
        assert result["preload"] is False

    def test_short_max_age_not_strong(self):
        result = _audit_hsts("max-age=600", is_https=True)
        assert result["present"] is True
        assert result["strong"] is False
        assert result["max_age"] == 600

    def test_preload_flag_detected(self):
        result = _audit_hsts(
            "max-age=63072000; includeSubDomains; preload", is_https=True
        )
        assert result["preload"] is True
        assert result["strong"] is True


# ── Cookie parsing ─────────────────────────────────────────────────────────


class TestParseSetCookie:
    def test_all_flags_present(self):
        ck = _parse_set_cookie("session=abc; Secure; HttpOnly; SameSite=Lax; Path=/")
        assert ck["name"] == "session"
        assert ck["secure"] is True
        assert ck["http_only"] is True
        assert ck["same_site"] == "Lax"
        assert ck["path"] == "/"

    def test_case_insensitive_flag_matching(self):
        ck = _parse_set_cookie("id=1; secure; httponly; samesite=strict")
        assert ck["secure"] is True
        assert ck["http_only"] is True
        assert ck["same_site"] == "strict"

    def test_missing_flags_are_false(self):
        ck = _parse_set_cookie("sid=xyz")
        assert ck["secure"] is False
        assert ck["http_only"] is False
        assert ck["same_site"] is None

    def test_empty_cookie_returns_empty_dict(self):
        assert _parse_set_cookie("") == {}


# ── End-to-end audit ───────────────────────────────────────────────────────


def _https_entry(headers: dict) -> dict:
    return {"final_url": "https://example.com/", "response_headers": headers}


class TestAuditResponse:
    def test_all_headers_present_on_https(self):
        audit = audit_response(
            _https_entry(
                {
                    "strict-transport-security": "max-age=31536000; includeSubDomains",
                    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                }
            )
        )
        # frame-ancestors in CSP satisfies clickjacking protection even
        # without X-Frame-Options.
        ids = {i["id"] for i in audit["issues"]}
        assert "hsts-missing" not in ids
        assert "csp-missing" not in ids
        assert "clickjacking-protection-missing" not in ids
        assert "content-type-sniffing" not in ids
        assert "referrer-policy-missing" not in ids

    def test_https_with_no_security_headers_flags_all(self):
        audit = audit_response(_https_entry({}))
        ids = {i["id"] for i in audit["issues"]}
        assert "hsts-missing" in ids
        assert "csp-missing" in ids
        assert "clickjacking-protection-missing" in ids
        assert "content-type-sniffing" in ids
        assert "referrer-policy-missing" in ids
        assert "permissions-policy-missing" in ids

    def test_http_does_not_require_hsts(self):
        audit = audit_response(
            {"final_url": "http://example.com/", "response_headers": {}}
        )
        ids = {i["id"] for i in audit["issues"]}
        assert "hsts-missing" not in ids
        # Other headers still missing, still flagged.
        assert "csp-missing" in ids

    def test_weak_hsts_is_low_severity(self):
        audit = audit_response(
            _https_entry({"strict-transport-security": "max-age=600"})
        )
        hsts_issues = [i for i in audit["issues"] if i["id"] == "hsts-weak"]
        assert len(hsts_issues) == 1
        assert hsts_issues[0]["severity"] == 1

    def test_xfo_alone_satisfies_clickjacking(self):
        audit = audit_response(
            _https_entry({"x-frame-options": "DENY"})
        )
        ids = {i["id"] for i in audit["issues"]}
        assert "clickjacking-protection-missing" not in ids

    def test_insecure_cookie_on_https_flagged(self):
        audit = audit_response(
            _https_entry({"set-cookie": ["session=abc; HttpOnly; SameSite=Lax"]})
        )
        ids = [i["id"] for i in audit["issues"]]
        assert "cookie-insecure" in ids

    def test_cookie_without_httponly_flagged(self):
        audit = audit_response(
            _https_entry(
                {"set-cookie": ["session=abc; Secure; SameSite=Lax"]}
            )
        )
        ids = [i["id"] for i in audit["issues"]]
        assert "cookie-not-httponly" in ids

    def test_samesite_none_without_secure(self):
        audit = audit_response(
            _https_entry(
                {"set-cookie": ["tracking=1; HttpOnly; SameSite=None"]}
            )
        )
        cookie_issues = [
            i for i in audit["issues"]
            if i["id"] == "cookie-samesite-none-insecure"
        ]
        assert len(cookie_issues) == 1
        assert cookie_issues[0]["severity"] == 2

    def test_multiple_set_cookie_list(self):
        audit = audit_response(
            _https_entry(
                {"set-cookie": [
                    "a=1; Secure; HttpOnly; SameSite=Lax",
                    "b=2",
                ]}
            )
        )
        assert len(audit["cookies"]) == 2
        names = {c["name"] for c in audit["cookies"]}
        assert names == {"a", "b"}

    def test_case_insensitive_header_names(self):
        audit = audit_response(
            _https_entry(
                {"Strict-Transport-Security": "max-age=31536000"}
            )
        )
        assert audit["security_headers"]["hsts"]["present"] is True

    def test_malformed_input_does_not_raise(self):
        # response_headers is a string (malformed) — module should tolerate.
        audit = audit_response(
            {"final_url": "https://example.com/", "response_headers": "not-a-dict"}
        )
        assert "security_headers" in audit
        assert audit["cookies"] == []

"""Security-header and cookie-flag audit over httpx JSON output.

Pure module. Takes one httpx -json entry, returns a structured audit:

    {
      "security_headers": { "hsts": {...}, "csp": {...}, ... },
      "cookies": [ { "name": ..., "secure": bool, "http_only": bool, ... } ],
      "issues": [ {"id": "...", "severity": "Medium", "detail": "..."} ],
    }

Policy thresholds follow OWASP Secure Headers Project + MDN guidance. Grading
lives here so the scanner can store a normalized view on the asset; finding
emission is layered on top in the backend (services/easm.py).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# ── Header-name normalization ──────────────────────────────────────────────
#
# httpx emits headers as a dict under `response_headers` (via `-include-response-header`
# or `-irh`). Keys are typically lowercased, but fall back to case-insensitive match
# to tolerate upstream changes and proxy rewrites.


def _get_header(headers: dict, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    for key, val in headers.items():
        if isinstance(key, str) and key.lower() == target:
            # httpx sometimes emits lists (for Set-Cookie) and sometimes strings.
            if isinstance(val, list):
                # Join for simple string headers; Set-Cookie is handled separately.
                return ", ".join(str(v) for v in val)
            return str(val)
    return None


def _get_set_cookies(headers: dict) -> list[str]:
    """Return every Set-Cookie value as its own string. httpx merges duplicates
    into a list; older builds join with a comma which is ambiguous (Expires
    contains commas) — callers should prefer the list form when available."""
    if not isinstance(headers, dict):
        return []
    for key, val in headers.items():
        if isinstance(key, str) and key.lower() == "set-cookie":
            if isinstance(val, list):
                return [str(v) for v in val]
            # Single string — don't split on comma (would break Expires).
            return [str(val)]
    return []


# ── HSTS ───────────────────────────────────────────────────────────────────

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_HSTS_MIN_SECONDS = 31_536_000  # 1 year — OWASP + Chromium preload minimum


def _audit_hsts(value: str | None, is_https: bool) -> dict:
    if not is_https:
        return {"present": False, "required": False}
    if not value:
        return {"present": False, "required": True}

    max_age_match = _HSTS_MAX_AGE_RE.search(value)
    max_age = int(max_age_match.group(1)) if max_age_match else None
    include_sub = "includesubdomains" in value.lower().replace("-", "")
    preload = "preload" in value.lower()

    return {
        "present": True,
        "required": True,
        "max_age": max_age,
        "include_subdomains": include_sub,
        "preload": preload,
        "strong": bool(max_age and max_age >= _HSTS_MIN_SECONDS),
    }


# ── Cookie parsing ─────────────────────────────────────────────────────────


def _parse_set_cookie(raw: str) -> dict:
    """Parse one Set-Cookie header into {name, value, secure, http_only, same_site, ...}.

    Intentionally tolerant — servers emit malformed cookies all the time, and
    a missing flag is *itself* the signal we're looking for.
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return {}

    name_value = parts[0]
    name, _, value = name_value.partition("=")
    cookie: dict[str, Any] = {
        "name": name.strip(),
        "has_value": bool(value),
        "secure": False,
        "http_only": False,
        "same_site": None,
    }

    for attr in parts[1:]:
        lower = attr.lower()
        if lower == "secure":
            cookie["secure"] = True
        elif lower == "httponly":
            cookie["http_only"] = True
        elif lower.startswith("samesite"):
            _, _, ss = attr.partition("=")
            cookie["same_site"] = ss.strip() or None
        elif lower.startswith("domain="):
            cookie["domain"] = attr.split("=", 1)[1].strip()
        elif lower.startswith("path="):
            cookie["path"] = attr.split("=", 1)[1].strip()

    return cookie


# ── Main entry point ───────────────────────────────────────────────────────


def _is_https(url: str | None) -> bool:
    if not url:
        return False
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False


def audit_response(httpx_entry: dict) -> dict:
    """Produce the normalized security-audit dict for one httpx JSON line.

    Caller writes the result into ``asset_enrichments.httpx_full.security_audit``
    so the backend can read it without a schema change.
    """
    headers = (
        httpx_entry.get("response_headers")
        or httpx_entry.get("header")
        or httpx_entry.get("headers")
        or {}
    )
    url = httpx_entry.get("final_url") or httpx_entry.get("url") or ""
    is_https = _is_https(url)

    # Security headers
    hsts = _audit_hsts(_get_header(headers, "strict-transport-security"), is_https)
    csp_raw = _get_header(headers, "content-security-policy")
    xfo = _get_header(headers, "x-frame-options")
    xcto = _get_header(headers, "x-content-type-options")
    referrer = _get_header(headers, "referrer-policy")
    permissions = _get_header(headers, "permissions-policy")

    csp = {
        "present": bool(csp_raw),
        # Report-Only is advisory — callers can grade separately if desired.
        "report_only": bool(_get_header(headers, "content-security-policy-report-only")),
        "has_frame_ancestors": bool(csp_raw and "frame-ancestors" in csp_raw.lower()),
    }

    security_headers = {
        "hsts": hsts,
        "csp": csp,
        "x_frame_options": {"present": bool(xfo), "value": xfo},
        "x_content_type_options": {
            "present": bool(xcto),
            "nosniff": bool(xcto and xcto.strip().lower() == "nosniff"),
        },
        "referrer_policy": {"present": bool(referrer), "value": referrer},
        "permissions_policy": {"present": bool(permissions), "value": permissions},
    }

    # Cookies
    cookies = [_parse_set_cookie(c) for c in _get_set_cookies(headers) if c]
    cookies = [c for c in cookies if c.get("name")]

    # Derive issues. Severity tiers follow the TLS-weak precedent in easm.py:
    # Critical (4), High (3), Medium (2), Low (1), Info (0).
    issues: list[dict] = []

    if is_https:
        if not hsts["present"]:
            issues.append({"id": "hsts-missing", "severity": 2, "detail": "Strict-Transport-Security header is missing on HTTPS response"})
        elif not hsts.get("strong"):
            max_age = hsts.get("max_age")
            issues.append({
                "id": "hsts-weak",
                "severity": 1,
                "detail": f"HSTS max-age is {max_age or 'unset'} (<1 year); browsers may not enforce HTTPS across sessions",
            })

    if not csp["present"]:
        issues.append({"id": "csp-missing", "severity": 2, "detail": "Content-Security-Policy header is missing"})
    if not security_headers["x_frame_options"]["present"] and not csp["has_frame_ancestors"]:
        issues.append({"id": "clickjacking-protection-missing", "severity": 2, "detail": "Neither X-Frame-Options nor CSP frame-ancestors is set; page may be embeddable in iframes"})
    if not security_headers["x_content_type_options"]["nosniff"]:
        issues.append({"id": "content-type-sniffing", "severity": 1, "detail": "X-Content-Type-Options: nosniff is missing"})
    if not security_headers["referrer_policy"]["present"]:
        issues.append({"id": "referrer-policy-missing", "severity": 1, "detail": "Referrer-Policy header is missing"})
    if not security_headers["permissions_policy"]["present"]:
        issues.append({"id": "permissions-policy-missing", "severity": 0, "detail": "Permissions-Policy header is missing (advisory)"})

    for ck in cookies:
        name = ck.get("name", "")
        if is_https and not ck.get("secure"):
            issues.append({"id": "cookie-insecure", "severity": 2, "detail": f"Cookie '{name}' lacks Secure flag on HTTPS response"})
        if not ck.get("http_only"):
            issues.append({"id": "cookie-not-httponly", "severity": 1, "detail": f"Cookie '{name}' lacks HttpOnly flag"})
        same_site = (ck.get("same_site") or "").lower()
        if not same_site:
            issues.append({"id": "cookie-samesite-missing", "severity": 1, "detail": f"Cookie '{name}' has no SameSite attribute"})
        elif same_site == "none" and not ck.get("secure"):
            # SameSite=None without Secure is rejected by modern browsers,
            # but some servers emit it anyway — flag as Medium.
            issues.append({"id": "cookie-samesite-none-insecure", "severity": 2, "detail": f"Cookie '{name}' has SameSite=None without Secure"})

    return {
        "url": url,
        "is_https": is_https,
        "security_headers": security_headers,
        "cookies": cookies,
        "issues": issues,
    }

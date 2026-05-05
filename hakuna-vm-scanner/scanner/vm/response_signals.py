"""Deterministic response-signature extractor.

Runs after every ``http_request`` tool call. Pulls structured facts out
of the response and emits them as typed capabilities so specialists see
a maintained app-model in their CAPABILITIES block instead of having to
re-derive framework/routing/validation behaviour from raw bytes on
every prompt turn.

Five signal classes today:

  - FRAMEWORK         — server stack inferred from headers, cookies, body chrome
  - WEB_ROOT          — absolute filesystem path leaked in a stack trace
  - ROUTE_TEMPLATE    — "this path/method exists and returned <status>"
  - PARAM_REFLECTION  — a param value sent in the request appears in the response
  - VALIDATION_RULE   — a 4xx body shaped like a known validator's error format

Cheap and bounded: each extractor is regex/dict-driven, runs in O(body)
once, and emits at most a handful of capabilities per response. The
capability store dedups by canonical value so re-probing the same
endpoint twenty times does not balloon the prompt.

Provenance is tagged ``signal:{specialist}`` so audit trails show which
specialist's probe surfaced the fact — useful for "why did the scan
choose this chain?" reviews.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from scanner.vm.capabilities import (
    Capability,
    CapabilityStore,
    CapabilityType,
    asset_scope,
)

logger = logging.getLogger(__name__)


# ── Framework fingerprints ───────────────────────────────────────
# Each tuple: (cookie-name regex, framework name, language). Cookie
# names are the highest-precision signal — a server can spoof headers,
# but framework-default cookie names are rarely customised.
_COOKIE_FRAMEWORK = [
    (re.compile(r"^laravel_session$", re.I),     "laravel",   "php"),
    (re.compile(r"^XSRF-TOKEN$"),                "laravel",   "php"),  # also Angular default
    (re.compile(r"^PHPSESSID$", re.I),           "php",       "php"),
    (re.compile(r"^JSESSIONID$"),                "java",      "java"),
    (re.compile(r"^connect\.sid$"),              "express",   "nodejs"),
    (re.compile(r"^session$", re.I),             "flask",     "python"),
    (re.compile(r"^csrftoken$"),                 "django",    "python"),
    (re.compile(r"^sessionid$"),                 "django",    "python"),
    (re.compile(r"^_session_id$"),               "rails",     "ruby"),
    (re.compile(r"^_csrf_token$"),               "rails",     "ruby"),
    (re.compile(r"^ASP\.NET_SessionId$", re.I),  "aspnet",    "csharp"),
    (re.compile(r"^\.AspNetCore\.", re.I),       "aspnetcore","csharp"),
    (re.compile(r"^ci_session$", re.I),          "codeigniter", "php"),
    (re.compile(r"^symfony$", re.I),             "symfony",   "php"),
]

# (header name (lowercased), value-regex, framework, language). header-derived
# framework hints have lower confidence than cookies because reverse proxies
# routinely strip or rewrite them.
_HEADER_FRAMEWORK = [
    ("x-powered-by", re.compile(r"PHP/?\s*(\S+)?", re.I),     "php",     "php"),
    ("x-powered-by", re.compile(r"Express", re.I),            "express", "nodejs"),
    ("x-powered-by", re.compile(r"ASP\.NET",  re.I),          "aspnet",  "csharp"),
    ("x-powered-by", re.compile(r"Next\.js",  re.I),          "nextjs",  "nodejs"),
    ("x-aspnet-version", re.compile(r".+"),                   "aspnet",  "csharp"),
    ("x-aspnetmvc-version", re.compile(r".+"),                "aspnet-mvc","csharp"),
    ("x-django-version", re.compile(r".+"),                   "django",  "python"),
    ("x-rails-version", re.compile(r".+"),                    "rails",   "ruby"),
    ("server",        re.compile(r"gunicorn",   re.I),        "wsgi",    "python"),
    ("server",        re.compile(r"uvicorn",    re.I),        "asgi",    "python"),
    ("server",        re.compile(r"puma",       re.I),        "puma",    "ruby"),
    ("server",        re.compile(r"unicorn",    re.I),        "unicorn", "ruby"),
    ("server",        re.compile(r"Microsoft-IIS", re.I),     "iis",     "csharp"),
    ("server",        re.compile(r"kestrel",    re.I),        "kestrel", "csharp"),
    ("server",        re.compile(r"tomcat",     re.I),        "tomcat",  "java"),
]

# Body-chrome patterns. Lowest confidence (a stub error page can be
# attacker-controlled), but useful when no headers are leaking framework
# info — common behind sanitising reverse proxies.
_BODY_FRAMEWORK = [
    (re.compile(r"Whoops, looks like something went wrong"),   "laravel",  "php"),
    (re.compile(r"You are seeing this error because you have DEBUG\s*=\s*True"), "django", "python"),
    (re.compile(r"ActionController::"),                        "rails",    "ruby"),
    (re.compile(r"<title>Werkzeug Debugger</title>"),          "flask",    "python"),
    (re.compile(r"FastAPI"),                                   "fastapi",  "python"),
    (re.compile(r"<title>Welcome to nginx"),                   "nginx",    None),
    (re.compile(r"Powered by\s*<a [^>]*>WordPress"),           "wordpress","php"),
]


def _parse_set_cookie_names(headers: dict) -> list[str]:
    """Extract cookie names from a Set-Cookie header. httpx flattens repeats
    into a comma-joined string, which is fine — we only need names, and
    cookie names cannot contain commas/semicolons."""
    raw = ""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            raw = value or ""
            break
    if not raw:
        return []
    names: list[str] = []
    for chunk in re.split(r",(?=[^;]*=)", raw):
        # First token before '=' is the cookie name; ignore attributes.
        name_part = chunk.split("=", 1)[0].strip()
        if name_part and "=" not in name_part:
            names.append(name_part)
    return names


def _detect_framework_from_response(
    headers: dict, body: str,
) -> list[tuple[str, str | None, str, float, str]]:
    """Return list of (name, language, evidence, confidence, version_or_none)."""
    out: list[tuple[str, str | None, str, float, str]] = []
    seen: set[str] = set()

    # Cookie-name match: highest confidence (0.9). Frameworks rarely
    # rename their default session cookie, so a JSESSIONID is essentially
    # a Java tomcat-class server.
    for name in _parse_set_cookie_names(headers):
        for rx, fw, lang in _COOKIE_FRAMEWORK:
            if rx.match(name) and fw not in seen:
                out.append((fw, lang, f"cookie:{name}", 0.9, ""))
                seen.add(fw)

    # Header match: 0.7. Reverse proxies (nginx, ALB) routinely strip
    # X-Powered-By so absence is uninformative; presence is reliable.
    for hk, rx, fw, lang in _HEADER_FRAMEWORK:
        v = headers.get(hk) or headers.get(hk.lower()) or ""
        if not v:
            continue
        m = rx.search(v)
        if m and fw not in seen:
            version = ""
            if m.groups():
                version = (m.group(1) or "").strip()
            out.append((fw, lang, f"header:{hk}", 0.7, version))
            seen.add(fw)

    # Body chrome: 0.5. Any debug-page string can be attacker-mimicked,
    # but combined with the request that triggered it (usually an
    # error oracle probe), it's still a strong hint.
    if body:
        for rx, fw, lang in _BODY_FRAMEWORK:
            if rx.search(body) and fw not in seen:
                out.append((fw, lang, "body_chrome", 0.5, ""))
                seen.add(fw)

    return out


# ── Stack-trace / web-root extraction ────────────────────────────
# Order matters — PHP-specific runs before generic absolute path so we
# don't tag every Linux path as "no framework".

_STACKTRACE_PATTERNS = [
    # Python: File "/path/to/file.py", line 42
    (re.compile(r'File "(/[^"\n]+\.py)", line \d+'),                "python"),
    # PHP fatal: ... in /path/to/file.php on line 42 (and the :LINE form)
    (re.compile(r' in (/[^\s:]+\.php)(?:\s+on line \d+|:\d+)'),      "php"),
    # Java: at com.foo.Bar(File.java:42) — class names hint stack but no
    # filesystem path, so we don't extract WEB_ROOT here.
    (re.compile(r'at\s+(?:[\w$]+\.)+[\w$]+\([^)]*\.java:\d+\)'),     "java"),
    # Ruby/Rails: from /path/to/file.rb:42:in `method`
    (re.compile(r'from\s+(/[^:\s]+\.rb):\d+:in '),                   "ruby"),
    # Node: at /path/to/file.js:42:11
    (re.compile(r'at\s+(/[^:\s]+\.(?:js|ts|mjs)):\d+:\d+'),          "nodejs"),
]


def _extract_web_root(body: str) -> tuple[str, str] | None:
    """Return (absolute_path, language_hint) from the first stack-trace match."""
    if not body:
        return None
    for rx, lang in _STACKTRACE_PATTERNS:
        m = rx.search(body)
        if m and m.groups():
            path = m.group(1)
            # Strip filename → directory. /var/www/app/index.php → /var/www/app
            root = path.rsplit("/", 1)[0]
            if root.startswith("/") and len(root) > 1:
                return root, lang
    return None


# ── Reflection detection ─────────────────────────────────────────


def _request_param_pairs(url: str, body: Any) -> list[tuple[str, str]]:
    """Collect (name, value) pairs the request actually carried.

    Skips short / boolean-like values: ``id=1`` reflects on virtually
    every endpoint and is noise. Threshold of 3 chars trades a small
    amount of recall for a major precision win.
    """
    pairs: list[tuple[str, str]] = []
    try:
        qs = urlparse(url).query
    except Exception:
        qs = ""
    if qs:
        for k, v in parse_qsl(qs, keep_blank_values=False):
            if v and len(v) >= 3:
                pairs.append((k, v))

    if isinstance(body, dict):
        for k, v in body.items():
            if isinstance(v, str) and len(v) >= 3:
                pairs.append((k, v))
            elif isinstance(v, (int, float)) and len(str(v)) >= 3:
                pairs.append((k, str(v)))
    elif isinstance(body, str) and "=" in body and "&" in body:
        # form-urlencoded
        for k, v in parse_qsl(body, keep_blank_values=False):
            if v and len(v) >= 3:
                pairs.append((k, v))

    return pairs


def _detect_reflection(
    url: str, body: Any, response_body: str, response_headers: dict,
) -> list[tuple[str, str, str]]:
    """Return list of (param_name, location, encoding) for each reflected param.

    location ∈ {"body", "header"}; encoding ∈ {"raw", "html", "url", "json"}.
    Order is request order; capability dedup collapses duplicates from
    re-probes.
    """
    if not response_body and not response_headers:
        return []

    out: list[tuple[str, str, str]] = []
    for name, value in _request_param_pairs(url, body):
        # Cheapest check first: raw substring in body. Most reflections
        # are raw — XSS sinks, error messages echoing input, etc.
        if response_body and value in response_body:
            out.append((name, "body", "raw"))
            continue
        # HTML-escaped form (the common XSS-mitigation case — lets us
        # know the param IS reflected even though the encoded form is
        # safe by default; useful for filter-bypass exploration).
        html_form = (value
                     .replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
        if html_form != value and response_body and html_form in response_body:
            out.append((name, "body", "html"))
            continue
        # JSON-escaped (quote-wrapped) — APIs that echo input back as a
        # JSON string field do this.
        json_form = json.dumps(value)
        if json_form != value and response_body and json_form in response_body:
            out.append((name, "body", "json"))
            continue
        # Header reflection — Location, Set-Cookie value, custom echo
        # headers. These are interesting for header-injection / open-
        # redirect classes.
        for hk, hv in (response_headers or {}).items():
            if value in str(hv):
                out.append((name, "header", "raw"))
                break

    return out


# ── Validation-error fingerprints ────────────────────────────────


def _detect_validation_rules(
    status: int, response_body: str,
) -> list[tuple[str | None, str]]:
    """Parse a 4xx body for known validator shapes.

    Returns list of (param_name, rule_text). Param can be None when the
    error talks about the request as a whole rather than a specific
    field (e.g., "Invalid JSON").
    """
    if status is None or status < 400 or status >= 500:
        return []
    if not response_body:
        return []

    out: list[tuple[str | None, str]] = []

    # Try JSON parse first — the cheapest, most common validator shape.
    try:
        parsed = json.loads(response_body)
    except (TypeError, ValueError):
        parsed = None

    if isinstance(parsed, dict):
        # FastAPI / Pydantic: {"detail": [{"loc": [...], "msg": ..., "type": ...}, ...]}
        detail = parsed.get("detail")
        if isinstance(detail, list):
            for item in detail[:10]:
                if not isinstance(item, dict):
                    continue
                loc = item.get("loc") or []
                msg = item.get("msg") or ""
                err_type = item.get("type") or ""
                # loc is ["body", "field_name"] or ["query", "name"], etc.
                param = None
                if isinstance(loc, list) and len(loc) >= 2:
                    param = str(loc[-1])
                rule = f"{err_type}: {msg}".strip(": ").strip()
                if rule:
                    out.append((param, rule))

        # Django REST / DRF: {"field": ["msg1", "msg2"], ...}
        # Heuristic: shallow object whose values are list-of-str.
        if not out:
            for k, v in parsed.items():
                if k in ("detail", "errors", "message"):
                    continue
                if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                    out.append((k, v[0][:200]))

        # Rails: {"errors": {"field": ["msg"]}}
        errors = parsed.get("errors")
        if isinstance(errors, dict) and not out:
            for k, v in errors.items():
                if isinstance(v, list) and v and isinstance(v[0], str):
                    out.append((str(k), v[0][:200]))

    # Body-text patterns when JSON parse fails or didn't yield specifics.
    # Bounded: only the first 2 matches per body so a verbose stack trace
    # doesn't fill the cap.
    if not out:
        for rx, label in _PLAIN_VALIDATION_PATTERNS:
            m = rx.search(response_body)
            if m:
                out.append((None, label))
                if len(out) >= 2:
                    break

    return out


_PLAIN_VALIDATION_PATTERNS = [
    (re.compile(r"Unexpected token .* in JSON", re.I),    "malformed_json"),
    (re.compile(r"Method Not Allowed", re.I),             "method_not_allowed"),
    (re.compile(r"Unsupported Media Type", re.I),         "unsupported_media_type"),
    (re.compile(r"Request Entity Too Large", re.I),       "payload_too_large"),
]


# ── Public entry point ───────────────────────────────────────────


def extract_signals(
    *,
    method: str,
    url: str,
    request_body: Any,
    response: dict,
    asset_id: str,
    provenance: str = "signal:http",
) -> list[Capability]:
    """Build capabilities from a single (request, response) pair.

    Pure function: returns capabilities, does NOT mutate any store. The
    caller decides whether to commit (the request handler does; tests
    inspect the list directly). Empty list when nothing matched —
    callers can ``store.add`` unconditionally over the result.
    """
    if not isinstance(response, dict):
        return []

    status = response.get("status_code")
    headers = response.get("headers") or {}
    body = response.get("body") or ""
    # Lowercase header dict so detectors don't have to retry casing.
    norm_headers = {str(k).lower(): v for k, v in headers.items()}

    scope = asset_scope(asset_id)
    caps: list[Capability] = []

    # ROUTE_TEMPLATE: every probed endpoint is a fact about what the
    # server exposes. Scoped to the path (not the full URL) so re-probes
    # with different query strings collapse into one row. Skip
    # connection-error responses — a 0/None status doesn't tell us the
    # route exists.
    try:
        path = urlparse(url).path or "/"
    except Exception:
        path = "/"
    if isinstance(status, int) and status > 0 and path:
        caps.append(Capability(
            type=CapabilityType.ROUTE_TEMPLATE,
            scope=scope,
            value={
                "path": path,
                "method": (method or "GET").upper(),
                "status": status,
            },
            confidence=0.8,
            provenance=provenance,
        ))

    # FRAMEWORK from headers/cookies/body chrome.
    for name, lang, evidence, conf, version in _detect_framework_from_response(
        norm_headers, body,
    ):
        value: dict[str, Any] = {"name": name, "evidence": evidence}
        if lang:
            value["language"] = lang
        if version:
            value["version"] = version
        caps.append(Capability(
            type=CapabilityType.FRAMEWORK,
            scope=scope,
            value=value,
            confidence=conf,
            provenance=provenance,
        ))

    # WEB_ROOT from stack trace. A path-disclosure leak is concrete and
    # high-leverage for LFI / SSTI — we already have a typed slot.
    web = _extract_web_root(body)
    if web:
        path_root, lang_hint = web
        value = {"path": path_root}
        if lang_hint:
            value["language"] = lang_hint
        caps.append(Capability(
            type=CapabilityType.WEB_ROOT,
            scope=scope,
            value=value,
            confidence=0.85,
            provenance=provenance,
        ))

    # PARAM_REFLECTION: every param value sent that comes back in the
    # response. Encoding tells the XSS specialist whether to chase
    # filter bypass (html-encoded), and tells injection that the input
    # actually reaches a sink (raw).
    for param, location, encoding in _detect_reflection(
        url, request_body, body, norm_headers,
    ):
        caps.append(Capability(
            type=CapabilityType.PARAM_REFLECTION,
            scope=scope,
            value={
                "endpoint": path,
                "param": param,
                "location": location,
                "encoding": encoding,
            },
            confidence=0.9,
            provenance=provenance,
        ))

    # VALIDATION_RULE: 4xx error shapes that disclose what the endpoint
    # checks for. Lets the LLM target probes that probe the *next* layer
    # rather than re-bouncing on the validator.
    for param, rule in _detect_validation_rules(status, body):
        value = {"endpoint": path, "rule": rule[:200], "rejected_with": status}
        if param:
            value["param"] = param
        caps.append(Capability(
            type=CapabilityType.VALIDATION_RULE,
            scope=scope,
            value=value,
            confidence=0.8,
            provenance=provenance,
        ))

    return caps


def commit_signals(
    capabilities: CapabilityStore, caps: list[Capability],
) -> int:
    """Add each capability to the store, return number actually inserted.

    Wraps the dedup loop so the request handler doesn't have to inline
    the bookkeeping. Failures (store full, dedup) are silent — the
    capability log is best-effort, never load-bearing for the request
    itself.
    """
    added = 0
    for cap in caps:
        try:
            if capabilities.add(cap):
                added += 1
        except Exception:  # pragma: no cover — defensive
            logger.exception("commit_signals: failed to add capability %s", cap.type)
    return added


__all__ = [
    "commit_signals",
    "extract_signals",
]

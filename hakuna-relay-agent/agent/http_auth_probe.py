"""Credentialed HTTP probe for the Hakuna relay agent.

Single relay method (``http_auth_probe``) used to fingerprint and audit
web admin panels exposed by network devices that aren't covered by the
SSH/WMI/SNMP families — IP cameras, network printers, IP phone provisioning
UIs, building-automation gateways, generic IoT admin consoles.

Operations
----------
- ``op="probe"``            — single HTTP request to a path; returns status,
                              headers, page title, server / product hints,
                              and a short body excerpt
- ``op="discover_admin"``   — try a fixed list of common admin paths; report
                              which respond, which redirect to login, which
                              are auth-required, and which are open

Auth schemes
------------
- HTTP Basic   (RFC 7617)  — ``{username, password}``
- HTTP Digest  (RFC 7616)  — ``{username, password}``
- Bearer token (RFC 6750)  — ``{token}``
- None (anonymous)         — credentials dict empty

All three are handled by httpx natively. The relay never follows redirects
to absolute external URLs (only same-origin), never executes JavaScript,
and never POSTs anything.

Result shape (per op)
---------------------
Both ops return:
    {
        "scheme": "http"|"https",
        "host": "...",
        "port": <int>,
        "auth_used": "none"|"basic"|"digest"|"bearer",
        <op-specific fields>,
        "_errors": {<key>: "..."}  # optional
    }
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 10
_BODY_EXCERPT_BYTES = 4096

# Paths probed by op="discover_admin". Kept short and well-known so the probe
# is cheap and predictable. Hardcoded at the relay — backend cannot supply
# arbitrary paths (defense in depth against prompt injection).
_ADMIN_PATHS = (
    # Generic
    "/", "/login", "/admin", "/admin/login", "/index.html", "/index.htm",
    # Printers / MFPs (IPP, JetDirect web UI, EWS)
    "/hp/device/this.LCDispatcher", "/web/guest/en/websys/webArch/header.cgi",
    "/general/status.htm",
    # IP cameras
    "/onvif/device_service", "/cgi-bin/snapshot.cgi", "/axis-cgi/usergroup.cgi",
    "/doc/page/login.asp", "/ISAPI/Security/userCheck",
    # IP phones (provisioning / web admin)
    "/servlet/main", "/Polycom_VVX", "/CGI/Java/Serviceability",
    # Building / IoT
    "/cwmpWeb/admin", "/cgi-bin/luci", "/setup.cgi",
)

# Title and product fingerprint patterns. Order matters — first match wins
# so vendor-specific patterns sit before generic web-server banners.
# Product fingerprint patterns. Each entry is (regex, label). Order matters —
# vendor-specific patterns sit before generic vendor catch-alls so e.g. an
# Axis camera is labeled axis_camera, not the bare vendor name. Patterns use
# bounded gaps (.{0,80}) between vendor and product noun so model numbers in
# between (e.g. "Axis P1448-LE Network Camera") don't break the match.
_PRODUCT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\baxis\b.{0,80}\b(?:network\s+)?camera\b", "axis_camera"),
    (r"\bhikvision\b|isapi/security", "hikvision_camera"),
    (r"\bdahua\b.{0,80}\b(?:web|technology|camera|dvr|nvr)\b", "dahua_camera"),
    (r"\bhp\b.{0,80}\b(?:laserjet|officejet|deskjet)\b|\bjetdirect\b", "hp_printer"),
    (r"\bxerox\b.{0,80}\b(?:workcentre|versalink|altalink|phaser)\b", "xerox_printer"),
    (r"\bcanon\b.{0,80}\b(?:imageclass|imagerunner|pixma|maxify)\b", "canon_printer"),
    (r"\bbrother\b.{0,80}\b(?:mfc|hl-|dcp-)\b", "brother_printer"),
    (r"\bricoh\b.{0,80}\b(?:aficio|mp|im|sp)\b", "ricoh_printer"),
    (r"\bkyocera\b.{0,80}\b(?:ecosys|taskalfa)\b", "kyocera_printer"),
    (r"\bpolycom\b.{0,80}\b(?:vvx|trio|soundpoint)\b|\bpoly\b.{0,80}\b(?:ccx|vvx)\b", "polycom_phone"),
    (r"\byealink\b", "yealink_phone"),
    (r"\bgrandstream\b", "grandstream_phone"),
    (r"\bcisco\b.{0,80}\bip\s+phone\b|\bcp-\d{4}\b", "cisco_phone"),
    (r"\bcrestron\b", "crestron_iot"),
    (r"\bmeraki\b", "meraki_device"),
    (r"\bunifi\b", "unifi_device"),
    (r"\bfortigate\b|\bforti(?:web|mail|switch|ap)\b", "fortinet_device"),
    (r"\bpalo\s*alto\b", "paloalto_device"),
    (r"\bsonicwall\b", "sonicwall_device"),
)


class HttpProbeError(Exception):
    """Any HTTP probe failure surfaced back to the backend."""


# ── Handler ──────────────────────────────────────────────────────────


@register_method("http_auth_probe")
async def http_auth_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise HttpProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    scheme = (transport_config or {}).get("scheme") or _infer_scheme(port)
    op = (params or {}).get("op") or "probe"
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    auth, auth_label = _build_auth(credentials or {})
    base = _base_url(scheme, target, port)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise HttpProbeError(
            f"unknown http probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        result = await asyncio.wait_for(
            handler(base, auth, auth_label, op_params, timeout_s),
            timeout=timeout_s + 5,
        )
    except asyncio.TimeoutError:
        return {"scheme": scheme, "host": target, "port": port,
                "auth_used": auth_label,
                "_errors": {op: f"probe timed out after {timeout_s}s"}}

    result.setdefault("scheme", scheme)
    result.setdefault("host", target)
    result.setdefault("port", port)
    result.setdefault("auth_used", auth_label)
    return result


# ── Auth + URL helpers ───────────────────────────────────────────────


def _build_auth(creds: dict) -> tuple[Any, str]:
    """Return (httpx_auth_obj, label). Label flows back to the agent so it
    can tell whether the credential was actually used."""
    scheme = (creds.get("scheme") or creds.get("_auth_type") or "").lower()
    token = creds.get("token") or creds.get("bearer_token")
    username = creds.get("username")
    password = creds.get("password")

    if scheme == "bearer" or (token and not username):
        return _BearerAuth(token), "bearer"
    if scheme == "digest" and username:
        return httpx.DigestAuth(username, password or ""), "digest"
    if username:
        # httpx.BasicAuth always sends the header — works for both Basic
        # servers and any server that accepts a preflight basic challenge.
        return httpx.BasicAuth(username, password or ""), "basic"
    return None, "none"


class _BearerAuth(httpx.Auth):
    def __init__(self, token: str):
        self.token = token or ""

    def auth_flow(self, request):
        if self.token:
            request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


def _infer_scheme(port: int) -> str:
    if port in (443, 8443, 9443):
        return "https"
    return "http"


def _base_url(scheme: str, host: str, port: int) -> str:
    if not port or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _is_same_origin(base: str, location: str) -> bool:
    """httpx will follow relative redirects via ``follow_redirects=True``;
    for absolute Location headers we want same-origin only to avoid being
    redirected to attacker-controlled external hosts."""
    try:
        b = urlparse(base)
        # Allow relative redirects (no scheme/netloc).
        target = urlparse(urljoin(base + "/", location))
        if not target.netloc:
            return True
        return (target.scheme == b.scheme and target.netloc == b.netloc)
    except Exception:
        return False


# ── op: probe ────────────────────────────────────────────────────────


async def _op_probe(base: str, auth: Any, auth_label: str,
                    op_params: dict, timeout_s: int) -> dict:
    """Fetch a single path. Returns status, headers, title, fingerprint, body excerpt."""
    path = op_params.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    method = (op_params.get("method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        return {"_errors": {"probe": f"method {method!r} not allowed; only GET/HEAD"}}

    url = base + path
    try:
        async with httpx.AsyncClient(
            timeout=timeout_s,
            verify=False,                  # admin UIs commonly use self-signed certs
            follow_redirects=False,        # we handle redirect classification ourselves
            trust_env=False,
        ) as client:
            resp = await client.request(method, url, auth=auth)
    except httpx.RequestError as e:
        return {"_errors": {"probe": f"{type(e).__name__}: {e}"}}

    return _shape_response(resp, method=method, path=path, auth_label=auth_label)


# ── op: discover_admin ───────────────────────────────────────────────


async def _op_discover_admin(base: str, auth: Any, auth_label: str,
                             op_params: dict, timeout_s: int) -> dict:
    """Try a fixed list of common admin paths in parallel and classify
    each: ``open`` (200 no auth header), ``auth_required`` (401/403),
    ``redirected_to_login`` (302/303 to a login page), ``not_found``,
    ``error``. Returns one summary entry per path."""
    per_request_timeout = max(2, min(timeout_s, 5))

    async with httpx.AsyncClient(
        timeout=per_request_timeout,
        verify=False,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async def _probe_one(path: str) -> dict:
            url = base + path
            try:
                resp = await client.get(url, auth=auth)
            except httpx.RequestError as e:
                return {"path": path, "classification": "error",
                        "error": f"{type(e).__name__}: {e}"}
            return {
                "path": path,
                "status": resp.status_code,
                "classification": _classify_admin_response(resp),
                "title": _extract_title(resp.text),
                "server": resp.headers.get("server") or "",
                "auth_header": resp.headers.get("www-authenticate", "")[:128],
                "location": resp.headers.get("location", "") if resp.is_redirect else "",
            }

        results = await asyncio.gather(*[_probe_one(p) for p in _ADMIN_PATHS])

    summary = {
        "total": len(results),
        "open": [r for r in results if r["classification"] == "open"],
        "auth_required": [r for r in results if r["classification"] == "auth_required"],
        "redirected_to_login": [r for r in results if r["classification"] == "redirected_to_login"],
        "other": [r for r in results
                  if r["classification"] not in ("open", "auth_required",
                                                 "redirected_to_login", "not_found", "error")],
        "results": results,
    }
    return summary


# ── Response classification ──────────────────────────────────────────


def _classify_admin_response(resp: httpx.Response) -> str:
    status = resp.status_code
    if status in (401, 403):
        return "auth_required"
    if status in (301, 302, 303, 307, 308):
        location = (resp.headers.get("location") or "").lower()
        if any(hint in location for hint in ("login", "signin", "auth", "sso")):
            return "redirected_to_login"
        return "redirected"
    if status == 404:
        return "not_found"
    if 200 <= status < 300:
        # 200 with a WWW-Authenticate header is still effectively auth-required
        # (some devices serve a 200 page that prompts via JS).
        if resp.headers.get("www-authenticate"):
            return "auth_required"
        return "open"
    if 500 <= status < 600:
        return "server_error"
    return "other"


# ── Response shaping ─────────────────────────────────────────────────


def _shape_response(resp: httpx.Response, *, method: str, path: str,
                    auth_label: str) -> dict:
    body_text = resp.text if method == "GET" else ""
    fingerprint = _fingerprint(resp, body_text)
    return {
        "path": path,
        "method": method,
        "status": resp.status_code,
        "classification": _classify_admin_response(resp),
        "server": resp.headers.get("server", ""),
        "content_type": resp.headers.get("content-type", ""),
        "content_length": int(resp.headers.get("content-length") or 0) or None,
        "title": _extract_title(body_text),
        "location": resp.headers.get("location") if resp.is_redirect else None,
        "auth_header": resp.headers.get("www-authenticate", "")[:128],
        "fingerprint": fingerprint,
        "body_excerpt": _excerpt(body_text),
        "auth_used": auth_label,
    }


def _excerpt(body: str) -> str:
    if not body:
        return ""
    if len(body) <= _BODY_EXCERPT_BYTES:
        return body
    return body[:_BODY_EXCERPT_BYTES] + "...[truncated]"


_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,400})</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(body: str) -> str:
    if not body:
        return ""
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    title = m.group(1).strip()
    return re.sub(r"\s+", " ", title)[:200]


def _fingerprint(resp: httpx.Response, body_text: str) -> str | None:
    """Single-string device hint. Looks at Server header + page title + first
    chunk of body. Returns ``None`` if no pattern matches."""
    haystack_parts = [
        resp.headers.get("server", ""),
        _extract_title(body_text),
        resp.headers.get("www-authenticate", ""),
        body_text[:1024] if body_text else "",
    ]
    haystack = " ".join(haystack_parts).lower()
    if not haystack.strip():
        return None
    for pattern, label in _PRODUCT_PATTERNS:
        if re.search(pattern, haystack):
            return label
    return None


_OP_HANDLERS = {
    "probe": _op_probe,
    "discover_admin": _op_discover_admin,
}


__all__ = [
    "HttpProbeError",
    "http_auth_probe_handler",
    "_ADMIN_PATHS",
    "_PRODUCT_PATTERNS",
]

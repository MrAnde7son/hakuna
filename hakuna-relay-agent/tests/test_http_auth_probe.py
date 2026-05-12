"""Unit tests for agent.http_auth_probe.

httpx is mocked at the AsyncClient layer so we exercise:
  - op allowlist (rejects unknown ops)
  - URL building (scheme inference, port omitted for default ports)
  - Auth shape selection (none → basic → digest → bearer)
  - Response classification (open / auth_required / redirected_to_login / not_found)
  - Product fingerprint matching
  - discover_admin parallel fan-out and bucket summary
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agent import http_auth_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Helpers ──────────────────────────────────────────────────────────


def _fake_response(*, status: int, headers: dict | None = None, text: str = "") -> MagicMock:
    """Build a MagicMock with the httpx.Response attributes we read."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    resp.is_redirect = status in (301, 302, 303, 307, 308)
    return resp


class _AsyncClientStub:
    """Patches in for ``httpx.AsyncClient`` and replays a script of responses."""

    def __init__(self, responses: list, request_log: list | None = None):
        self._responses = list(responses)
        self.request_log = request_log if request_log is not None else []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a, **kw):
        return False

    async def request(self, method, url, auth=None, **kw):
        self.request_log.append({"method": method, "url": url, "auth": auth})
        return self._next()

    async def get(self, url, auth=None, **kw):
        self.request_log.append({"method": "GET", "url": url, "auth": auth})
        return self._next()

    def _next(self):
        if not self._responses:
            raise AssertionError("AsyncClientStub: more requests than scripted responses")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# ── Op allowlist ─────────────────────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(http_auth_probe.HttpProbeError, match="unknown http probe op"):
        _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.1", "port": 80},
            credentials={},
            params={"op": "post", "op_params": {"path": "/"}},
        ))


def test_handler_rejects_missing_target():
    with pytest.raises(http_auth_probe.HttpProbeError, match="transport_config.target"):
        _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={}, transport_config={}, credentials={},
            params={"op": "probe"},
        ))


def test_probe_rejects_non_get_head_method():
    """The relay must enforce GET/HEAD even if the backend tool ever forgets."""
    request_log: list = []
    stub = _AsyncClientStub([_fake_response(status=200)], request_log=request_log)

    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        out = _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.1", "port": 80, "scheme": "http"},
            credentials={},
            params={"op": "probe", "op_params": {"path": "/", "method": "POST"}},
        ))

    assert "_errors" in out
    assert "POST" in out["_errors"]["probe"]
    assert request_log == []  # no network call was made


# ── URL building ─────────────────────────────────────────────────────


@pytest.mark.parametrize("port,expected_scheme", [
    (80, "http"),
    (8080, "http"),
    (443, "https"),
    (8443, "https"),
])
def test_scheme_inference_from_port(port, expected_scheme):
    assert http_auth_probe._infer_scheme(port) == expected_scheme


def test_base_url_omits_default_ports():
    assert http_auth_probe._base_url("http", "x", 80) == "http://x"
    assert http_auth_probe._base_url("https", "x", 443) == "https://x"
    assert http_auth_probe._base_url("http", "x", 8080) == "http://x:8080"
    assert http_auth_probe._base_url("https", "x", 8443) == "https://x:8443"


def test_probe_builds_correct_url():
    request_log: list = []
    stub = _AsyncClientStub([_fake_response(status=200)], request_log=request_log)
    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.5", "port": 8080},
            credentials={},
            params={"op": "probe", "op_params": {"path": "/admin"}},
        ))
    assert request_log[0]["url"] == "http://10.0.0.5:8080/admin"


# ── Auth shape selection ─────────────────────────────────────────────


def test_auth_anonymous_when_no_credentials():
    auth, label = http_auth_probe._build_auth({})
    assert auth is None
    assert label == "none"


def test_auth_basic_when_username_no_scheme():
    auth, label = http_auth_probe._build_auth({"username": "admin", "password": "x"})
    assert label == "basic"
    assert isinstance(auth, httpx.BasicAuth)


def test_auth_digest_when_scheme_digest():
    auth, label = http_auth_probe._build_auth({
        "scheme": "digest", "username": "admin", "password": "x",
    })
    assert label == "digest"
    assert isinstance(auth, httpx.DigestAuth)


def test_auth_bearer_when_token_present():
    auth, label = http_auth_probe._build_auth({"token": "abc123"})
    assert label == "bearer"
    assert isinstance(auth, http_auth_probe._BearerAuth)
    # Verify the auth flow injects the header.
    req = httpx.Request("GET", "http://x/")
    list(auth.auth_flow(req))
    assert req.headers["Authorization"] == "Bearer abc123"


# ── Response classification ──────────────────────────────────────────


@pytest.mark.parametrize("status,headers,want", [
    (200, {},                                "open"),
    (200, {"www-authenticate": "Basic realm=x"}, "auth_required"),  # 200 + challenge
    (401, {},                                "auth_required"),
    (403, {},                                "auth_required"),
    (404, {},                                "not_found"),
    (500, {},                                "server_error"),
    (302, {"location": "/login.html"},       "redirected_to_login"),
    (302, {"location": "/signin"},           "redirected_to_login"),
    (302, {"location": "/sso/oauth"},        "redirected_to_login"),
    (302, {"location": "/dashboard"},        "redirected"),
])
def test_classify_admin_response(status, headers, want):
    resp = _fake_response(status=status, headers=headers)
    assert http_auth_probe._classify_admin_response(resp) == want


# ── Title + fingerprint extraction ───────────────────────────────────


def test_extract_title_strips_whitespace():
    body = "<html><head><title>  HP LaserJet  Pro\n  M404n  </title></head></html>"
    assert http_auth_probe._extract_title(body) == "HP LaserJet Pro M404n"


def test_extract_title_missing_returns_empty():
    assert http_auth_probe._extract_title("<html>no title</html>") == ""
    assert http_auth_probe._extract_title("") == ""


@pytest.mark.parametrize("server,title,want", [
    ("Axis Network Camera", "",                "axis_camera"),
    ("",                    "Hikvision Web",   "hikvision_camera"),
    ("HP JetDirect 2.5",    "",                "hp_printer"),
    ("",                    "Polycom VVX 411", "polycom_phone"),
    ("Yealink",             "",                "yealink_phone"),
    ("Apache/2.4.1",        "Generic Page",    None),
])
def test_fingerprint_picks_correct_label(server, title, want):
    body = f"<html><head><title>{title}</title></head></html>"
    resp = _fake_response(status=200, headers={"server": server}, text=body)
    assert http_auth_probe._fingerprint(resp, body) == want


# ── op="probe" end-to-end ────────────────────────────────────────────


def test_probe_returns_full_payload():
    body = ("<html><head><title>Axis P1448-LE Network Camera</title></head>"
            "<body>config</body></html>")
    stub = _AsyncClientStub([
        _fake_response(status=200, headers={"server": "Axis", "content-type": "text/html"},
                       text=body),
    ])
    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        out = _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.5", "port": 80, "scheme": "http"},
            credentials={"username": "root", "password": "pass"},
            params={"op": "probe", "op_params": {"path": "/"}},
        ))

    assert out["status"] == 200
    assert out["scheme"] == "http"
    assert out["host"] == "10.0.0.5"
    assert out["port"] == 80
    assert out["auth_used"] == "basic"
    assert out["classification"] == "open"
    assert out["title"] == "Axis P1448-LE Network Camera"
    assert out["fingerprint"] == "axis_camera"
    assert "config" in out["body_excerpt"]


def test_probe_excerpt_truncates_long_body():
    long_body = "x" * 8000
    stub = _AsyncClientStub([_fake_response(status=200, text=long_body)])
    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        out = _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "x", "port": 80, "scheme": "http"},
            credentials={},
            params={"op": "probe", "op_params": {"path": "/"}},
        ))
    assert out["body_excerpt"].endswith("...[truncated]")
    assert len(out["body_excerpt"]) <= http_auth_probe._BODY_EXCERPT_BYTES + len("...[truncated]")


# ── op="discover_admin" ──────────────────────────────────────────────


def test_discover_admin_classifies_buckets():
    paths = http_auth_probe._ADMIN_PATHS
    # Build a response per path: alternate between open / auth-required /
    # redirected-to-login / not-found.
    responses = []
    for i, _path in enumerate(paths):
        mod = i % 4
        if mod == 0:
            responses.append(_fake_response(status=200,
                                            headers={"server": "Hikvision"},
                                            text="<title>Hikvision</title>"))
        elif mod == 1:
            responses.append(_fake_response(
                status=401,
                headers={"www-authenticate": 'Digest realm="cam"'}))
        elif mod == 2:
            responses.append(_fake_response(status=302,
                                            headers={"location": "/login.html"}))
        else:
            responses.append(_fake_response(status=404))

    stub = _AsyncClientStub(responses)
    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        out = _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.5", "port": 80, "scheme": "http"},
            credentials={},
            params={"op": "discover_admin"},
        ))

    assert out["total"] == len(paths)
    # Every path is in one of the buckets — none escaped to "other".
    bucketed = (len(out["open"]) + len(out["auth_required"])
                + len(out["redirected_to_login"]))
    not_found = sum(1 for r in out["results"] if r["classification"] == "not_found")
    errors = sum(1 for r in out["results"] if r["classification"] == "error")
    assert bucketed + not_found + errors == len(paths)


def test_discover_admin_records_per_path_metadata():
    paths = http_auth_probe._ADMIN_PATHS
    responses = [
        _fake_response(status=401,
                       headers={"www-authenticate": 'Basic realm="HP LaserJet"',
                                "server": "HP HTTP Server"})
        for _ in paths
    ]
    stub = _AsyncClientStub(responses)
    with patch("agent.http_auth_probe.httpx.AsyncClient", return_value=stub):
        out = _run(http_auth_probe.http_auth_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.7", "port": 80, "scheme": "http"},
            credentials={},
            params={"op": "discover_admin"},
        ))

    first = out["results"][0]
    assert first["server"] == "HP HTTP Server"
    assert "Basic realm" in first["auth_header"]
    assert first["classification"] == "auth_required"

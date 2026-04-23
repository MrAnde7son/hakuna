"""Tests for scan-target preflight.

Covers the deterministic classification of probe_http results and the
``should_preflight`` gate. The worker integration (short-circuit when
unreachable) is exercised separately via agent_worker tests — here we
pin the unit-level mapping from exception → reason so the classifier
stays stable as httpx versions roll.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from scanner.vm.preflight import (
    PreflightResult,
    probe_http,
    probe_tcp,
    should_preflight,
)


class TestShouldPreflight:
    def test_http_target_probed(self):
        assert should_preflight("http://dvwa") is True

    def test_https_target_probed(self):
        assert should_preflight("https://example.com") is True

    def test_bare_ip_skipped(self):
        # No known scheme — protocol-aware preflight belongs upstream.
        assert should_preflight("10.0.0.1") is False

    def test_empty_skipped(self):
        assert should_preflight("") is False

    def test_non_http_scheme_skipped(self):
        assert should_preflight("ftp://example.com") is False


def _mock_client_raising(exc: Exception):
    """Build an httpx.Client mock whose .request() raises ``exc``."""
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    client.request.side_effect = exc
    return client


def _mock_client_returning(status_code: int):
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    resp = MagicMock()
    resp.status_code = status_code
    client.request.return_value = resp
    return client


class TestProbeHttpReachable:
    def test_200_is_reachable(self):
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_returning(200)):
            r = probe_http("http://dvwa")
        assert r.reachable is True
        assert r.reason == "ok"
        assert r.status_code == 200

    def test_401_is_reachable(self):
        # A server that demands auth is still alive and probeable.
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_returning(401)):
            r = probe_http("http://dvwa")
        assert r.reachable is True
        assert r.status_code == 401

    def test_500_is_reachable(self):
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_returning(500)):
            r = probe_http("http://dvwa")
        assert r.reachable is True
        assert r.status_code == 500

    def test_head_405_falls_back_to_get(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        head_resp = MagicMock(status_code=405)
        get_resp = MagicMock(status_code=200)
        client.request.side_effect = [head_resp, get_resp]
        with patch("scanner.vm.preflight.httpx.Client", return_value=client):
            r = probe_http("http://dvwa")
        assert r.reachable is True
        assert r.status_code == 200
        assert client.request.call_count == 2


class TestProbeHttpUnreachable:
    def test_connect_refused(self):
        exc = httpx.ConnectError("Connection refused")
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_raising(exc)):
            r = probe_http("http://dvwa")
        assert r.reachable is False
        assert r.reason == "connect_refused"

    def test_dns_failure_classified(self):
        exc = httpx.ConnectError("nodename nor servname provided, or not known")
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_raising(exc)):
            r = probe_http("http://dvwa")
        assert r.reason == "dns_fail"

    def test_tls_failure_classified(self):
        exc = httpx.ConnectError("SSL: CERTIFICATE_VERIFY_FAILED")
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_raising(exc)):
            r = probe_http("https://dvwa")
        assert r.reason == "tls_fail"

    def test_timeout(self):
        exc = httpx.ConnectTimeout("connect timeout")
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_raising(exc)):
            r = probe_http("http://dvwa")
        assert r.reachable is False
        assert r.reason == "timeout"

    def test_invalid_target_scheme(self):
        r = probe_http("not a url")
        assert r.reachable is False
        assert r.reason == "invalid_target"

    def test_invalid_target_empty_host(self):
        r = probe_http("http://")
        assert r.reachable is False
        assert r.reason == "invalid_target"


class TestProbeTcp:
    def test_connect_ok(self):
        # Stand up an ephemeral listener so we know the port answers.
        import socket as _sock
        listener = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            r = probe_tcp("127.0.0.1", port, timeout=1.0)
            assert r.reachable is True
            assert r.reason == "ok"
        finally:
            listener.close()

    def test_refused(self):
        # Port 1 is reserved and never bound on any sane host.
        r = probe_tcp("127.0.0.1", 1, timeout=1.0)
        assert r.reachable is False
        assert r.reason in ("connect_refused", "timeout")

    def test_invalid_port(self):
        r = probe_tcp("127.0.0.1", 0)
        assert r.reachable is False
        assert r.reason == "invalid_target"

    def test_invalid_host(self):
        r = probe_tcp("", 80)
        assert r.reachable is False
        assert r.reason == "invalid_target"


class TestPreflightResultShape:
    def test_to_dict_roundtrip(self):
        with patch("scanner.vm.preflight.httpx.Client", return_value=_mock_client_returning(200)):
            r = probe_http("http://dvwa")
        d = r.to_dict()
        assert {"reachable", "reason", "detail", "probed_at", "elapsed_ms", "status_code"} <= set(d.keys())
        assert isinstance(d["elapsed_ms"], int)
        assert d["probed_at"].endswith("Z")

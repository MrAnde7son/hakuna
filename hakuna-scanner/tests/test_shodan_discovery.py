"""Tests for Shodan ingest module.

Mocks aiohttp so no network call is made.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class _FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class _FakeSession:
    def __init__(self, responses: list[_FakeResponse]):
        self._responses = list(responses)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, url):
        return self._responses.pop(0) if self._responses else _FakeResponse(500, {})


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


SAMPLE_MATCH = {
    "ip_str": "203.0.113.10",
    "port": 443,
    "hostnames": ["dev.example.com", "old.example.com"],
    "product": "nginx",
    "version": "1.18.0",
    "org": "Acme Inc",
    "asn": "AS64500",
    "vulns": {"CVE-2021-23017": {"verified": False}},
}

ORPHAN_IP_MATCH = {
    "ip_str": "203.0.113.99",
    "port": 22,
    "hostnames": [],
    "product": "OpenSSH",
    "version": "7.4",
    "org": "Acme Inc",
    "asn": "AS64500",
}


class TestQueryShodan:
    def test_returns_empty_when_no_key(self):
        from app.ingest.shodan_discovery import query_shodan

        result = _run(query_shodan("", "example.com"))
        assert result == []

    def test_flattens_hostnames_and_keeps_orphan_ips(self):
        from app.ingest import shodan_discovery

        # Two queries (ssl: + hostname:) × 1 page each. We return matches
        # only on the first call to keep the test focused on flattening.
        responses = [
            _FakeResponse(200, {"matches": [SAMPLE_MATCH, ORPHAN_IP_MATCH], "total": 2}),
            _FakeResponse(200, {"matches": [], "total": 0}),
        ]

        with patch.object(
            shodan_discovery.aiohttp,
            "ClientSession",
            return_value=_FakeSession(responses),
        ), patch.object(shodan_discovery.asyncio, "sleep", new=AsyncMock()):
            hosts = _run(shodan_discovery.query_shodan("fake-key", "example.com"))

        # 2 hostnames from SAMPLE_MATCH + 1 IP-only orphan
        assert len(hosts) == 3
        by_host = {h["host"]: h for h in hosts}
        assert "dev.example.com" in by_host
        assert "old.example.com" in by_host
        assert "203.0.113.99" in by_host  # orphan kept under its IP

        dev = by_host["dev.example.com"]
        assert dev["ip"] == "203.0.113.10"
        assert dev["asn"] == "64500"  # AS prefix stripped
        assert dev["asn_org"] == "Acme Inc"
        assert dev["shodan_port"] == 443
        assert dev["shodan_product"] == "nginx"
        assert dev["shodan_vulns"] == ["CVE-2021-23017"]

    def test_unauthorized_returns_empty(self):
        from app.ingest import shodan_discovery

        responses = [_FakeResponse(401, {}), _FakeResponse(401, {})]
        with patch.object(
            shodan_discovery.aiohttp,
            "ClientSession",
            return_value=_FakeSession(responses),
        ), patch.object(shodan_discovery.asyncio, "sleep", new=AsyncMock()):
            hosts = _run(shodan_discovery.query_shodan("bad-key", "example.com"))

        assert hosts == []

    def test_falls_back_to_dns_domain_on_paid_only_403(self):
        """On free tier the host/search filters return 403. When that happens
        we should fall through to /dns/domain/{domain} (free for all tiers)
        and surface its subdomains as host records — otherwise free-tier
        deployments contribute no Shodan data at all."""
        from app.ingest import shodan_discovery

        dns_payload = {
            "domain": "example.com",
            "subdomains": ["www", "api"],
            "data": [
                {"subdomain": "www", "type": "A", "value": "203.0.113.10"},
                {"subdomain": "api", "type": "CNAME", "value": "lb.example.net"},
                # Apex record — empty subdomain.
                {"subdomain": "", "type": "A", "value": "203.0.113.1"},
                # Duplicate (www, A, 203.0.113.10) should dedup.
                {"subdomain": "www", "type": "A", "value": "203.0.113.10"},
            ],
        }
        # Two 403s for the search queries, then 200 for the DNS fallback.
        responses = [
            _FakeResponse(403, {}),
            _FakeResponse(403, {}),
            _FakeResponse(200, dns_payload),
        ]

        with patch.object(
            shodan_discovery.aiohttp,
            "ClientSession",
            return_value=_FakeSession(responses),
        ), patch.object(shodan_discovery.asyncio, "sleep", new=AsyncMock()):
            hosts = _run(shodan_discovery.query_shodan("free-key", "example.com"))

        by_host = {h["host"]: h for h in hosts}
        assert "www.example.com" in by_host
        assert "api.example.com" in by_host
        assert "example.com" in by_host  # apex
        assert by_host["www.example.com"]["ip"] == "203.0.113.10"
        # CNAMEs don't carry IPs at this stage — dnsx resolves them later.
        assert by_host["api.example.com"]["ip"] is None
        # Paid-tier metadata is absent on the DNS fallback path.
        assert by_host["www.example.com"]["shodan_port"] is None

    def test_no_fallback_on_401(self):
        """A 401 means the key itself is bad. Falling back to /dns/domain
        with the same key would just 401 again — and worse, would mask the
        real misconfig from the operator."""
        from app.ingest import shodan_discovery

        # If the fallback fired, this test would fail because there's no
        # third response queued; _FakeSession would return a default 500.
        responses = [_FakeResponse(401, {}), _FakeResponse(401, {})]
        with patch.object(
            shodan_discovery.aiohttp,
            "ClientSession",
            return_value=_FakeSession(responses),
        ), patch.object(shodan_discovery.asyncio, "sleep", new=AsyncMock()):
            hosts = _run(shodan_discovery.query_shodan("bad-key", "example.com"))

        assert hosts == []

    def test_dedups_across_queries(self):
        """ssl: and hostname: queries often overlap — same (host, ip) once."""
        from app.ingest import shodan_discovery

        responses = [
            _FakeResponse(200, {"matches": [SAMPLE_MATCH], "total": 1}),
            _FakeResponse(200, {"matches": [SAMPLE_MATCH], "total": 1}),
        ]

        with patch.object(
            shodan_discovery.aiohttp,
            "ClientSession",
            return_value=_FakeSession(responses),
        ), patch.object(shodan_discovery.asyncio, "sleep", new=AsyncMock()):
            hosts = _run(shodan_discovery.query_shodan("fake-key", "example.com"))

        # Two hostnames, deduped across the two queries
        assert len(hosts) == 2
        assert sorted(h["host"] for h in hosts) == ["dev.example.com", "old.example.com"]

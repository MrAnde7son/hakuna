"""Tests for OTX passive DNS ingest module.

Mocks aiohttp so no network call is made.
"""

import asyncio
from unittest.mock import patch

import pytest

from app.ingest.otx_passive_dns import query_otx_passive_dns


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
        self.requested_urls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, url):
        self.requested_urls.append(url)
        return self._responses.pop(0) if self._responses else _FakeResponse(500, {})


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


SAMPLE_PAYLOAD = {
    "passive_dns": [
        {"hostname": "api.example.com", "address": "1.2.3.4"},
        {"hostname": "DEV.Example.com", "address": "1.2.3.5"},          # case-insensitive
        {"hostname": "*.wild.example.com", "address": "1.2.3.6"},        # wildcard stripped
        {"hostname": "example.com", "address": "1.2.3.7"},               # apex kept
        {"hostname": "evil.attacker.com", "address": "9.9.9.9"},         # out-of-scope, dropped
        {"hostname": "", "address": "1.2.3.8"},                          # empty, dropped
        {"hostname": "noTLD", "address": "1.2.3.9"},                     # no dot, dropped
        {"hostname": "api.example.com", "address": "1.2.3.10"},          # duplicate, dedup'd
    ]
}


def test_returns_empty_when_no_api_key():
    result = _run(query_otx_passive_dns("example.com", ""))
    assert result == []


def test_parses_and_filters_in_scope_hosts():
    fake = _FakeSession([_FakeResponse(200, SAMPLE_PAYLOAD)])
    with patch("app.ingest.otx_passive_dns.aiohttp.ClientSession", return_value=fake):
        result = _run(query_otx_passive_dns("example.com", "fake-key"))

    assert result == sorted({
        "api.example.com",
        "dev.example.com",
        "wild.example.com",
        "example.com",
    })
    assert "evil.attacker.com" not in result
    assert "otx.alienvault.com" in fake.requested_urls[0]


def test_returns_empty_on_http_error():
    fake = _FakeSession([_FakeResponse(500, {})])
    with patch("app.ingest.otx_passive_dns.aiohttp.ClientSession", return_value=fake):
        result = _run(query_otx_passive_dns("example.com", "fake-key"))
    assert result == []


def test_retries_once_on_429():
    fake = _FakeSession([
        _FakeResponse(429, {}),
        _FakeResponse(200, SAMPLE_PAYLOAD),
    ])
    with patch("app.ingest.otx_passive_dns.aiohttp.ClientSession", return_value=fake), \
         patch("app.ingest.otx_passive_dns.asyncio.sleep", return_value=None):
        result = _run(query_otx_passive_dns("example.com", "fake-key"))
    assert len(result) == 4
    assert len(fake.requested_urls) == 2


def test_swallows_network_exception():
    class _Boom:
        async def __aenter__(self):
            raise RuntimeError("network down")

        async def __aexit__(self, *_):
            return False

    with patch("app.ingest.otx_passive_dns.aiohttp.ClientSession", return_value=_Boom()):
        result = _run(query_otx_passive_dns("example.com", "fake-key"))
    assert result == []


def test_handles_missing_passive_dns_key():
    fake = _FakeSession([_FakeResponse(200, {})])
    with patch("app.ingest.otx_passive_dns.aiohttp.ClientSession", return_value=fake):
        result = _run(query_otx_passive_dns("example.com", "fake-key"))
    assert result == []

"""Tests for ProjectDiscovery Chaos ingest module.

Mocks aiohttp so no network call is made.
"""

import asyncio
from unittest.mock import patch

from app.ingest.chaos import query_chaos


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
    "domain": "example.com",
    "subdomains": [
        "api",
        "DEV",                  # case-insensitive
        "*.wild",               # wildcard stripped
        "@",                    # apex marker
        "api",                  # duplicate, dedup'd
        "",                     # empty, dropped
        "deep.nested",          # multi-label prefix
        "already.example.com",  # already-fqdn, kept as-is
    ],
}


def test_returns_empty_when_no_api_key():
    assert _run(query_chaos("example.com", "")) == []


def test_parses_and_expands_prefixes():
    fake = _FakeSession([_FakeResponse(200, SAMPLE_PAYLOAD)])
    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=fake):
        result = _run(query_chaos("example.com", "fake-key"))

    assert result == sorted({
        "api.example.com",
        "dev.example.com",
        "wild.example.com",
        "example.com",
        "deep.nested.example.com",
        "already.example.com",
    })
    assert "dns.projectdiscovery.io" in fake.requested_urls[0]


def test_returns_empty_on_http_error():
    fake = _FakeSession([_FakeResponse(500, {})])
    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=fake):
        assert _run(query_chaos("example.com", "fake-key")) == []


def test_returns_empty_on_401():
    fake = _FakeSession([_FakeResponse(401, {})])
    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=fake):
        assert _run(query_chaos("example.com", "fake-key")) == []


def test_retries_once_on_429():
    fake = _FakeSession([
        _FakeResponse(429, {}),
        _FakeResponse(200, SAMPLE_PAYLOAD),
    ])
    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=fake), \
         patch("app.ingest.chaos.asyncio.sleep", return_value=None):
        result = _run(query_chaos("example.com", "fake-key"))
    assert "api.example.com" in result
    assert len(fake.requested_urls) == 2


def test_swallows_network_exception():
    class _Boom:
        async def __aenter__(self):
            raise RuntimeError("network down")

        async def __aexit__(self, *_):
            return False

    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=_Boom()):
        assert _run(query_chaos("example.com", "fake-key")) == []


def test_handles_missing_subdomains_key():
    fake = _FakeSession([_FakeResponse(200, {"domain": "example.com"})])
    with patch("app.ingest.chaos.aiohttp.ClientSession", return_value=fake):
        assert _run(query_chaos("example.com", "fake-key")) == []

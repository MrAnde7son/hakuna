"""Tests for the cloud-provider IP-range matcher and fetcher."""

import asyncio
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from app.ingest import cloud_ranges as cr


@pytest.fixture(autouse=True)
def _reset_matcher():
    """Each test reloads the matcher so seed/disk state doesn't leak."""
    cr._tree4 = None
    cr._tree6 = None
    cr._loaded_from = None
    yield
    cr._tree4 = None
    cr._tree6 = None
    cr._loaded_from = None


def test_seed_classifies_known_provider_ips(tmp_path, monkeypatch):
    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))
    cr.reload()

    # Cloudflare 104.16.0.0/16
    assert cr.identify_cloud_provider("104.16.5.10") == "cloudflare"
    # GCP 35.0.0.0/8
    assert cr.identify_cloud_provider("35.190.10.5") == "gcp"
    # Azure 20.0.0.0/8
    assert cr.identify_cloud_provider("20.85.40.1") == "azure"
    # AWS 52.0.0.0/8 (note: also in Azure seed; longest-prefix match wins —
    # for /8 vs /8 the deterministic order is whichever was inserted last;
    # we only assert one of the two, since the seed has both as /8s.)
    aws_or_azure = cr.identify_cloud_provider("52.10.20.30")
    assert aws_or_azure in {"aws", "azure"}


def test_unknown_ip_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))
    cr.reload()
    # 8.8.8.8 isn't in any seed range
    assert cr.identify_cloud_provider("8.8.8.8") is None


def test_empty_and_invalid_inputs():
    assert cr.identify_cloud_provider(None) is None
    assert cr.identify_cloud_provider("") is None
    assert cr.identify_cloud_provider("not-an-ip") is None


def test_disk_overrides_seed(tmp_path, monkeypatch):
    """When a per-provider JSON file is on disk, its CIDRs replace the
    seed entry for that provider — so a fresh AWS feed wins over the
    bundled /8 fallbacks.
    """
    aws_path = tmp_path / "aws.json"
    aws_path.write_text(json.dumps({
        "updated_at": "2026-01-01T00:00:00Z",
        "cidrs": ["198.51.100.0/24"],
    }))

    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))
    cr.reload()

    assert cr.identify_cloud_provider("198.51.100.42") == "aws"
    # An IP that was in the AWS seed (52.0.0.0/8) should NO LONGER classify
    # as AWS — disk replaced the entire AWS list. But it might still match
    # the Azure seed since Azure includes "52.0.0.0/8".
    classification = cr.identify_cloud_provider("52.10.20.30")
    assert classification != "aws"


def test_longest_prefix_wins(tmp_path, monkeypatch):
    """A /24 disk entry beats a /8 seed entry for the same IP."""
    cf_path = tmp_path / "cloudflare.json"
    cf_path.write_text(json.dumps({
        "updated_at": "2026-01-01T00:00:00Z",
        "cidrs": ["20.0.0.0/24"],
    }))
    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))
    cr.reload()

    # 20.0.0.5 is inside both Azure /8 (seed) and Cloudflare /24 (disk).
    # /24 is longer — Cloudflare wins.
    assert cr.identify_cloud_provider("20.0.0.5") == "cloudflare"
    # 20.5.5.5 is outside the /24 → falls back to Azure /8.
    assert cr.identify_cloud_provider("20.5.5.5") == "azure"


def test_malformed_disk_json_is_skipped(tmp_path, monkeypatch, caplog):
    bad = tmp_path / "aws.json"
    bad.write_text("{not json")
    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))

    # Should not raise; matcher continues with seed.
    cr.reload()
    assert cr.identify_cloud_provider("104.16.5.10") == "cloudflare"


def test_pytricia_unavailable_returns_none(tmp_path, monkeypatch):
    """If pytricia isn't importable, the matcher degrades gracefully."""
    monkeypatch.setattr(cr.settings, "cloud_ranges_dir", str(tmp_path))
    monkeypatch.setattr(cr, "_new_pytricia", lambda width: None)
    cr.reload()
    assert cr.identify_cloud_provider("104.16.5.10") is None


# ── Fetcher tests ──────────────────────────────────────────────────────


from app.tasks import cloud_ranges as fetcher  # noqa: E402


SAMPLE_AWS = {
    "prefixes": [
        {"ip_prefix": "3.5.140.0/22", "region": "us-east-1"},
        {"ip_prefix": "52.94.0.0/22", "region": "us-east-1"},
    ],
    "ipv6_prefixes": [
        {"ipv6_prefix": "2600:1f00::/29"},
    ],
}

SAMPLE_GCP = {
    "prefixes": [
        {"ipv4Prefix": "34.64.0.0/10"},
        {"ipv6Prefix": "2600:1900::/28"},
    ],
}

SAMPLE_CLOUDFLARE_V4 = "173.245.48.0/20\n103.21.244.0/22\n"
SAMPLE_CLOUDFLARE_V6 = "2400:cb00::/32\n"

SAMPLE_ORACLE = {
    "regions": [
        {"region": "us-ashburn-1", "cidrs": [{"cidr": "129.146.0.0/16"}]},
    ],
}

SAMPLE_DO_CSV = "104.236.0.0/16,US,California,Santa Clara,95054\n138.197.0.0/16,US,New York,New York,10001\n"

SAMPLE_FASTLY = {
    "addresses": ["151.101.0.0/16", "199.232.0.0/16"],
    "ipv6_addresses": ["2a04:4e42::/32"],
}


class _FakeResponse:
    def __init__(self, status: int, text: str):
        self.status = status
        self._text = text

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class _FakeSession:
    def __init__(self, by_url: dict[str, _FakeResponse]):
        self._by_url = by_url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, url):
        if url not in self._by_url:
            return _FakeResponse(404, "")
        return self._by_url[url]


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_fetcher_writes_per_provider_files(tmp_path, monkeypatch):
    monkeypatch.setattr(fetcher.settings, "cloud_ranges_dir", str(tmp_path))

    by_url = {
        fetcher._AWS_URL: _FakeResponse(200, json.dumps(SAMPLE_AWS)),
        fetcher._GCP_URL: _FakeResponse(200, json.dumps(SAMPLE_GCP)),
        fetcher._CLOUDFLARE_URL: _FakeResponse(200, SAMPLE_CLOUDFLARE_V4),
        fetcher._CLOUDFLARE_V6_URL: _FakeResponse(200, SAMPLE_CLOUDFLARE_V6),
        fetcher._ORACLE_URL: _FakeResponse(200, json.dumps(SAMPLE_ORACLE)),
        fetcher._DIGITALOCEAN_URL: _FakeResponse(200, SAMPLE_DO_CSV),
        fetcher._FASTLY_URL: _FakeResponse(200, json.dumps(SAMPLE_FASTLY)),
    }

    with patch("app.tasks.cloud_ranges.aiohttp.ClientSession", return_value=_FakeSession(by_url)):
        summary = _run(fetcher._refresh_all())

    # Every provider returned ok with the right count.
    assert summary["aws"] == {"status": "ok", "count": 3}
    assert summary["gcp"] == {"status": "ok", "count": 2}
    assert summary["cloudflare"] == {"status": "ok", "count": 3}
    assert summary["oracle"] == {"status": "ok", "count": 1}
    assert summary["digitalocean"] == {"status": "ok", "count": 2}
    assert summary["fastly"] == {"status": "ok", "count": 3}

    # Files exist with the expected shape.
    aws = json.loads((tmp_path / "aws.json").read_text())
    assert "updated_at" in aws
    assert "3.5.140.0/22" in aws["cidrs"]
    assert "2600:1f00::/29" in aws["cidrs"]


def test_fetcher_handles_partial_failure(tmp_path, monkeypatch):
    """If one provider 500s, others still write."""
    monkeypatch.setattr(fetcher.settings, "cloud_ranges_dir", str(tmp_path))

    by_url = {
        fetcher._AWS_URL: _FakeResponse(500, ""),
        fetcher._GCP_URL: _FakeResponse(200, json.dumps(SAMPLE_GCP)),
        fetcher._CLOUDFLARE_URL: _FakeResponse(200, SAMPLE_CLOUDFLARE_V4),
        fetcher._CLOUDFLARE_V6_URL: _FakeResponse(200, SAMPLE_CLOUDFLARE_V6),
        fetcher._ORACLE_URL: _FakeResponse(200, json.dumps(SAMPLE_ORACLE)),
        fetcher._DIGITALOCEAN_URL: _FakeResponse(200, SAMPLE_DO_CSV),
        fetcher._FASTLY_URL: _FakeResponse(200, json.dumps(SAMPLE_FASTLY)),
    }

    with patch("app.tasks.cloud_ranges.aiohttp.ClientSession", return_value=_FakeSession(by_url)):
        summary = _run(fetcher._refresh_all())

    assert summary["aws"]["status"] == "empty"
    assert summary["gcp"]["status"] == "ok"
    # AWS file should NOT exist — we only write on success.
    assert not (tmp_path / "aws.json").exists()
    assert (tmp_path / "gcp.json").exists()

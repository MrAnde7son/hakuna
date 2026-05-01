"""Unit tests for the AJP13 CPing/CPong probe.

Covers:

* CPing magic byte structure (regression guard against accidental edits)
* CPong frame validation: correct magic + prefix → success
* Wrong-magic / wrong-prefix / short-frame → None
* Connection refused / timeout → None (no crash)
* ``probe_batch`` honors the service_type / legacy-port gate

Network I/O is mocked at ``asyncio.open_connection`` — these tests don't
hit a real socket. Style mirrors ``tests/test_banner_grab.py``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


def _run(coro):
    """Run a coroutine on a fresh event loop without closing the
    default loop — ``asyncio.run`` closes whichever loop it sets, which
    can break later tests that rely on ``asyncio.get_event_loop()``
    (see tests/test_delta_udp.py)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Static structural checks ──────────────────────────────────────────────


class TestAjpCPingFrame:
    def test_cping_bytes_are_correct(self):
        """The CPing magic + length + prefix is fixed by the AJP13 spec.
        A drift here means every Tomcat AJP probe stops working."""
        from app.ingest.ajp_probe import _AJP_CPING
        # 0x12 0x34 magic (client→server), length 0x00 0x01, prefix 0x0A
        assert _AJP_CPING == b"\x12\x34\x00\x01\x0a"
        assert len(_AJP_CPING) == 5

    def test_cpong_constants_are_correct(self):
        from app.ingest.ajp_probe import (
            _AJP_CPONG_MAGIC,
            _AJP_CPONG_PREFIX,
            _AJP_CPONG_FRAME,
        )
        assert _AJP_CPONG_MAGIC == b"\x41\x42"  # "AB"
        assert _AJP_CPONG_PREFIX == 0x09
        assert _AJP_CPONG_FRAME == b"\x41\x42\x00\x01\x09"

    def test_legacy_port_set_is_8009(self):
        """Default AJP port is 8009 — guard against typos."""
        from app.ingest.ajp_probe import _LEGACY_PORTS, _SERVICE_TYPES
        assert _LEGACY_PORTS == {8009}
        assert _SERVICE_TYPES == {"ajp"}


# ── _probe_single ─────────────────────────────────────────────────────────


def _make_streams(read_bytes: bytes):
    """Build an (reader, writer) pair where reader.readexactly returns
    ``read_bytes`` and writer collects everything written."""
    reader = MagicMock()
    reader.readexactly = AsyncMock(return_value=read_bytes)

    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer._written = []  # populated below

    def _capture_write(data):
        writer._written.append(data)

    writer.write.side_effect = _capture_write
    return reader, writer


class TestAjpProbeSingle:
    def test_valid_cpong_returns_hit(self):
        """A correct CPong (AB 00 01 09) must produce a banner_finding."""
        from app.ingest import ajp_probe

        reader, writer = _make_streams(b"\x41\x42\x00\x01\x09")

        async def fake_open(*_args, **_kwargs):
            return reader, writer

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is not None
        assert result["protocol"] == "ajp"
        assert result["port"] == 8009
        assert result["version"]["product"] == "Tomcat-AJP"
        # Verify CPing was actually written
        assert writer._written == [ajp_probe._AJP_CPING]

    def test_wrong_magic_returns_none(self):
        """A non-AJP service that happens to send 5 bytes back must not
        be misclassified as AJP."""
        from app.ingest import ajp_probe

        # HTTP-ish prefix — definitely not AJP
        reader, writer = _make_streams(b"HTTP/")

        async def fake_open(*_args, **_kwargs):
            return reader, writer

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is None

    def test_wrong_prefix_returns_none(self):
        """Right magic but wrong prefix code (e.g. SEND_BODY_CHUNK 0x03)
        is not a CPong — must reject."""
        from app.ingest import ajp_probe

        reader, writer = _make_streams(b"\x41\x42\x00\x01\x03")

        async def fake_open(*_args, **_kwargs):
            return reader, writer

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is None

    def test_connection_refused_returns_none(self):
        """OSError on connect must be swallowed — probes are best-effort."""
        from app.ingest import ajp_probe

        async def fake_open(*_args, **_kwargs):
            raise ConnectionRefusedError()

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is None

    def test_connect_timeout_returns_none(self):
        """asyncio.TimeoutError on connect must be swallowed."""
        from app.ingest import ajp_probe

        async def fake_open(*_args, **_kwargs):
            raise asyncio.TimeoutError()

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is None

    def test_short_frame_returns_none(self):
        """If the server closes mid-frame (IncompleteReadError), bail."""
        from app.ingest import ajp_probe

        reader = MagicMock()
        reader.readexactly = AsyncMock(
            side_effect=asyncio.IncompleteReadError(b"\x41\x42", 5),
        )
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        async def fake_open(*_args, **_kwargs):
            return reader, writer

        with patch.object(ajp_probe.asyncio, "open_connection", side_effect=fake_open):
            result = _run(ajp_probe._probe_single("10.0.0.1", 8009))

        assert result is None


# ── probe_batch ───────────────────────────────────────────────────────────


class TestAjpProbeBatch:
    def test_batch_skips_assets_without_matching_port(self):
        """An asset without 8009 (and no service_type=ajp stamp) must be
        skipped entirely — no probe call."""
        from app.ingest import ajp_probe

        assets = [{
            "hostname": "no-ajp.example.com",
            "ip": "10.0.0.2",
            "open_ports": [80, 443],
            "port_service_types": {},
        }]

        with patch.object(ajp_probe, "_probe_single", new=AsyncMock(return_value=None)) as mock_probe:
            results = _run(ajp_probe.probe_batch(assets))

        assert results == {}
        mock_probe.assert_not_called()

    def test_batch_probes_legacy_port_8009(self):
        """An asset with port 8009 and no service_type stamp must be
        probed (legacy-port fallback)."""
        from app.ingest import ajp_probe

        assets = [{
            "hostname": "tomcat.example.com",
            "ip": "10.0.0.3",
            "open_ports": [8009],
            "port_service_types": {},
        }]

        hit = {
            "protocol": "ajp",
            "port": 8009,
            "banner": "AJP13 CPong",
            "version": {"product": "Tomcat-AJP"},
        }
        with patch.object(ajp_probe, "_probe_single", new=AsyncMock(return_value=hit)) as mock_probe:
            results = _run(ajp_probe.probe_batch(assets))

        mock_probe.assert_awaited_once_with("10.0.0.3", 8009)
        assert "tomcat.example.com" in results
        assert results["tomcat.example.com"][0]["protocol"] == "ajp"

    def test_batch_probes_non_canonical_port_when_typed(self):
        """An asset with service_type=ajp on a non-canonical port (e.g.
        18009) must still be probed — service_type beats the port number."""
        from app.ingest import ajp_probe

        assets = [{
            "hostname": "tomcat-alt.example.com",
            "ip": "10.0.0.4",
            "open_ports": [18009],
            "port_service_types": {18009: "ajp"},
        }]

        hit = {
            "protocol": "ajp",
            "port": 18009,
            "banner": "AJP13 CPong",
            "version": {"product": "Tomcat-AJP"},
        }
        with patch.object(ajp_probe, "_probe_single", new=AsyncMock(return_value=hit)) as mock_probe:
            results = _run(ajp_probe.probe_batch(assets))

        mock_probe.assert_awaited_once_with("10.0.0.4", 18009)
        assert results["tomcat-alt.example.com"][0]["port"] == 18009

    def test_batch_skips_typed_non_ajp_port(self):
        """If port 8009 carries a non-ajp service_type stamp (operator
        re-purposed the port), skip it. service_type beats legacy port."""
        from app.ingest import ajp_probe

        assets = [{
            "hostname": "weird.example.com",
            "ip": "10.0.0.5",
            "open_ports": [8009],
            "port_service_types": {8009: "http"},
        }]

        with patch.object(ajp_probe, "_probe_single", new=AsyncMock(return_value=None)) as mock_probe:
            results = _run(ajp_probe.probe_batch(assets))

        assert results == {}
        mock_probe.assert_not_called()

    def test_batch_swallows_per_port_exceptions(self):
        """A single port's probe raising must not kill the batch — other
        assets/ports still get probed."""
        from app.ingest import ajp_probe

        assets = [
            {
                "hostname": "broken.example.com",
                "ip": "10.0.0.6",
                "open_ports": [8009],
                "port_service_types": {},
            },
            {
                "hostname": "ok.example.com",
                "ip": "10.0.0.7",
                "open_ports": [8009],
                "port_service_types": {},
            },
        ]

        async def _fake_probe(host, _port):
            if host == "10.0.0.6":
                raise RuntimeError("kaboom")
            return {
                "protocol": "ajp",
                "port": 8009,
                "banner": "AJP13 CPong",
                "version": {"product": "Tomcat-AJP"},
            }

        with patch.object(ajp_probe, "_probe_single", new=AsyncMock(side_effect=_fake_probe)):
            results = _run(ajp_probe.probe_batch(assets))

        assert "broken.example.com" not in results
        assert "ok.example.com" in results


# ── orchestrator integration: _BANNER_SERVICE_TYPE wiring ─────────────────


class TestAjpOrchestratorWiring:
    """The orchestrator (``_do_banner_grab`` in ``tasks/enrichment.py``)
    is what actually calls ``upsert_asset_port`` based on the
    ``protocol`` field of each banner_finding. Verify the mapping exists
    so a returned ``protocol="ajp"`` banner gets stamped with
    ``service_type='ajp'`` at confidence 90."""

    def test_banner_service_type_includes_ajp(self):
        from app.tasks.enrichment import _BANNER_SERVICE_TYPE
        assert "ajp" in _BANNER_SERVICE_TYPE
        svc_type, conf = _BANNER_SERVICE_TYPE["ajp"]
        assert svc_type == "ajp"
        assert conf == 90

    def test_banner_service_product_returns_tomcat_ajp(self):
        from app.tasks.enrichment import _banner_service_product
        product = _banner_service_product({
            "protocol": "ajp",
            "version": {"product": "Tomcat-AJP"},
        })
        assert product == "Tomcat-AJP"

    def test_banner_service_product_defaults_when_version_missing(self):
        from app.tasks.enrichment import _banner_service_product
        product = _banner_service_product({"protocol": "ajp", "version": {}})
        assert product == "Tomcat-AJP"

    def test_banner_legacy_ports_includes_8009(self):
        from app.tasks.enrichment import BANNER_LEGACY_PORTS
        assert 8009 in BANNER_LEGACY_PORTS

    def test_banner_service_types_includes_ajp(self):
        from app.tasks.enrichment import BANNER_SERVICE_TYPES
        assert "ajp" in BANNER_SERVICE_TYPES

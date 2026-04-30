"""Tests for NaabuRunner port-list construction and port_scan_state tracking.

Covers two regressions:
  1. 8081 (and other non-curated common ports) silently skipped because
     they weren't in the legacy `naabu_ports` list.
  2. Empty `open_ports` indistinguishable from "scan failed" or "never
     scanned" — fixed by port_scan_state column populated by update_ports.
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.runner.port_lists import NMAP_TOP_1000_TCP, merge_port_strings
from app.runner.tools import NaabuRunner, _default_naabu_ports


class TestMergePortStrings:
    def test_dedups_singles(self):
        assert merge_port_strings("80,443,80") == "80,443"

    def test_sorts_singles(self):
        assert merge_port_strings("443,22,80") == "22,80,443"

    def test_handles_empty_inputs(self):
        assert merge_port_strings("", "80", None) == "80"

    def test_preserves_ranges(self):
        # Ranges aren't expanded — they pass through after the singles block.
        out = merge_port_strings("80,443", "1-100")
        assert out == "80,443,1-100"

    def test_merges_two_lists(self):
        out = merge_port_strings("80,443,8080", "8443,80,9090")
        assert out == "80,443,8080,8443,9090"


class TestDefaultNaabuPorts:
    def test_top1000_includes_8081(self):
        # Core regression: 8081 (DVWA, common HTTP-alt) was missing.
        with patch("app.runner.tools.settings") as s:
            s.naabu_use_top1000 = True
            s.naabu_ports = "11434,6333"  # specialty extras only
            ports = _default_naabu_ports()
        port_set = {int(p) for p in ports.split(",")}
        assert 8081 in port_set
        # Spot-check other common ports that were absent from the legacy list.
        for p in (81, 8181, 9080, 9081):
            assert p in port_set, f"expected {p} in top-1000 union"

    def test_top1000_unions_specialty(self):
        with patch("app.runner.tools.settings") as s:
            s.naabu_use_top1000 = True
            s.naabu_ports = "11434,6333,19530"  # AI / vector DB ports
            ports = _default_naabu_ports()
        port_set = {int(p) for p in ports.split(",")}
        # Top-1000 contributions:
        assert 80 in port_set and 443 in port_set
        # Specialty contributions (none of these are in nmap top-1000):
        assert 11434 in port_set
        assert 6333 in port_set
        assert 19530 in port_set

    def test_top1000_disabled_uses_legacy_list(self):
        with patch("app.runner.tools.settings") as s:
            s.naabu_use_top1000 = False
            s.naabu_ports = "80,443,11434"
            ports = _default_naabu_ports()
        # Pass-through, no top-1000 union.
        assert ports == "80,443,11434"
        assert "8081" not in ports.split(",")

    def test_top1000_constant_is_sorted_and_unique(self):
        # Guard against accidental hand-edits introducing dupes/reorders.
        assert list(NMAP_TOP_1000_TCP) == sorted(set(NMAP_TOP_1000_TCP))
        assert 8081 in NMAP_TOP_1000_TCP


class TestNaabuRunnerCommand:
    def test_explicit_ports_override_default(self):
        # Liveness recheck passes explicit ports; that should take precedence
        # over both top-1000 and the specialty list.
        runner = NaabuRunner(["host1.example.com"], ports="80,443")
        try:
            cmd = runner.build_command()
        finally:
            import os
            if runner._tmpfile and os.path.exists(runner._tmpfile):
                os.unlink(runner._tmpfile)
        # Find the -p arg
        p_idx = cmd.index("-p")
        assert cmd[p_idx + 1] == "80,443"

    def test_default_command_includes_8081(self):
        with patch("app.runner.tools.settings") as s:
            s.naabu_use_top1000 = True
            s.naabu_ports = ""
            s.naabu_rate = 2000
            runner = NaabuRunner(["host1.example.com"])
            try:
                cmd = runner.build_command()
            finally:
                import os
                if runner._tmpfile and os.path.exists(runner._tmpfile):
                    os.unlink(runner._tmpfile)
        p_idx = cmd.index("-p")
        port_set = {int(p) for p in cmd[p_idx + 1].split(",") if "-" not in p}
        assert 8081 in port_set


class TestUpdatePortsState:
    """Verify port_scan_state classification for scanned/empty/failed hosts."""

    @pytest.mark.asyncio
    async def test_scanned_host_with_results_marked_scanned(self):
        from app.ingest.assets import update_ports

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        org_id = uuid.uuid4()

        await update_ports(
            db, org_id,
            port_results=[{"host": "a.example.com", "port": 8081}],
            scanned_hosts=["a.example.com"],
            failed_hosts=[],
        )

        # First UPDATE writes ports + state='scanned' for hosts with results.
        first_call = db.execute.call_args_list[0]
        sql = str(first_call.args[0])
        assert "port_scan_state = 'scanned'" in sql
        assert "open_ports = :ports" in sql
        params = first_call.args[1]
        assert params["host"] == "a.example.com"
        assert params["ports"] == [8081]

    @pytest.mark.asyncio
    async def test_scanned_host_with_no_results_marked_empty(self):
        from app.ingest.assets import update_ports

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        org_id = uuid.uuid4()

        await update_ports(
            db, org_id,
            port_results=[],
            scanned_hosts=["dead.example.com"],
            failed_hosts=[],
        )

        # Should issue exactly one UPDATE for the empty bucket.
        empty_call = db.execute.call_args_list[0]
        sql = str(empty_call.args[0])
        assert "open_ports = ARRAY[]::int[]" in sql
        assert "port_scan_state = 'scanned'" in sql
        assert empty_call.args[1]["hosts"] == ["dead.example.com"]

    @pytest.mark.asyncio
    async def test_failed_host_marked_failed_without_overwriting_ports(self):
        from app.ingest.assets import update_ports

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        org_id = uuid.uuid4()

        await update_ports(
            db, org_id,
            port_results=[],
            scanned_hosts=[],
            failed_hosts=["broken.example.com"],
        )

        failed_call = db.execute.call_args_list[0]
        sql = str(failed_call.args[0])
        assert "port_scan_state = 'failed'" in sql
        # Critical: failed updates must NOT touch open_ports — stale data
        # is more useful than nothing while debugging the failure.
        assert "open_ports" not in sql
        assert failed_call.args[1]["hosts"] == ["broken.example.com"]

    @pytest.mark.asyncio
    async def test_mixed_batch_scanned_empty_and_failed(self):
        from app.ingest.assets import update_ports

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        org_id = uuid.uuid4()

        await update_ports(
            db, org_id,
            port_results=[{"host": "a.example.com", "port": 80}],
            scanned_hosts=["a.example.com", "empty.example.com"],
            failed_hosts=["broken.example.com"],
        )

        # 3 SQL calls: scanned-with-results, scanned-empty, failed.
        assert db.execute.call_count == 3
        sqls = [str(c.args[0]) for c in db.execute.call_args_list]
        assert any("port_scan_state = 'scanned'" in s and "open_ports = :ports" in s for s in sqls)
        assert any("ARRAY[]::int[]" in s for s in sqls)
        assert any("port_scan_state = 'failed'" in s for s in sqls)

    @pytest.mark.asyncio
    async def test_legacy_call_without_state_lists_still_works(self):
        """Existing callers that don't pass scanned_hosts/failed_hosts must
        keep working — only hosts with results get touched."""
        from app.ingest.assets import update_ports

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()

        await update_ports(
            db, uuid.uuid4(),
            port_results=[{"host": "x.example.com", "port": 443}],
        )

        # Only the per-host UPDATE — no empty or failed bucket calls.
        assert db.execute.call_count == 1

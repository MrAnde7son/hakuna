"""End-to-end test for ``_do_banner_grab``.

Exercises the full pipeline-step entry point — six protocol modules
running concurrently via ``asyncio.gather``, per-host merge, and the
``UPDATE assets`` / ``INSERT findings`` SQL writes — with every external
dependency mocked. Catches regressions the parser unit tests in
``test_banner_grab.py`` can't (e.g. a module raising propagating up,
or per-host merge dropping severity-tagged banners on conflict).

Why mock the database: the real path uses Postgres JSONB ``||``
semantics that SQLite can't fake. We assert the SQL shape + bound
parameters instead.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.tasks import enrichment


def _mk_session_factory(executed: list, fetched_ids: dict[str, int]):
    """Returns an async-callable ``sf`` that yields a stub session.

    ``executed`` collects every (sql_text_str, params_dict) tuple so
    assertions can inspect the SQL pipeline.
    ``fetched_ids`` maps hostname → asset_id for the SELECT-by-hostname
    lookup; missing hostnames simulate the "asset disappeared" race and
    skip the UPDATE/INSERT.
    """
    db = MagicMock()

    async def _execute(sql, params=None):
        sql_str = str(sql).strip()
        executed.append((sql_str, params or {}))
        if "SELECT id FROM assets" in sql_str:
            host = (params or {}).get("host")
            row = MagicMock()
            row.id = fetched_ids.get(host)
            cursor = MagicMock()
            cursor.fetchone.return_value = row if row.id is not None else None
            return cursor
        cursor = MagicMock()
        cursor.fetchone.return_value = None
        return cursor

    db.execute = _execute
    db.commit = AsyncMock()

    @asynccontextmanager
    async def _ctx():
        yield db

    def sf():
        return _ctx()

    return sf


def _banner_finding(*, protocol="ssh", port=22, severity=None, finding_title=None, **extra):
    out = {"protocol": protocol, "port": port, "banner": "raw-banner-bytes"}
    if severity is not None:
        out["severity"] = severity
    if finding_title is not None:
        out["finding_title"] = finding_title
    out.update(extra)
    return out


@pytest.mark.asyncio
async def test_no_assets_short_circuits():
    """If the asset query returns nothing, the pipeline must not fan
    out modules at all (saves 6 round-trips when the org has no scope)."""
    sf = _mk_session_factory(executed=[], fetched_ids={})
    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=[])):
        with patch.object(enrichment, "ssh_banner_batch", AsyncMock()) as ssh:
            result = await enrichment._do_banner_grab(sf, "org-1")
    assert result == {"probed": 0}
    ssh.assert_not_called()


@pytest.mark.asyncio
async def test_no_banner_ports_short_circuits():
    """Assets exist but none expose any banner-relevant port — skip
    every module rather than calling them with an empty list."""
    sf = _mk_session_factory(executed=[], fetched_ids={})
    assets = [{"hostname": "web-only", "open_ports": [80, 443]}]
    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=assets)):
        with patch.object(enrichment, "ssh_banner_batch", AsyncMock()) as ssh:
            result = await enrichment._do_banner_grab(sf, "org-1")
    assert result == {"probed": 0, "no_banner_ports": True}
    ssh.assert_not_called()


@pytest.mark.asyncio
async def test_runs_all_six_modules_in_parallel_and_persists():
    """Happy path: candidates exist, every module returns a banner for
    a different host, the merge keeps all hits, and the SQL writes are
    issued in the expected shape (UPDATE then conditional INSERTs)."""
    executed: list = []
    sf = _mk_session_factory(
        executed=executed,
        fetched_ids={"ssh-host": 1, "rdp-host": 2, "smtp-host": 3},
    )
    assets = [
        {"hostname": "ssh-host", "open_ports": [22]},
        {"hostname": "rdp-host", "open_ports": [3389]},
        {"hostname": "smtp-host", "open_ports": [25, 587]},
        {"hostname": "noisy", "open_ports": [22, 3389, 25, 631, 1900, 3306]},
    ]
    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=assets)):
        with patch.object(enrichment, "ssh_banner_batch",
                          AsyncMock(return_value={"ssh-host": [_banner_finding(protocol="ssh")]})), \
             patch.object(enrichment, "rdp_nla_batch",
                          AsyncMock(return_value={"rdp-host": [
                              _banner_finding(protocol="rdp", port=3389,
                                              severity=2, finding_title="RDP NLA disabled"),
                          ]})), \
             patch.object(enrichment, "mail_banner_batch",
                          AsyncMock(return_value={"smtp-host": [
                              _banner_finding(protocol="smtp", port=25,
                                              severity=3, finding_title="SMTP open relay"),
                          ]})), \
             patch.object(enrichment, "printer_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "tr069_upnp_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "db_banner_batch", AsyncMock(return_value={})):
            result = await enrichment._do_banner_grab(sf, "org-1")

    # 4 candidates after the port pre-filter (all 4 carry banner-relevant
    # ports, "noisy" matches via its 22/3389/25/631/1900/3306 set).
    assert result["probed"] == 4
    assert result["assets_with_banners"] == 3
    assert result["total_banners"] == 3
    # Two banners are severity-tagged (RDP + SMTP) → 2 finding rows.
    assert result["findings_created"] == 2

    # SQL pipeline shape: per-asset SELECT, then UPDATE, then optional INSERT.
    select_count = sum(1 for s, _ in executed if "SELECT id FROM assets" in s)
    update_count = sum(1 for s, _ in executed if "UPDATE assets" in s)
    insert_count = sum(1 for s, _ in executed if "INSERT INTO findings" in s)
    assert select_count == 3
    assert update_count == 3
    assert insert_count == 2


@pytest.mark.asyncio
async def test_module_exception_does_not_abort_pipeline():
    """A single module raising mid-gather must not lose the other
    five modules' results — that's the whole point of
    ``return_exceptions=True``."""
    sf = _mk_session_factory(executed=[], fetched_ids={"ssh-host": 1})
    assets = [{"hostname": "ssh-host", "open_ports": [22, 3389]}]

    async def _boom(_):
        raise RuntimeError("rdp module crashed")

    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=assets)):
        with patch.object(enrichment, "ssh_banner_batch",
                          AsyncMock(return_value={"ssh-host": [_banner_finding(protocol="ssh")]})), \
             patch.object(enrichment, "rdp_nla_batch", side_effect=_boom), \
             patch.object(enrichment, "mail_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "printer_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "tr069_upnp_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "db_banner_batch", AsyncMock(return_value={})):
            result = await enrichment._do_banner_grab(sf, "org-1")

    assert result["probed"] == 1
    assert result["assets_with_banners"] == 1
    assert result["total_banners"] == 1
    assert result["findings_created"] == 0


@pytest.mark.asyncio
async def test_missing_asset_row_skips_writes():
    """If a banner module reports a hostname the assets table doesn't
    have any longer (asset got pruned mid-scan), skip the UPDATE/INSERT
    rather than crashing on a NULL id."""
    executed: list = []
    # Note: ``ghost-host`` deliberately not in fetched_ids → SELECT returns None.
    sf = _mk_session_factory(executed=executed, fetched_ids={})
    assets = [{"hostname": "ghost-host", "open_ports": [22]}]

    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=assets)):
        with patch.object(enrichment, "ssh_banner_batch",
                          AsyncMock(return_value={"ghost-host": [
                              _banner_finding(protocol="ssh", severity=2,
                                              finding_title="OpenSSH 7.x"),
                          ]})), \
             patch.object(enrichment, "rdp_nla_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "mail_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "printer_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "tr069_upnp_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "db_banner_batch", AsyncMock(return_value={})):
            result = await enrichment._do_banner_grab(sf, "org-1")

    # Banner reported but the SELECT couldn't find the row, so no UPDATE/INSERT.
    assert result["assets_with_banners"] == 1
    assert result["total_banners"] == 1
    assert result["findings_created"] == 0
    update_count = sum(1 for s, _ in executed if "UPDATE assets" in s)
    insert_count = sum(1 for s, _ in executed if "INSERT INTO findings" in s)
    assert update_count == 0
    assert insert_count == 0


@pytest.mark.asyncio
async def test_per_host_merge_preserves_multi_module_hits():
    """The same hostname can appear in multiple module result dicts
    (e.g. SSH on 22 and a DB banner on 3306). The merge must keep both
    banners and emit a single UPDATE per host carrying the union."""
    executed: list = []
    sf = _mk_session_factory(executed=executed, fetched_ids={"dual-host": 7})
    assets = [{"hostname": "dual-host", "open_ports": [22, 3306]}]

    with patch.object(enrichment, "_get_confirmed_alive_assets", AsyncMock(return_value=assets)):
        with patch.object(enrichment, "ssh_banner_batch",
                          AsyncMock(return_value={"dual-host": [_banner_finding(protocol="ssh")]})), \
             patch.object(enrichment, "rdp_nla_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "mail_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "printer_banner_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "tr069_upnp_batch", AsyncMock(return_value={})), \
             patch.object(enrichment, "db_banner_batch",
                          AsyncMock(return_value={"dual-host": [
                              _banner_finding(protocol="postgres", port=5432),
                          ]})):
            result = await enrichment._do_banner_grab(sf, "org-1")

    assert result["assets_with_banners"] == 1
    assert result["total_banners"] == 2
    update_calls = [(s, p) for s, p in executed if "UPDATE assets" in s]
    assert len(update_calls) == 1
    # Both banners must be in the JSON payload sent to UPDATE.
    payload = update_calls[0][1].get("banners")
    assert "ssh" in payload and "postgres" in payload

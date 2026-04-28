"""Tests for Shodan observation merge + port_change synthesis in
``app.ingest.delta.apply_shodan_observations``.

Scope:
  * merges Shodan ports into ``open_ports`` without clobbering naabu's view
  * stashes shodan_vulns inside ``services[port].shodan_vulns`` so the
    backend's _build_easm_data can surface it on Asset.easm_data
  * emits one ``port_change`` event per asset whose port set actually grew,
    tagged with ``payload.source = "shodan"``
  * does NOT emit an event when the Shodan port was already in open_ports
    (avoids re-firing audits on assets we've already swept)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _fake_db(asset_row):
    """Mock AsyncSession that returns ``asset_row`` on SELECT, captures
    UPDATE/INSERT params for assertions."""
    db = MagicMock()
    captured: dict = {"updates": [], "events": []}

    async def _execute(stmt, params=None):
        sql = str(stmt)
        result = MagicMock()
        if "SELECT" in sql and "FROM assets" in sql:
            result.fetchone = lambda: asset_row
        elif "UPDATE assets" in sql:
            captured["updates"].append(dict(params or {}))
        elif "INSERT INTO asset_events" in sql:
            captured["events"].append(dict(params or {}))
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db._captured = captured
    return db


def _asset_row(asset_id=None, open_ports=None, services=None):
    r = MagicMock()
    r.id = asset_id or uuid.uuid4()
    r.open_ports = open_ports
    r.services = services
    return r


def test_merges_shodan_port_into_open_ports_and_emits_port_change():
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    db = _fake_db(_asset_row(asset_id=asset_id, open_ports=[80], services={}))

    hosts = [{
        "host": "vpn.example.com",
        "ip": "203.0.113.10",
        "shodan_port": 443,
        "shodan_product": "Fortinet FortiGate",
        "shodan_version": "7.2.4",
        "shodan_vulns": ["CVE-2024-21762"],
    }]

    result = _run(apply_shodan_observations(db, org_id, hosts))

    assert result == {"updated": 1, "events": 1}

    # Ports merged: existing 80 + new 443
    update = db._captured["updates"][0]
    assert update["ports"] == [80, 443]
    services = json.loads(update["services"])
    assert services["443"]["product"] == "Fortinet FortiGate"
    assert services["443"]["version"] == "7.2.4"
    assert services["443"]["shodan_vulns"] == ["CVE-2024-21762"]

    # port_change event emitted only for the genuinely new port
    event = db._captured["events"][0]
    payload = json.loads(event["payload"])
    assert payload["transport"] == "tcp"
    assert payload["new_ports"] == [443]
    assert payload["source"] == "shodan"


def test_skips_event_when_port_already_open():
    """Re-running Shodan over an asset whose port was already known via naabu
    should not fan out a fresh audit on every ingest cycle."""
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    db = _fake_db(_asset_row(
        asset_id=asset_id, open_ports=[443], services={"443": {"name": "https"}},
    ))

    hosts = [{
        "host": "vpn.example.com",
        "ip": "203.0.113.10",
        "shodan_port": 443,
        "shodan_product": "Fortinet",
        "shodan_vulns": [],
    }]

    result = _run(apply_shodan_observations(db, org_id, hosts))

    assert result["updated"] == 1
    assert result["events"] == 0
    assert db._captured["events"] == []


def test_does_not_clobber_richer_naabu_banner():
    """If naabu already populated services[port] with a product, Shodan's
    thinner banner shouldn't overwrite it — naabu's -sV is closer to ground
    truth than Shodan's cached fingerprint."""
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    naabu_services = {"443": {
        "name": "https", "product": "naabu-detected-product", "version": "9.9.9",
    }}
    db = _fake_db(_asset_row(
        asset_id=asset_id, open_ports=[443], services=naabu_services,
    ))

    hosts = [{
        "host": "vpn.example.com",
        "shodan_port": 443,
        "shodan_product": "shodan-thin-banner",
        "shodan_version": "1.0",
        "shodan_vulns": ["CVE-2024-21762"],
    }]

    _run(apply_shodan_observations(db, org_id, hosts))

    update = db._captured["updates"][0]
    services = json.loads(update["services"])
    # Naabu's product/version preserved
    assert services["443"]["product"] == "naabu-detected-product"
    assert services["443"]["version"] == "9.9.9"
    # But shodan_vulns added — that's signal naabu doesn't have
    assert services["443"]["shodan_vulns"] == ["CVE-2024-21762"]


def test_aggregates_multiple_ports_for_same_host():
    """Shodan emits one observation per (host, port) — for a single host
    with multiple exposed ports, we should get one UPDATE and one event
    listing all newly-observed ports."""
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    db = _fake_db(_asset_row(asset_id=asset_id, open_ports=[], services={}))

    hosts = [
        {
            "host": "shadow.example.com",
            "ip": "203.0.113.10",
            "shodan_port": 22,
            "shodan_product": "OpenSSH",
            "shodan_version": "7.4",
        },
        {
            "host": "shadow.example.com",
            "ip": "203.0.113.10",
            "shodan_port": 3389,
            "shodan_product": "Microsoft RDP",
        },
    ]

    result = _run(apply_shodan_observations(db, org_id, hosts))

    assert result == {"updated": 1, "events": 1}
    update = db._captured["updates"][0]
    assert update["ports"] == [22, 3389]
    payload = json.loads(db._captured["events"][0]["payload"])
    assert payload["new_ports"] == [22, 3389]


def test_skips_hosts_without_shodan_port():
    """Entries without shodan_port (e.g. crtsh-derived hostnames) should be
    silently ignored — no UPDATE, no event."""
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    db = _fake_db(_asset_row(open_ports=[80], services={}))

    hosts = [{"host": "cert-only.example.com"}]

    result = _run(apply_shodan_observations(db, org_id, hosts))

    assert result == {"updated": 0, "events": 0}


def test_skips_unknown_assets():
    """If the SELECT returns no row (asset upsert raced or rolled back),
    skip the host without crashing."""
    from app.ingest.delta import apply_shodan_observations

    org_id = uuid.uuid4()
    db = _fake_db(asset_row=None)

    hosts = [{
        "host": "ghost.example.com",
        "shodan_port": 443,
        "shodan_vulns": ["CVE-2024-21762"],
    }]

    result = _run(apply_shodan_observations(db, org_id, hosts))

    assert result == {"updated": 0, "events": 0}

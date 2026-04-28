"""Delta engine: compare new scan results against existing DB state and emit events."""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def emit_new_asset_events(
    db: AsyncSession,
    org_id: uuid.UUID,
    new_asset_ids: list[uuid.UUID],
) -> int:
    """Create 'new_asset' events for freshly discovered hosts."""
    now = datetime.now(timezone.utc)
    for asset_id in new_asset_ids:
        row = await db.execute(
            text("SELECT hostname, ip, source FROM assets WHERE id = :id"),
            {"id": asset_id},
        )
        asset = row.fetchone()
        if not asset:
            continue

        await db.execute(
            text("""
                INSERT INTO asset_events (id, org_id, asset_id, event_type, payload, created_at)
                VALUES (:id, :org_id, :asset_id, 'new_asset', cast(:payload as jsonb), :now)
            """),
            {
                "id": uuid.uuid4(),
                "org_id": org_id,
                "asset_id": asset_id,
                "payload": json.dumps({"hostname": asset.hostname, "ip": str(asset.ip) if asset.ip else None, "source": asset.source}),
                "now": now,
            },
        )
    await db.commit()
    return len(new_asset_ids)


async def apply_shodan_observations(
    db: AsyncSession,
    org_id: uuid.UUID,
    hosts: list[dict],
) -> dict:
    """Merge Shodan port/banner/CVE observations onto existing assets and emit
    port_change events for any genuinely new ports.

    Designed to run *after* upsert_discovered_hosts so the asset row already
    exists. We deliberately *merge* (not overwrite) ``open_ports`` and
    ``services`` — Shodan's view is partial, and we don't want to clobber a
    naabu sweep that landed earlier with a richer port list.

    Per-port banner data lands in ``services[port]`` along with a
    ``shodan_vulns`` array — the backend's _build_easm_data forwards this into
    the platform's ``Asset.easm_data`` so prioritization and the VM
    auto-trigger can see the high-confidence CVE banners.

    Each genuinely-new port produces one ``port_change`` event with
    ``payload.source = 'shodan'``. The backend's audit auto-trigger fires on
    these the same way it fires on naabu-derived events; the synthesized event
    carries enough context (hostname, transport, new_ports) for the existing
    matcher.

    Returns ``{"updated": n, "events": m}``.
    """
    if not hosts:
        return {"updated": 0, "events": 0}

    # Aggregate per (hostname, ip): one Shodan host can appear in our entry
    # list multiple times (one row per port observation). Group them so we
    # do a single UPDATE per asset.
    by_host: dict[tuple[str, str | None], list[dict]] = {}
    for entry in hosts:
        hostname = (entry.get("host") or entry.get("hostname") or "").strip().lower()
        if not hostname:
            continue
        port = entry.get("shodan_port")
        if port is None:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        ip = entry.get("ip")
        by_host.setdefault((hostname, ip), []).append({
            "port": port,
            "product": entry.get("shodan_product"),
            "version": entry.get("shodan_version"),
            "vulns": entry.get("shodan_vulns") or [],
        })

    if not by_host:
        return {"updated": 0, "events": 0}

    now = datetime.now(timezone.utc)
    updated = 0
    events_emitted = 0

    for (hostname, _ip), observations in by_host.items():
        row = await db.execute(
            text("""
                SELECT id, open_ports, services
                FROM assets
                WHERE org_id = :org_id AND hostname = :hostname
            """),
            {"org_id": org_id, "hostname": hostname},
        )
        asset = row.fetchone()
        if not asset:
            continue

        existing_ports = set(asset.open_ports or [])
        new_ports_set: set[int] = set()
        merged_services = dict(asset.services or {})
        for ob in observations:
            p = ob["port"]
            if p not in existing_ports:
                new_ports_set.add(p)
            svc_entry = dict(merged_services.get(str(p)) or {})
            # Don't clobber a richer naabu banner with a thinner Shodan one.
            if ob["product"] and not svc_entry.get("product"):
                svc_entry["product"] = ob["product"]
            if ob["version"] and not svc_entry.get("version"):
                svc_entry["version"] = ob["version"]
            if "name" not in svc_entry and svc_entry.get("product"):
                svc_entry["name"] = svc_entry["product"].lower()
            if ob["vulns"]:
                # Union with any prior CVE list on the same port.
                prior = set(svc_entry.get("shodan_vulns") or [])
                svc_entry["shodan_vulns"] = sorted(prior | set(ob["vulns"]))
            merged_services[str(p)] = svc_entry

        merged_ports = sorted(existing_ports | {ob["port"] for ob in observations})

        await db.execute(
            text("""
                UPDATE assets SET
                    open_ports = :ports,
                    services = cast(:services as json),
                    last_seen = :now
                WHERE id = :id
            """),
            {
                "ports": merged_ports,
                "services": json.dumps(merged_services),
                "now": now,
                "id": asset.id,
            },
        )
        updated += 1

        if new_ports_set:
            await _insert_event(
                db, org_id, asset.id, "port_change",
                {
                    "hostname": hostname,
                    "transport": "tcp",
                    "new_ports": sorted(new_ports_set),
                    "removed_ports": [],
                    "source": "shodan",
                },
                now,
            )
            events_emitted += 1

    await db.commit()
    logger.info(
        "shodan: org=%s assets_updated=%d port_change_events=%d",
        org_id, updated, events_emitted,
    )
    return {"updated": updated, "events": events_emitted}


async def detect_changes(
    db: AsyncSession,
    org_id: uuid.UUID,
    previous_snapshot: list[dict],
) -> int:
    """Compare current asset state with a previous snapshot and emit change events.

    `previous_snapshot` should be a list of dicts with keys:
    {id, hostname, ip, open_ports, open_udp_ports, tech_stack, tls_cert}
    captured before the scan run updated the assets. ``open_udp_ports`` is
    optional for back-compat with snapshots taken before Phase 4.0.
    """
    now = datetime.now(timezone.utc)
    events_created = 0

    for prev in previous_snapshot:
        asset_id = prev["id"]
        row = await db.execute(
            text("""
                SELECT hostname, host(ip) as ip, open_ports, open_udp_ports,
                       tech_stack, tls_cert
                FROM assets WHERE id = :id
            """),
            {"id": asset_id},
        )
        current = row.fetchone()
        if not current:
            continue

        # IP change
        prev_ip = str(prev.get("ip") or "")
        curr_ip = str(current.ip or "")
        if prev_ip and curr_ip and prev_ip != curr_ip:
            await _insert_event(db, org_id, asset_id, "ip_change", {
                "hostname": current.hostname, "old_ip": prev_ip, "new_ip": curr_ip,
            }, now)
            events_created += 1

        # TCP port change
        prev_ports = sorted(prev.get("open_ports") or [])
        curr_ports = sorted(current.open_ports or [])
        if prev_ports != curr_ports:
            new_ports = [p for p in curr_ports if p not in prev_ports]
            removed_ports = [p for p in prev_ports if p not in curr_ports]
            if new_ports or removed_ports:
                await _insert_event(db, org_id, asset_id, "port_change", {
                    "hostname": current.hostname,
                    "transport": "tcp",
                    "new_ports": new_ports,
                    "removed_ports": removed_ports,
                }, now)
                events_created += 1

        # UDP port change (Phase 4.0). Same payload shape as TCP — the
        # ``transport`` field is what the audit auto-trigger filters on.
        prev_udp = sorted(prev.get("open_udp_ports") or [])
        curr_udp = sorted(current.open_udp_ports or [])
        if prev_udp != curr_udp:
            new_udp = [p for p in curr_udp if p not in prev_udp]
            removed_udp = [p for p in prev_udp if p not in curr_udp]
            if new_udp or removed_udp:
                await _insert_event(db, org_id, asset_id, "port_change", {
                    "hostname": current.hostname,
                    "transport": "udp",
                    "new_ports": new_udp,
                    "removed_ports": removed_udp,
                }, now)
                events_created += 1

        # Tech stack change
        prev_tech = prev.get("tech_stack") or {}
        curr_tech = current.tech_stack or {}
        if prev_tech != curr_tech:
            await _insert_event(db, org_id, asset_id, "tech_change", {
                "hostname": current.hostname,
                "old_tech": prev_tech,
                "new_tech": curr_tech,
            }, now)
            events_created += 1

    await db.commit()
    logger.info("org=%s delta events=%d", org_id, events_created)
    return events_created


async def detect_cert_expiring(db: AsyncSession, org_id: uuid.UUID) -> int:
    """Emit 'cert_expiring' for assets with TLS cert expiring in <30 days."""
    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=30)

    rows = await db.execute(
        text("""
            SELECT id, hostname, tls_cert
            FROM assets
            WHERE org_id = :org_id AND tls_cert IS NOT NULL
        """),
        {"org_id": org_id},
    )

    events = 0
    for row in rows.fetchall():
        cert = row.tls_cert or {}
        expiry_str = cert.get("expiry")
        if not expiry_str:
            continue

        try:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue

        if expiry < threshold:
            await _insert_event(db, org_id, row.id, "cert_expiring", {
                "hostname": row.hostname,
                "expiry": expiry_str,
                "days_remaining": max(0, (expiry - now).days),
            }, now)
            events += 1

            # Auto-tag
            await db.execute(
                text("""
                    UPDATE assets SET tags = array_append(
                        array_remove(tags, 'expired-cert'), 'expired-cert'
                    ) WHERE id = :id
                """),
                {"id": row.id},
            )

    await db.commit()
    return events


async def detect_gone_assets(db: AsyncSession, org_id: uuid.UUID, lookback_scans: int = 3) -> int:
    """Emit 'asset_gone' for hosts not seen in the last N scan cycles.

    Uses last_seen compared against the Nth most recent scan finish time.
    """
    now = datetime.now(timezone.utc)

    result = await db.execute(
        text("""
            SELECT finished_at FROM scan_runs
            WHERE org_id = :org_id AND status = 'done'
            ORDER BY finished_at DESC
            LIMIT 1 OFFSET :offset
        """),
        {"org_id": org_id, "offset": lookback_scans - 1},
    )
    cutoff_row = result.fetchone()
    if not cutoff_row or not cutoff_row.finished_at:
        return 0

    cutoff = cutoff_row.finished_at
    stale = await db.execute(
        text("""
            SELECT id, hostname, host(ip) as ip, last_seen
            FROM assets
            WHERE org_id = :org_id AND last_seen < :cutoff
        """),
        {"org_id": org_id, "cutoff": cutoff},
    )

    events = 0
    for row in stale.fetchall():
        await _insert_event(db, org_id, row.id, "asset_gone", {
            "hostname": row.hostname,
            "ip": str(row.ip) if row.ip else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        }, now)
        events += 1

    await db.commit()
    return events


async def auto_tag_assets(db: AsyncSession, org_id: uuid.UUID) -> int:
    """Apply automatic tags based on asset attributes."""
    now = datetime.now(timezone.utc)
    tagged = 0

    # internet-facing: has open ports
    await db.execute(
        text("""
            UPDATE assets SET tags = array_append(
                array_remove(tags, 'internet-facing'), 'internet-facing'
            )
            WHERE org_id = :org_id AND open_ports IS NOT NULL AND array_length(open_ports, 1) > 0
        """),
        {"org_id": org_id},
    )

    # cdn: has cdn_provider
    await db.execute(
        text("""
            UPDATE assets SET tags = array_append(
                array_remove(tags, 'cdn'), 'cdn'
            )
            WHERE org_id = :org_id AND cdn_provider IS NOT NULL
        """),
        {"org_id": org_id},
    )

    await db.commit()
    return tagged


async def _insert_event(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    event_type: str,
    payload: dict,
    created_at: datetime,
):
    await db.execute(
        text("""
            INSERT INTO asset_events (id, org_id, asset_id, event_type, payload, created_at)
            VALUES (:id, :org_id, :asset_id, :event_type, cast(:payload as jsonb), :now)
        """),
        {
            "id": uuid.uuid4(),
            "org_id": org_id,
            "asset_id": asset_id,
            "event_type": event_type,
            "payload": json.dumps(payload),
            "now": created_at,
        },
    )

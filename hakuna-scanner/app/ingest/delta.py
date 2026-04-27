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

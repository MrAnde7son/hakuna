"""Credentialed Windows inventory scans via the relay agent.

Dispatches `method=wmi_query` tasks to a connected relay agent (which runs
impacket under the hood, see hakuna-relay-agent/agent/wmi_query.py), collects
per-host results, writes Inventory* rows via services.wmi_result_mapper, and
hands off to services.post_ingest.finalize_scan for dedup/TI/risk scoring.

Distinct from services.vm_scanner.start_vm_scan: that one HTTP-POSTs to the
VM scanner container. WMI goes through the relay WebSocket because the target
is on-prem Windows hosts behind the customer network, and the relay is the
only component that can reach them.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from models.models import Asset, Organization, Scan
from services.credential_manager import load_credentials
from services.post_ingest import finalize_scan
from services.relay_broker import get_relay_broker
from services.wmi_result_mapper import ingest_result

logger = logging.getLogger(__name__)


# Cap concurrent in-flight WMI tasks per scan. DCOM setup is RAM-heavy on the
# relay side; 5 is comfortable for a 1GB container and keeps the impacket
# thread pool from starving.
DEFAULT_CONCURRENCY = 5

# Default profiles — mirrors hakuna-relay-agent/agent/wmi_catalog.py's
# DEFAULT_PROFILES. Duplicated here rather than imported so the backend
# doesn't depend on relay-agent source.
DEFAULT_PROFILES: list[str] = [
    "os_info",
    "software_uninstall",
    "software_product",
    "services",
    "patches",
    "shares",
    "local_users",
    "local_groups",
    "group_membership",
]


async def start_wmi_scan(
    db: Session,
    org: Organization,
    asset_ids: list[int],
    credential_id: str,
    relay_agent_id: str,
    profiles: list[str] | None = None,
    per_host_timeout_s: int = 120,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> dict[str, Any]:
    """Run a credentialed WMI inventory sweep across the given assets.

    Returns a summary: {scan_id, assets_scanned, assets_failed, rows_written}.
    On broker disconnect or credential resolution failure the whole scan is
    marked failed — per-host errors don't fail the scan, they just count
    toward `assets_failed`.
    """
    if not asset_ids:
        raise ValueError("asset_ids is required")
    if not credential_id:
        raise ValueError("credential_id is required")
    if not relay_agent_id:
        raise ValueError("relay_agent_id is required")

    profile_list = profiles or DEFAULT_PROFILES

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"Relay agent {relay_agent_id} is not connected")

    # 1. Resolve + shape creds for the agent. The agent expects plain
    #    {username, password, domain}; credential_manager returns a dict with
    #    a "_auth_type" marker which we strip.
    raw_creds = await load_credentials(db, credential_id, org.id)
    if not raw_creds or not raw_creds.get("username"):
        raise ValueError(
            f"Credential {credential_id} missing or has no username "
            "(expected auth_type=basic with {username, password, domain})"
        )
    wmi_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", ""),
        "domain": raw_creds.get("domain", "") or "",
    }

    # 2. Create the Scan row. We use source_type="wmi_inventory" so
    #    post_ingest hooks that filter by source (e.g. SLA for VM vs. EASM)
    #    can distinguish this pipeline.
    scan = Scan(
        org_id=org.id,
        filename=f"wmi://{relay_agent_id}/{len(asset_ids)}hosts",
        scan_name=f"WMI Inventory — {len(asset_ids)} host(s)",
        scan_date=datetime.utcnow().isoformat(),
        scan_type="wmi_inventory",
        source_type="wmi_inventory",
        status="running",
        raw_metadata={
            "relay_agent_id": relay_agent_id,
            "asset_ids": asset_ids,
            "profiles": profile_list,
            "credential_id": credential_id,
        },
    )
    db.add(scan)
    db.flush()  # get scan.id before kicking off parallel tasks

    # 3. Look up the targets. We resolve once up-front so a single bad asset
    #    ID doesn't cause N individual query failures.
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    asset_by_id = {a.id: a for a in assets}
    missing = [aid for aid in asset_ids if aid not in asset_by_id]
    if missing:
        logger.warning("wmi_scan: %d asset(s) not found: %s", len(missing), missing)

    # 4. Fire queries in parallel, bounded by concurrency.
    sem = asyncio.Semaphore(concurrency)

    async def _run_one(asset: Asset) -> tuple[int, dict | None, str | None]:
        target = _resolve_target(asset)
        if not target:
            return asset.id, None, "asset has no hostname or ip"
        async with sem:
            try:
                result = await broker.send_task(
                    agent_id=relay_agent_id,
                    method="wmi_query",
                    config={"target": target},
                    credentials=wmi_creds,
                    params={
                        "profiles": profile_list,
                        "timeout_s": per_host_timeout_s,
                    },
                )
                return asset.id, result, None
            except Exception as e:
                logger.warning("wmi_scan: asset=%s target=%s failed: %s", asset.id, target, e)
                return asset.id, None, str(e)

    completions = await asyncio.gather(*(_run_one(a) for a in assets))

    # 5. Ingest results host-by-host. We flush (not commit) after each host
    #    so a later host's failure doesn't roll back earlier inserts.
    assets_scanned = 0
    assets_failed = len(missing)
    rows_written = 0
    errors: list[dict] = []

    for asset_id, result, err in completions:
        if err is not None or result is None:
            assets_failed += 1
            errors.append({"asset_id": asset_id, "error": err})
            continue
        try:
            counts = ingest_result(db, scan, asset_id, result)
            rows_written += sum(counts.values())
            # Persist os_info back onto the Asset row if we got it — cheap win.
            os_info = (result.get("os_info") or [{}])[0] if result.get("os_info") else {}
            if os_info:
                _apply_os_info(db, asset_id, os_info)
            db.flush()
            assets_scanned += 1
        except Exception as e:
            logger.exception("wmi_scan: ingest failed for asset=%s", asset_id)
            assets_failed += 1
            errors.append({"asset_id": asset_id, "error": f"ingest: {e}"})

    # 6. Finalize scan status and hand off to the ingest pipeline.
    if assets_scanned == 0:
        scan.status = "failed"
    elif assets_failed > 0:
        scan.status = "partial"
    else:
        scan.status = "completed"
    scan.last_run_at = datetime.utcnow()
    # Stash errors in raw_metadata for ops triage without adding a column.
    md = dict(scan.raw_metadata or {})
    md["errors"] = errors[:50]   # bound to keep the row small
    md["rows_written"] = rows_written
    scan.raw_metadata = md

    db.commit()

    # 7. Run dedup / TI / risk scoring (only if at least one host landed data).
    if assets_scanned > 0:
        try:
            finalize_scan(db, scan_id=scan.id, org_id=org.id)
        except Exception:
            logger.exception("wmi_scan: finalize_scan failed for scan=%s", scan.id)

    return {
        "scan_id": scan.id,
        "assets_scanned": assets_scanned,
        "assets_failed": assets_failed,
        "rows_written": rows_written,
        "status": scan.status,
    }


def _resolve_target(asset: Asset) -> str | None:
    """Pick the best address for a WMI connection.

    DCOM is happier with an IP than a hostname that may fail DNS on the
    relay side; but some domain-joined hosts only answer Kerberos over
    FQDN. Prefer hostname/FQDN when present, fall back to IP.
    """
    return asset.fqdn or asset.hostname or asset.ip or None


def _apply_os_info(db: Session, asset_id: int, os_info: dict) -> None:
    """Merge the single os_info row onto Asset.os (and cpe when possible).

    We don't overwrite user-set OS strings — only fill when missing so a
    later Nessus export (which has richer OS strings) takes precedence.
    """
    caption = os_info.get("Caption")
    if not caption:
        return
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset and not asset.os:
        asset.os = caption

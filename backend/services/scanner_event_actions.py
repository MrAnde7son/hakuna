"""Workflow actions triggered by scanner events.

Registered with workflow_engine.register_action so they can be used as
action nodes in workflows. Exposed actions:

  - rerun_nuclei_for_asset: kick off a VM scan for an asset that had
    a tech/port change detected by the scanner.

Actions receive `items` from the workflow pipeline (typically the
payload from the scanner event, containing asset_id).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.orm import Session

from models.models import Asset, Organization
from services import workflow_engine

logger = logging.getLogger(__name__)


def _resolve_asset_ids(items: list) -> list[int]:
    """Extract integer asset IDs from a list of event payloads or items."""
    ids: list[int] = []
    for it in items or []:
        if isinstance(it, dict):
            for key in ("asset_id", "id"):
                val = it.get(key)
                if val is None:
                    continue
                try:
                    ids.append(int(val))
                    break
                except (TypeError, ValueError):
                    continue
        elif isinstance(it, int):
            ids.append(it)
    return list(dict.fromkeys(ids))  # dedup, preserve order


def _action_rerun_nuclei_for_asset(db: Session, config: dict, items: list):
    """Trigger a VM (Nuclei) scan for the assets referenced in items.

    Handler signature required by workflow_engine.register_action:
      (db, config, items) -> (affected: int, items: list)

    Config fields:
      - max_targets: int (default 10) — cap how many assets per workflow run
      - use_hostname: bool (default True) — prefer hostname over IP as target
    """
    from services.vm_scanner import start_vm_scan

    asset_ids = _resolve_asset_ids(items)
    if not asset_ids:
        return 0, items

    max_targets = int(config.get("max_targets", 10))
    prefer_hostname = bool(config.get("use_hostname", True))

    # Group assets by org (actions run per-workflow, but items may span orgs)
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids[:max_targets])).all()
    if not assets:
        return 0, items

    by_org: dict[int, list[Asset]] = {}
    for a in assets:
        by_org.setdefault(a.org_id, []).append(a)

    affected = 0
    for org_id, org_assets in by_org.items():
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            continue

        targets: list[str] = []
        aids: list[int] = []
        for a in org_assets:
            tgt = (a.hostname if prefer_hostname else None) or a.hostname or str(a.ip or "")
            if not tgt:
                continue
            targets.append(tgt)
            aids.append(a.id)

        if not targets:
            continue

        try:
            result = asyncio.run(start_vm_scan(db, org, targets, asset_ids=aids))
            if result:
                affected += len(targets)
                logger.info(
                    "rerun_nuclei_for_asset: org=%d scan=%s targets=%d",
                    org_id, result.get("scan_id"), len(targets),
                )
        except RuntimeError as e:
            # start_vm_scan is async; RuntimeError likely means we're already in an event loop.
            # Fall back to creating a new loop manually.
            if "asyncio.run" in str(e) or "event loop" in str(e):
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(start_vm_scan(db, org, targets, asset_ids=aids))
                    if result:
                        affected += len(targets)
                finally:
                    loop.close()
            else:
                logger.warning("rerun_nuclei_for_asset failed for org %d: %s", org_id, e)
        except Exception as e:
            logger.warning("rerun_nuclei_for_asset failed for org %d: %s", org_id, e)

    return affected, items


def register() -> None:
    """Register event-driven actions with the workflow engine. Idempotent."""
    workflow_engine.register_action("rerun_nuclei_for_asset", _action_rerun_nuclei_for_asset)
    logger.info("Scanner event actions registered")

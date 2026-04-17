"""Scheduled replanning of stale Adaptive Scan Plans.

Runs every 6h via the APScheduler in app.py. Walks every org and
recomputes plans for at most ``MAX_ASSETS_PER_ORG_PER_RUN`` stale
assets per org per invocation. Asset-level failures are logged and
swallowed so one bad asset can't take down the whole sweep.
"""
from __future__ import annotations

import asyncio
import logging
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.models import Organization
from services import scan_planner

logger = logging.getLogger(__name__)


# Per-org cap so the sweep can't accidentally dump 10k LLM calls in one
# run when a large customer's enrichment refresh invalidates the world.
# Spread across 6h intervals = up to ~200 assets/day/org via the sweep
# alone (manual /refresh and end-of-enrichment triggers are unbounded).
MAX_ASSETS_PER_ORG_PER_RUN = int(os.getenv("SCAN_PLAN_REPLAN_MAX_PER_ORG", "50"))
DEFAULT_MAX_AGE_HOURS = int(os.getenv("SCAN_PLAN_REFRESH_HOURS", "168"))


def replan_stale_plans() -> dict:
    """Sync entrypoint for APScheduler.

    Returns ``{"orgs_processed": n, "plans_recomputed": m, "failed": k}``.
    """
    db: Session = SessionLocal()
    orgs_processed = 0
    plans_recomputed = 0
    failed = 0

    try:
        org_ids = [o.id for o in db.query(Organization.id).all()]
        for org_id in org_ids:
            try:
                stale_ids = scan_planner.invalidate_stale_plans(
                    db, org_id, max_age_hours=DEFAULT_MAX_AGE_HOURS,
                )
            except Exception:
                logger.exception("replan_stale_plans: stale lookup failed for org %s", org_id)
                continue

            if not stale_ids:
                continue

            orgs_processed += 1
            for asset_id in stale_ids[:MAX_ASSETS_PER_ORG_PER_RUN]:
                try:
                    plan = asyncio.run(
                        scan_planner.compute_and_persist_scan_plan(
                            db, org_id, asset_id, force=False,
                        )
                    )
                    if plan is not None:
                        plans_recomputed += 1
                    else:
                        failed += 1
                except Exception:
                    logger.exception(
                        "replan_stale_plans: compute failed for asset %s (org %s)",
                        asset_id, org_id,
                    )
                    failed += 1

        logger.info(
            "replan_stale_plans: orgs=%d recomputed=%d failed=%d",
            orgs_processed, plans_recomputed, failed,
        )
    finally:
        db.close()

    return {
        "orgs_processed": orgs_processed,
        "plans_recomputed": plans_recomputed,
        "failed": failed,
    }

"""Adaptive Scan Planner API routes."""

import hashlib
import hmac
import logging
import os
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from models.models import Asset, Organization, Scan
from services import scan_planner
from services.scan_planner import generate_scan_plan, generate_batch_plans

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan-planner", tags=["Scan Planner"])


@router.get("/plan/{asset_id}")
async def get_plan(
    asset_id: int,
    provider: str = Query("anthropic", description="LLM provider for plan generation"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Generate an adaptive scan plan for a single asset."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    plan = await generate_scan_plan(db, org_id, asset_id, llm_provider=provider)
    return plan.to_dict()


@router.get("/plans")
async def get_batch_plans(
    top_n: int = Query(50, le=200, description="Number of top-risk assets to plan for"),
    provider: str = Query("anthropic", description="LLM provider for plan generation"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Generate adaptive scan plans for top N assets by risk."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    plans = await generate_batch_plans(db, org_id, top_n=top_n, llm_provider=provider)
    return [p.to_dict() for p in plans]


@router.post("/execute/{asset_id}")
async def execute_plan(
    asset_id: int,
    provider: str = Query("anthropic", description="LLM provider"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Generate and trigger execution of a scan plan for an asset."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")

    plan = await generate_scan_plan(db, org_id, asset_id, llm_provider=provider)

    if plan.skip_reason:
        return {"plan": plan.to_dict(), "executed": False, "reason": plan.skip_reason}

    # Trigger VM scan with the plan's nuclei tags
    nuclei_actions = [a for a in plan.actions if a.tool == "nuclei"]
    if nuclei_actions:
        from services.vm_scanner import start_vm_scan

        # start_vm_scan expects an Organization object
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(status_code=400, detail="Organization not found")

        scan_result = await start_vm_scan(
            db, org,
            targets=[plan.asset_hostname],
            asset_ids=[asset_id],
        )
        return {"plan": plan.to_dict(), "executed": True, "scan": scan_result}

    return {"plan": plan.to_dict(), "executed": False, "reason": "No executable actions in plan"}


# ── Persisted plan endpoints (PR 5 of Adaptive Scan Plan) ───────────


class PersistedPlanResponse(BaseModel):
    asset_id: int
    plan: dict | None
    version: int
    computed_at: datetime | None
    signature: str | None


class StalePlanRow(BaseModel):
    asset_id: int
    hostname: str | None
    last_enriched: datetime | None
    scan_plan_computed_at: datetime | None


class RefreshResponse(BaseModel):
    asset_id: int
    version: int
    risk_tier: str
    actions_count: int
    cached: bool


class InternalComputeRequest(BaseModel):
    """Bulk compute request from the scanner side at end of enrichment.

    HMAC-authenticated via X-Internal-Signature against
    INTERNAL_PLANNER_HMAC_SECRET so we don't reuse user JWTs from a
    container that doesn't have one.
    """
    org_id: int
    asset_ids: list[int]
    force: bool = False


class InternalComputeResponse(BaseModel):
    requested: int
    computed: int
    skipped_cached: int
    failed: int


def _verify_internal_signature(body_bytes: bytes, signature: str | None) -> None:
    """Constant-time HMAC check. Refuses unsigned bypass even when the
    secret is unset — a missing secret signals a misconfiguration that
    we should fail loudly on, not silently allow.
    """
    secret = os.getenv("INTERNAL_PLANNER_HMAC_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="Internal planner HMAC not configured")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing X-Internal-Signature")
    expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid X-Internal-Signature")


@router.get("/persisted/{asset_id}", response_model=PersistedPlanResponse)
async def get_persisted_plan(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Return the persisted plan for an asset (NULL when never computed).

    Distinct from ``GET /plan/{asset_id}``, which always re-invokes the
    planner. This route is the right one for UI surfaces that show "what
    will the scanner do for this asset" without paying the LLM cost on
    every page load.
    """
    asset = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Asset.id == asset_id, Scan.org_id.in_(org_ids))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return PersistedPlanResponse(
        asset_id=asset.id,
        plan=asset.scan_plan,
        version=asset.scan_plan_version or 0,
        computed_at=asset.scan_plan_computed_at,
        signature=asset.scan_plan_signature,
    )


@router.post("/refresh/{asset_id}", response_model=RefreshResponse)
async def refresh_persisted_plan(
    asset_id: int,
    force: bool = Query(True, description="Skip the signature cache"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Recompute and persist the plan for one asset.

    Default ``force=True`` — operators only hit this endpoint when they
    actually want a fresh plan; the cache-respecting path is the
    automatic enrichment-pipeline trigger.
    """
    asset = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Asset.id == asset_id, Scan.org_id.in_(org_ids))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    sig_before = asset.scan_plan_signature
    org_id_for_asset = asset.scan.org_id if asset.scan else org_ids[0]

    plan = await scan_planner.compute_and_persist_scan_plan(
        db, org_id_for_asset, asset_id, force=force,
    )
    if not plan:
        raise HTTPException(status_code=500, detail="Plan computation returned no result")

    db.refresh(asset)
    return RefreshResponse(
        asset_id=asset_id,
        version=asset.scan_plan_version or 0,
        risk_tier=plan.risk_tier,
        actions_count=len(plan.actions),
        cached=(asset.scan_plan_signature == sig_before and not force),
    )


@router.get("/stale", response_model=List[StalePlanRow])
async def list_stale_plans(
    max_age_hours: int = Query(168, ge=1),
    limit: int = Query(200, le=1000),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List assets whose plans are NULL or older than ``max_age_hours``."""
    out: list[StalePlanRow] = []
    for org_id in org_ids:
        if len(out) >= limit:
            break
        ids = scan_planner.invalidate_stale_plans(db, org_id, max_age_hours=max_age_hours)
        if not ids:
            continue
        rows = (
            db.query(
                Asset.id, Asset.hostname,
                Asset.last_enriched, Asset.scan_plan_computed_at,
            )
            .filter(Asset.id.in_(ids[: max(0, limit - len(out))]))
            .all()
        )
        for r in rows:
            out.append(StalePlanRow(
                asset_id=r.id, hostname=r.hostname,
                last_enriched=r.last_enriched,
                scan_plan_computed_at=r.scan_plan_computed_at,
            ))
    return out[:limit]


@router.post("/internal/compute", response_model=InternalComputeResponse)
async def internal_compute(
    request: Request,
    x_internal_signature: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """Bulk-compute plans. Auth via HMAC; called by the scanner pipeline.

    No JWT — this endpoint is meant for the in-cluster scanner container
    which doesn't carry a user identity. The HMAC secret is shared via
    INTERNAL_PLANNER_HMAC_SECRET in both deployments.
    """
    body_bytes = await request.body()
    _verify_internal_signature(body_bytes, x_internal_signature)

    try:
        payload = InternalComputeRequest.model_validate_json(body_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid body: {e}")

    computed = 0
    skipped = 0
    failed = 0

    for aid in payload.asset_ids:
        try:
            row = (
                db.query(Asset.scan_plan_signature)
                .filter(Asset.id == aid)
                .first()
            )
            sig_before = row[0] if row else None

            plan = await scan_planner.compute_and_persist_scan_plan(
                db, payload.org_id, aid, force=payload.force,
            )
            if plan is None:
                failed += 1
                continue

            row_after = (
                db.query(Asset.scan_plan_signature)
                .filter(Asset.id == aid)
                .first()
            )
            sig_after = row_after[0] if row_after else None

            if sig_before == sig_after and not payload.force:
                skipped += 1
            else:
                computed += 1
        except Exception:
            logger.exception("internal_compute: failed for asset %s", aid)
            failed += 1

    return InternalComputeResponse(
        requested=len(payload.asset_ids),
        computed=computed,
        skipped_cached=skipped,
        failed=failed,
    )

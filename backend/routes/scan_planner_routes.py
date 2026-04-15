"""Adaptive Scan Planner API routes."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from models.models import Organization
from services.scan_planner import generate_scan_plan, generate_batch_plans

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

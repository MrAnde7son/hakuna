"""Onboarding wizard API — track first-run progress and mark completion."""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user
from models.models import User, Scan, Campaign

router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


class StepCompleteRequest(BaseModel):
    step: str  # scan_uploaded | priorities_reviewed | campaign_created


@router.get("/status")
async def get_onboarding_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return current onboarding state for the authenticated user."""
    state = current_user.onboarding_state or {}

    # Auto-detect completed steps from real data
    has_scans = db.query(Scan).filter(Scan.org_id == current_user.org_id).first() is not None
    has_campaigns = db.query(Campaign).filter(Campaign.org_id == current_user.org_id).first() is not None

    if has_scans and not state.get("scan_uploaded"):
        state["scan_uploaded"] = True
    if has_campaigns and not state.get("campaign_created"):
        state["campaign_created"] = True

    return {
        "onboarding_completed": bool(current_user.onboarding_completed),
        "state": state,
        "has_scans": has_scans,
        "has_campaigns": has_campaigns,
    }


@router.post("/complete-step")
async def complete_onboarding_step(
    body: StepCompleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark an onboarding step as completed."""
    valid_steps = {"scan_uploaded", "priorities_reviewed", "campaign_created"}
    if body.step not in valid_steps:
        raise HTTPException(400, f"Invalid step. Valid: {', '.join(sorted(valid_steps))}")

    state = dict(current_user.onboarding_state or {})
    state[body.step] = True
    current_user.onboarding_state = state
    db.commit()

    return {"status": "ok", "state": state}


@router.post("/complete")
async def complete_onboarding(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark onboarding as fully completed (dismiss the wizard)."""
    current_user.onboarding_completed = True
    current_user.onboarding_state = {
        **(current_user.onboarding_state or {}),
        "completed_at": datetime.utcnow().isoformat(),
    }
    db.commit()

    return {"status": "ok", "onboarding_completed": True}


@router.post("/skip")
async def skip_onboarding(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Skip onboarding — marks as completed without doing the steps."""
    current_user.onboarding_completed = True
    current_user.onboarding_state = {
        **(current_user.onboarding_state or {}),
        "skipped": True,
        "completed_at": datetime.utcnow().isoformat(),
    }
    db.commit()

    return {"status": "ok", "onboarding_completed": True}

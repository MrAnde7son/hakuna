"""
Onboarding wizard API endpoints.

Handles:
- GET  /api/onboarding/options     — available industries, team functions, objectives
- GET  /api/onboarding/status      — whether onboarding is completed for current org
- POST /api/onboarding/recommend   — get package recommendations based on profile
- POST /api/onboarding/apply       — apply selected packages to the org
- GET  /api/onboarding/domain-info — attempt domain enrichment from corporate email
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from models.models import Organization
from services.onboarding_packages import (
    INDUSTRIES, TEAM_FUNCTIONS, OBJECTIVES, NOTIFICATION_OPTIONS,
    get_recommendations, apply_packages,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/onboarding", tags=["onboarding"])


# ── Schemas ──────────────────────────────────────────────────────

class RecommendRequest(BaseModel):
    industry: str | None = None
    org_size: str | None = None  # 1-50, 51-200, 201-1000, 1000+
    team_size: str | None = None  # 1-5, 6-15, 16-50, 50-100, 100+
    team_functions: list[str] = []
    objectives: list[str] = []

class ApplyRequest(BaseModel):
    industry: str | None = None
    org_size: str | None = None
    team_size: str | None = None
    team_functions: list[str] = []
    objectives: list[str] = []
    notification_prefs: list[str] = []
    # Allow user to deselect specific packages
    selected_packages: list[str] | None = None


# ── Endpoints ────────────────────────────────────────────────────

@router.get("/options")
async def get_onboarding_options():
    """Return all available options for the onboarding wizard."""
    return {
        "industries": INDUSTRIES,
        "team_functions": TEAM_FUNCTIONS,
        "objectives": OBJECTIVES,
        "notification_options": NOTIFICATION_OPTIONS,
        "org_sizes": [
            {"id": "1-50", "label": "1-50 employees"},
            {"id": "51-200", "label": "51-200 employees"},
            {"id": "201-1000", "label": "201-1,000 employees"},
            {"id": "1000+", "label": "1,000+ employees"},
        ],
        "team_sizes": [
            {"id": "1-5", "label": "1-5 people"},
            {"id": "6-15", "label": "6-15 people"},
            {"id": "16-50", "label": "16-50 people"},
            {"id": "50-100", "label": "50-100 people"},
            {"id": "100+", "label": "100+ people"},
        ],
    }


@router.get("/status")
async def get_onboarding_status(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Check if onboarding has been completed for the current org."""
    org_id = org_ids[0] if org_ids else current_user.org_id
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings = org.settings or {}
    onboarding = settings.get("onboarding", {})
    return {
        "completed": onboarding.get("completed", False),
        "profile": onboarding.get("profile"),
        "objectives": onboarding.get("objectives"),
    }


@router.post("/recommend")
async def recommend_packages(
    body: RecommendRequest,
    current_user = Depends(get_current_user),
):
    """Return recommended packages based on the user's profile and objectives."""
    result = get_recommendations(
        objectives=body.objectives,
        team_functions=body.team_functions,
        team_size=body.team_size or "6-15",
        industry=body.industry,
    )
    return result


@router.post("/apply")
async def apply_onboarding_packages(
    body: ApplyRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Apply selected onboarding packages — provisions all entities."""
    org_id = org_ids[0] if org_ids else current_user.org_id
    user_id = current_user.id

    # Use selected_packages if provided, otherwise use all objectives
    objectives = body.selected_packages if body.selected_packages else body.objectives

    profile = {
        "industry": body.industry,
        "org_size": body.org_size,
        "team_size": body.team_size,
        "team_functions": body.team_functions,
        "all_objectives": body.objectives,
    }

    created = apply_packages(
        db=db,
        org_id=org_id,
        user_id=user_id,
        objectives=objectives,
        team_functions=body.team_functions,
        team_size=body.team_size or "6-15",
        profile=profile,
        notification_prefs=body.notification_prefs or None,
    )

    return {
        "success": True,
        "created": created,
    }


@router.post("/skip")
async def skip_onboarding(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Mark onboarding as skipped so the wizard won't show again."""
    org_id = org_ids[0] if org_ids else current_user.org_id
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings = org.settings or {}
    settings["onboarding"] = {
        "completed": True,
        "skipped": True,
    }
    org.settings = settings
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(org, "settings")
    db.commit()
    return {"success": True}


@router.get("/domain-info")
async def lookup_domain_info(
    email: str | None = None,
    current_user = Depends(get_current_user),
):
    """
    Attempt to extract org info from a corporate email domain.
    Returns basic domain info — does NOT call external APIs.
    """
    target_email = email or (current_user.email or "")
    if not target_email or "@" not in target_email:
        return {"enriched": False}

    domain = target_email.split("@")[1].lower()

    # Skip free email providers
    free_providers = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "aol.com", "icloud.com", "mail.com", "protonmail.com",
        "proton.me", "zoho.com", "yandex.com", "gmx.com",
    }
    if domain in free_providers:
        return {"enriched": False, "is_free_email": True, "domain": domain}

    # Extract org name from domain
    parts = domain.split(".")
    org_name_guess = parts[0].replace("-", " ").replace("_", " ").title()

    return {
        "enriched": True,
        "domain": domain,
        "org_name_guess": org_name_guess,
        "is_free_email": False,
    }

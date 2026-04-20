"""Public, passcode-gated endpoints for external campaign collaborators.

These endpoints are the COUNTERPART to the admin-side endpoints in
campaign_routes.py. They're what the `/c/:shareToken` page on the frontend
talks to.

Auth model — intentionally separate from the main JWT flow:
  1. GET  /api/public/campaigns/{token}/meta   — anonymous, before unlock.
                                                  Returns just campaign name +
                                                  inviting org name.
  2. POST /api/public/campaigns/{token}/unlock — anonymous, accepts passcode.
                                                  On success, sets a
                                                  `guest_session` HttpOnly
                                                  cookie (JWT signed with
                                                  GUEST_JWT_SECRET).
  3. All other endpoints require the `guest_session` cookie via
     Depends(get_guest_context). No User record is ever produced.

Audit — every external action is logged via core.audit.log_audit with
`actor=None`, the inviter's org_id, and the external email as entity_name.
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from pydantic import BaseModel, constr
from sqlalchemy.orm import Session

from core.database import get_db
from core.audit import log_audit
from core.auth import GuestContext, get_guest_context
from core.tokens import (
    GUEST_SESSION_MINUTES, create_guest_session_token, verify_passcode,
    should_lock, next_lock_until, PASSCODE_FAILURE_THRESHOLD,
)
from models.models import (
    Campaign, CampaignShareLink, CampaignCollaborator, CampaignActivity,
    Organization, Finding,
)

router = APIRouter()


GUEST_COOKIE_NAME = "guest_session"


# ─── Helpers ──────────────────────────────────────────────────────────

def _load_link_by_token(db: Session, share_token: str) -> CampaignShareLink:
    link = db.query(CampaignShareLink).filter(
        CampaignShareLink.share_token == share_token,
    ).first()
    if not link or link.revoked_at is not None:
        # Don't distinguish revoked vs missing — same 404 to callers.
        raise HTTPException(status_code=404, detail="Link not found")
    if link.expires_at is not None and link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Link expired")
    return link


def _activity_to_dict(a: CampaignActivity) -> dict:
    return {
        "id": a.id,
        "author_type": a.author_type,
        "author_display_name": a.author_display_name,
        "kind": a.kind,
        "body": a.body,
        "extra": a.extra or {},
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


# ─── Pydantic ─────────────────────────────────────────────────────────

class UnlockBody(BaseModel):
    passcode: constr(strip_whitespace=True, min_length=4, max_length=32)


class ActivityPostBody(BaseModel):
    body: constr(strip_whitespace=True, min_length=1, max_length=5000)
    kind: str = "comment"


# ─── Endpoints ────────────────────────────────────────────────────────

@router.get("/api/public/campaigns/{share_token}/meta")
def public_meta(share_token: str, db: Session = Depends(get_db)):
    """Before-unlock metadata — just enough to render the unlock screen.

    Deliberately does NOT leak campaign content (findings, description,
    attached automations). The page name + inviting org + locked state are
    enough to tell the external "yes, this is the campaign I was emailed about".
    """
    link = _load_link_by_token(db, share_token)
    campaign = db.query(Campaign).filter(Campaign.id == link.campaign_id).first()
    org = db.query(Organization).filter(Organization.id == link.org_id).first()
    locked_out = link.lock_until is not None and link.lock_until > datetime.utcnow()
    return {
        "campaign_name": campaign.name if campaign else "",
        "invited_by_org_name": org.name if org else "",
        "requires_passcode": True,
        "locked_out": locked_out,
        "lock_until": link.lock_until.isoformat() if link.lock_until else None,
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
    }


@router.post("/api/public/campaigns/{share_token}/unlock")
def public_unlock(
    share_token: str,
    body: UnlockBody,
    response: Response,
    db: Session = Depends(get_db),
):
    """Verify passcode; on success, set a guest_session HttpOnly cookie.

    Brute-force protection: 5 consecutive failures locks the link for 15 min.
    Successful unlock resets the counter.
    """
    link = _load_link_by_token(db, share_token)

    if link.lock_until is not None and link.lock_until > datetime.utcnow():
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again at {link.lock_until.isoformat()}",
        )

    if not verify_passcode(body.passcode, link.passcode_hash):
        link.failed_attempts = (link.failed_attempts or 0) + 1
        if should_lock(link.failed_attempts):
            link.lock_until = next_lock_until()
            link.failed_attempts = 0
        db.commit()
        log_audit(
            db, "failed_unlock", "campaign_share_link", link.id,
            entity_name="", actor=None, org_id=link.org_id,
        )
        raise HTTPException(status_code=401, detail="Incorrect passcode")

    # Success: reset counter, resolve collaborator record, find email for audit.
    link.failed_attempts = 0
    link.lock_until = None
    collab = (
        db.query(CampaignCollaborator)
        .filter(CampaignCollaborator.share_link_id == link.id)
        .first()
    )
    if collab:
        collab.last_seen_at = datetime.utcnow()
    db.commit()

    token = create_guest_session_token(
        share_link_id=link.id,
        campaign_id=link.campaign_id,
        org_id=link.org_id,
        external_email=(collab.external_email if collab else None),
    )
    response.set_cookie(
        key=GUEST_COOKIE_NAME,
        value=token,
        max_age=GUEST_SESSION_MINUTES * 60,
        httponly=True,
        secure=True,       # Cookies only over HTTPS in production
        samesite="lax",    # Allow top-level navigations; same-origin for API calls
    )
    log_audit(
        db, "unlock", "campaign_share_link", link.id,
        entity_name=(collab.external_email if collab else ""),
        actor=None, org_id=link.org_id,
    )
    return {"status": "ok"}


@router.post("/api/public/campaigns/{share_token}/logout")
def public_logout(response: Response):
    response.delete_cookie(GUEST_COOKIE_NAME)
    return {"status": "ok"}


@router.get("/api/public/campaigns/{share_token}")
def public_campaign_payload(
    share_token: str,
    ctx: GuestContext = Depends(get_guest_context),
    db: Session = Depends(get_db),
):
    """Full campaign payload for the unlocked external user.

    Guards: the share_token in the URL must match the share_link carried in
    the guest_session cookie. This prevents a cookie issued for token A from
    being used with URL token B.
    """
    link = _load_link_by_token(db, share_token)
    if link.id != ctx.share_link_id:
        raise HTTPException(status_code=403, detail="Session mismatch")

    campaign = db.query(Campaign).filter(Campaign.id == ctx.campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    org = db.query(Organization).filter(Organization.id == ctx.org_id).first()

    # Minimal findings view — scoped to the campaign's attached findings only,
    # so there's no path to see cross-campaign data even if cookie were stolen.
    finding_ids = [cf.finding_id for cf in campaign.findings] if campaign.findings else []
    findings = (
        db.query(Finding).filter(Finding.id.in_(finding_ids)).limit(100).all()
        if finding_ids else []
    )

    return {
        "campaign": {
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "status": campaign.status,
        },
        "invited_by_org_name": org.name if org else "",
        "permissions": ctx.permissions,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "severity_label": getattr(f, "severity_label", None),
                "plugin_name": f.plugin_name,
                "description": getattr(f, "description", None),
                "asset_id": f.asset_id,
            }
            for f in findings
        ],
    }


@router.get("/api/public/campaigns/{share_token}/activity")
def public_list_activity(
    share_token: str,
    page: int = 1,
    page_size: int = 100,
    ctx: GuestContext = Depends(get_guest_context),
    db: Session = Depends(get_db),
):
    link = _load_link_by_token(db, share_token)
    if link.id != ctx.share_link_id:
        raise HTTPException(status_code=403, detail="Session mismatch")

    total = db.query(CampaignActivity).filter(CampaignActivity.campaign_id == ctx.campaign_id).count()
    rows = (
        db.query(CampaignActivity)
        .filter(CampaignActivity.campaign_id == ctx.campaign_id)
        .order_by(CampaignActivity.created_at.asc())
        .offset(max(0, (page - 1) * page_size))
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "activity": [_activity_to_dict(a) for a in rows],
    }


@router.post("/api/public/campaigns/{share_token}/activity")
def public_post_activity(
    share_token: str,
    body: ActivityPostBody,
    ctx: GuestContext = Depends(get_guest_context),
    db: Session = Depends(get_db),
):
    link = _load_link_by_token(db, share_token)
    if link.id != ctx.share_link_id:
        raise HTTPException(status_code=403, detail="Session mismatch")
    if not (ctx.permissions or {}).get("comment", True):
        raise HTTPException(status_code=403, detail="Comments not permitted")

    collab = (
        db.query(CampaignCollaborator)
        .filter(CampaignCollaborator.share_link_id == link.id)
        .first()
    )
    display_name = (collab.external_name if collab else None) or ctx.external_email or "External"

    entry = CampaignActivity(
        campaign_id=ctx.campaign_id,
        author_type="external",
        author_collaborator_id=collab.id if collab else None,
        author_display_name=display_name,
        kind="comment",  # phase 1 is comment-only from externals
        body=body.body,
        extra={},
    )
    db.add(entry)
    db.flush()
    log_audit(
        db, "comment", "campaign_activity", entry.id,
        entity_name=f"campaign:{ctx.campaign_id}",
        actor=None, org_id=ctx.org_id,
    )
    if collab:
        collab.last_seen_at = datetime.utcnow()
    db.commit()
    db.refresh(entry)
    return _activity_to_dict(entry)

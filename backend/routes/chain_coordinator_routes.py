"""Chain Coordinator — operator-facing API.

Today exposes the approval queue for `requires_approval=True`
hypotheses (currently only `cred_found`). The AttackPaths UI reads
this list to surface a "ready to validate" badge and call back to
approve / reject decisions.

See `docs/cross-scan-chain-coordinator-plan.md` (Phase 3 dispatch
gating, item 4: "explicit operator approval gate").
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, get_current_user
from core.database import get_db
from models.models import Asset, CoordinatorPendingApproval, Organization
from services.audit_auto_trigger import AUTO_AUDIT_SETTING_KEYS

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chain-coordinator", tags=["chain-coordinator"])


def _serialize(row: CoordinatorPendingApproval, asset_label: str | None) -> dict:
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "asset_label": asset_label,
        "pattern": row.pattern,
        "protocol": row.protocol,
        "mission": row.mission,
        "rationale": row.rationale,
        "score": float(row.score or 0.0),
        "score_factors": row.score_factors or {},
        "status": row.status,
        "decided_by": row.decided_by,
        "decided_at": row.decided_at.isoformat() if row.decided_at else None,
        "consumed_by_scan_id": row.consumed_by_scan_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


@router.get("/settings")
async def list_settings(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Return the discoverable set of `auto_audit_*` toggles plus the
    caller's current org-level values. Lets the UI render a settings
    panel without hard-coding the key list (operators can otherwise
    set/unset these only via the org settings JSON, which is not
    discoverable).
    """
    if org_ids is None or not org_ids:
        return {"keys": list(AUTO_AUDIT_SETTING_KEYS.keys()), "values": {}}
    org = db.query(Organization).filter(Organization.id == org_ids[0]).first()
    settings = (org.settings or {}) if org else {}
    items = []
    for key, meta in AUTO_AUDIT_SETTING_KEYS.items():
        explicit = settings.get(key)
        items.append({
            "key": key,
            "description": meta["description"],
            "default": meta["default"],
            "value": bool(explicit) if explicit is not None else meta["default"],
            "explicit": explicit is not None,
        })
    return {"items": items}


@router.get("/pending-approvals")
async def list_pending_approvals(
    status: Optional[str] = "pending",
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List approval-gated hypotheses for the caller's accessible orgs.

    Defaults to `status=pending`. Pass `status=all` to see decided
    rows too — useful for an audit trail in the UI.
    """
    q = db.query(CoordinatorPendingApproval)
    if org_ids is not None:
        q = q.filter(CoordinatorPendingApproval.org_id.in_(org_ids))
    if status and status != "all":
        q = q.filter(CoordinatorPendingApproval.status == status)
    rows = q.order_by(
        CoordinatorPendingApproval.score.desc(),
        CoordinatorPendingApproval.created_at.desc(),
    ).limit(200).all()

    asset_ids = {r.asset_id for r in rows if r.asset_id}
    labels: dict[int, str] = {}
    if asset_ids:
        for aid, hostname, ip in db.query(Asset.id, Asset.hostname, Asset.ip).filter(
            Asset.id.in_(asset_ids),
        ).all():
            labels[aid] = hostname or (str(ip) if ip else f"asset#{aid}")

    return {
        "items": [_serialize(r, labels.get(r.asset_id)) for r in rows],
        "count": len(rows),
    }


def _load_for_decision(
    db: Session, approval_id: int, org_ids: Optional[list],
) -> CoordinatorPendingApproval:
    row = db.query(CoordinatorPendingApproval).filter(
        CoordinatorPendingApproval.id == approval_id,
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if org_ids is not None and row.org_id not in org_ids:
        raise HTTPException(status_code=403, detail="Approval not in accessible org")
    if row.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Approval already {row.status}; cannot re-decide",
        )
    return row


@router.post("/pending-approvals/{approval_id}/approve")
async def approve_pending(
    approval_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Approve a pending hypothesis. The next coordinator tick honors
    the decision and dispatches via the normal path. We do NOT dispatch
    inline — the dispatch path needs the relay-picker, cooldown stamp,
    and DB-backed debounce that already live in `_dispatch_hypothesis`.
    """
    row = _load_for_decision(db, approval_id, org_ids)
    row.status = "approved"
    row.decided_by = (current_user or {}).get("email") or (current_user or {}).get("sub")
    row.decided_at = datetime.utcnow()
    db.commit()
    logger.info(
        "chain_coordinator approval=%d approved by %s pattern=%s asset=%s",
        approval_id, row.decided_by, row.pattern, row.asset_id,
    )
    return {"ok": True, "approval": _serialize(row, None)}


@router.post("/pending-approvals/{approval_id}/reject")
async def reject_pending(
    approval_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Reject a pending hypothesis. The coordinator will not re-prompt
    for the same `(asset, pattern, protocol, mission)` until the row
    is removed.
    """
    row = _load_for_decision(db, approval_id, org_ids)
    row.status = "rejected"
    row.decided_by = (current_user or {}).get("email") or (current_user or {}).get("sub")
    row.decided_at = datetime.utcnow()
    db.commit()
    logger.info(
        "chain_coordinator approval=%d rejected by %s pattern=%s asset=%s",
        approval_id, row.decided_by, row.pattern, row.asset_id,
    )
    return {"ok": True, "approval": _serialize(row, None)}

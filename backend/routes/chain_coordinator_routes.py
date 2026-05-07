"""Chain Coordinator — operator-facing API.

Surfaces the approval queue for ``requires_approval=True`` hypotheses
(currently only ``cred_found``). The AttackPaths UI reads this list to
render a "ready to validate" badge and call back to approve / reject
decisions.

As of mig 068 these approvals live in the unified ``agent_approvals``
table (``source='coordinator'``) rather than the legacy
``coordinator_pending_approvals`` table. The routes below preserve the
original response shape so AttackPaths.jsx keeps working without a
frontend change — coordinator-specific fields (pattern / protocol /
mission / score / score_factors / asset_id / rationale) get pulled out
of ``tool_input`` JSON. The unified ``/api/agents/approvals`` queue
sees these rows automatically because it doesn't filter by source.

See ``docs/cross-scan-chain-coordinator-plan.md`` (Phase 3 dispatch
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
from models.models import AgentApproval, Asset, Organization
from services.audit_auto_trigger import AUTO_AUDIT_SETTING_KEYS

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chain-coordinator", tags=["chain-coordinator"])


def _serialize(row: AgentApproval, asset_label: Optional[str]) -> dict:
    """Pull coordinator-shaped fields out of the unified approval row.

    The frontend's AttackPaths.jsx expects the legacy
    ``CoordinatorPendingApproval`` shape (pattern/protocol/mission at
    top level, decided_by as a string, etc.). We preserve that shape so
    the UI doesn't need a parallel migration.
    """
    ti = row.tool_input or {}
    decided_by_id = row.decided_by
    return {
        "id": row.id,
        "asset_id": ti.get("asset_id"),
        "asset_label": asset_label,
        "pattern": ti.get("pattern"),
        "protocol": ti.get("protocol"),
        "mission": ti.get("mission"),
        "rationale": ti.get("rationale"),
        "score": float(ti.get("score") or 0.0),
        "score_factors": ti.get("score_factors") or {},
        "status": row.status,
        # Frontend rendered the legacy decided_by (a string email). Now
        # decided_by is a User.id; we look up the email lazily below
        # only on the decision endpoints, which is where the value is
        # written. List endpoint just returns the raw id stringified —
        # the AttackPaths queue UI doesn't show it.
        "decided_by": str(decided_by_id) if decided_by_id is not None else None,
        "decided_at": row.decided_at.isoformat() if row.decided_at else None,
        "consumed_by_scan_id": ti.get("consumed_by_scan_id"),
        "created_at": row.requested_at.isoformat() if row.requested_at else None,
        "last_seen_at": ti.get("last_seen_at"),
    }


def _coordinator_query(db: Session, org_ids: Optional[list]):
    q = db.query(AgentApproval).filter(AgentApproval.source == "coordinator")
    if org_ids is not None:
        q = q.filter(AgentApproval.org_id.in_(org_ids))
    return q


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
    q = _coordinator_query(db, org_ids)
    if status and status != "all":
        q = q.filter(AgentApproval.status == status)

    # Order by requested_at desc (newest first). Score-based ordering
    # would need PG-specific JSON extraction — the operator queue is
    # small enough that chronological order is fine.
    rows = q.order_by(AgentApproval.requested_at.desc()).limit(200).all()

    asset_ids = {(r.tool_input or {}).get("asset_id") for r in rows}
    asset_ids = {aid for aid in asset_ids if aid}
    labels: dict[int, str] = {}
    if asset_ids:
        for aid, hostname, ip in db.query(Asset.id, Asset.hostname, Asset.ip).filter(
            Asset.id.in_(asset_ids),
        ).all():
            labels[aid] = hostname or (str(ip) if ip else f"asset#{aid}")

    return {
        "items": [_serialize(r, labels.get((r.tool_input or {}).get("asset_id"))) for r in rows],
        "count": len(rows),
    }


def _load_for_decision(
    db: Session, approval_id: int, org_ids: Optional[list],
) -> AgentApproval:
    row = db.query(AgentApproval).filter(
        AgentApproval.id == approval_id,
        AgentApproval.source == "coordinator",
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
    row.decided_by = getattr(current_user, "id", None) if current_user else None
    row.decided_at = datetime.utcnow()
    db.commit()
    ti = row.tool_input or {}
    logger.info(
        "chain_coordinator approval=%d approved by user=%s pattern=%s asset=%s",
        approval_id, row.decided_by, ti.get("pattern"), ti.get("asset_id"),
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
    row.decided_by = getattr(current_user, "id", None) if current_user else None
    row.decided_at = datetime.utcnow()
    db.commit()
    ti = row.tool_input or {}
    logger.info(
        "chain_coordinator approval=%d rejected by user=%s pattern=%s asset=%s",
        approval_id, row.decided_by, ti.get("pattern"), ti.get("asset_id"),
    )
    return {"ok": True, "approval": _serialize(row, None)}

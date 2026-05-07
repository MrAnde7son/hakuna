"""Org-shared memory API.

Read/list/forget endpoints over the cross-agent memory layer in
`services/org_memory.py`. Every endpoint scopes by org_ids returned from
`get_accessible_org_ids` so MSSP parents can only see their own / their
clients' memory.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, require_auth
from core.database import get_db
from models.models import User
from services import org_memory

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/org-memory", tags=["org-memory"])


class RememberRequest(BaseModel):
    namespace: str = Field(..., min_length=1, max_length=64)
    key: str = Field(..., min_length=1, max_length=255)
    value: Any
    evidence: Optional[dict] = None
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    ttl_days: Optional[int] = Field(None, ge=1, le=365 * 5)


def _resolve_org_id(
    org_ids: Optional[list[int]],
    user: User,
) -> int:
    """Pick the effective org for write/list ops.

    superadmin without X-Org-Context → uses their own org_id.
    Otherwise: use the first accessible org (X-Org-Context narrows this).
    """
    if org_ids:
        return org_ids[0]
    if user.org_id:
        return user.org_id
    raise HTTPException(400, "No org context available")


@router.get("/namespaces")
async def list_namespaces(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """List active namespaces with fact counts for the caller's orgs."""
    org_id = _resolve_org_id(org_ids, user)
    return {"namespaces": org_memory.list_namespaces(db, org_id=org_id)}


@router.get("/{namespace}")
async def list_facts(
    namespace: str,
    limit: int = 100,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """List active facts in a namespace, newest first."""
    org_id = _resolve_org_id(org_ids, user)
    facts = org_memory.recall(db, org_id=org_id, namespace=namespace, limit=limit)
    return {"namespace": namespace, "facts": facts, "count": len(facts)}


@router.get("/{namespace}/{key}/history")
async def fact_history(
    namespace: str,
    key: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """Return the full supersede chain for a key, oldest first."""
    org_id = _resolve_org_id(org_ids, user)
    chain = org_memory.history(db, org_id=org_id, namespace=namespace, key=key)
    return {"namespace": namespace, "key": key, "history": chain, "count": len(chain)}


@router.post("")
async def remember_fact(
    body: RememberRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """Persist a new fact (admin/analyst-driven). Supersedes prior key value."""
    if user.role not in ("superadmin", "org_admin", "analyst"):
        raise HTTPException(403, "Analyst+ role required to add facts")
    org_id = _resolve_org_id(org_ids, user)
    fact = org_memory.remember(
        db,
        org_id=org_id,
        namespace=body.namespace,
        key=body.key,
        value=body.value,
        evidence=body.evidence,
        confidence=body.confidence,
        ttl_days=body.ttl_days,
    )
    db.commit()
    return {"id": fact.id, "namespace": body.namespace, "key": body.key, "status": "remembered"}


class PromoteRequest(BaseModel):
    target_namespace: str = Field(..., min_length=1, max_length=64)
    target_key: Optional[str] = Field(None, min_length=1, max_length=255)
    confidence: float = Field(0.85, ge=0.0, le=1.0)


@router.post("/{namespace}/{key}/promote")
async def promote_fact(
    namespace: str,
    key: str,
    body: PromoteRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """Promote a low-confidence suggestion into a real, agent-visible namespace.

    Mines from `behavior_suggestions` typically — but works on any source
    namespace. Inserts a new fact in the target namespace at higher
    confidence (default 0.85), then forgets the source so the suggestion
    list shrinks. Both writes are append-only; full history survives.
    """
    if user.role not in ("superadmin", "org_admin", "analyst"):
        raise HTTPException(403, "Promotion requires analyst+ role")
    org_id = _resolve_org_id(org_ids, user)

    source = org_memory.recall(db, org_id=org_id, namespace=namespace, key=key, limit=1)
    if not source:
        raise HTTPException(404, "No active fact at that namespace/key")
    src = source[0]

    target_key = body.target_key or key
    promoted = org_memory.remember(
        db,
        org_id=org_id,
        namespace=body.target_namespace,
        key=target_key,
        value=src["value"],
        evidence={
            "promoted_from": {"namespace": namespace, "key": key, "id": src["id"]},
            "promoted_by_user_id": user.id,
        },
        confidence=body.confidence,
    )
    org_memory.forget(db, org_id=org_id, namespace=namespace, key=key)
    db.commit()
    return {
        "promoted_id": promoted.id,
        "target_namespace": body.target_namespace,
        "target_key": target_key,
        "status": "promoted",
    }


@router.delete("/{namespace}/{key}")
async def forget_fact(
    namespace: str,
    key: str,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
    org_ids: Optional[list[int]] = Depends(get_accessible_org_ids),
):
    """Forget (supersede with sentinel) a key. Admin-only."""
    if user.role not in ("superadmin", "org_admin"):
        raise HTTPException(403, "Admin role required")
    org_id = _resolve_org_id(org_ids, user)
    count = org_memory.forget(db, org_id=org_id, namespace=namespace, key=key)
    db.commit()
    return {"forgotten": count, "namespace": namespace, "key": key}

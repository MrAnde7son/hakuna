"""Org activity feed — agent-authored narrative stream.

The feed is the home surface for the "agent at the center of action"
UX. Entries are written by agents through the ``post_feed_entry`` tool;
this router surfaces them to the UI and lets the user mark them as
read, acted on, or dismissed.

Org isolation: every query filters by the user's accessible org IDs.
The MSP parent-child case (a parent operator viewing a child's feed)
already works via ``get_accessible_org_ids`` returning the full
descendant set.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, require_auth
from core.database import get_db
from models.models import Agent, OrgFeedEntry, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/feed", tags=["feed"])


class FeedActionDecision(BaseModel):
    status: str = Field(..., description="acted | dismissed")


class FeedEntryOut(BaseModel):
    id: int
    org_id: int
    agent_id: Optional[int]
    agent_name: Optional[str]
    agent_run_id: Optional[int]
    kind: str
    headline: str
    body_md: Optional[str]
    event_type: Optional[str]
    event_ref: dict
    proposed_actions: list
    severity: str
    status: str
    is_read: bool
    created_at: datetime


def _serialize(entry: OrgFeedEntry, agent_name: Optional[str], user_id: int) -> FeedEntryOut:
    read_by = entry.read_by or []
    return FeedEntryOut(
        id=entry.id,
        org_id=entry.org_id,
        agent_id=entry.agent_id,
        agent_name=agent_name,
        agent_run_id=entry.agent_run_id,
        kind=entry.kind,
        headline=entry.headline,
        body_md=entry.body_md,
        event_type=entry.event_type,
        event_ref=entry.event_ref or {},
        proposed_actions=entry.proposed_actions or [],
        severity=entry.severity,
        status=entry.status,
        is_read=user_id in read_by,
        created_at=entry.created_at,
    )


@router.get("", response_model=list[FeedEntryOut])
def list_feed(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="open | acted | dismissed | expired"),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Newest-first list of feed entries for the user's accessible orgs."""
    if not org_ids:
        return []

    q = db.query(OrgFeedEntry).filter(OrgFeedEntry.org_id.in_(org_ids))
    if status:
        q = q.filter(OrgFeedEntry.status == status)
    if severity:
        q = q.filter(OrgFeedEntry.severity == severity)
    if event_type:
        q = q.filter(OrgFeedEntry.event_type == event_type)

    entries = (
        q.order_by(desc(OrgFeedEntry.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Resolve agent names in one query.
    agent_ids = {e.agent_id for e in entries if e.agent_id is not None}
    name_by_id: dict[int, str] = {}
    if agent_ids:
        for aid, name in db.query(Agent.id, Agent.name).filter(Agent.id.in_(agent_ids)).all():
            name_by_id[aid] = name

    return [
        _serialize(e, name_by_id.get(e.agent_id), current_user.id)
        for e in entries
    ]


@router.get("/unread-count")
def unread_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Count of open + unread entries — drives the home-nav badge."""
    if not org_ids:
        return {"count": 0}
    # Pull the candidate set (open entries only) and filter in Python on
    # ``read_by`` containment. JSONB containment ops would be faster but
    # the open-entry set is small (UI-bound) and the SQLite test path
    # doesn't have JSONB operators.
    rows = (
        db.query(OrgFeedEntry.read_by)
        .filter(
            OrgFeedEntry.org_id.in_(org_ids),
            OrgFeedEntry.status == "open",
        )
        .all()
    )
    count = sum(1 for (read_by,) in rows if current_user.id not in (read_by or []))
    return {"count": count}


@router.post("/{entry_id}/read")
def mark_read(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Stamp the current user's id into ``read_by``. Idempotent."""
    entry = (
        db.query(OrgFeedEntry)
        .filter(OrgFeedEntry.id == entry_id, OrgFeedEntry.org_id.in_(org_ids or [0]))
        .first()
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Feed entry not found")

    read_by = list(entry.read_by or [])
    if current_user.id not in read_by:
        read_by.append(current_user.id)
        entry.read_by = read_by
        db.commit()
    return {"id": entry.id, "is_read": True}


def _load_templates() -> list[dict]:
    """List form of the templates, for the bootstrap route. Wraps the
    shared dict loader in ``services.agent_dispatcher`` so the dispatcher
    and the route share one source of truth + parse path.
    """
    from services.agent_dispatcher import load_templates_by_name
    return list(load_templates_by_name().values())


class BootstrapRequest(BaseModel):
    only: Optional[list[str]] = Field(None, description="Restrict to these template names. Default: all.")
    overwrite: bool = Field(False, description="If true, overwrite existing agents' system_prompt + tools. Use with care — wipes any operator edits.")


@router.post("/agents/bootstrap")
def bootstrap_agents(
    body: BootstrapRequest = BootstrapRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Create the event-driven feed agents in the caller's org from
    ``backend/config/feed_agent_templates.json``.

    Idempotent by default: existing agents (matched by ``(org_id, name)``)
    are left alone. Pass ``overwrite=true`` to refresh ``system_prompt`` +
    ``tools`` from the template — useful when a prompt is iterated.

    Targets the user's primary org (``current_user.org_id``). MSP parents
    can re-run for each child via the org-context header; this endpoint
    doesn't fan out.
    """
    if current_user.role != "org_admin" and current_user.role != "platform_admin":
        raise HTTPException(status_code=403, detail="Only org admins can bootstrap feed agents.")

    target_org_id = current_user.org_id
    if not target_org_id or target_org_id not in (org_ids or []):
        raise HTTPException(status_code=400, detail="No org context for bootstrap.")

    templates = _load_templates()
    if body.only:
        wanted = set(body.only)
        templates = [t for t in templates if t.get("name") in wanted]
    if not templates:
        return {"created": [], "updated": [], "skipped": [], "note": "No matching templates."}

    created, updated, skipped = [], [], []
    for tpl in templates:
        name = tpl.get("name")
        if not name:
            continue
        existing = (
            db.query(Agent)
            .filter(Agent.org_id == target_org_id, Agent.name == name)
            .first()
        )
        if existing is None:
            agent = Agent(
                org_id=target_org_id,
                name=name,
                description=tpl.get("description"),
                system_prompt=tpl.get("system_prompt") or "",
                tools=tpl.get("tools") or [],
                guardrails=tpl.get("guardrails") or {},
                model=tpl.get("model") or "vertex/gemini-2.5-pro",
            )
            db.add(agent)
            db.flush()
            created.append({"name": name, "id": agent.id})
        elif body.overwrite:
            existing.description = tpl.get("description") or existing.description
            existing.system_prompt = tpl.get("system_prompt") or existing.system_prompt
            existing.tools = tpl.get("tools") or existing.tools
            existing.guardrails = tpl.get("guardrails") or existing.guardrails
            existing.model = tpl.get("model") or existing.model
            db.flush()
            updated.append({"name": name, "id": existing.id})
        else:
            skipped.append({"name": name, "id": existing.id, "reason": "exists"})
    db.commit()
    return {"created": created, "updated": updated, "skipped": skipped}


# ── Feed-page chat context ────────────────────────────────────────
#
# The feed page composes a chat that delegates to the Security Copilot
# (``/api/copilot/conversations/{id}/message``). To anchor the assistant
# on what the user is looking at we expose a small endpoint that returns
# the formatted recent-feed block the frontend then passes via the
# copilot's ``context`` field. Keeping the formatting server-side means
# the prompt contract (IDs, severities, references) stays consistent
# regardless of which surface asks for it.


def _format_feed_context(entries: list[OrgFeedEntry], name_by_id: dict[int, str]) -> str:
    if not entries:
        return "(no recent feed entries)"
    import json as _json
    lines: list[str] = []
    for e in entries:
        ref = _json.dumps(e.event_ref or {}, sort_keys=True, default=str) if e.event_ref else "{}"
        body = (e.body_md or "").strip().replace("\n", " ")
        if len(body) > 240:
            body = body[:240] + "…"
        lines.append(
            f"#{e.id} [{e.severity}/{e.kind}] {e.headline}\n"
            f"   event={e.event_type or '-'} ref={ref} agent={name_by_id.get(e.agent_id) or '-'} "
            f"created={e.created_at.isoformat() if e.created_at else '-'}\n"
            f"   {body}"
        )
    return "\n".join(lines)


@router.get("/chat-context")
def feed_chat_context(
    size: int = Query(5, ge=0, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Return the recent-feed context block the feed-page chat passes to
    the copilot as its ``context`` field. The block is a stable, machine-
    readable summary keyed by feed entry id so the assistant can resolve
    references like 'that scan' or 'the latest critical' to real IDs.
    """
    if not org_ids or size <= 0:
        return {"context": ""}

    recent = (
        db.query(OrgFeedEntry)
        .filter(OrgFeedEntry.org_id.in_(org_ids))
        .order_by(desc(OrgFeedEntry.created_at))
        .limit(size)
        .all()
    )
    name_by_id: dict[int, str] = {}
    agent_ids = {e.agent_id for e in recent if e.agent_id is not None}
    if agent_ids:
        for aid, name in db.query(Agent.id, Agent.name).filter(Agent.id.in_(agent_ids)).all():
            name_by_id[aid] = name

    block = (
        "[feed_chat_context]\n"
        "The user is on the activity feed page. Use these recent feed entries "
        "to anchor references like 'that scan' or 'the latest critical' to real IDs. "
        "Don't restate the block back at the user.\n"
        "──── recent feed (most recent first) ────\n"
        f"{_format_feed_context(recent, name_by_id)}"
    )
    return {"context": block}


@router.post("/{entry_id}/decision")
def record_decision(
    entry_id: int,
    decision: FeedActionDecision,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auth),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """User clicked through, dismissed, or otherwise resolved this entry.

    The actual approval (if the entry references one in proposed_actions)
    is handled by the existing ``/api/agents/approvals`` endpoint — this
    just stamps the feed entry's status so the UI can stop highlighting it.
    """
    if decision.status not in ("acted", "dismissed"):
        raise HTTPException(status_code=400, detail="status must be 'acted' or 'dismissed'")

    entry = (
        db.query(OrgFeedEntry)
        .filter(OrgFeedEntry.id == entry_id, OrgFeedEntry.org_id.in_(org_ids or [0]))
        .first()
    )
    if entry is None:
        raise HTTPException(status_code=404, detail="Feed entry not found")

    entry.status = decision.status
    read_by = list(entry.read_by or [])
    if current_user.id not in read_by:
        read_by.append(current_user.id)
        entry.read_by = read_by
    db.commit()
    return {"id": entry.id, "status": entry.status}

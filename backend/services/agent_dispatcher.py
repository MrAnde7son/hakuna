"""Event → agent dispatcher.

Maps system events (``scan_complete``, ``asset_created``, ``validated_chain``,
…) to the agent that should reason about them and post a feed entry.

The agent is looked up by a magic name within the org. To wire an org for
event-driven narration the operator just creates an ``Agent`` row named
e.g. ``triage_scan_results`` with the right system prompt + tool list;
no separate "template" or "trigger" config table needed for v1.

Runs are dispatched async via ``job_manager.dispatch`` so emit sites
(post_ingest, asset upsert, chain coordinator) don't block on LLM
latency. A per-org per-event debounce window collapses bursty emits
(e.g. multi-batch EASM ingest) into a single agent run.

Composition with the existing approval gate: agents that draft
``HARD_WRITE`` actions create rows in ``agent_approvals`` as usual; the
``post_feed_entry`` tool then references those approval IDs in
``proposed_actions`` so the inline approve/reject button on the feed
entry resolves through the existing queue.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy.orm import Session

from models.models import Agent, AgentRun

logger = logging.getLogger(__name__)


# ── Template loader (shared with the bootstrap route) ──────────────


_TEMPLATES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "feed_agent_templates.json",
)


def load_templates_by_name() -> dict[str, dict]:
    """Load feed agent templates keyed by name. Read on every call so a
    config edit reaches the next dispatch without a server restart.
    Returns an empty dict on parse failure rather than raising — a bad
    config file shouldn't take down the event pipeline.
    """
    try:
        with open(_TEMPLATES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("agent_dispatcher: failed to load templates: %s", e)
        return {}
    out: dict[str, dict] = {}
    for tpl in data.get("templates", []):
        name = tpl.get("name")
        if name:
            out[name] = tpl
    return out


# ── Event → agent-name map ─────────────────────────────────────────
#
# Adding a new event-driven agent: pick a stable name, drop a row here,
# create an Agent in each org that wants the behavior. No code change
# at emit sites — they go through ``event_bus.emit`` which looks the
# event up in this map.

EVENT_TO_AGENT_NAME: dict[str, str] = {
    # Scan lifecycle — three states share one agent. The agent reads the
    # ``[event:NAME]`` tag in its input and switches voice accordingly:
    #   scan_started        — "I'm starting a scan, here's what I'll do"
    #   scan_batch_complete — "Here's what I've found so far"
    #   scan_complete       — "Scan finished, here's the summary"
    "scan_started": "triage_scan_results",
    "scan_batch_complete": "triage_scan_results",
    "scan_complete": "triage_scan_results",
    "asset_created": "triage_new_asset",
    "validated_chain": "chain_narrator",
    "kev_match": "kev_alerter",
    # One-shot welcome at the end of the onboarding wizard. Lazy-create
    # gives us this agent on the first ``org_onboarded`` event without
    # any operator setup.
    "org_onboarded": "welcome_narrator",
}


# Per-org per-event debounce. Bursty emits (multi-batch ingest) collapse
# to one run. Tight enough that a real second event for the same org
# still gets its own run within a few minutes.
_DEBOUNCE_WINDOW = timedelta(seconds=90)

# Hard cap on agent runs per org per event type per hour. Defends
# against pathological loops where an agent's actions trigger more
# events that re-dispatch the agent. Tune via env if it bites.
_MAX_RUNS_PER_HOUR = 30


def dispatch(
    db: Session,
    *,
    event_type: str,
    org_id: int,
    payload: dict[str, Any],
    dedup_key: Optional[Any] = None,
) -> dict:
    """Dispatch one agent run for an event. Returns a small status dict.

    Lookup order:
      1. ``EVENT_TO_AGENT_NAME[event_type]`` → agent name.
      2. ``Agent`` row matching ``(org_id, name)``. If absent, the org
         hasn't opted into this event — return ``{dispatched: False,
         reason: "no_agent"}`` so the caller can log it without raising.
      3. Debounce + rate-limit checks against recent ``AgentRun`` rows.
      4. Build a ``user_input`` from the payload, create the run, queue
         it via ``job_manager.dispatch``.

    ``dedup_key`` (optional): a stable id within the event — typically
    the primary entity in the payload (``scan_id`` for scan_complete,
    ``asset_id`` for asset_created, ``finding_id`` for validated_chain).
    When provided, debounce + rate-limit key on
    ``(agent, event_type, dedup_key)`` instead of just
    ``(agent, event_type)`` — so two scans landing within the window
    each get their own narrator run, while the same scan re-firing
    (e.g. retry) is correctly suppressed. When ``None``, falls back to
    the legacy per-event-type behavior.
    """
    if not event_type or not org_id:
        return {"dispatched": False, "reason": "missing_context"}

    agent_name = EVENT_TO_AGENT_NAME.get(event_type)
    if agent_name is None:
        return {"dispatched": False, "reason": "no_mapping", "event_type": event_type}

    agent = (
        db.query(Agent)
        .filter(Agent.org_id == org_id, Agent.name == agent_name)
        .first()
    )
    if agent is None:
        # Lazy auto-create from the template. Removes the operator-visible
        # "configure an agent" friction — a fresh tenant lands on the
        # feed, the first event fires, the agent springs into existence.
        # Operator edits to the agent (system_prompt, tools) persist
        # because we only create when missing, never overwrite.
        agent = _create_agent_from_template(db, org_id, agent_name)
        if agent is None:
            return {
                "dispatched": False,
                "reason": "no_template",
                "agent_name": agent_name,
            }
        logger.info(
            "agent_dispatcher: auto-created agent=%d name=%s for org=%d",
            agent.id, agent_name, org_id,
        )

    if _is_debounced(db, agent.id, event_type, dedup_key):
        return {"dispatched": False, "reason": "debounced", "agent_id": agent.id}

    if _is_rate_limited(db, agent.id, event_type, dedup_key):
        logger.warning(
            "agent_dispatcher: rate-limited agent=%d event=%s key=%s — over %d/hr",
            agent.id, event_type, dedup_key, _MAX_RUNS_PER_HOUR,
        )
        return {"dispatched": False, "reason": "rate_limited", "agent_id": agent.id}

    user_input = _build_user_input(event_type, payload, dedup_key)
    job_id = _queue_run(agent.id, user_input, event_type)

    logger.info(
        "agent_dispatcher: dispatched agent=%d event=%s key=%s job=%s",
        agent.id, event_type, dedup_key, job_id,
    )
    return {
        "dispatched": True,
        "agent_id": agent.id,
        "agent_name": agent.name,
        "job_id": job_id,
    }


# ── Internals ──────────────────────────────────────────────────────


def _input_like_pattern(event_type: str, dedup_key: Optional[Any]) -> str:
    """Build the LIKE pattern used to match ``AgentRun.input`` for
    debounce + rate-limit lookups. With a key, narrows to that exact
    payload identity; without one, matches any run for the event type.
    """
    if dedup_key is None:
        return f"[event:{event_type}]%"
    return f"[event:{event_type}][key:{dedup_key}]%"


def _is_debounced(
    db: Session, agent_id: int, event_type: str, dedup_key: Optional[Any] = None,
) -> bool:
    """True if an AgentRun for the same key was created within the
    debounce window. The ``[event:NAME][key:V]`` prefix written by
    ``_build_user_input`` is what we LIKE-match on, so a cheap text
    scan is enough without a new index.
    """
    cutoff = datetime.utcnow() - _DEBOUNCE_WINDOW
    return (
        db.query(AgentRun.id)
        .filter(
            AgentRun.agent_id == agent_id,
            AgentRun.created_at >= cutoff,
            AgentRun.input.like(_input_like_pattern(event_type, dedup_key)),
        )
        .first()
        is not None
    )


def _is_rate_limited(
    db: Session, agent_id: int, event_type: str, dedup_key: Optional[Any] = None,
) -> bool:
    cutoff = datetime.utcnow() - timedelta(hours=1)
    count = (
        db.query(AgentRun.id)
        .filter(
            AgentRun.agent_id == agent_id,
            AgentRun.created_at >= cutoff,
            AgentRun.input.like(_input_like_pattern(event_type, dedup_key)),
        )
        .count()
    )
    return count >= _MAX_RUNS_PER_HOUR


def _build_user_input(
    event_type: str, payload: dict[str, Any], dedup_key: Optional[Any] = None,
) -> str:
    """Render the event payload into the user_input string the agent
    receives as its first message. The ``[event:NAME][key:V]`` prefix is
    a machine tag the dispatcher uses for debounce/rate-limit lookups
    (the key is omitted entirely when there isn't one); the rest is
    human-readable so the trace makes sense to a developer reading the
    run later.
    """
    import json as _json
    body = _json.dumps(payload, default=str, sort_keys=True, indent=2)
    key_tag = f"[key:{dedup_key}]" if dedup_key is not None else ""
    return (
        f"[event:{event_type}]{key_tag}\n"
        f"You were triggered by the '{event_type}' event. The event payload follows. "
        f"Reason about what happened, then call post_feed_entry exactly once with a "
        f"narrative summary for the user. If you want to draft an action that needs "
        f"approval, create the AgentApproval first and reference its id in "
        f"proposed_actions on the feed entry.\n\n"
        f"event_payload:\n{body}"
    )


def _create_agent_from_template(db: Session, org_id: int, name: str) -> Optional[Agent]:
    """Create an Agent row in ``org_id`` from the named template. Returns
    None when no matching template exists (caller should treat as
    no-op rather than raise).
    """
    templates = load_templates_by_name()
    tpl = templates.get(name)
    if tpl is None:
        return None
    agent = Agent(
        org_id=org_id,
        name=name,
        description=tpl.get("description"),
        system_prompt=tpl.get("system_prompt") or "",
        tools=tpl.get("tools") or [],
        guardrails=tpl.get("guardrails") or {},
        model=tpl.get("model") or "vertex/gemini-2.5-pro",
    )
    db.add(agent)
    db.flush()
    # Commit so the row is durable before the background job thread
    # opens a fresh SessionLocal and tries to read it. Mirrors the
    # post-commit pattern the chain coordinator uses for emit.
    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("agent_dispatcher: failed to commit auto-created agent")
        return None
    db.refresh(agent)
    return agent


def _queue_run(agent_id: int, user_input: str, event_type: str) -> Optional[str]:
    """Queue ``run_agent`` for this agent on the job manager.

    ``run_agent`` creates its own AgentRun row using ``user_input`` as
    the input — the ``[event:NAME]`` prefix on that input is what
    debounce/rate-limit checks key off of on the next tick.

    Imports inline so this module stays cheap to import at app boot —
    ``agent_engine`` pulls in every LLM SDK on first import.
    """
    from core.database import SessionLocal
    from services.job_manager import dispatch as job_dispatch

    def _run():
        bg = SessionLocal()
        try:
            from agents.agent_engine import run_agent
            agent = bg.query(Agent).filter(Agent.id == agent_id).first()
            if agent is None:
                return {"error": "agent_missing", "agent_id": agent_id}
            return run_agent(agent, user_input, bg)
        finally:
            bg.close()

    job_name = f"agent_dispatch_{agent_id}_{event_type}"
    try:
        job = job_dispatch(job_name, _run, timeout=300)
        return job.id
    except Exception:
        logger.exception("agent_dispatcher: job_dispatch failed for agent=%d event=%s", agent_id, event_type)
        return None

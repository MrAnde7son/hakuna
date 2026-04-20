"""Protocol Audit runner — kicks off ReAct agent runs per asset for a chosen
(protocol, mission) pair.

Shape:
  - One `Scan` row per audit run, regardless of asset count. raw_metadata
    holds the per-asset AgentRun IDs, mission, protocol, and budgets.
  - One `AgentRun` per asset. Each run uses a **scratch Agent** created just
    for this audit so per-run context (relay_agent_id, credential_id,
    asset_id) can be stashed in `Agent.memory["_run_ctx"]` and picked up by
    tools via the engine's injection hook. Scratch agents are deleted after
    the run to keep the Agents table clean.
  - Kickoff is async via services.job_manager so the route returns fast.

Why scratch-agents-per-run instead of one pooled agent:
  - The tool palette needs per-asset relay + credential context. Tools can't
    read it from the LLM's input (that's brittle) and can't read it from a
    shared Agent.memory (runs would race). A fresh agent per run isolates
    that context cleanly without plumbing new columns through AgentRun.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.models import Agent, Asset, Organization, Scan
from agents.audit_registry import AUDITS, MissionTemplate, ProtocolAudit
from agents.agent_prompts import ENHANCED_PROMPTS

logger = logging.getLogger(__name__)


class AuditDispatchError(Exception):
    """Raised when an audit can't be kicked off (missing inputs, bad protocol)."""


def dispatch_audit_run(
    db: Session,
    org: Organization,
    protocol: str,
    mission: str,
    asset_ids: list[int],
    relay_agent_id: str,
    credential_id: str,
    max_steps: int | None = None,
    wallclock_s: int | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Create the Scan row + one AgentRun per asset, dispatch runs in background.

    Returns:
        {
          "scan_id": int,
          "runs": [{asset_id, agent_run_id, agent_id, job_id, status}, ...],
          "protocol": str,
          "mission": str,
        }
    """
    if protocol not in AUDITS:
        raise AuditDispatchError(f"unknown protocol {protocol!r}; registered: {sorted(AUDITS.keys())}")
    audit = AUDITS[protocol]
    m = audit.mission(mission)
    if m is None:
        raise AuditDispatchError(
            f"unknown mission {mission!r} for protocol {protocol}; "
            f"available: {[mt.key for mt in audit.missions]}"
        )
    if not asset_ids:
        raise AuditDispatchError("asset_ids is required")
    if not relay_agent_id:
        raise AuditDispatchError("relay_agent_id is required")
    if not credential_id:
        raise AuditDispatchError("credential_id is required")

    resolved_max_steps = int(max_steps or m.suggested_budget)
    resolved_wallclock = int(wallclock_s or audit.default_wallclock_s)
    resolved_model = model or audit.default_model

    # ── Scan row (one per audit run) ──
    scan = Scan(
        org_id=org.id,
        filename=f"{protocol}_audit://{relay_agent_id}/{mission}/{len(asset_ids)}hosts",
        scan_name=f"{audit.label} — {m.label} — {len(asset_ids)} host(s)",
        scan_date=datetime.utcnow().isoformat(),
        scan_type=f"{protocol}_audit",
        source_type=f"{protocol}_audit",
        status="running",
        raw_metadata={
            "protocol": protocol,
            "mission": mission,
            "asset_ids": list(asset_ids),
            "relay_agent_id": relay_agent_id,
            "credential_id": credential_id,
            "max_steps": resolved_max_steps,
            "wallclock_s": resolved_wallclock,
            "model": resolved_model,
            "agent_run_ids": [],                    # filled as runs are created
        },
    )
    db.add(scan)
    db.flush()

    # Validate assets belong to the org up-front so a bad ID doesn't waste an LLM call.
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    asset_by_id = {a.id: a for a in assets}
    missing = [aid for aid in asset_ids if aid not in asset_by_id]
    if missing:
        logger.warning(
            "audit_runner: protocol=%s %d asset(s) not found: %s",
            protocol, len(missing), missing,
        )

    # ── Per-asset scratch agents ──
    #
    # We create an Agent per asset but let `run_agent` create its own AgentRun
    # in the background job. The Agent.id is the stable link between the Scan
    # and the eventual AgentRun (AgentRun.agent_id); the Scans API resolves
    # runs on demand.
    runs_meta: list[dict] = []
    scratch_agent_ids: list[int] = []
    for asset_id in asset_ids:
        if asset_id not in asset_by_id:
            continue
        agent = _create_scratch_agent(
            db, org.id, audit, m, asset_id,
            relay_agent_id=relay_agent_id,
            credential_id=credential_id,
            max_steps=resolved_max_steps,
            model=resolved_model,
            scan_id=scan.id,
        )
        user_input = _build_user_input(audit, m, asset_by_id[asset_id])
        scratch_agent_ids.append(agent.id)
        runs_meta.append({
            "asset_id": asset_id,
            "agent_id": agent.id,
            "status": "pending",
        })
        _dispatch_background_run(
            agent_id=agent.id,
            user_input=user_input,
            wallclock_s=resolved_wallclock,
        )

    md = dict(scan.raw_metadata or {})
    md["scratch_agent_ids"] = scratch_agent_ids
    scan.raw_metadata = md
    db.commit()

    return {
        "scan_id": scan.id,
        "protocol": protocol,
        "mission": mission,
        "status": "running",
        "runs": runs_meta,
    }


# ── Scratch agent creation ───────────────────────────────────────────


def _create_scratch_agent(
    db: Session,
    org_id: int,
    audit: ProtocolAudit,
    mission: MissionTemplate,
    asset_id: int,
    relay_agent_id: str,
    credential_id: str,
    max_steps: int,
    model: str,
    scan_id: int,
) -> Agent:
    """Create a one-shot Agent whose memory carries per-run tool context."""
    prompt = ENHANCED_PROMPTS.get(mission.prompt_key)
    if not prompt:
        raise AuditDispatchError(f"prompt {mission.prompt_key!r} not found in ENHANCED_PROMPTS")

    agent = Agent(
        org_id=org_id,
        name=f"{audit.label} — {mission.label} — asset {asset_id} — scan {scan_id}",
        description=(
            f"Scratch agent for one {audit.protocol} {mission.key} audit run. "
            f"Created by audit_runner; deleted after the run completes."
        ),
        system_prompt=prompt,
        tools=list(audit.tool_names),
        guardrails={
            "max_steps": max_steps,
            "read_only": False,                     # emit_finding writes Findings
            "autonomy_level": "autonomous",         # read-only probes; no HITL
            "scratch": True,                        # marker for scratch-agent cleanup
        },
        memory={
            "_run_ctx": {
                "_relay_agent_id": relay_agent_id,
                "_credential_id": credential_id,
                "_scan_id": scan_id,
                "_protocol": audit.protocol,
                "_mission": mission.key,
                # Tools that take asset_id from the LLM will see the LLM's value;
                # we still stash it so tools that forgot to ask for it can fall back.
                "_asset_id": asset_id,
            },
        },
        model=model,
    )
    db.add(agent)
    db.flush()
    return agent


def _build_user_input(audit: ProtocolAudit, mission: MissionTemplate, asset: Asset) -> str:
    """Short human-readable kickoff prompt. The system prompt does the heavy lifting."""
    host_ref = asset.fqdn or asset.hostname or asset.ip or f"asset-{asset.id}"
    return (
        f"Run the {audit.label}: {mission.label} mission against asset {asset.id} "
        f"({host_ref}).\n\n"
        f"Host: {host_ref}\n"
        f"OS: {asset.os or 'unknown'}\n"
        f"Mission: {mission.description}\n\n"
        f"Start with `wmi_get_computer_system` to orient, then work through "
        f"the checklist. Emit findings via `emit_finding` with "
        f"`protocol=\"{audit.protocol}\"` and `mission=\"{mission.key}\"`."
    )


# ── Background dispatch ──────────────────────────────────────────────


def _dispatch_background_run(agent_id: int, user_input: str, wallclock_s: int) -> None:
    """Kick off the agent run on the job manager.

    Opens a fresh DB session inside the job since the FastAPI request session
    is closed when the route returns. `run_agent` creates + manages the
    AgentRun row internally; we just pass in the Agent + user input.

    `wallclock_s` is captured here for future enforcement (not yet wired into
    agent_engine — tracked separately). For now the engine's own `max_steps`
    bounds runtime; wall-clock is an upper limit we log but don't enforce.
    """
    from services.job_manager import dispatch

    def _work():
        from agents.agent_engine import run_agent
        bg_db = SessionLocal()
        try:
            agent = bg_db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                logger.warning("audit job: agent=%s not found", agent_id)
                return
            run_agent(agent, user_input, bg_db)
        except Exception:
            logger.exception("audit job agent=%s failed", agent_id)
        finally:
            bg_db.close()

    dispatch(f"audit_agent_{agent_id}", _work)

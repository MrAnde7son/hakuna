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

import ipaddress
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import or_
from sqlalchemy.orm import Session

from core.database import SessionLocal
from models.models import Agent, AgentRun, Asset, Organization, Scan
from agents.audit_registry import AUDITS, MissionTemplate, ProtocolAudit
from agents.agent_prompts import ENHANCED_PROMPTS
from agents.tools._target_utils import split_host_port

logger = logging.getLogger(__name__)


# Protocols whose tools support unauthenticated operation (e.g. SMB null
# sessions, SNMP default-community sweeps). Dispatch without a credential
# is allowed for these; the tools that actually need auth will surface a
# clean "no credential provided" error to the LLM when called.
_ANON_CAPABLE_PROTOCOLS = {"smb", "snmp"}


class AuditDispatchError(Exception):
    """Raised when an audit can't be kicked off (missing inputs, bad protocol)."""


def _asset_open_ports(asset: Asset) -> list[int]:
    """Best-effort read of an asset's discovered open ports.

    open_ports lives inside the ``easm_data`` JSON blob (alongside
    tech_stack, tls_cert, etc.). Returns a list of ints; malformed
    entries are dropped. Empty result means "no evidence either way" —
    callers must treat that as unknown, not "closed."
    """
    data = asset.easm_data or {}
    if not isinstance(data, dict):
        return []
    raw = data.get("open_ports")
    out: list[int] = []
    if isinstance(raw, list):
        for p in raw:
            try:
                n = int(p)
            except (TypeError, ValueError):
                continue
            if 0 < n <= 65535:
                out.append(n)
    # A user-supplied audit port (via "host:port" in the free-form target
    # flow) is authoritative — treat it as observed so preflight doesn't
    # reject a legitimate non-standard-port audit when the discovery scan
    # never saw that port.
    atp = data.get("audit_target_port")
    try:
        atp_n = int(atp) if atp is not None else None
    except (TypeError, ValueError):
        atp_n = None
    if atp_n is not None and 0 < atp_n <= 65535 and atp_n not in out:
        out.append(atp_n)
    return out


def _preflight_audit_asset(
    asset: Asset, audit: ProtocolAudit,
) -> tuple[bool, str | None]:
    """Decide whether the audit should run against this asset.

    Returns ``(ok, reason)``:
      - ``(True, None)``  — reachable, or no evidence to conclude
        otherwise (asset never scanned, protocol has no required_ports)
      - ``(False, reason)`` — positive evidence the port is closed:
        asset has a discovered open_ports list, and none of
        ``audit.required_ports`` appear in it.

    Backend-side preflight using asset.easm_data.open_ports. Does NOT
    probe the network — relay topology means most audit targets are
    unreachable from the backend anyway, and a failed probe wouldn't
    prove they're down. Using pre-existing discovery data is both
    cheaper and correct: a VM scan already observed whether the port
    answers; re-probing from here would just duplicate work (and for
    relay-only targets, produce false negatives).
    """
    required = list(audit.required_ports or ())
    if not required:
        return True, None
    observed = _asset_open_ports(asset)
    if not observed:
        # Never scanned / no evidence. Don't false-flag — dispatch
        # and let the audit itself surface unreachability at the
        # first relay tool call.
        return True, None
    if any(p in observed for p in required):
        return True, None
    target = asset.fqdn or asset.hostname or asset.ip or f"asset {asset.id}"
    req_str = "/".join(str(p) for p in required)
    return False, (
        f"target {target} has no {audit.protocol.upper()}-compatible port open "
        f"(required: {req_str}; observed open: {sorted(observed)}). "
        f"Re-run a discovery scan if the service is listening on a non-standard port."
    )


def _validate_dispatch_inputs(
    protocol: str,
    mission: str,
    relay_agent_id: str,
    credential_id: str | None,
    asset_ids: list[int] | None,
    targets: list[str] | None,
) -> tuple[ProtocolAudit, MissionTemplate]:
    """Shared validation for both initial dispatch and rescan. Returns the
    resolved ``(audit, mission_template)`` tuple so callers can pick up the
    defaults (suggested_budget, label) without re-looking them up."""
    if protocol not in AUDITS:
        raise AuditDispatchError(f"unknown protocol {protocol!r}; registered: {sorted(AUDITS.keys())}")
    audit = AUDITS[protocol]
    m = audit.mission(mission)
    if m is None:
        raise AuditDispatchError(
            f"unknown mission {mission!r} for protocol {protocol}; "
            f"available: {[mt.key for mt in audit.missions]}"
        )
    if bool(asset_ids) == bool(targets):
        raise AuditDispatchError("provide exactly one of asset_ids or targets")
    # Cloud audits (relay_method="none") run in-process against the cloud
    # control plane — no relay needed. All other protocols require a relay.
    if audit.relay_method != "none" and not relay_agent_id:
        raise AuditDispatchError("relay_agent_id is required")
    # credential_id is optional — protocols/missions that support anonymous
    # operation (e.g. SMB null sessions) can dispatch without one. Tools that
    # require authentication surface a clean error to the LLM when called
    # without a credential.
    if not credential_id and protocol not in _ANON_CAPABLE_PROTOCOLS:
        raise AuditDispatchError(
            f"credential_id is required for protocol {protocol!r}"
        )
    return audit, m


def _resolve_asset_ids_for_scan(
    db: Session,
    org_id: int,
    scan_id: int,
    asset_ids: list[int] | None,
    targets: list[str] | None,
) -> list[int]:
    """Free-form target flow: upsert an Asset per target (matched by IP/hostname
    within org, or created fresh rooted at ``scan_id``). Returns the resolved
    asset_ids list. If ``asset_ids`` is already populated it's returned as-is."""
    if targets:
        resolved: list[int] = []
        for t in targets:
            aid = _upsert_asset_by_target(db, org_id, scan_id, t)
            if aid is not None:
                resolved.append(aid)
        if not resolved:
            raise AuditDispatchError("no valid targets could be resolved")
        return resolved
    return list(asset_ids or [])


def _spawn_scratch_agents_for_scan(
    db: Session,
    org_id: int,
    scan: Scan,
    audit: ProtocolAudit,
    mission_template: MissionTemplate,
    asset_ids: list[int],
    max_steps: int,
    wallclock_s: int,
    model: str,
    relay_agent_id: str,
    credential_id: str | None,
) -> dict[str, Any]:
    """Create one scratch Agent per asset, dispatch a Celery run per agent,
    and stamp ``scratch_agent_ids`` + ``task_ids`` onto the scan's metadata.

    Shared by the initial dispatch path and rescan. Caller is responsible for
    having set scan.status = 'running' and having written the per-run fields
    (mission, credential_id, relay_agent_id, asset_ids, …) onto
    ``scan.raw_metadata`` before calling — this helper only owns the scratch
    agent + task_id plumbing.
    """
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    asset_by_id = {a.id: a for a in assets}
    missing = [aid for aid in asset_ids if aid not in asset_by_id]
    if missing:
        logger.warning(
            "audit_runner: protocol=%s %d asset(s) not found: %s",
            audit.protocol, len(missing), missing,
        )

    runs_meta: list[dict] = []
    scratch_agent_ids: list[int] = []
    # task_ids mirrors scratch_agent_ids — stored on the scan so the cancel
    # endpoint has handles to revoke. Keyed by agent_id so we can revoke a
    # single run without touching the others if the UI ever gains per-run
    # cancel.
    task_ids_by_agent: dict[int, str] = {}
    for asset_id in asset_ids:
        if asset_id not in asset_by_id:
            continue
        agent = _create_scratch_agent(
            db, org_id, audit, mission_template, asset_id,
            relay_agent_id=relay_agent_id,
            credential_id=credential_id,
            max_steps=max_steps,
            model=model,
            scan_id=scan.id,
        )
        scratch_agent_ids.append(agent.id)

        # Preflight — if the asset's discovered open_ports exclude every
        # port the protocol needs, fail the run before dispatching a
        # Celery task. Creates the scratch agent (so the UI still has
        # something to link to) but records a failed AgentRun with the
        # unreachable reason and skips _dispatch_background_run. The
        # _finalize_scan_if_complete path already handles AgentRuns that
        # terminate at creation time.
        ok, unreachable_reason = _preflight_audit_asset(asset_by_id[asset_id], audit)
        if not ok:
            logger.info(
                "audit preflight skipped dispatch protocol=%s asset=%s agent=%s reason=%s",
                audit.protocol, asset_id, agent.id, unreachable_reason,
            )
            db.add(AgentRun(
                agent_id=agent.id,
                input="(skipped — target unreachable)",
                status="failed",
                error=unreachable_reason,
                finished_at=datetime.utcnow(),
            ))
            runs_meta.append({
                "asset_id": asset_id,
                "agent_id": agent.id,
                "status": "unreachable",
                "error": unreachable_reason,
            })
            continue

        user_input = _build_user_input(audit, mission_template, asset_by_id[asset_id])
        runs_meta.append({
            "asset_id": asset_id,
            "agent_id": agent.id,
            "status": "pending",
        })
        task_id = _dispatch_background_run(
            agent_id=agent.id,
            user_input=user_input,
            wallclock_s=wallclock_s,
        )
        # Only record string task ids — tests commonly mock
        # `_dispatch_background_run` with a default MagicMock that returns
        # another MagicMock, which isn't JSON-serializable and would blow up
        # the raw_metadata commit below.
        if isinstance(task_id, str) and task_id:
            task_ids_by_agent[agent.id] = task_id

    md = dict(scan.raw_metadata or {})
    md["scratch_agent_ids"] = scratch_agent_ids
    md["task_ids"] = task_ids_by_agent
    scan.raw_metadata = md
    return {"runs": runs_meta, "scratch_agent_ids": scratch_agent_ids}


def dispatch_audit_run(
    db: Session,
    org: Organization,
    protocol: str,
    mission: str,
    relay_agent_id: str,
    credential_id: str | None,
    asset_ids: list[int] | None = None,
    targets: list[str] | None = None,
    max_steps: int | None = None,
    wallclock_s: int | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Create the Scan row + one AgentRun per asset, dispatch runs in background.

    Accepts either ``asset_ids`` (existing assets) or ``targets`` (free-form
    IPs / hostnames / URLs which get upserted into Asset rows rooted at this
    audit's Scan). Exactly one must be provided. Callers that pass ``targets``
    have already expanded any CIDR subnets upstream.

    Returns:
        {
          "scan_id": int,
          "runs": [{asset_id, agent_run_id, agent_id, job_id, status}, ...],
          "protocol": str,
          "mission": str,
        }
    """
    audit, m = _validate_dispatch_inputs(
        protocol, mission, relay_agent_id, credential_id, asset_ids, targets,
    )

    resolved_max_steps = int(max_steps or m.suggested_budget)
    resolved_wallclock = int(wallclock_s or audit.default_wallclock_s)
    resolved_model = model or audit.default_model

    # host_count drives scan naming. For free-form targets we only know the
    # final count after upsert, so use the input length as an upper bound.
    host_count = len(asset_ids) if asset_ids else len(targets)

    # ── Scan row (one per audit run) ──
    scan = Scan(
        org_id=org.id,
        filename=f"{protocol}_audit://{relay_agent_id}/{mission}/{host_count}hosts",
        scan_name=f"{audit.label} — {m.label} — {host_count} host(s)",
        scan_date=datetime.utcnow().isoformat(),
        scan_type=f"{protocol}_audit",
        source_type=f"{protocol}_audit",
        status="running",
        raw_metadata={
            "protocol": protocol,
            "mission": mission,
            "asset_ids": [],                        # filled after upsert/validation
            "relay_agent_id": relay_agent_id,
            "credential_id": credential_id,
            "max_steps": resolved_max_steps,
            "wallclock_s": resolved_wallclock,
            "model": resolved_model,
            "agent_run_ids": [],                    # filled as runs are created
            "status": "running",
        },
    )
    db.add(scan)
    db.flush()

    asset_ids = _resolve_asset_ids_for_scan(
        db, org.id, scan.id, asset_ids=asset_ids, targets=targets,
    )
    md = dict(scan.raw_metadata or {})
    if targets:
        md["ad_hoc_targets"] = list(targets)
    md["asset_ids"] = list(asset_ids)
    scan.raw_metadata = md
    db.flush()

    spawn_result = _spawn_scratch_agents_for_scan(
        db, org.id, scan, audit, m,
        asset_ids=asset_ids,
        max_steps=resolved_max_steps,
        wallclock_s=resolved_wallclock,
        model=resolved_model,
        relay_agent_id=relay_agent_id,
        credential_id=credential_id,
    )
    db.commit()

    # Use the helper's per-run status — it's the only source of truth
    # for preflight short-circuits (unreachable runs have their
    # AgentRow pre-flipped to failed and never got enqueued).
    return {
        "scan_id": scan.id,
        "protocol": protocol,
        "mission": mission,
        "status": "running",
        "runs": spawn_result["runs"],
    }


def rescan_audit_scan(
    db: Session,
    org: Organization,
    scan: Scan,
    mission: str | None = None,
    credential_id: str | None = None,
    relay_agent_id: str | None = None,
    asset_ids: list[int] | None = None,
    targets: list[str] | None = None,
    max_steps: int | None = None,
    wallclock_s: int | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Re-run an existing audit scan in-place — same Scan.id, new batch of
    scratch agents. Mirrors ``rescan_vm_scan`` so the scan list doesn't grow
    a new row per rerun.

    Any override left ``None`` inherits the current value from the scan's
    ``raw_metadata``. The prior run's scratch_agent_ids + task_ids + status
    get snapshotted into ``raw_metadata["run_history"]`` before the new batch
    overwrites them, so ``/audits/scans/{id}/history`` can render every past
    run's AgentRuns.
    """
    md = dict(scan.raw_metadata or {})
    protocol = md.get("protocol")
    if not protocol:
        raise AuditDispatchError("scan metadata missing protocol; cannot rescan")

    resolved_mission = mission or md.get("mission")
    resolved_credential = credential_id if credential_id is not None else md.get("credential_id")
    resolved_relay = relay_agent_id or md.get("relay_agent_id")

    # Prefer explicit overrides; otherwise inherit targets or asset_ids from
    # the scan. Exactly one of (asset_ids, targets) must end up populated.
    inherit_targets = None
    inherit_asset_ids = None
    if targets is None and asset_ids is None:
        if md.get("ad_hoc_targets"):
            inherit_targets = list(md["ad_hoc_targets"])
        elif md.get("asset_ids"):
            inherit_asset_ids = list(md["asset_ids"])
    effective_targets = targets if targets is not None else inherit_targets
    effective_asset_ids = asset_ids if asset_ids is not None else inherit_asset_ids

    audit, m = _validate_dispatch_inputs(
        protocol, resolved_mission, resolved_relay, resolved_credential,
        effective_asset_ids, effective_targets,
    )

    resolved_max_steps = int(max_steps or md.get("max_steps") or m.suggested_budget)
    resolved_wallclock = int(wallclock_s or md.get("wallclock_s") or audit.default_wallclock_s)
    resolved_model = model or md.get("model") or audit.default_model

    # Snapshot the outgoing run so the history endpoint can walk back through
    # every past batch of scratch agents. Append-only; capped defensively.
    run_history = list(md.get("run_history") or [])
    run_history.append({
        "scan_date": scan.scan_date,
        "status": md.get("status") or scan.status,
        "scratch_agent_ids": list(md.get("scratch_agent_ids") or []),
        "task_ids": dict(md.get("task_ids") or {}),
        "asset_ids": list(md.get("asset_ids") or []),
        "mission": md.get("mission"),
        "credential_id": md.get("credential_id"),
        "relay_agent_id": md.get("relay_agent_id"),
        "ad_hoc_targets": list(md.get("ad_hoc_targets") or []),
        "error": md.get("error"),
    })

    # Resolve targets/asset_ids against the existing scan id so upserted
    # assets stay rooted to it.
    final_asset_ids = _resolve_asset_ids_for_scan(
        db, org.id, scan.id,
        asset_ids=effective_asset_ids, targets=effective_targets,
    )

    # Rotate run fields in place. Preserve history + protocol, overwrite
    # everything that describes the current run.
    now_iso = datetime.utcnow().isoformat()
    new_md = {
        "protocol": protocol,
        "mission": resolved_mission,
        "asset_ids": list(final_asset_ids),
        "relay_agent_id": resolved_relay,
        "credential_id": resolved_credential,
        "max_steps": resolved_max_steps,
        "wallclock_s": resolved_wallclock,
        "model": resolved_model,
        "agent_run_ids": [],
        "scratch_agent_ids": [],
        "task_ids": {},
        "status": "running",
        "run_history": run_history,
    }
    if effective_targets is not None:
        new_md["ad_hoc_targets"] = list(effective_targets)
    elif "ad_hoc_targets" in md and not asset_ids:
        # Inherited from prior run — keep it.
        new_md["ad_hoc_targets"] = list(md["ad_hoc_targets"])

    scan.raw_metadata = new_md
    scan.status = "running"
    scan.scan_date = now_iso
    # Refresh the display name so the "N host(s)" suffix matches the new run.
    scan.scan_name = f"{audit.label} — {m.label} — {len(final_asset_ids)} host(s)"
    db.flush()

    spawn_result = _spawn_scratch_agents_for_scan(
        db, org.id, scan, audit, m,
        asset_ids=final_asset_ids,
        max_steps=resolved_max_steps,
        wallclock_s=resolved_wallclock,
        model=resolved_model,
        relay_agent_id=resolved_relay,
        credential_id=resolved_credential,
    )
    db.commit()

    return {
        "scan_id": scan.id,
        "protocol": protocol,
        "mission": resolved_mission,
        "status": "running",
        "runs": spawn_result["runs"],
    }


# ── Scratch agent creation ───────────────────────────────────────────


def _create_scratch_agent(
    db: Session,
    org_id: int,
    audit: ProtocolAudit,
    mission: MissionTemplate,
    asset_id: int,
    relay_agent_id: str,
    credential_id: str | None,
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


# ── Free-form target resolution ──────────────────────────────────────


def _classify_target(target: str) -> tuple[dict[str, str | None], int | None]:
    """Split a user-entered target string into ip / hostname / fqdn fields + port.

    Accepts bare IPs, hostnames, FQDNs, URLs (scheme stripped), and any of
    those suffixed with ``:port`` (e.g. ``ssh:2222``, ``10.0.0.5:1389``).
    Returns ``(identity_dict, port_or_none)``. The port is split OUT of the
    identity so we don't contaminate asset.hostname/fqdn with a port number —
    it's threaded separately to the protocol tool via easm_data.
    """
    raw = (target or "").strip()
    if not raw:
        return {}, None
    host = raw
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = parsed.hostname or raw
    host, port = split_host_port(host)
    try:
        ipaddress.ip_address(host)
        return {"ip": host}, port
    except ValueError:
        pass
    # Dotted name → treat as both hostname and fqdn so either match path hits.
    if "." in host:
        return {"hostname": host, "fqdn": host}, port
    return {"hostname": host}, port


def _upsert_asset_by_target(
    db: Session, org_id: int, scan_id: int, target: str,
) -> int | None:
    """Find an Asset in the org matching the target's IP/hostname/FQDN, or
    create a new one rooted at ``scan_id``. Returns the asset id, or None if
    the target couldn't be classified.

    If the user-entered target included a non-standard port (``ssh:2222``),
    the port is stripped from the stored identity and persisted to
    ``easm_data['audit_target_port']`` on the asset. Protocol tools read it
    back when dispatching so the port still reaches the relay.
    """
    ident, port = _classify_target(target)
    if not ident:
        return None

    # Org-scope via the Scan join since Asset has no org_id column.
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == org_id)
    if ident.get("ip"):
        existing = q.filter(Asset.ip == ident["ip"]).first()
    else:
        name = ident.get("fqdn") or ident.get("hostname")
        existing = q.filter(or_(Asset.hostname == name, Asset.fqdn == name)).first()
    if existing:
        asset = existing
        current_sources = list(asset.source_systems or [])
        if "audit_agent" not in current_sources:
            asset.source_systems = current_sources + ["audit_agent"]
    else:
        asset = Asset(
            scan_id=scan_id,
            ip=ident.get("ip"),
            hostname=ident.get("hostname"),
            fqdn=ident.get("fqdn"),
            source_systems=["audit_agent"],
        )
        db.add(asset)
        db.flush()

    if port is not None:
        easm = dict(asset.easm_data or {})
        easm["audit_target_port"] = port
        asset.easm_data = easm
        db.flush()

    return asset.id


# ── Background dispatch ──────────────────────────────────────────────


class AuditWorkerUnavailableError(AuditDispatchError):
    """Raised when the Celery broker is unreachable at dispatch time.

    Surfaces as a 503 on the `/api/audits/run` route so callers see an
    actionable error ("audit worker isn't running") instead of a queued task
    that nobody drains. Inherits from AuditDispatchError so existing
    catch-sites pick it up unchanged.
    """


def _dispatch_background_run(agent_id: int, user_input: str, wallclock_s: int) -> str:
    """Enqueue one scratch-agent run on the `audits` Celery queue.

    Returns the Celery task id. The caller stores it on the Scan so the
    cancel endpoint can revoke the task later — without this, "stop scan"
    has no handle to reach a running LLM loop in the worker process.

    The audit-worker container (`docker compose --profile audits up -d`)
    consumes the queue and runs `run_agent` out-of-process. This keeps the
    LLM loop off uvicorn's event loop so request handlers don't block on it.

    If redis is unreachable (worker not brought up), `apply_async` raises a
    connection error. We translate that into `AuditWorkerUnavailableError`
    so the route can return 503 instead of a generic 500.

    `wallclock_s` is captured here for future enforcement. The engine's own
    `max_steps` + Celery's `task_time_limit` bound runtime today.
    """
    from services.audit_worker import run_scratch_agent_task

    try:
        # countdown=1 hides a race: the API request's final `db.commit()` in
        # dispatch_audit_run runs *after* this call, so a worker that picks the
        # task up instantly can miss the Agent row. One second is longer than
        # any realistic commit path and invisible compared to LLM latency.
        result = run_scratch_agent_task.apply_async(
            args=(agent_id, user_input, wallclock_s),
            queue="audits",
            countdown=1,
            # Redundant with the global `task_ignore_result=True` but explicit
            # here so a reader doesn't have to cross-reference celery_app.conf
            # to understand why the backend doesn't subscribe to result pubsub.
            ignore_result=True,
        )
        return result.id
    except Exception as e:
        # kombu / redis exceptions all funnel here. Narrow the message to
        # something actionable without swallowing the root cause.
        raise AuditWorkerUnavailableError(
            f"audit worker queue unavailable: {e}. "
            "Bring up the worker with: docker compose --profile audits up -d"
        ) from e


def revoke_audit_tasks(task_ids: list[str]) -> dict:
    """Revoke queued/running audit tasks. Returns {"revoked": [...], "errors": {...}}.

    `terminate=True` SIGTERMs the worker child if the task is already running
    — that's the only way to interrupt a mid-LLM-call loop. Tasks still on the
    queue just get removed. Unknown ids are a no-op.
    """
    from services.celery_app import celery_app

    revoked: list[str] = []
    errors: dict[str, str] = {}
    for tid in task_ids or []:
        if not tid:
            continue
        try:
            celery_app.control.revoke(tid, terminate=True, signal="SIGTERM")
            revoked.append(tid)
        except Exception as e:
            errors[tid] = str(e)
    return {"revoked": revoked, "errors": errors}

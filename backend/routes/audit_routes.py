"""Protocol Audit routes — discover available audits + run them.

Prefix: /api/audits

One endpoint serves every protocol (wmi now; ldap/smb/kerberos/snmp/winrm later).
The `protocol` field on the request body picks the tool palette + mission catalog
from the shared `AUDITS` registry ([agents/audit_registry.py]).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from core.auth import require_auth
from core.database import get_db
from core.time_utils import iso_utc
from core.subscription import check_scan_limit
from core.token_quota import check_token_quota, get_token_usage
from models.models import Agent, AgentRun, Asset, Finding, Organization, Scan, User
from agents.audit_registry import AUDITS, describe_all, list_audits
from services.audit_runner import (
    AuditDispatchError, AuditWorkerUnavailableError,
    dispatch_audit_run, rescan_audit_scan,
)
from services.target_expander import expand_cidr_targets

# Audit runs are N × ~15k LLM tokens per host, so we cap CIDR expansion
# much tighter than VM scans (1024). A /26 or smaller is still permitted
# inline; larger ranges should be split into separate runs intentionally.
AUDIT_MAX_EXPANDED_HOSTS = 64

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audits", tags=["audits"])


def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


# ── Discovery ────────────────────────────────────────────────────────


@router.get("/protocols")
def list_protocol_audits(user: User = Depends(require_auth)):
    """List all registered protocol audits + their missions.

    The frontend 'New Scan → Authenticated Audit' dropdown reads this to
    build the protocol + mission pickers. As LDAP/SMB/Kerberos/SNMP/WinRM
    audits register themselves in `agents.tools.*_tools` they appear here
    automatically — no route change needed.
    """
    return {"audits": describe_all()}


@router.get("/protocols/{protocol}")
def get_protocol_audit(protocol: str, user: User = Depends(require_auth)):
    """Capability descriptor for one protocol audit."""
    if protocol not in AUDITS:
        raise HTTPException(404, f"Unknown protocol: {protocol}")
    return AUDITS[protocol].to_dict()


# ── Kickoff ──────────────────────────────────────────────────────────


class AuditRunRequest(BaseModel):
    protocol: str = Field(..., description="e.g. 'wmi' — must be registered in AUDITS")
    mission: str = Field(..., description="Mission key (identity|privesc|software_cve|network_hygiene|explore)")
    # Optional — SMB anonymous missions (null sessions) can run without a
    # credential. Protocols that require auth reject None in audit_runner.
    credential_id: str | None = None
    relay_agent_id: str
    # Exactly one of asset_ids or targets must be provided.
    # targets accepts IPs, hostnames, URLs, and CIDR subnets (expanded server-side).
    asset_ids: list[int] | None = Field(default=None, min_length=1)
    targets: list[str] | None = Field(default=None, min_length=1)
    max_steps: int | None = None         # defaults to the mission's suggested_budget
    wallclock_s: int | None = None       # defaults to the protocol's default_wallclock_s
    model: str | None = None             # defaults to the protocol's default_model

    @model_validator(mode="after")
    def _exactly_one_target_source(self):
        has_assets = bool(self.asset_ids)
        has_targets = bool(self.targets)
        if has_assets == has_targets:
            raise ValueError("Provide exactly one of asset_ids or targets")
        return self


@router.post("/run", dependencies=[Depends(check_scan_limit)])
def create_audit_run(
    body: AuditRunRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Kick off a Protocol Audit run.

    Creates one Scan row + N background agent runs (one per asset). Returns
    immediately with the scan_id and agent_id list; poll `/api/audits/scans/{scan_id}`
    for progress.
    """
    org = _get_org(db, user)

    # Pre-flight token quota check. Each audit run is N agent runs × ~15k tokens,
    # so if the org is already over limit we fail here with one 429 instead of
    # letting every background job 429 individually with no user feedback.
    # Individual `check_token_quota` calls still run inside `run_agent` per run
    # — they catch mid-audit exhaustion. This check catches pre-exhaustion.
    check_token_quota(org.id, db)

    # Expand CIDR subnets before dispatch so the runner sees only individual
    # hosts. Tight cap (64) reflects the LLM cost per host.
    expanded_targets: list[str] | None = None
    if body.targets:
        try:
            expanded_targets = expand_cidr_targets(
                body.targets, max_hosts=AUDIT_MAX_EXPANDED_HOSTS,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not expanded_targets:
            raise HTTPException(400, "No valid targets provided")

    try:
        result = dispatch_audit_run(
            db=db,
            org=org,
            protocol=body.protocol,
            mission=body.mission,
            asset_ids=body.asset_ids,
            targets=expanded_targets,
            relay_agent_id=body.relay_agent_id,
            credential_id=body.credential_id,
            max_steps=body.max_steps,
            wallclock_s=body.wallclock_s,
            model=body.model,
        )
    except AuditWorkerUnavailableError as e:
        # Worker/redis not up. 503 is the right signal — client should try
        # again after starting the audits profile.
        raise HTTPException(503, str(e))
    except AuditDispatchError as e:
        raise HTTPException(400, str(e))

    from core.audit import log_audit
    scan_row = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
    log_audit(
        db, "start", "scan", entity_id=result["scan_id"],
        entity_name=(scan_row.scan_name if scan_row else None),
        changes={
            "source_type": f"{body.protocol}_audit",
            "protocol": body.protocol,
            "mission": body.mission,
            "host_count": len(result.get("runs") or []),
        },
        actor=user,
    )
    db.commit()

    return result


# ── Status / transcript ──────────────────────────────────────────────


@router.get("/scans/{scan_id}")
def get_audit_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Return the audit scan + per-asset agent run statuses.

    Frontend uses this to render progress on the scan page (one row per
    asset with its current step count + status).
    """
    org = _get_org(db, user)
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.org_id == org.id)
        .first()
    )
    if not scan:
        raise HTTPException(404, "Audit scan not found")
    if not (scan.scan_type or "").endswith("_audit"):
        raise HTTPException(400, f"Scan {scan_id} is not an audit scan")

    md = scan.raw_metadata or {}
    scratch_agent_ids: list[int] = md.get("scratch_agent_ids") or []
    runs_by_agent: dict[int, AgentRun] = {}
    if scratch_agent_ids:
        # The most recent AgentRun per scratch agent (one per scratch agent).
        runs = (
            db.query(AgentRun)
            .filter(AgentRun.agent_id.in_(scratch_agent_ids))
            .order_by(AgentRun.id.desc())
            .all()
        )
        for r in runs:
            runs_by_agent.setdefault(r.agent_id, r)

    # Resolve agent → asset_id via the scratch agent's memory
    agents = (
        db.query(Agent)
        .filter(Agent.id.in_(scratch_agent_ids))
        .all() if scratch_agent_ids else []
    )
    run_entries: list[dict] = []
    for a in agents:
        ctx = (a.memory or {}).get("_run_ctx") or {}
        r = runs_by_agent.get(a.id)
        run_entries.append({
            "agent_id": a.id,
            "asset_id": ctx.get("_asset_id"),
            "agent_run_id": r.id if r else None,
            "status": r.status if r else "pending",
            "steps_used": r.steps_used if r else 0,
            "created_at": iso_utc(r.created_at) if r else None,
            "finished_at": iso_utc(r.finished_at) if r else None,
            "error": r.error if r else None,
        })

    return {
        "scan_id": scan.id,
        "protocol": md.get("protocol"),
        "mission": md.get("mission"),
        "status": scan.status,
        "runs": run_entries,
    }


# ── Rescan / Edit-and-rerun ──────────────────────────────────────────


class AuditRescanRequest(BaseModel):
    """Optional overrides for edit-and-rerun. Any field left None inherits
    the original scan's value from ``raw_metadata``. Matches the shape of
    VM scanner's rescan (see ``routes/vm_routes.rescan``)."""
    mission: str | None = None
    credential_id: str | None = None
    relay_agent_id: str | None = None
    asset_ids: list[int] | None = None
    targets: list[str] | None = None
    max_steps: int | None = None
    wallclock_s: int | None = None
    model: str | None = None


def _load_audit_scan(db: Session, scan_id: int, user: User) -> Scan:
    org = _get_org(db, user)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.org_id == org.id).first()
    if not scan:
        raise HTTPException(404, "Audit scan not found")
    if not (scan.scan_type or "").endswith("_audit"):
        raise HTTPException(400, f"Scan {scan_id} is not an audit scan")
    return scan


@router.post("/scans/{scan_id}/rescan", dependencies=[Depends(check_scan_limit)])
def rescan_audit(
    scan_id: int,
    body: AuditRescanRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Replay an audit scan in place. Pass overrides to edit-and-rerun; omit
    to replay as-is.

    Mirrors ``rescan_vm_scan``: the same Scan row is re-used (no duplicate
    rows in the scan list). The outgoing run's scratch_agent_ids + status get
    archived into ``raw_metadata["run_history"]`` so ``/history`` can still
    surface every past run's AgentRuns.
    """
    scan = _load_audit_scan(db, scan_id, user)
    org = _get_org(db, user)
    check_token_quota(org.id, db)

    body = body or AuditRescanRequest()

    targets = body.targets
    if targets:
        try:
            targets = expand_cidr_targets(targets, max_hosts=AUDIT_MAX_EXPANDED_HOSTS)
        except ValueError as e:
            raise HTTPException(400, str(e))

    try:
        result = rescan_audit_scan(
            db=db,
            org=org,
            scan=scan,
            mission=body.mission,
            credential_id=body.credential_id,
            relay_agent_id=body.relay_agent_id,
            asset_ids=body.asset_ids,
            targets=targets,
            max_steps=body.max_steps,
            wallclock_s=body.wallclock_s,
            model=body.model,
        )
    except AuditWorkerUnavailableError as e:
        raise HTTPException(503, str(e))
    except AuditDispatchError as e:
        raise HTTPException(400, str(e))

    from core.audit import log_audit
    log_audit(
        db, "rescan", "scan", entity_id=scan_id,
        entity_name=scan.scan_name,
        changes={
            "source_type": scan.scan_type,
            "overrides_applied": any(
                v is not None for v in (
                    body.mission, body.credential_id, body.relay_agent_id,
                    body.asset_ids, body.targets, body.max_steps,
                    body.wallclock_s, body.model,
                )
            ),
        },
        actor=user,
    )
    db.commit()

    return result


class AuditScanUpdateRequest(BaseModel):
    """Patch the *defaults* a scheduled audit scan will use on its next run.

    Only the fields you include are changed. This is the non-executing twin
    of ``rescan`` — useful when the user edits a schedule's target or
    credential and doesn't want to fire an immediate run.
    """
    mission: str | None = None
    credential_id: str | None = None
    relay_agent_id: str | None = None
    targets: list[str] | None = None
    asset_ids: list[int] | None = None
    max_steps: int | None = None
    wallclock_s: int | None = None
    model: str | None = None


@router.patch("/scans/{scan_id}")
def update_audit_scan(
    scan_id: int,
    body: AuditScanUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Update the stored parameters on an audit scan (for scheduled reruns).

    The scheduler reads from ``raw_metadata`` at fire time, so writing there
    is sufficient — no separate "edit" table. We validate mission against the
    registry so the UI can't save an unknown mission."""
    scan = _load_audit_scan(db, scan_id, user)
    md = dict(scan.raw_metadata or {})

    protocol = md.get("protocol")
    if body.mission is not None:
        if protocol and protocol in AUDITS:
            if not any(m.key == body.mission for m in AUDITS[protocol].missions):
                raise HTTPException(
                    400,
                    f"unknown mission {body.mission!r} for protocol {protocol}; "
                    f"available: {[m.key for m in AUDITS[protocol].missions]}"
                )
        md["mission"] = body.mission
    if body.credential_id is not None:
        md["credential_id"] = body.credential_id
    if body.relay_agent_id is not None:
        md["relay_agent_id"] = body.relay_agent_id
    if body.targets is not None:
        try:
            md["ad_hoc_targets"] = expand_cidr_targets(
                body.targets, max_hosts=AUDIT_MAX_EXPANDED_HOSTS,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))
        # Targets + asset_ids are mutually exclusive on dispatch; clear the other.
        md.pop("asset_ids", None)
    if body.asset_ids is not None:
        md["asset_ids"] = list(body.asset_ids)
        md.pop("ad_hoc_targets", None)
    if body.max_steps is not None:
        md["max_steps"] = int(body.max_steps)
    if body.wallclock_s is not None:
        md["wallclock_s"] = int(body.wallclock_s)
    if body.model is not None:
        md["model"] = body.model

    scan.raw_metadata = md
    db.commit()

    from core.audit import log_audit
    log_audit(
        db, "update", "scan", entity_id=scan.id,
        entity_name=scan.scan_name,
        changes={"source_type": scan.scan_type, "edited_fields": [
            k for k, v in body.model_dump(exclude_none=True).items()
        ]},
        actor=user,
    )
    db.commit()

    return {
        "scan_id": scan.id,
        "protocol": md.get("protocol"),
        "mission": md.get("mission"),
        "credential_id": md.get("credential_id"),
        "relay_agent_id": md.get("relay_agent_id"),
        "asset_ids": md.get("asset_ids"),
        "targets": md.get("ad_hoc_targets"),
    }


@router.get("/scans/{scan_id}/history")
def audit_scan_history(
    scan_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """All AgentRuns tied to this scan — current run plus every archived
    run from ``raw_metadata.run_history``. One row per run, newest first.

    Analog of ``VmScanHistory`` on the frontend — the component already knows
    how to render a list of runs; we just need to provide them."""
    scan = _load_audit_scan(db, scan_id, user)
    md = scan.raw_metadata or {}

    # Flatten all scratch_agent_ids: current run + every archived run.
    # Use dict.fromkeys to dedupe while preserving order (newest first).
    scratch_agent_ids: list[int] = list(md.get("scratch_agent_ids") or [])
    for past in reversed(md.get("run_history") or []):
        scratch_agent_ids.extend(past.get("scratch_agent_ids") or [])
    scratch_agent_ids = list(dict.fromkeys(scratch_agent_ids))

    runs = []
    if scratch_agent_ids:
        rows = (
            db.query(AgentRun)
            .filter(AgentRun.agent_id.in_(scratch_agent_ids))
            .order_by(AgentRun.id.desc())
            .all()
        )
        agents_by_id = {
            a.id: a for a in db.query(Agent).filter(Agent.id.in_(scratch_agent_ids)).all()
        }

        # Resolve asset labels and findings counts in two bulk queries so the
        # row count doesn't drive N+1 lookups.
        asset_ids: list[int] = []
        for a in agents_by_id.values():
            ctx = (a.memory or {}).get("_run_ctx") or {}
            aid = ctx.get("_asset_id")
            if isinstance(aid, int):
                asset_ids.append(aid)
        assets_by_id = {
            asset.id: asset
            for asset in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        } if asset_ids else {}

        from sqlalchemy import func
        finding_pairs = []
        for a in agents_by_id.values():
            ctx = (a.memory or {}).get("_run_ctx") or {}
            sid, aid = ctx.get("_scan_id"), ctx.get("_asset_id")
            if isinstance(sid, int) and isinstance(aid, int):
                finding_pairs.append((sid, aid))
        findings_by_pair: dict[tuple[int, int], int] = {}
        if finding_pairs:
            scan_ids = list({p[0] for p in finding_pairs})
            aids = list({p[1] for p in finding_pairs})
            counts = (
                db.query(Finding.scan_id, Finding.asset_id, func.count(Finding.id))
                .filter(Finding.scan_id.in_(scan_ids), Finding.asset_id.in_(aids))
                .group_by(Finding.scan_id, Finding.asset_id)
                .all()
            )
            findings_by_pair = {(s, a_): c for s, a_, c in counts}

        for r in rows:
            a = agents_by_id.get(r.agent_id)
            ctx = (a.memory or {}).get("_run_ctx") if a else {}
            asset_id = ctx.get("_asset_id") if ctx else None
            scan_ctx_id = ctx.get("_scan_id") if ctx else None
            asset = assets_by_id.get(asset_id) if isinstance(asset_id, int) else None
            asset_label = None
            if asset:
                asset_label = asset.fqdn or asset.hostname or asset.ip or f"asset-{asset.id}"
            duration_s = None
            if r.created_at and r.finished_at:
                duration_s = round((r.finished_at - r.created_at).total_seconds(), 1)
            findings_count = findings_by_pair.get(
                (scan_ctx_id, asset_id), 0
            ) if isinstance(scan_ctx_id, int) and isinstance(asset_id, int) else None
            runs.append({
                "agent_run_id": r.id,
                "agent_id": r.agent_id,
                "asset_id": asset_id,
                "asset_label": asset_label,
                "protocol": ctx.get("_protocol") if ctx else None,
                "mission": ctx.get("_mission") if ctx else None,
                "scan_id": scan_ctx_id,
                "status": r.status,
                "steps_used": r.steps_used,
                "findings_count": findings_count,
                "duration_s": duration_s,
                "created_at": iso_utc(r.created_at),
                "finished_at": iso_utc(r.finished_at),
                "error": r.error,
            })

    return {
        "scan_id": scan.id,
        "related_scan_ids": [scan.id],
        "runs": runs,
    }

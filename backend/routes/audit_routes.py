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
from models.models import Agent, AgentRun, Organization, Scan, User
from agents.audit_registry import AUDITS, describe_all, list_audits
from services.audit_runner import AuditDispatchError, dispatch_audit_run
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
    credential_id: str
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

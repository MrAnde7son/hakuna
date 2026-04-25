"""Audit Scanner API — trigger runs, check status.

Mirrors hakuna-vm-scanner/scanner/vm/api.py at a smaller surface:

  POST   /audit/scans/         — kick off one audit run; returns job_id
  GET    /audit/scans/{job_id} — Celery state + result payload
  GET    /audit/audits/        — list registered protocols + missions
                                   (for kickoff UIs)
  POST   /audit/missions/validate — dry-run a YAML mission file

Auth is intentionally absent — the OSS service is meant to sit behind
the operator's own ingress (or be invoked directly by a Celery
producer in the backend). Adding bearer-token auth is a 10-line
middleware when needed.
"""

from __future__ import annotations

import logging
from typing import Literal

import yaml
from fastapi import APIRouter, FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

# Side-effect import: registers protocol tools and audits before the
# first request lands.
from scanner.audit import tools as _registered_tools  # noqa: F401
from scanner.audit.audit_registry import AUDITS, describe_all
from scanner.audit.audit_worker import run_audit_scan
from scanner.audit.celery_app import celery_app
from scanner.audit.mission_loader import load_missions

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/audit", tags=["audit-scanner"])


# ── Request / response models ─────────────────────────────────────


class AuditCredentials(BaseModel):
    """Plaintext credentials passed in by the caller. Backend resolves
    from the vault; OSS users supply directly. Mirrors the VM
    scanner's ``ScanCredentials`` shape — this dict is forwarded to the
    relay, never logged or echoed in responses."""
    username: str | None = None
    password: str | None = None
    private_key: str | None = None
    private_key_passphrase: str | None = None
    port: int | None = None
    domain: str | None = None  # used by SMB/LDAP/WMI


class AuditScanRequest(BaseModel):
    asset_id: str = Field(description="UUID of the asset row in the shared Postgres")
    protocol: Literal["ssh", "wmi", "ldap", "smb", "snmp", "cloud"]
    mission_key: str
    credentials: AuditCredentials
    relay_agent_id: str | None = None
    credential_id: str | None = None
    max_steps: int | None = None
    wallclock_s: int | None = None
    model_override: str | None = Field(
        default=None,
        description="Pin a specific model id (e.g. 'claude-sonnet-4-6'). When "
                    "unset, the worker uses the highest-priority configured provider.",
    )
    org_id: str | None = None


class AuditScanResponse(BaseModel):
    job_id: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    result: dict | None = None


# ── Routes ────────────────────────────────────────────────────────


@router.post("/scans/", response_model=AuditScanResponse)
async def create_scan(body: AuditScanRequest):
    audit = AUDITS.get(body.protocol)
    if audit is None:
        raise HTTPException(404, f"unknown protocol {body.protocol!r}")
    if audit.mission(body.mission_key) is None:
        raise HTTPException(
            404,
            f"unknown mission {body.mission_key!r} for {body.protocol!r}; "
            f"valid: {[m.key for m in audit.missions]}",
        )

    task = run_audit_scan.apply_async(
        kwargs={
            "asset_id": body.asset_id,
            "protocol": body.protocol,
            "mission_key": body.mission_key,
            "credentials": body.credentials.model_dump(exclude_none=True),
            "relay_agent_id": body.relay_agent_id,
            "credential_id": body.credential_id,
            "max_steps": body.max_steps,
            "wallclock_s": body.wallclock_s,
            "model_override": body.model_override,
            "org_id": body.org_id,
        },
        queue="audit_queue",
    )
    return AuditScanResponse(job_id=task.id)


@router.get("/scans/{job_id}", response_model=JobStatusResponse)
async def get_scan_status(job_id: str):
    res = celery_app.AsyncResult(job_id)
    payload = None
    if res.ready():
        try:
            payload = res.result if isinstance(res.result, dict) else {"raw": str(res.result)}
        except Exception as e:
            payload = {"error": f"failed to read result: {e}"}
    return JobStatusResponse(job_id=job_id, status=res.state, result=payload)


@router.get("/audits/")
async def list_audits():
    """List registered protocols + missions for kickoff UIs."""
    load_missions()
    return {"audits": describe_all()}


class MissionValidationResponse(BaseModel):
    valid: bool
    errors: list[str]


@router.post("/missions/validate", response_model=MissionValidationResponse)
async def validate_mission(file: UploadFile = File(...)):
    """Dry-run a YAML mission file — same shape as VM scanner's
    ``/vm/templates/validate``."""
    contents = await file.read()
    errors: list[str] = []
    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as e:
        return MissionValidationResponse(valid=False, errors=[f"yaml parse: {e}"])

    if not isinstance(data, dict):
        return MissionValidationResponse(valid=False, errors=["top-level must be a mapping"])

    for required in ("protocol", "mission_key", "prompt_key", "system_prompt"):
        if not data.get(required):
            errors.append(f"missing required field: {required}")
    if data.get("protocol") and data["protocol"] not in AUDITS and not data.get("audit_label"):
        errors.append(
            f"protocol {data['protocol']!r} is not registered and the YAML "
            "doesn't supply audit_label/audit_description to bootstrap a stub"
        )
    return MissionValidationResponse(valid=not errors, errors=errors)


# ── App factory ───────────────────────────────────────────────────


def create_app() -> FastAPI:
    app = FastAPI(
        title="Hakuna Audit Scanner",
        version="0.1.0",
        description=(
            "Credentialed protocol-audit ReAct agent. Kicks off LLM-driven "
            "audits (SSH/WMI/LDAP/SMB/SNMP) against assets, dispatches "
            "protocol queries through hakuna-relay-agent, and returns "
            "structured findings for backend ingest."
        ),
    )
    app.include_router(router)

    @app.get("/health")
    async def health():
        return {"ok": True, "audits": list(AUDITS.keys())}

    return app


app = create_app()

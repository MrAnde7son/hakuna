"""VM Scanner API — trigger scans, check status, manage custom templates."""

import glob
import os
import tempfile
import uuid
from typing import Literal

import yaml
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from scanner.vm.agent_worker import run_agent_scan
from scanner.vm.agent_specialists import AGENT_CATEGORIES
from scanner.vm.config import CONTENT_DISCOVERY_ENABLED, TEMPLATES_DIR
from scanner.vm.content_discovery_worker import run_content_discovery_scan
from scanner.vm.nuclei_worker import fetch_alive_assets, run_nuclei_adhoc, run_nuclei_scan
from scanner.vm.schemathesis_worker import run_schemathesis_scan
from scanner.vm.template_validator import validate_custom_template

router = APIRouter(prefix="/vm", tags=["vm-scanner"])


# ---------- Request / Response models ----------

class ScanCredentials(BaseModel):
    """Authentication material to be injected into Nuclei HTTP requests.

    Raw secrets MUST NOT be logged or echoed back in responses. The scanner
    worker redacts the values when emitting the command line for debugging.
    Only one logical scheme is used at a time (basic | bearer | cookie |
    header) — extra fields are ignored. For `header`, `headers` is a dict of
    arbitrary header name → value pairs and is mutually compatible with any
    of the other schemes (they all collapse to `-H` flags).
    """
    type: Literal["basic", "bearer", "cookie", "header"]
    username: str | None = None
    password: str | None = None
    token: str | None = None
    cookie: str | None = None
    headers: dict[str, str] | None = None


class ScanRequest(BaseModel):
    asset_ids: list[str] | None = None
    targets: list[str] | None = None  # Raw IPs/hostnames/URLs for ad-hoc scans
    scan_all: bool = False
    org_id: str | None = None
    credentials: ScanCredentials | None = Field(
        default=None,
        description="Optional credential material for authenticated scans. "
                    "Never logged or persisted by the scanner.",
    )
    scan_plans: dict[str, dict] | None = Field(
        default=None,
        description="Pre-computed adaptive scan plans keyed by target string "
                    "(URL/hostname/IP). Each value: {plan: <ScanPlan dict>, "
                    "version: <int>}. When present, the worker uses the plan "
                    "instead of the static template router. Plans for targets "
                    "not in this map fall through to the legacy router.",
    )
    enable_agents: bool = Field(
        default=False,
        description="When true, fan out the specialist LLM agents alongside "
                    "nuclei for every asset_id. Cost is measured in LLM tokens, "
                    "not CPU — the backend MUST opt in explicitly per scan so "
                    "an 'enabled by default' config change can't quietly burn "
                    "budget. Pairs with `agent_categories` to narrow scope.",
    )
    agent_categories: list[str] | None = Field(
        default=None,
        description="Optional list of agent categories to run when "
                    "enable_agents=true. Valid values: "
                    "injection, xss, ssrf, authn, authz. None = run all five "
                    "(each still self-gates via applicable_when).",
    )
    enable_content_discovery: bool = Field(
        default=True,
        description="When true, fan out the ffuf-based content-discovery "
                    "worker for each asset with a web-serving port open. "
                    "On by default — content discovery fills the gap left "
                    "by Nuclei/Schemathesis, which only fuzz known URLs. "
                    "Callers can opt out per scan by setting false. The "
                    "worker-side CONTENT_DISCOVERY_ENABLED env var is a "
                    "separate global kill-switch that ops can flip without "
                    "coordinating with the backend.",
    )


class ScanResponse(BaseModel):
    job_ids: list[str]
    assets_queued: int
    targets_queued: int = 0


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    result: dict | None = None


class ValidationResponse(BaseModel):
    valid: bool
    errors: list[str]
    warnings: list[str]


class TemplateInfo(BaseModel):
    path: str
    name: str
    tags: str
    severity: str
    source: str


# ---------- Endpoints ----------

@router.post("/scans/", response_model=ScanResponse)
async def create_scan(body: ScanRequest):
    """Enqueue Nuclei scans for specified assets, raw targets, or all confirmed-alive assets."""
    if not body.asset_ids and not body.targets and not body.scan_all:
        raise HTTPException(
            status_code=400,
            detail="Provide asset_ids, targets, or set scan_all=true",
        )

    job_ids: list[str] = []
    offset = 0

    # Serialize credentials once — passed to Celery as a plain dict so the
    # worker process can reconstruct the ScanCredentials without importing
    # Pydantic-typed args. Broker never sees them unless the caller provided.
    credentials_payload = body.credentials.model_dump() if body.credentials else None
    scan_plans = body.scan_plans or {}

    # Queue asset-based scans
    if body.scan_all:
        assets = await fetch_alive_assets()
        asset_ids = [str(a["id"]) for a in assets]
    else:
        asset_ids = body.asset_ids or []

    # Assets with OpenAPI/GraphQL endpoints get an additional schemathesis
    # job alongside nuclei. Check once up-front so we don't do one DB round
    # trip per asset inside the dispatch loop.
    api_fuzz_asset_ids = await _assets_with_api_specs(asset_ids) if asset_ids else set()

    # Content discovery needs a web-serving port. The caller opts in
    # with enable_content_discovery AND the worker env CONTENT_DISCOVERY_ENABLED
    # must be true — both gates so a forgotten scan option can't quietly
    # burn request budget against customer hosts. Asset-side port check
    # happens in the worker via _resolve_base_url (returns None for non-web).
    dispatch_content_discovery = bool(
        body.enable_content_discovery and CONTENT_DISCOVERY_ENABLED
    )
    content_discovery_asset_ids = (
        await _assets_with_web_ports(asset_ids) if (dispatch_content_discovery and asset_ids) else set()
    )

    # Validate requested agent categories once so a typo fails the whole
    # dispatch up-front instead of quietly dropping agents per asset.
    agent_categories: list[str] | None = None
    if body.enable_agents and body.agent_categories:
        invalid = [c for c in body.agent_categories if c not in AGENT_CATEGORIES]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown agent_categories: {invalid}. Valid: {list(AGENT_CATEGORIES)}",
            )
        agent_categories = body.agent_categories

    for i, aid in enumerate(asset_ids):
        # Asset-based plans key by asset_id when callers want to send them.
        plan_payload = scan_plans.get(aid)
        result = run_nuclei_scan.apply_async(
            args=[aid],
            kwargs={"credentials": credentials_payload, "scan_plan": plan_payload},
            countdown=i * 5,
        )
        job_ids.append(result.id)

        if aid in api_fuzz_asset_ids:
            # Stagger schemathesis slightly after nuclei so the shared HTTP
            # budget on the target isn't doubly pressured during the first
            # few seconds of the scan.
            sm_result = run_schemathesis_scan.apply_async(
                args=[aid],
                kwargs={"credentials": credentials_payload},
                countdown=i * 5 + 2,
            )
            job_ids.append(sm_result.id)

        if aid in content_discovery_asset_ids:
            # Content discovery goes first in the per-asset sub-sequence
            # (countdown +1) so the endpoints it uncovers land in
            # asset_endpoints before downstream workers run — this is
            # the feedback-loop pay-off. The next scan's Nuclei-DAST /
            # schemathesis stage will see them as fresh targets.
            cd_result = run_content_discovery_scan.apply_async(
                args=[aid],
                kwargs={"credentials": credentials_payload},
                countdown=i * 5 + 1,
            )
            job_ids.append(cd_result.id)

        if body.enable_agents:
            # Agents go last in the countdown so nuclei + schemathesis
            # have warmed up the target (and potentially populated more
            # asset_endpoints via their own probes) before the LLM-driven
            # specialists start spending tokens. Each specialist
            # self-gates via applicable_when, so an asset with no HTTP
            # surface still won't waste an LLM call.
            agent_result = run_agent_scan.apply_async(
                args=[aid],
                kwargs={
                    "credentials": credentials_payload,
                    "categories": agent_categories,
                },
                countdown=i * 5 + 4,
            )
            job_ids.append(agent_result.id)
    offset = len(asset_ids)

    # Queue ad-hoc target scans
    targets = body.targets or []
    for i, target in enumerate(targets):
        target = target.strip()
        if not target:
            continue
        # Adhoc plans key by target string (URL/hostname/IP). The backend's
        # vm_scanner.start_vm_scan composes these from target_asset_map so
        # adhoc-mode tasks can still benefit from per-asset plans even though
        # the scanner doesn't see backend asset ids directly.
        plan_payload = scan_plans.get(target)
        result = run_nuclei_adhoc.apply_async(
            args=[target, body.org_id],
            kwargs={"credentials": credentials_payload, "scan_plan": plan_payload},
            countdown=(offset + i) * 5,
        )
        job_ids.append(result.id)

    return ScanResponse(
        job_ids=job_ids,
        assets_queued=len(asset_ids),
        targets_queued=len(targets),
    )


@router.get("/scans/{job_id}", response_model=JobStatusResponse)
async def get_scan_status(job_id: str):
    """Get Celery task status and result for a scan job."""
    from scanner.vm.celery_app import celery_app
    result = celery_app.AsyncResult(job_id)

    status = result.status  # PENDING, STARTED, SUCCESS, FAILURE, RETRY
    result_data = None

    if result.ready():
        try:
            result_data = result.result
            if isinstance(result_data, Exception):
                result_data = {"error": str(result_data)}
        except Exception as exc:
            result_data = {"error": str(exc)}

    return JobStatusResponse(
        job_id=job_id,
        status=status,
        result=result_data,
    )


@router.post("/templates/validate", response_model=ValidationResponse)
async def validate_template(file: UploadFile = File(...)):
    """Upload and validate a custom Nuclei template YAML."""
    if not file.filename or not file.filename.endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="File must be a .yaml or .yml file")

    content = await file.read()
    if len(content) > 1_000_000:
        raise HTTPException(status_code=400, detail="Template file too large (max 1MB)")

    # Write to temp file for nuclei -validate
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="wb") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = validate_custom_template(tmp_path)
        return ValidationResponse(
            valid=result.valid,
            errors=result.errors,
            warnings=result.warnings,
        )
    finally:
        os.unlink(tmp_path)


@router.get("/templates/custom", response_model=list[TemplateInfo])
async def list_custom_templates():
    """List all custom templates with parsed metadata."""
    custom_dir = os.path.join(TEMPLATES_DIR, "custom")
    if not os.path.isdir(custom_dir):
        return []

    templates: list[TemplateInfo] = []
    for path in sorted(glob.glob(os.path.join(custom_dir, "**", "*.yaml"), recursive=True)):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            info = data.get("info", {})
            metadata = info.get("metadata", {})
            rel_path = os.path.relpath(path, TEMPLATES_DIR)
            templates.append(TemplateInfo(
                path=rel_path,
                name=info.get("name", os.path.basename(path)),
                tags=info.get("tags", ""),
                severity=info.get("severity", "info"),
                source=metadata.get("source", "unknown"),
            ))
        except Exception:
            continue

    return templates


async def _assets_with_api_specs(asset_ids: list[str]) -> set[str]:
    """Return the subset of ``asset_ids`` that have OpenAPI/GraphQL endpoints.

    Used to gate the schemathesis fan-out so we don't enqueue no-op tasks
    for every nuclei dispatch. One batched query keeps this cheap even
    when ``scan_all=true`` sends hundreds of ids.

    Degrades gracefully: any error (DB unreachable, id parse failure)
    returns an empty set. The nuclei scan is the primary signal and must
    not be aborted because the optional API-fuzz fan-out can't be resolved.
    """
    if not asset_ids:
        return set()
    import logging
    import uuid as _uuid

    import asyncpg

    from scanner.vm.config import DATABASE_URL
    from scanner.vm.db import _normalize_dsn

    _logger = logging.getLogger(__name__)

    try:
        uuids = [_uuid.UUID(a) for a in asset_ids]
    except (ValueError, TypeError):
        return set()

    try:
        conn = await asyncpg.connect(_normalize_dsn(DATABASE_URL))
    except Exception as e:
        _logger.warning("schemathesis fan-out skipped — cannot reach DB: %s", e)
        return set()

    try:
        rows = await conn.fetch(
            """
            SELECT DISTINCT asset_id
            FROM asset_endpoints
            WHERE asset_id = ANY($1::uuid[])
              AND source IN ('openapi', 'graphql')
            """,
            uuids,
        )
        return {str(r["asset_id"]) for r in rows}
    except Exception as e:
        _logger.warning("schemathesis fan-out skipped — asset_endpoints query failed: %s", e)
        return set()
    finally:
        await conn.close()


async def _assets_with_web_ports(asset_ids: list[str]) -> set[str]:
    """Return the subset of ``asset_ids`` that have a web-serving port open.

    Checks ``assets.open_ports`` for any of the standard HTTP(S) ports we
    gate content discovery on. Matches the port set in
    ``scanner.vm.router._WEB_PORTS`` — kept as a literal here to avoid
    importing the template router into the dispatch path (the router
    depends on TEMPLATES_DIR which may not exist in slim API containers).

    Degrades gracefully: any error returns an empty set so the rest of
    the fan-out still dispatches.
    """
    if not asset_ids:
        return set()
    import logging
    import uuid as _uuid

    import asyncpg

    from scanner.vm.config import DATABASE_URL
    from scanner.vm.db import _normalize_dsn

    _logger = logging.getLogger(__name__)

    try:
        uuids = [_uuid.UUID(a) for a in asset_ids]
    except (ValueError, TypeError):
        return set()

    try:
        conn = await asyncpg.connect(_normalize_dsn(DATABASE_URL))
    except Exception as e:
        _logger.warning("content-discovery fan-out skipped — cannot reach DB: %s", e)
        return set()

    web_ports = [80, 443, 3000, 5000, 8000, 8001, 8080, 8443]
    try:
        rows = await conn.fetch(
            """
            SELECT id FROM assets
            WHERE id = ANY($1::uuid[])
              AND open_ports && $2::int[]
            """,
            uuids,
            web_ports,
        )
        return {str(r["id"]) for r in rows}
    except Exception as e:
        _logger.warning("content-discovery fan-out skipped — assets query failed: %s", e)
        return set()
    finally:
        await conn.close()


def create_app():
    """Create the FastAPI app for the VM scanner API service."""
    from fastapi import FastAPI

    app = FastAPI(title="Hakuna VM Scanner", version="1.0.0")
    app.include_router(router)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "vm-scanner"}

    return app

"""VM Scanner API — trigger scans, check status, manage custom templates."""

import glob
import os
import tempfile
import uuid

import yaml
from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from scanner.vm.config import TEMPLATES_DIR
from scanner.vm.nuclei_worker import fetch_alive_assets, run_nuclei_scan
from scanner.vm.template_validator import validate_custom_template

router = APIRouter(prefix="/vm", tags=["vm-scanner"])


# ---------- Request / Response models ----------

class ScanRequest(BaseModel):
    asset_ids: list[str] | None = None
    scan_all: bool = False


class ScanResponse(BaseModel):
    job_ids: list[str]
    assets_queued: int


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
    """Enqueue Nuclei scans for specified assets or all confirmed-alive assets."""
    if not body.asset_ids and not body.scan_all:
        raise HTTPException(status_code=400, detail="Provide asset_ids or set scan_all=true")

    if body.scan_all:
        from scanner.vm.nuclei_worker import _run_async
        assets = _run_async(fetch_alive_assets())
        asset_ids = [str(a["id"]) for a in assets]
    else:
        asset_ids = body.asset_ids or []

    job_ids = []
    for i, aid in enumerate(asset_ids):
        result = run_nuclei_scan.apply_async(
            args=[aid],
            countdown=i * 5,  # Light stagger for on-demand scans
        )
        job_ids.append(result.id)

    return ScanResponse(job_ids=job_ids, assets_queued=len(asset_ids))


@router.get("/scans/{job_id}", response_model=JobStatusResponse)
async def get_scan_status(job_id: str):
    """Get Celery task status and result for a scan job."""
    result = run_nuclei_scan.AsyncResult(job_id)

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


def create_app():
    """Create the FastAPI app for the VM scanner API service."""
    from fastapi import FastAPI

    app = FastAPI(title="Hakuna VM Scanner", version="1.0.0")
    app.include_router(router)

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "vm-scanner"}

    return app

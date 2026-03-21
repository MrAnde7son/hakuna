"""
VM Scanner service — proxies scan requests to the hakuna-vm-scanner container
and manages Scan records in the main database.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

import os

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.models import Asset, Finding, Scan, Organization

logger = logging.getLogger(__name__)

VM_SCANNER_URL = os.getenv("VM_SCANNER_URL", "http://localhost:8002")


async def _vm_request(method: str, path: str, **kwargs) -> Optional[dict]:
    """Make a request to the VM scanner API."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(method, f"{VM_SCANNER_URL}{path}", **kwargs)
            resp.raise_for_status()
            return resp.json()
    except Exception:
        logger.exception("VM scanner request failed: %s %s", method, path)
        return None


async def start_vm_scan(
    db: Session,
    org: Organization,
    targets: list[str],
    asset_ids: list[int] | None = None,
) -> Optional[dict]:
    """
    Create a Scan record and dispatch targets to the VM scanner container.
    asset_ids: optional list of existing asset IDs (parallel to targets) to link findings to.
    Returns dict with scan_id, job_ids, status.
    """
    now = datetime.utcnow()
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"

    # Build target→asset_id map for linking findings to existing assets
    target_asset_map = {}
    if asset_ids and len(asset_ids) == len(targets):
        for t, aid in zip(targets, asset_ids):
            target_asset_map[t] = aid

    scan = Scan(
        org_id=org.id,
        filename=f"vm-scan-{now.strftime('%Y%m%d-%H%M%S')}",
        scan_name=f"VM Scan — {target_label}",
        scan_date=now.isoformat(),
        scan_type="vm_scan",
        source_type="vm_scanner",
        raw_metadata={
            "targets": targets,
            "target_asset_map": target_asset_map,
            "status": "running",
            "job_ids": [],
            "completed_jobs": 0,
            "total_jobs": len(targets),
            "findings_emitted": 0,
            "imported_job_ids": [],
        },
    )
    db.add(scan)
    db.flush()  # get scan.id

    # Dispatch to VM scanner container
    result = await _vm_request("POST", "/vm/scans/", json={
        "targets": targets,
    })

    if result and result.get("job_ids"):
        scan.raw_metadata = {
            **scan.raw_metadata,
            "job_ids": result["job_ids"],
            "total_jobs": len(result["job_ids"]),
        }
    else:
        scan.raw_metadata = {**scan.raw_metadata, "status": "failed"}

    db.commit()

    return {
        "scan_id": scan.id,
        "job_ids": result.get("job_ids", []) if result else [],
        "targets_queued": result.get("targets_queued", 0) if result else 0,
        "status": scan.raw_metadata["status"],
    }


async def rescan_vm_scan(db: Session, scan: Scan) -> Optional[dict]:
    """
    Re-run an existing VM scan in-place: clear old results and re-dispatch the same targets.
    """
    targets = (scan.raw_metadata or {}).get("targets", [])
    if not targets:
        return None

    now = datetime.utcnow()

    # Delete findings and assets from the previous run that belong to this scan
    finding_ids = [r[0] for r in db.query(Finding.id).filter(Finding.scan_id == scan.id).all()]
    if finding_ids:
        db.query(Finding).filter(Finding.id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.scan_id == scan.id).delete(synchronize_session=False)

    # Reset scan state
    scan.scan_date = now.isoformat()
    scan.raw_metadata = {
        **scan.raw_metadata,
        "status": "running",
        "job_ids": [],
        "completed_jobs": 0,
        "total_jobs": len(targets),
        "findings_emitted": 0,
        "imported_job_ids": [],
    }
    db.flush()

    # Re-dispatch to VM scanner container
    result = await _vm_request("POST", "/vm/scans/", json={"targets": targets})

    if result and result.get("job_ids"):
        scan.raw_metadata = {
            **scan.raw_metadata,
            "job_ids": result["job_ids"],
            "total_jobs": len(result["job_ids"]),
        }
    else:
        scan.raw_metadata = {**scan.raw_metadata, "status": "failed"}

    db.commit()

    return {
        "scan_id": scan.id,
        "job_ids": result.get("job_ids", []) if result else [],
        "targets_queued": result.get("targets_queued", 0) if result else 0,
        "status": scan.raw_metadata["status"],
    }


async def refresh_vm_scan(db: Session, scan_id: int) -> Optional[dict]:
    """
    Poll job statuses from the VM scanner and update the Scan record.
    Imports findings from completed jobs as Asset + Finding rows.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.source_type != "vm_scanner":
        return None

    meta = dict(scan.raw_metadata or {})
    if meta.get("status") in ("completed", "failed"):
        return meta

    job_ids = meta.get("job_ids", [])
    if not job_ids:
        return meta

    imported_job_ids = set(meta.get("imported_job_ids", []))
    completed = 0
    total_findings = meta.get("findings_emitted", 0)
    all_done = True
    any_failed = False

    for job_id in job_ids:
        result = await _vm_request("GET", f"/vm/scans/{job_id}")
        if not result:
            all_done = False
            continue

        status = result.get("status", "PENDING")
        if status in ("SUCCESS",):
            completed += 1
            job_result = result.get("result")

            # Import findings from this job if not already imported
            if job_result and job_id not in imported_job_ids:
                new_findings = _import_adhoc_findings(db, scan, job_result)
                total_findings += new_findings
                imported_job_ids.add(job_id)

        elif status == "FAILURE":
            completed += 1
            any_failed = True
        else:
            all_done = False

    # Update metadata
    new_meta = {
        **meta,
        "completed_jobs": completed,
        "findings_emitted": total_findings,
        "imported_job_ids": list(imported_job_ids),
    }

    if all_done:
        new_meta["status"] = "completed" if not any_failed else "completed_with_errors"
    else:
        new_meta["status"] = "running"

    scan.raw_metadata = new_meta
    db.commit()

    # Run full post-ingest pipeline when scan completes
    if all_done:
        from services.post_ingest import finalize_scan
        finalize_scan(db, scan_id=scan.id, org_id=scan.org_id)

    return new_meta


def _import_adhoc_findings(db: Session, scan: Scan, job_result: dict) -> int:
    """Import findings from a completed adhoc nuclei job into the scan.

    If the target was linked to an existing asset (via target_asset_map),
    findings are attached to that asset. Otherwise creates a new asset.
    Returns the number of findings created.
    """
    target = job_result.get("target", "")
    findings_data = job_result.get("findings", [])

    meta = scan.raw_metadata or {}
    target_asset_map = meta.get("target_asset_map", {})

    # Check if this target maps to an existing asset
    existing_asset_id = target_asset_map.get(target)
    asset = None
    if existing_asset_id:
        asset = db.query(Asset).filter(Asset.id == existing_asset_id).first()

    if not asset:
        # Try to find an existing asset in this org by IP or hostname (dedup)
        if _is_ip(target):
            asset = (
                db.query(Asset)
                .join(Scan, Asset.scan_id == Scan.id)
                .filter(Scan.org_id == scan.org_id, Asset.ip == target)
                .first()
            )
        else:
            asset = (
                db.query(Asset)
                .join(Scan, Asset.scan_id == Scan.id)
                .filter(
                    Scan.org_id == scan.org_id,
                    or_(Asset.hostname == target, Asset.fqdn == target),
                )
                .first()
            )

    if not asset:
        # No existing asset found — create one under this scan
        asset = Asset(
            scan_id=scan.id,
            ip=target if _is_ip(target) else "",
            hostname=target if not _is_ip(target) else "",
        )
        db.add(asset)
        db.flush()

    if not findings_data:
        return 0

    # Insert findings
    created = 0
    now = datetime.utcnow()
    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for f in findings_data:
        severity_str = (f.get("severity") or "info").lower()
        if severity_str not in severity_map:
            severity_str = "info"

        # Check for duplicate
        existing = db.query(Finding.id).filter(
            Finding.scan_id == scan.id,
            Finding.asset_id == asset.id,
            Finding.plugin_id == f.get("template_id", ""),
        ).first()
        if existing:
            continue

        finding = Finding(
            scan_id=scan.id,
            asset_id=asset.id,
            source_type="vm_scanner",
            source_systems=["vm_scanner"],
            plugin_id=f.get("template_id", ""),
            plugin_name=f.get("name", ""),
            severity=severity_map.get(severity_str, 0),
            description=f.get("description", ""),
            solution="",
            plugin_family="Nuclei",
            plugin_output=f.get("matched_at", ""),
            port=str(f.get("port", "")) if f.get("port") else None,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
        created += 1

    db.flush()
    return created


def _is_ip(s: str) -> bool:
    """Quick check if a string looks like an IP address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


async def get_vm_health() -> Optional[dict]:
    """Check if the VM scanner container is reachable."""
    return await _vm_request("GET", "/health")

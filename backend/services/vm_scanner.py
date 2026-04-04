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
from sqlalchemy import cast, or_, String
from sqlalchemy.orm import Session

from models.models import Asset, Finding, Scan, Organization
from services.asset_observations import record_observation, record_finding_observation

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
    meta = dict(scan.raw_metadata or {})

    # Snapshot previous run before wiping state
    previous_run = {
        "status": meta.get("status", "unknown"),
        "completed_jobs": meta.get("completed_jobs", 0),
        "total_jobs": meta.get("total_jobs", 0),
        "findings_emitted": meta.get("findings_emitted", 0),
        "job_statuses": meta.get("job_statuses", {}),
        "scan_date": scan.scan_date,
    }

    # Delete findings and assets from the previous run that belong to this scan
    finding_ids = [r[0] for r in db.query(Finding.id).filter(Finding.scan_id == scan.id).all()]
    if finding_ids:
        db.query(Finding).filter(Finding.id.in_(finding_ids)).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.scan_id == scan.id).delete(synchronize_session=False)

    # Reset scan state, preserving previous_run history
    scan.scan_date = now.isoformat()
    scan.raw_metadata = {
        **meta,
        "status": "running",
        "job_ids": [],
        "completed_jobs": 0,
        "total_jobs": len(targets),
        "findings_emitted": 0,
        "imported_job_ids": [],
        "job_statuses": {},
        "previous_run": previous_run,
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

    # Auto-fail scans that have been running for more than 3 hours (Celery results expire)
    try:
        scan_started = datetime.fromisoformat(scan.scan_date)
        if (datetime.utcnow() - scan_started).total_seconds() > 3 * 3600:
            logger.warning("VM scan %d has been running >3h — marking as failed (stale)", scan_id)
            stale_meta = {**meta, "status": "failed", "error": "Scan timed out — job results may have expired"}
            scan.raw_metadata = stale_meta
            db.commit()
            return stale_meta
    except Exception:
        pass

    imported_job_ids = set(meta.get("imported_job_ids", []))
    completed = 0
    total_findings = meta.get("findings_emitted", 0)
    all_done = True
    any_failed = False

    # Per-job status log: {job_id: {target, status, findings_count, error}}
    job_statuses = dict(meta.get("job_statuses", {}))

    for job_id in job_ids:
        result = await _vm_request("GET", f"/vm/scans/{job_id}")
        if not result:
            all_done = False
            job_statuses[job_id] = {**job_statuses.get(job_id, {}), "status": "PENDING"}
            continue

        status = result.get("status", "PENDING")
        job_result = result.get("result") or {}
        target = job_result.get("target", "")

        if status == "SUCCESS":
            completed += 1
            findings_data = job_result.get("findings", [])

            # Import findings from this job if not already imported
            if job_result and job_id not in imported_job_ids:
                new_findings = _import_adhoc_findings(db, scan, job_result)
                total_findings += new_findings
                imported_job_ids.add(job_id)

            job_status = {
                "target": target,
                "status": "SUCCESS",
                "findings_count": len(findings_data),
                "templates_matched": job_result.get("templates_matched", 0),
                "templates_loaded": job_result.get("templates_loaded", 0),
                "requests_sent": job_result.get("requests_sent", 0),
                "duration_seconds": job_result.get("duration_seconds"),
                "nuclei_status": job_result.get("status"),
                "routing_info": job_result.get("routing_info"),
            }
            if job_result.get("nuclei_stderr"):
                job_status["nuclei_stderr"] = job_result["nuclei_stderr"]
            job_statuses[job_id] = job_status

        elif status == "FAILURE":
            completed += 1
            any_failed = True
            error_msg = job_result.get("error") or job_result.get("traceback") or "Job failed"
            # Truncate long tracebacks to keep metadata lean
            if len(error_msg) > 300:
                error_msg = error_msg[:300] + "…"
            job_statuses[job_id] = {
                "target": target or job_statuses.get(job_id, {}).get("target", ""),
                "status": "FAILURE",
                "error": error_msg,
            }
        else:
            all_done = False
            job_statuses[job_id] = {**job_statuses.get(job_id, {}), "status": "PENDING"}

    # Update metadata
    new_meta = {
        **meta,
        "completed_jobs": completed,
        "findings_emitted": total_findings,
        "imported_job_ids": list(imported_job_ids),
        "job_statuses": job_statuses,
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
            source_systems=["vm_scanner"],
        )
        db.add(asset)
        db.flush()
    else:
        # Extend the existing asset's source_systems to include vm_scanner
        existing_sources = list(asset.source_systems or [])
        if "vm_scanner" not in existing_sources:
            asset.source_systems = existing_sources + ["vm_scanner"]

    # Record per-source observation
    record_observation(
        db, asset_id=asset.id, source_system="vm_scanner",
        raw_fields={"ip": target if _is_ip(target) else "", "hostname": target if not _is_ip(target) else ""},
        scan_id=scan.id, org_id=scan.org_id,
    )

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
        db.flush()

        record_finding_observation(
            db, finding_id=finding.id, source_system="vm_scanner",
            raw_fields=f, scan_id=scan.id, org_id=scan.org_id,
        )
        created += 1

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


# ── Auto VM scan after EASM discovery ─────────────────────────────

# High-value ports that indicate scannable services (web apps, admin panels, APIs)
_HIGH_VALUE_PORTS = {80, 443, 8080, 8443, 8888, 3000, 5000, 8000, 9090, 9443}

MAX_AUTO_VM_TARGETS = 20


async def trigger_vm_scan_for_easm_assets(
    db: Session, org: Organization, easm_scan_id: int, domain: str,
) -> Optional[dict]:
    """
    Auto-trigger a VM scan on the most valuable EASM-discovered assets.

    Called after EASM import completes. Selects up to MAX_AUTO_VM_TARGETS assets
    prioritized by: has high-value open ports, has detected tech stack,
    not behind CDN/WAF (direct targets yield better results).

    Creates a proper Scan record so it appears on the scans page.
    Idempotent — skips if a VM scan was already triggered for this EASM scan.
    """
    # Guard: don't trigger twice for the same EASM scan
    existing = db.query(Scan.id).filter(
        Scan.org_id == org.id,
        Scan.source_type == "vm_scanner",
        cast(Scan.raw_metadata, String).contains(f'"easm_scan_id": {easm_scan_id}'),
    ).first()
    if existing:
        logger.info("VM scan already triggered for EASM scan %s (vm_scan=%s), skipping", easm_scan_id, existing[0])
        return None

    # Fetch EASM assets from this scan
    assets = db.query(Asset).filter(
        Asset.scan_id == easm_scan_id,
        Asset.is_internet_facing == True,
    ).all()

    if not assets:
        logger.info("No EASM assets to auto-scan for org %s", org.id)
        return None

    # Score and rank assets for VM scanning
    scored: list[tuple[float, Asset]] = []
    for asset in assets:
        easm = asset.easm_data or {}
        score = 0.0

        # Prefer assets with high-value open ports
        ports = set(easm.get("open_ports") or [])
        high_value_hits = ports & _HIGH_VALUE_PORTS
        score += len(high_value_hits) * 2.0

        # Prefer assets with detected tech stack (more templates will match)
        tech = easm.get("tech_stack") or []
        if tech:
            score += min(len(tech), 5)  # cap contribution

        # Prefer assets that are alive (have HTTP response)
        if easm.get("http_status"):
            score += 3.0

        # Deprioritize assets behind CDN/WAF (scans hit the CDN, not the origin)
        if easm.get("cdn_provider"):
            score -= 4.0
        if easm.get("waf"):
            score -= 2.0

        # Skip assets with no ports and no HTTP — nothing to scan
        if not ports and not easm.get("http_status"):
            continue

        scored.append((score, asset))

    if not scored:
        logger.info("No scannable EASM assets for org %s (all filtered out)", org.id)
        return None

    # Sort by score descending, take top N
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = scored[:MAX_AUTO_VM_TARGETS]

    # Build targets and asset_id mapping
    targets = []
    asset_ids = []
    for _score, asset in selected:
        # Prefer FQDN (Nuclei works best with hostnames), fall back to IP
        target = asset.fqdn or asset.hostname or asset.ip
        if target:
            targets.append(target)
            asset_ids.append(asset.id)

    if not targets:
        return None

    logger.info(
        "Auto-triggering VM scan for %d EASM assets (org=%s, domain=%s)",
        len(targets), org.id, domain,
    )

    result = await start_vm_scan(db, org, targets, asset_ids=asset_ids)

    if result and result.get("scan_id"):
        # Tag the scan so the UI knows it was auto-triggered from EASM
        scan = db.query(Scan).filter(Scan.id == result["scan_id"]).first()
        if scan:
            scan.scan_name = f"VM Scan — {domain} (auto, from EASM)"
            scan.raw_metadata = {
                **scan.raw_metadata,
                "auto_triggered": True,
                "triggered_by": "easm",
                "easm_scan_id": easm_scan_id,
                "easm_domain": domain,
            }
            db.commit()

    return result

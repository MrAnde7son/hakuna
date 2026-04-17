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

# A running VM scan older than this is considered stale. Celery result TTL in
# the VM scanner is effectively bounded by Redis lifetime, and anything older
# than this is almost certainly orphaned (worker/broker restart, lost job ids).
VM_SCAN_STALE_THRESHOLD_SECONDS = 3 * 3600

# Tighter cap for the "broker-restart orphan" case: when every job id we submitted
# still comes back PENDING (not STARTED/SUCCESS/FAILURE), the worker has never
# picked up any of our tasks. Celery returns PENDING for both "queued, waiting"
# AND "unknown task id", so after this threshold we treat it as the latter —
# the Redis broker was restarted and our job ids point to nothing. Reasonable
# scans start producing STARTED/SUCCESS statuses within a few minutes even for
# slow targets, so 20 min is well outside the normal ramp-up window.
VM_SCAN_PENDING_ORPHAN_SECONDS = 20 * 60


def _has_observed_progress(job_statuses: dict) -> bool:
    """True if any job has ever transitioned out of PENDING.

    Used to distinguish "tasks are sitting in a live queue" (at least one
    STARTED/SUCCESS/FAILURE) from "broker has no record of our tasks" (every
    job perpetually PENDING). Called by both the refresh path and the reaper
    so they agree on what "orphan" means.
    """
    for info in (job_statuses or {}).values():
        status = (info or {}).get("status")
        if status and status != "PENDING":
            return True
    return False


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


async def _resolve_scan_credentials(
    db: Session, org_id: int, credential_id: str,
) -> dict:
    """Resolve an IntegrationCredential into the scanner's ScanCredentials shape.

    Decrypts the credential via credential_manager.load_credentials and maps
    the stored values onto the type=basic|bearer|cookie|header payload the
    scanner expects. Raises HTTPException(404) if the credential does not
    exist or does not belong to ``org_id``.

    The decrypted values are never logged. Only the credential id and auth
    type are echoed to the logger so an operator can verify routing.
    """
    from fastapi import HTTPException
    from models.models import IntegrationCredential
    from services import credential_manager

    cred_row = db.query(IntegrationCredential).filter(
        IntegrationCredential.id == credential_id,
        IntegrationCredential.org_id == org_id,
    ).first()
    if not cred_row:
        raise HTTPException(status_code=404, detail="Credential not found")

    values = await credential_manager.load_credentials(db, credential_id, org_id)
    if not values:
        raise HTTPException(status_code=404, detail="Credential not found")

    auth_type = (cred_row.auth_type or "").lower()
    payload: dict = {"type": "header", "headers": {}}

    if auth_type == "basic":
        payload = {
            "type": "basic",
            "username": values.get("username") or values.get("user") or "",
            "password": values.get("password") or values.get("pass") or "",
        }
    elif auth_type in ("bearer", "oauth2", "pat"):
        token = (
            values.get("access_token")
            or values.get("token")
            or values.get("api_token")
            or values.get("pat")
            or ""
        )
        payload = {"type": "bearer", "token": token}
    elif auth_type == "api_key":
        # API keys are typically sent as a header. Use an explicit header
        # name from the credential blob when provided; otherwise fall back
        # to Authorization: Bearer so the common case works out of the box.
        header_name = values.get("_header_name") or values.get("header_name")
        api_key = values.get("api_key") or values.get("token") or ""
        if header_name and api_key:
            payload = {"type": "header", "headers": {header_name: api_key}}
        elif api_key:
            payload = {"type": "bearer", "token": api_key}
    else:
        # Unknown / custom: try to be useful if a cookie or arbitrary headers
        # were stored, otherwise leave an empty header map — the scanner
        # will run unauthenticated rather than shelling bad args.
        cookie = values.get("cookie") or values.get("session")
        extra_headers = values.get("headers") if isinstance(values.get("headers"), dict) else None
        if cookie:
            payload = {"type": "cookie", "cookie": cookie}
        elif extra_headers:
            payload = {"type": "header", "headers": extra_headers}

    logger.info(
        "VM scan using credential id=%s org=%s auth_type=%s (values not logged)",
        credential_id, org_id, auth_type,
    )
    return payload


async def start_vm_scan(
    db: Session,
    org: Organization,
    targets: list[str],
    asset_ids: list[int] | None = None,
    credential_id: str | None = None,
) -> Optional[dict]:
    """
    Create a Scan record and dispatch targets to the VM scanner container.
    asset_ids: optional list of existing asset IDs (parallel to targets) to link findings to.
    credential_id: optional IntegrationCredential.id whose decrypted secrets are
      passed to the scanner as HTTP headers. The credential must belong to
      ``org``; HTTPException(404) is raised if not. Decrypted values are
      never logged or persisted on the scan record.
    Returns dict with scan_id, job_ids, status.
    """
    now = datetime.utcnow()
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"

    # Build target→asset_id map for linking findings to existing assets
    target_asset_map = {}
    if asset_ids and len(asset_ids) == len(targets):
        for t, aid in zip(targets, asset_ids):
            target_asset_map[t] = aid

    # Resolve credentials (if requested) before creating the Scan record so
    # a bad credential_id fails fast with no side effects on the DB.
    credentials_payload: dict | None = None
    if credential_id:
        credentials_payload = await _resolve_scan_credentials(db, org.id, credential_id)

    scan_metadata = {
        "targets": targets,
        "target_asset_map": target_asset_map,
        "status": "running",
        "job_ids": [],
        "completed_jobs": 0,
        "total_jobs": len(targets),
        "findings_emitted": 0,
        "imported_job_ids": [],
    }
    # Store only the credential id reference — NEVER the decrypted values.
    if credential_id:
        scan_metadata["credential_id"] = credential_id

    scan = Scan(
        org_id=org.id,
        filename=f"vm-scan-{now.strftime('%Y%m%d-%H%M%S')}",
        scan_name=f"VM Scan — {target_label}",
        scan_date=now.isoformat(),
        scan_type="vm_scan",
        source_type="vm_scanner",
        raw_metadata=scan_metadata,
    )
    db.add(scan)
    db.flush()  # get scan.id

    # Look up persisted scan plans for any assets we're targeting and key
    # them by the target string the scanner will see (URL/hostname/IP). The
    # scanner queues per-target tasks and doesn't know backend asset ids,
    # so target-keyed plans let nuclei_worker pick the right plan for each
    # task without a second round-trip. Assets without a plan flow through
    # the legacy TemplateRouter path — backwards compatible.
    scan_plans: dict[str, dict] = {}
    if asset_ids and target_asset_map:
        plan_rows = (
            db.query(Asset.id, Asset.scan_plan, Asset.scan_plan_version)
            .filter(Asset.id.in_(asset_ids))
            .all()
        )
        plans_by_aid = {
            row.id: {"plan": row.scan_plan, "version": row.scan_plan_version or 0}
            for row in plan_rows if row.scan_plan
        }
        for tgt, aid in target_asset_map.items():
            if aid in plans_by_aid:
                scan_plans[tgt] = plans_by_aid[aid]

    # Dispatch to VM scanner container. The credentials block is in the POST
    # body only; VM_SCANNER_URL must be a trusted internal endpoint.
    scan_body: dict = {"targets": targets}
    if credentials_payload:
        scan_body["credentials"] = credentials_payload
    if scan_plans:
        scan_body["scan_plans"] = scan_plans
        scan_metadata["scan_plan_count"] = len(scan_plans)
    result = await _vm_request("POST", "/vm/scans/", json=scan_body)

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

    # Auto-fail scans that have been running longer than the stale threshold
    # (Celery results expire, broker may have restarted, etc.)
    try:
        scan_started = datetime.fromisoformat(scan.scan_date)
        if (datetime.utcnow() - scan_started).total_seconds() > VM_SCAN_STALE_THRESHOLD_SECONDS:
            logger.warning(
                "VM scan %d has been running >%dh — marking as failed (stale)",
                scan_id, VM_SCAN_STALE_THRESHOLD_SECONDS // 3600,
            )
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

    # Track whether the VM scanner API answered at all during this refresh.
    # Used below to disambiguate "API unreachable (transient)" from "API up
    # but broker has no record of our tasks (orphan)" — only the latter
    # should trip the 20-min PENDING orphan timeout.
    any_api_response = False

    # Accumulate per-job-imported IDs so finalize_batch can run after this
    # refresh commits. Running it inline per-job would risk holding an
    # in-flight transaction open across multiple steps; running it once
    # after the whole refresh commits keeps savepoint semantics clean while
    # still being strictly incremental (scan is still running).
    batch_new_asset_ids: list[int] = []
    batch_new_finding_ids: list[int] = []

    for job_id in job_ids:
        result = await _vm_request("GET", f"/vm/scans/{job_id}")
        if not result:
            # Transient API failure — leave the prior status as-is so the
            # orphan detector doesn't mistake API downtime for broker loss.
            all_done = False
            if job_id not in job_statuses:
                job_statuses[job_id] = {"status": "PENDING"}
            continue

        any_api_response = True
        status = result.get("status", "PENDING")
        job_result = result.get("result") or {}
        target = job_result.get("target", "")

        if status == "SUCCESS":
            completed += 1
            findings_data = job_result.get("findings", [])

            # Import findings from this job if not already imported
            if job_result and job_id not in imported_job_ids:
                import_result = _import_nuclei_job_findings(db, scan, job_result)
                total_findings += import_result["count"]
                batch_new_asset_ids.extend(import_result["new_asset_ids"])
                batch_new_finding_ids.extend(import_result["new_finding_ids"])
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
            # Preserve the actual Celery state (PENDING/STARTED/RETRY/…) so
            # the orphan detector can see when the worker has picked a task
            # up. Flattening everything to PENDING here used to mask that.
            all_done = False
            job_statuses[job_id] = {
                **job_statuses.get(job_id, {}),
                "status": status,
                "target": target or job_statuses.get(job_id, {}).get("target", ""),
            }

    # Update metadata
    new_meta = {
        **meta,
        "completed_jobs": completed,
        "findings_emitted": total_findings,
        "imported_job_ids": list(imported_job_ids),
        "job_statuses": job_statuses,
    }

    # Broker-restart orphan detection: if the VM scanner answered our polls
    # (so we know it's up) but *no* job has ever advanced past PENDING after
    # VM_SCAN_PENDING_ORPHAN_SECONDS, the Celery broker has lost our task ids
    # — the jobs will sit at PENDING forever. Fail fast so the UI doesn't
    # spin and the user can rescan.
    if (
        not all_done
        and any_api_response
        and not _has_observed_progress(job_statuses)
    ):
        try:
            scan_started = datetime.fromisoformat(scan.scan_date)
            age_seconds = (datetime.utcnow() - scan_started).total_seconds()
        except Exception:
            age_seconds = 0
        if age_seconds > VM_SCAN_PENDING_ORPHAN_SECONDS:
            logger.warning(
                "VM scan %d orphaned — all %d jobs PENDING after %.0fs; broker likely restarted",
                scan_id, len(job_ids), age_seconds,
            )
            new_meta["status"] = "failed"
            new_meta["error"] = (
                "Orphaned — scanner broker lost the job queue (likely restart). "
                "Rescan to dispatch fresh jobs."
            )
            scan.raw_metadata = new_meta
            db.commit()
            return new_meta

    if all_done:
        new_meta["status"] = "completed" if not any_failed else "completed_with_errors"
    else:
        new_meta["status"] = "running"

    scan.raw_metadata = new_meta
    db.commit()

    # Incremental post-ingest: tag, prioritize, and fire triggers for rows
    # imported during THIS refresh so partial results look triaged in the UI
    # immediately. Skipped when the scan is terminal (finalize_scan covers it).
    if not all_done and (batch_new_asset_ids or batch_new_finding_ids):
        try:
            from services.post_ingest import finalize_batch
            finalize_batch(
                db,
                scan_id=scan.id,
                org_id=scan.org_id,
                new_asset_ids=batch_new_asset_ids,
                new_finding_ids=batch_new_finding_ids,
            )
            db.commit()
        except Exception:
            logger.exception(
                "finalize_batch failed for scan %d (non-fatal; finalize_scan will reprocess)",
                scan.id,
            )

    # Run full post-ingest pipeline when scan completes
    if all_done:
        from services.post_ingest import finalize_scan
        finalize_scan(db, scan_id=scan.id, org_id=scan.org_id)

    return new_meta


def reap_stale_vm_scans(db: Session | None = None) -> dict:
    """Mark orphaned VM scans as failed.

    The staleness check inside ``refresh_vm_scan`` only fires when someone
    polls the scan (e.g. the Scan Management page). If no user is watching,
    a scan can sit in ``status=running`` forever after a VM scanner / Redis
    restart wipes the job ids. This reaper runs as a periodic background job
    to close that gap.

    Returns ``{"checked": n, "reaped": m}``.
    """
    from core.database import SessionLocal

    own_session = db is None
    if own_session:
        db = SessionLocal()

    reaped = 0
    checked = 0
    try:
        # All VM scans that may still be running. The set is small (running
        # scans, per org), so filter status in Python to stay dialect-agnostic
        # across SQLite/Postgres JSON access.
        candidates = (
            db.query(Scan)
            .filter(Scan.source_type == "vm_scanner")
            .all()
        )

        now = datetime.utcnow()
        for scan in candidates:
            meta = scan.raw_metadata or {}
            if meta.get("status") != "running":
                continue
            checked += 1
            try:
                scan_started = datetime.fromisoformat(scan.scan_date)
            except Exception:
                continue
            age_seconds = (now - scan_started).total_seconds()

            # Hard cap: anything running for 3h+ is definitely orphaned
            # (Celery result TTL, broker lifetime, etc.).
            if age_seconds > VM_SCAN_STALE_THRESHOLD_SECONDS:
                logger.warning(
                    "Reaper: VM scan %d (org=%s) running >%dh — marking failed",
                    scan.id, scan.org_id, VM_SCAN_STALE_THRESHOLD_SECONDS // 3600,
                )
                scan.raw_metadata = {
                    **meta,
                    "status": "failed",
                    "error": "Scan timed out — job results may have expired (reaped by background job)",
                }
                reaped += 1
                continue

            # Tighter cap: if a prior refresh populated job_statuses and every
            # observed job is still PENDING after VM_SCAN_PENDING_ORPHAN_SECONDS,
            # the broker dropped the queue. job_statuses is only populated by
            # refresh_vm_scan, so a scan that nobody has ever polled won't get
            # caught here — the 3h cap above covers that case.
            job_statuses = meta.get("job_statuses") or {}
            if (
                job_statuses
                and age_seconds > VM_SCAN_PENDING_ORPHAN_SECONDS
                and not _has_observed_progress(job_statuses)
            ):
                logger.warning(
                    "Reaper: VM scan %d (org=%s) all jobs PENDING after %.0fs — marking failed (broker orphan)",
                    scan.id, scan.org_id, age_seconds,
                )
                scan.raw_metadata = {
                    **meta,
                    "status": "failed",
                    "error": (
                        "Orphaned — scanner broker lost the job queue (likely restart). "
                        "Rescan to dispatch fresh jobs."
                    ),
                }
                reaped += 1
                continue

        if reaped:
            db.commit()
    except Exception:
        logger.exception("VM scan reaper failed")
        db.rollback()
    finally:
        if own_session:
            db.close()

    return {"checked": checked, "reaped": reaped}


def _build_nuclei_plugin_output(f: dict) -> str:
    """Compose a human-readable plugin_output for a Nuclei finding.

    Nuclei templates often use `extractors` to pull the concrete evidence
    (e.g. the specific weak SSH algorithms, exposed headers, leaked values).
    Surface those extracted values in plugin_output so they show up on the
    finding's Overview tab instead of being buried in Sources raw fields.
    """
    lines: list[str] = []
    matched_at = f.get("matched_at") or ""
    if matched_at:
        lines.append(f"Matched at: {matched_at}")

    extracted = f.get("extracted_results") or []
    if isinstance(extracted, list) and extracted:
        lines.append("Extracted values:")
        for val in extracted:
            lines.append(f"  - {val}")
    elif isinstance(extracted, str) and extracted.strip():
        lines.append("Extracted values:")
        lines.append(f"  - {extracted}")

    matcher_name = f.get("matcher_name") or ""
    if matcher_name and not extracted:
        lines.append(f"Matcher: {matcher_name}")

    return "\n".join(lines)


def _import_nuclei_job_findings(db: Session, scan: Scan, job_result: dict) -> dict:
    """Import findings from a completed nuclei Celery job into the scan.

    Handles both adhoc results (keyed by `target`) and asset-based results
    (keyed by `asset_id`). The raw findings list is identical between the
    two — only asset resolution differs:

      asset-based: asset_id is already known, look up directly
      adhoc:       target → existing asset (via map/IP/hostname) or create new

    Dedup of these findings is NOT performed here. Cross-scan dedup is
    applied by services/post_ingest.finalize_scan, which is the single
    authority for per-org dedup rules.

    Returns a dict ``{count, new_asset_ids, new_finding_ids}`` so the caller
    can drive per-batch finalize_batch without rescanning the DB.
    """
    findings_data = job_result.get("findings", [])
    target = job_result.get("target", "")
    asset_id_in = job_result.get("asset_id")

    meta = scan.raw_metadata or {}
    asset: Asset | None = None
    new_asset_ids: list[int] = []

    # Asset-based job (from run_nuclei_scan) — asset_id is authoritative.
    if asset_id_in:
        try:
            asset = db.query(Asset).filter(Asset.id == asset_id_in).first()
        except Exception:
            asset = None
        if not asset:
            logger.warning(
                "VM scan job referenced asset_id %s which no longer exists — skipping",
                asset_id_in,
            )
            return {"count": 0, "new_asset_ids": [], "new_finding_ids": []}
        existing_sources = list(asset.source_systems or [])
        if "vm_scanner" not in existing_sources:
            asset.source_systems = existing_sources + ["vm_scanner"]
    else:
        # Adhoc job — resolve by target against this scan's prefilled map,
        # then by IP/hostname in the same org, creating a new asset if none.
        target_asset_map = meta.get("target_asset_map", {})
        existing_asset_id = target_asset_map.get(target)
        if existing_asset_id:
            asset = db.query(Asset).filter(Asset.id == existing_asset_id).first()

        if not asset:
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
            asset = Asset(
                scan_id=scan.id,
                ip=target if _is_ip(target) else "",
                hostname=target if not _is_ip(target) else "",
                source_systems=["vm_scanner"],
            )
            db.add(asset)
            db.flush()
            new_asset_ids.append(asset.id)
        else:
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
        return {"count": 0, "new_asset_ids": new_asset_ids, "new_finding_ids": []}

    # Insert findings
    created = 0
    new_finding_ids: list[int] = []
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
            plugin_output=_build_nuclei_plugin_output(f),
            port=str(f.get("port", "")) if f.get("port") else None,
            first_seen=now,
            last_seen=now,
        )
        db.add(finding)
        db.flush()
        new_finding_ids.append(finding.id)

        record_finding_observation(
            db, finding_id=finding.id, source_system="vm_scanner",
            raw_fields=f, scan_id=scan.id, org_id=scan.org_id,
        )
        created += 1

    return {
        "count": created,
        "new_asset_ids": new_asset_ids,
        "new_finding_ids": new_finding_ids,
    }


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

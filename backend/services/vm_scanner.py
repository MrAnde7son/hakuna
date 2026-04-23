"""
VM Scanner service — proxies scan requests to the hakuna-vm-scanner container
and manages Scan records in the main database.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

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


def _revoke_vm_jobs_sync(job_ids: list[str]) -> int:
    """Best-effort revoke of Celery task ids on the VM scanner.

    Called from the sync reaper when marking a scan failed. Without this,
    the tasks keep draining the queue and burning request budget against
    targets for a Scan record that's already dead — and worse, block newer
    scans behind the dead scan's backlog. Short per-request timeout so one
    unreachable scanner can't stall the reaper's whole sweep.
    """
    if not job_ids:
        return 0
    revoked = 0
    try:
        with httpx.Client(timeout=5) as client:
            for job_id in job_ids:
                try:
                    resp = client.delete(f"{VM_SCANNER_URL}/vm/scans/{job_id}")
                    if resp.status_code == 200 and resp.json().get("revoked"):
                        revoked += 1
                except Exception:
                    logger.debug("revoke failed for job %s (scanner unreachable?)", job_id)
    except Exception:
        logger.exception("VM revoke sweep failed")
    return revoked


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


async def _resolve_auth_profile(
    db: Session, org_id: int, auth_profile_id: str,
) -> dict:
    """Resolve an AuthProfile into a ScanCredentials payload.

    Branches on AuthProfile.profile_type:

    - ``static``     — reference to a credential; we map it through
                       ``_resolve_scan_credentials`` and hand the payload
                       straight to the scanner. No Playwright.
    - ``form_login`` — drive Playwright (cached in Redis/DB) via
                       services.session_broker, then fold the resulting
                       cookies + scraped headers onto the credential-derived
                       payload. nuclei_worker's ``-H`` builder is additive
                       on ``headers`` on top of any basic/bearer/cookie
                       scheme — see hakuna-vm-scanner/scanner/vm/nuclei_worker.py.
    """
    from fastapi import HTTPException
    from models.models import AuthProfile
    from services import session_broker

    profile = db.query(AuthProfile).filter(
        AuthProfile.id == auth_profile_id,
        AuthProfile.org_id == org_id,
    ).first()
    if not profile:
        raise HTTPException(status_code=404, detail="AuthProfile not found")

    # Credential mapping is the common base for both types — static returns
    # it directly, form_login adds session cookies on top.
    payload = await _resolve_scan_credentials(db, org_id, profile.credential_id)

    if (profile.profile_type or "").lower() == "static":
        logger.info(
            "VM scan applying auth_profile id=%s org=%s type=static",
            auth_profile_id, org_id,
        )
        return payload

    # form_login — drive the browser, merge session onto the payload
    try:
        bundle = await session_broker.get_or_create_session(db, org_id, auth_profile_id)
    except session_broker.SessionBrokerError as e:
        raise HTTPException(status_code=400, detail=f"AuthProfile login failed: {e}")

    merged_headers = dict(payload.get("headers") or {})
    if bundle.cookie_header:
        existing_cookie = merged_headers.get("Cookie") or ""
        merged = "; ".join(c for c in (existing_cookie, bundle.cookie_header) if c)
        if merged:
            merged_headers["Cookie"] = merged
    for name, value in (bundle.headers or {}).items():
        merged_headers[name] = value

    new_payload = dict(payload)
    new_payload["headers"] = merged_headers
    logger.info(
        "VM scan applying auth_profile id=%s org=%s type=form_login cookies=%d headers=%d",
        auth_profile_id, org_id,
        len(bundle.cookie_header.split("; ")) if bundle.cookie_header else 0,
        len(bundle.headers or {}),
    )
    return new_payload


async def start_vm_scan(
    db: Session,
    org: Organization,
    targets: list[str],
    asset_ids: list[int] | None = None,
    credential_id: str | None = None,
    auth_profile_id: str | None = None,
    enable_agents: bool = False,
    agent_categories: list[str] | None = None,
    enable_content_discovery: bool = True,
) -> Optional[dict]:
    """
    Create a Scan record and dispatch targets to the VM scanner container.
    asset_ids: optional list of existing asset IDs (parallel to targets) to link findings to.
    credential_id: optional IntegrationCredential.id whose decrypted secrets are
      passed to the scanner as HTTP headers. The credential must belong to
      ``org``; HTTPException(404) is raised if not. Decrypted values are
      never logged or persisted on the scan record.
    auth_profile_id: optional AuthProfile.id — when set, the session broker
      drives Playwright through the profile's login flow and merges the
      resulting cookies/headers into credentials_payload before dispatch.
      Only the id is persisted on the scan record; the session blob itself
      lives inline on the AuthProfile row (encrypted).
    Returns dict with scan_id, job_ids, status.
    """
    now = datetime.utcnow()
    target_label = targets[0] if len(targets) == 1 else f"{len(targets)} targets"

    # Build target→asset_id map for linking findings to existing assets
    target_asset_map = {}
    if asset_ids and len(asset_ids) == len(targets):
        for t, aid in zip(targets, asset_ids):
            target_asset_map[t] = aid

    # Resolve auth before creating the Scan record so a bad id fails fast
    # with no side effects. auth_profile_id wins if both are set — a profile
    # already bundles a credential reference, and re-merging on top of a
    # second credential_id produces a confusing payload.
    credentials_payload: dict | None = None
    if auth_profile_id:
        credentials_payload = await _resolve_auth_profile(db, org.id, auth_profile_id)
    elif credential_id:
        credentials_payload = await _resolve_scan_credentials(db, org.id, credential_id)

    scan_metadata = {
        "targets": targets,
        "target_asset_map": target_asset_map,
        "status": "running",
        "job_ids": [],
        "completed_jobs": 0,
        "total_jobs": len(targets),
        "completed_targets": 0,
        "total_targets": len(targets),
        "findings_emitted": 0,
        "imported_job_ids": [],
        "current_run_id": uuid.uuid4().hex,
    }
    # Store only id references — NEVER the decrypted values / session blob.
    if credential_id:
        scan_metadata["credential_id"] = credential_id
    if auth_profile_id:
        scan_metadata["auth_profile_id"] = auth_profile_id
    # Persist the agent-fanout intent so rescan replays the same settings
    # without the caller having to re-opt-in. False values are omitted to
    # keep existing metadata rows untouched.
    if enable_agents:
        scan_metadata["enable_agents"] = True
        if agent_categories:
            scan_metadata["agent_categories"] = list(agent_categories)
    if enable_content_discovery:
        scan_metadata["enable_content_discovery"] = True

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
    if enable_agents:
        scan_body["enable_agents"] = True
        if agent_categories:
            scan_body["agent_categories"] = list(agent_categories)
    if enable_content_discovery:
        scan_body["enable_content_discovery"] = True
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


async def rescan_vm_scan(
    db: Session,
    scan: Scan,
    targets_override: list[str] | None = None,
    credential_id_override: str | None = None,
    auth_profile_id_override: str | None = None,
    enable_agents_override: bool | None = None,
    agent_categories_override: list[str] | None = None,
    overrides_applied: bool = False,
) -> Optional[dict]:
    """
    Re-run an existing VM scan in-place: clear old results and re-dispatch.

    By default replays the original targets, credential_id, and auth_profile_id
    captured in scan.raw_metadata. Any ``*_override`` argument replaces the
    corresponding field — used by the edit-and-rerun flow so the UI can let
    users tweak targets or auth without creating a brand-new scan row.
    ``overrides_applied=True`` signals that the caller explicitly passed
    overrides (even empty ones), so we treat ``[]`` as "clear targets".
    """
    meta = dict(scan.raw_metadata or {})
    targets = targets_override if (targets_override is not None) else meta.get("targets", [])
    if not targets:
        return None

    credential_id = credential_id_override if overrides_applied else meta.get("credential_id")
    auth_profile_id = auth_profile_id_override if overrides_applied else meta.get("auth_profile_id")
    # Rescan replays agent settings when the caller doesn't override. An
    # explicit ``enable_agents_override=False`` with overrides_applied=True
    # turns agents back off.
    if overrides_applied and enable_agents_override is not None:
        enable_agents = bool(enable_agents_override)
        agent_categories = agent_categories_override
    else:
        enable_agents = bool(meta.get("enable_agents"))
        agent_categories = meta.get("agent_categories")
    # Content discovery is on by default. Rescans replay the stored
    # flag when it's present; when absent (scans predating the feature)
    # we default to True so rescans of legacy scans pick up the new
    # surface automatically. Callers that need to suppress it should
    # set scan_metadata["enable_content_discovery"]=False explicitly.
    enable_content_discovery = bool(
        meta.get("enable_content_discovery", True)
    )

    now = datetime.utcnow()

    # Snapshot previous run before rotating state. We keep the prior run's
    # findings/assets in place (tagged with previous_run_id) until the new run
    # finalizes successfully — see _drop_superseded_run in post_ingest.
    previous_run_id = meta.get("current_run_id")
    previous_run = {
        "status": meta.get("status", "unknown"),
        "completed_jobs": meta.get("completed_jobs", 0),
        "total_jobs": meta.get("total_jobs", 0),
        "completed_targets": meta.get("completed_targets", 0),
        "total_targets": meta.get("total_targets", len(meta.get("targets") or [])),
        "findings_emitted": meta.get("findings_emitted", 0),
        "job_statuses": meta.get("job_statuses", {}),
        "scan_date": scan.scan_date,
        "targets": meta.get("targets", []),
        "credential_id": meta.get("credential_id"),
        "auth_profile_id": meta.get("auth_profile_id"),
        "run_id": previous_run_id,
    }

    # Resolve auth before wiping state — a bad profile/credential should fail
    # the whole rescan, not leave the scan in a half-cleared state.
    credentials_payload: dict | None = None
    if auth_profile_id:
        credentials_payload = await _resolve_auth_profile(db, scan.org_id, auth_profile_id)
    elif credential_id:
        credentials_payload = await _resolve_scan_credentials(db, scan.org_id, credential_id)

    # Reset scan state, preserving previous_run history + updated targets/auth.
    # Old run's Finding/Asset rows stay in the DB until finalize — a failed
    # rescan then rolls back via _rollback_failed_run and the prior run is
    # restored intact.
    new_run_id = uuid.uuid4().hex
    new_meta = {
        **meta,
        "targets": targets,
        "status": "running",
        "job_ids": [],
        "completed_jobs": 0,
        "total_jobs": len(targets),
        "completed_targets": 0,
        "total_targets": len(targets),
        "findings_emitted": 0,
        "imported_job_ids": [],
        "job_statuses": {},
        "previous_run": previous_run,
        "previous_run_id": previous_run_id,
        "current_run_id": new_run_id,
    }
    # Update id references (or drop them if cleared)
    if credential_id:
        new_meta["credential_id"] = credential_id
    else:
        new_meta.pop("credential_id", None)
    if auth_profile_id:
        new_meta["auth_profile_id"] = auth_profile_id
    else:
        new_meta.pop("auth_profile_id", None)
    if enable_agents:
        new_meta["enable_agents"] = True
        if agent_categories:
            new_meta["agent_categories"] = list(agent_categories)
        else:
            new_meta.pop("agent_categories", None)
    else:
        new_meta.pop("enable_agents", None)
        new_meta.pop("agent_categories", None)
    if enable_content_discovery:
        new_meta["enable_content_discovery"] = True
    else:
        new_meta.pop("enable_content_discovery", None)

    scan.scan_date = now.isoformat()
    scan.raw_metadata = new_meta
    db.flush()

    # Re-dispatch to VM scanner container
    scan_body: dict = {"targets": targets}
    if credentials_payload:
        scan_body["credentials"] = credentials_payload
    if enable_agents:
        scan_body["enable_agents"] = True
        if agent_categories:
            scan_body["agent_categories"] = list(agent_categories)
    if enable_content_discovery:
        scan_body["enable_content_discovery"] = True
    result = await _vm_request("POST", "/vm/scans/", json=scan_body)

    if result and result.get("job_ids"):
        scan.raw_metadata = {
            **scan.raw_metadata,
            "job_ids": result["job_ids"],
            "total_jobs": len(result["job_ids"]),
        }
    else:
        _rollback_failed_run(db, scan)
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
            _revoke_vm_jobs_sync(job_ids)
            _rollback_failed_run(db, scan)
            rolled_meta = dict(scan.raw_metadata or {})
            stale_meta = {**rolled_meta, "status": "failed", "error": "Scan timed out — job results may have expired"}
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

    # Target-level progress: a target is complete only when *every* job it
    # fanned out into (nuclei + content discovery + agent scans) is terminal.
    # Users submit targets, so we show targets — the underlying job count is
    # a scanner implementation detail.
    terminal_states = {"SUCCESS", "FAILURE"}
    jobs_by_target: dict[str, list[str]] = {}
    for info in job_statuses.values():
        tgt = (info or {}).get("target") or ""
        if not tgt:
            continue
        jobs_by_target.setdefault(tgt, []).append((info or {}).get("status") or "")
    completed_targets = sum(
        1 for statuses in jobs_by_target.values()
        if statuses and all(s in terminal_states for s in statuses)
    )
    total_targets = meta.get("total_targets") or len(meta.get("targets") or [])

    # Update metadata
    new_meta = {
        **meta,
        "completed_jobs": completed,
        "completed_targets": completed_targets,
        "total_targets": total_targets,
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
            _revoke_vm_jobs_sync(job_ids)
            scan.raw_metadata = new_meta
            _rollback_failed_run(db, scan)
            orphan_meta = dict(scan.raw_metadata or {})
            orphan_meta["status"] = "failed"
            orphan_meta["error"] = (
                "Orphaned — scanner broker lost the job queue (likely restart). "
                "Rescan to dispatch fresh jobs."
            )
            scan.raw_metadata = orphan_meta
            db.commit()
            return orphan_meta

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
        try:
            from services.post_ingest import finalize_scan
            finalize_scan(db, scan_id=scan.id, org_id=scan.org_id)
            db.commit()
        except Exception:
            logger.exception("finalize_scan failed for scan %d", scan.id)
            db.rollback()

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
        # scans, per org), so filter status in Python rather than reaching
        # into the JSON column in SQL.
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
                # Revoke before mutating metadata so the tasks stop consuming
                # queue time even if the commit below fails.
                _revoke_vm_jobs_sync(meta.get("job_ids") or [])
                _rollback_failed_run(db, scan)
                rolled = dict(scan.raw_metadata or {})
                scan.raw_metadata = {
                    **rolled,
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
                _revoke_vm_jobs_sync(meta.get("job_ids") or [])
                _rollback_failed_run(db, scan)
                rolled = dict(scan.raw_metadata or {})
                scan.raw_metadata = {
                    **rolled,
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


def current_run_scope(scan: Scan, column):
    """Return a SQLAlchemy filter clause that scopes rows to the scan's
    current run_id (NULL-safe so legacy rows and non-VM scans aren't dropped).

    Use this when querying Findings/Assets for a scan whose rescan may have
    an old run and a new run temporarily coexisting — e.g. in-flight rescan
    counts and listings. Pass ``Finding.scan_run_id`` or ``Asset.scan_run_id``
    as the ``column``.
    """
    meta = (scan.raw_metadata or {}) if scan is not None else {}
    current_run_id = meta.get("current_run_id")
    if not current_run_id:
        return True  # no run scoping available — match everything
    return or_(column.is_(None), column == current_run_id)


def _rollback_failed_run(db: Session, scan: Scan) -> dict:
    """Undo the in-flight run when a VM scan fails or is reaped.

    Deletes Finding/Asset rows stamped with the current run_id and restores
    the metadata pointer to the previous run_id so the UI keeps showing the
    last successful scan. For first-ever scans (no previous_run_id) this
    just empties the scan — the rollback is idempotent.

    Mutates scan.raw_metadata in place; caller is responsible for the commit.
    """
    meta = dict(scan.raw_metadata or {})
    current_run_id = meta.get("current_run_id")
    previous_run_id = meta.get("previous_run_id")
    if not current_run_id:
        return {"findings_deleted": 0, "assets_deleted": 0}

    findings_deleted = db.query(Finding).filter(
        Finding.scan_id == scan.id,
        Finding.scan_run_id == current_run_id,
    ).delete(synchronize_session=False)

    # An asset tagged with current_run_id isn't necessarily *new* to this run —
    # imports re-stamp pre-existing assets with the in-flight run_id so mid-scan
    # query scoping works. If the prior run's findings still reference it, the
    # asset pre-existed and must be preserved (revert its stamp); otherwise it's
    # safe to delete. Hard-deleting an asset with surviving findings tripped a
    # FK integrity error on stop/rollback.
    assets_deleted = 0
    if previous_run_id:
        db.query(Asset).filter(
            Asset.scan_id == scan.id,
            Asset.scan_run_id == current_run_id,
            Asset.id.in_(
                db.query(Finding.asset_id).filter(
                    Finding.scan_id == scan.id,
                    Finding.scan_run_id == previous_run_id,
                )
            ),
        ).update({Asset.scan_run_id: previous_run_id}, synchronize_session=False)

        assets_deleted = db.query(Asset).filter(
            Asset.scan_id == scan.id,
            Asset.scan_run_id == current_run_id,
        ).delete(synchronize_session=False)
    else:
        assets_deleted = db.query(Asset).filter(
            Asset.scan_id == scan.id,
            Asset.scan_run_id == current_run_id,
        ).delete(synchronize_session=False)

    # Restore the previous run_id so mid-scan query scoping falls back to
    # the preserved prior run. If there was no previous run, clear the field.
    if previous_run_id:
        meta["current_run_id"] = previous_run_id
    else:
        meta.pop("current_run_id", None)
    meta.pop("previous_run_id", None)
    scan.raw_metadata = meta

    if findings_deleted or assets_deleted:
        logger.info(
            "Rolled back failed run (scan_id=%s run_id=%s): findings=%d assets=%d",
            scan.id, current_run_id, findings_deleted, assets_deleted,
        )
    return {
        "findings_deleted": findings_deleted,
        "assets_deleted": assets_deleted,
    }


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_nuclei_cves(f: dict) -> list[str]:
    """Pull CVE IDs off a Nuclei result. Nuclei reports them under
    info.classification["cve-id"] (string or list) for CVE-tagged templates;
    for templates named CVE-YYYY-NNNN(.yaml) we also fall back to the
    template_id so the finding still ties to a CVE even when the template
    author skipped the classification block.
    """
    cves: list[str] = []
    classification = f.get("classification") or {}
    raw = classification.get("cve-id") if isinstance(classification, dict) else None
    if isinstance(raw, str):
        cves.extend(m.group(0).upper() for m in _CVE_RE.finditer(raw))
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                cves.extend(m.group(0).upper() for m in _CVE_RE.finditer(item))

    template_id = f.get("template_id") or ""
    if isinstance(template_id, str):
        cves.extend(m.group(0).upper() for m in _CVE_RE.finditer(template_id))

    seen: set[str] = set()
    unique: list[str] = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def _extract_nuclei_cvss(f: dict) -> tuple[Optional[float], Optional[str]]:
    """Return (cvss3_score, cvss3_vector) from a Nuclei result's
    classification block, or (None, None) if absent/unparseable.
    """
    classification = f.get("classification") or {}
    if not isinstance(classification, dict):
        return None, None

    score: Optional[float] = None
    raw_score = classification.get("cvss-score")
    if isinstance(raw_score, (int, float)):
        score = float(raw_score)
    elif isinstance(raw_score, str):
        try:
            score = float(raw_score.strip())
        except ValueError:
            score = None

    vector: Optional[str] = None
    raw_vec = classification.get("cvss-metrics")
    if isinstance(raw_vec, str) and raw_vec.strip():
        vector = raw_vec.strip()

    return score, vector


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
    current_run_id = meta.get("current_run_id")
    asset: Asset | None = None
    new_asset_ids: list[int] = []
    cls = _classify_vm_target(target) if target else {
        "asset_type": "host", "url": None, "ip": None, "hostname": None,
    }

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
        if asset.scan_id == scan.id and current_run_id:
            asset.scan_run_id = current_run_id
    else:
        # Adhoc job — resolve by target against this scan's prefilled map,
        # then by IP/hostname/url in the same org, creating a new asset if none.
        target_asset_map = meta.get("target_asset_map", {})
        existing_asset_id = target_asset_map.get(target)
        if existing_asset_id:
            asset = db.query(Asset).filter(Asset.id == existing_asset_id).first()

        if not asset:
            if cls["asset_type"] == "web_app":
                # Match an existing web_app by the shared dedup key (url)
                from services.dedup import resolve_asset_by_dedup_keys
                asset = resolve_asset_by_dedup_keys(
                    db,
                    {"asset_identity": {"url": cls["url"]}},
                    scan.org_id,
                    asset_type="web_app",
                )
            elif cls["ip"]:
                asset = (
                    db.query(Asset)
                    .join(Scan, Asset.scan_id == Scan.id)
                    .filter(Scan.org_id == scan.org_id, Asset.ip == cls["ip"])
                    .first()
                )
            elif cls["hostname"]:
                asset = (
                    db.query(Asset)
                    .join(Scan, Asset.scan_id == Scan.id)
                    .filter(
                        Scan.org_id == scan.org_id,
                        or_(Asset.hostname == cls["hostname"], Asset.fqdn == cls["hostname"]),
                    )
                    .first()
                )

        if not asset:
            asset_kwargs = {
                "scan_id": scan.id,
                "scan_run_id": current_run_id,
                "ip": cls["ip"] or "",
                "hostname": cls["hostname"] or "",
                "source_systems": ["vm_scanner"],
            }
            if cls["asset_type"] == "web_app":
                asset_kwargs["asset_type"] = "web_app"
                asset_kwargs["asset_identity"] = {"url": cls["url"]}
            asset = Asset(**asset_kwargs)
            db.add(asset)
            db.flush()
            new_asset_ids.append(asset.id)
        else:
            existing_sources = list(asset.source_systems or [])
            if "vm_scanner" not in existing_sources:
                asset.source_systems = existing_sources + ["vm_scanner"]
            if asset.scan_id == scan.id and current_run_id:
                asset.scan_run_id = current_run_id

    # Record per-source observation
    record_observation(
        db, asset_id=asset.id, source_system="vm_scanner",
        raw_fields={
            "ip": cls["ip"] or "",
            "hostname": cls["hostname"] or "",
            "url": cls["url"],
        },
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

        # Check for duplicate within the current run only — old-run rows
        # coexist until finalize swaps them out, so we must scope by run_id
        # or we'd silently drop fresh findings as "already ingested".
        existing = db.query(Finding.id).filter(
            Finding.scan_id == scan.id,
            Finding.scan_run_id == current_run_id,
            Finding.asset_id == asset.id,
            Finding.plugin_id == f.get("template_id", ""),
        ).first()
        if existing:
            continue

        # plugin_family distinguishes Nuclei signature matches from
        # Schemathesis property-based check failures and specialist
        # agent LLM-driven findings — all three flow through this
        # worker → backend path via identical payload shape, but
        # downstream (llm validator, rule engine, UI badge) wants to
        # treat them differently.
        _finding_type = (f.get("type") or "").lower()
        if _finding_type == "agent-vuln":
            plugin_family = "Agent"
        elif _finding_type == "api-fuzz":
            plugin_family = "Schemathesis"
        elif _finding_type == "content-discovery":
            plugin_family = "ContentDiscovery"
        else:
            plugin_family = "Nuclei"

        # Schemathesis pre-seeds llm_validation.verdict on its results so
        # high-confidence findings (server errors, schema violations)
        # bypass the async LLM re-validation queue and feed the
        # prioritizer immediately. The Nuclei path leaves this None and
        # the post-ingest llm_vuln_validator fills it in.
        llm_validation = f.get("llm_validation") if isinstance(f.get("llm_validation"), dict) else None

        cves = _extract_nuclei_cves(f)
        cvss3_score, cvss3_vector = _extract_nuclei_cvss(f)

        finding = Finding(
            scan_id=scan.id,
            scan_run_id=current_run_id,
            asset_id=asset.id,
            source_type="vm_scanner",
            source_systems=["vm_scanner"],
            plugin_id=f.get("template_id", ""),
            plugin_name=f.get("name", ""),
            severity=severity_map.get(severity_str, 0),
            description=f.get("description", ""),
            solution="",
            plugin_family=plugin_family,
            plugin_output=_build_nuclei_plugin_output(f),
            port=str(f.get("port", "")) if f.get("port") else None,
            first_seen=now,
            last_seen=now,
            llm_validation=llm_validation,
            cves=cves,
            normalized_id=cves[0] if cves else None,
            cvss3_score=cvss3_score,
            cvss3_vector=cvss3_vector,
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


def _classify_vm_target(target: str) -> dict:
    """Classify a VM scan target string into identity fields.

    Returns keys: asset_type ("host"|"web_app"), url, ip, hostname.
    URL targets (http:// or https://) become web_app so they dedup with
    Nessus WAS and other URL-scoped sources instead of landing as a bogus
    host named "http://...". IPs and bare hostnames stay as host.
    """
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            from services.dedup import normalize_web_app_url
            return {
                "asset_type": "web_app",
                "url": normalize_web_app_url(t) or t,
                "ip": host if _is_ip(host) else None,
                "hostname": host if not _is_ip(host) else None,
            }
    return {
        "asset_type": "host",
        "url": None,
        "ip": t if _is_ip(t) else None,
        "hostname": t if t and not _is_ip(t) else None,
    }


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

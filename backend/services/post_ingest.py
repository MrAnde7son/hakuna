"""
Post-ingest pipeline — the single finalization step that runs after any
asset/finding batch lands in the database, regardless of source (VM scan
upload, EASM import, VM scanner, integration builder, etc.).

Every enrichment, tagging, ownership, SLA, dedup, and exception step that
was previously hardcoded in the upload endpoint lives here so that all
ingestion paths get consistent treatment.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def finalize_batch(
    db: Session,
    scan_id: int,
    org_id: Optional[int] = None,
    new_asset_ids: Optional[list] = None,
    new_finding_ids: Optional[list] = None,
):
    """Run the *incremental* subset of post-ingest for a partial batch of
    newly-imported assets/findings inside a still-running scan.

    Called from streaming ingestion paths (VM per-job import, EASM per-poll
    import) so that partial results shown mid-scan are already tagged,
    owned, exception-filtered, prioritized, and trigger workflows — i.e.,
    they behave the same in the UI as rows that arrive in a completed scan.

    Each step is non-fatal. Scoped to the provided IDs where the underlying
    engine supports scoping; otherwise scoped to scan_id (still incremental
    because newly-imported rows are the only un-processed rows in the scan).

    Scan-level steps (SLA rollup, cross-scan dedup, corporate-tree sync,
    auto VM scan trigger, scan-complete notifications) are deliberately
    *not* run here — they belong in finalize_scan at the terminal transition.
    """
    results = {}

    # OS & Software auto-tags (scan-scoped, idempotent on existing rows)
    results["os_software_tags"] = _step(
        db, "OS/Software auto-tags (batch)", lambda: _run_os_software_tags(db, scan_id)
    )

    # Auto-tag rules (user-defined, scan-scoped, idempotent)
    results["auto_tag"] = _step(
        db, "Auto-tag rules (batch)", lambda: _run_auto_tag_rules(db, scan_id)
    )

    # Ownership rules + inference (scan-scoped, idempotent)
    results["ownership_rules"] = _step(
        db, "Ownership rules (batch)", lambda: _run_ownership_rules(db, scan_id)
    )
    results["ownership_inference"] = _step(
        db, "Ownership inference (batch)", lambda: _run_ownership_inference(db, scan_id)
    )

    # Global exceptions — apply to any new findings in scope
    results["exceptions"] = _step(
        db, "Global exceptions (batch)", lambda: _apply_global_exceptions(db, scan_id)
    )

    # Compliance evaluator — runs after exceptions so verdict can reflect
    # exception_id; runs before threat-intel so any KEV-driven rule that
    # fires this batch will re-fire on the next finalize once enrichment
    # adds is_kev=True (idempotent upsert keeps that re-fire cheap).
    results["compliance"] = _step(
        db, "Compliance evaluator (batch)",
        lambda: _run_compliance_eval(db, scan_id, org_id, new_finding_ids=new_finding_ids),
    )

    # Threat intel + TTP enrichment — local to findings in this scan
    results["threat_intel"] = _step(
        db, "Threat intel enrichment (batch)", lambda: _enrich_threat_intel(db, scan_id)
    )
    results["ttp"] = _step(
        db, "TTP matching (batch)", lambda: _match_ttps(db, scan_id)
    )

    # Finding prioritization — scoped to the newly-imported rows so partial
    # results carry a real priority_score in the UI. Runs after threat intel
    # enrichment so KEV/EPSS/exploit-maturity feed into the score.
    results["prioritize"] = _step(
        db, "Finding prioritization (batch)",
        lambda: _prioritize_findings(db, scan_id, org_id, new_finding_ids=new_finding_ids),
    )

    # Severity counter recomputation — recounts critical/high/medium/low/info
    # per asset across ALL findings (not just this scan) for assets touched by
    # the batch. Required because scanners that link findings to pre-existing
    # assets (VM scanner → EASM-discovered web_app) otherwise leave the
    # counter columns stale, and the assets inventory reads them directly.
    results["severity_counts"] = _step(
        db, "Asset severity counts (batch)",
        lambda: _recompute_asset_severity_counts(db, scan_id, new_finding_ids=new_finding_ids),
    )

    # Risk score recomputation — only affects assets in this scan
    results["risk_scores"] = _step(
        db, "Risk score recomputation (batch)",
        lambda: _recompute_risk_scores(db, scan_id),
    )

    # Fire workflow triggers for the newly-imported rows
    results["workflows"] = _step(
        db, "Workflow triggers (batch)",
        lambda: _fire_data_triggers(db, scan_id, new_asset_ids, new_finding_ids),
    )

    return results


def finalize_scan(
    db: Session,
    scan_id: int,
    org_id: Optional[int] = None,
    new_asset_ids: Optional[list] = None,
    new_finding_ids: Optional[list] = None,
):
    """Run the full post-ingest pipeline for a scan.

    Called from every ingestion path after assets/findings are committed.
    Each step is non-fatal — a failure in one step won't block the rest.

    new_asset_ids / new_finding_ids: IDs of newly *inserted* records (not updates).
    When provided, event-driven workflow triggers fire at the end of the pipeline.

    This runs the full set — the per-row steps (safe to re-run idempotently
    over the whole scan) plus the scan-level rollups that only make sense
    once all data has arrived (SLA, cross-scan dedup, auto-VM-scan trigger,
    corporate-tree sync, etc.).
    """
    results = {}

    # 0. Drop superseded run rows — VM rescans write new-run findings
    # alongside the previous run's rows. At successful finalize, we resolve
    # any open tickets on the prior run's findings (the vuln wasn't re-
    # detected, so the work is done) and delete rows tagged with a stale
    # run_id. Must run BEFORE cross-scan dedup so the dedup pass doesn't
    # see stale rows and keep them as the latest.
    results["drop_superseded_run"] = _step(
        db, "Drop superseded run rows",
        lambda: _drop_superseded_run(db, scan_id),
    )

    # 1a. OS & Software auto-tags (built-in)
    results["os_software_tags"] = _step(
        db, "OS/Software auto-tags", lambda: _run_os_software_tags(db, scan_id)
    )

    # 1b. Auto-tag rules (user-defined)
    results["auto_tag"] = _step(
        db, "Auto-tag rules", lambda: _run_auto_tag_rules(db, scan_id)
    )

    # 2. Ownership rules
    results["ownership_rules"] = _step(
        db, "Ownership rules", lambda: _run_ownership_rules(db, scan_id)
    )

    # 3. Ownership inference from inventory data
    results["ownership_inference"] = _step(
        db, "Ownership inference", lambda: _run_ownership_inference(db, scan_id)
    )

    # 4. Global exceptions
    results["exceptions"] = _step(
        db, "Global exceptions", lambda: _apply_global_exceptions(db, scan_id)
    )

    # 4b. Compliance evaluator — full-scan mode (new_finding_ids=None)
    # wipes prior compliance_finding_status rows for findings in this scan
    # so unmatched/resolved findings don't leave stale "failing" entries.
    results["compliance"] = _step(
        db, "Compliance evaluator",
        lambda: _run_compliance_eval(db, scan_id, org_id, new_finding_ids=None),
    )

    # 5b. Solution aggregation
    results["solutions"] = _step(
        db, "Solution aggregation", lambda: _aggregate_solutions(db, scan_id)
    )

    # 6. Threat intel enrichment
    results["threat_intel"] = _step(
        db, "Threat intel enrichment", lambda: _enrich_threat_intel(db, scan_id)
    )

    # 6b. Mirror KEV-flagged findings into the unified edge graph as
    # `cve_on_asset` anchors. Must run after threat-intel enrichment
    # (which is what flips `Finding.is_kev`). Idempotent — re-runs
    # only update last_seen_at on existing edges.
    if org_id:
        results["cve_edges"] = _step(
            db, "KEV cve_on_asset edges",
            lambda: _emit_kev_cve_edges(db, scan_id, org_id),
        )

    # 7. TTP matching
    results["ttp"] = _step(
        db, "TTP matching", lambda: _match_ttps(db, scan_id)
    )

    # 8. SLA computation
    results["sla"] = _step(
        db, "SLA computation", lambda: _compute_sla(db, scan_id)
    )

    # 9. Cross-scan asset dedup
    if org_id:
        results["dedup"] = _step(
            db, "Cross-scan dedup", lambda: _cross_scan_dedup(db, org_id)
        )

    # 9b. Cross-scan finding dedup — applies the org's resolved findings rule
    # so scanners (VM, EASM, Nessus parser, integrations) can emit raw rows
    # while the engine remains the single dedup authority.
    if org_id:
        results["finding_dedup"] = _step(
            db, "Cross-scan finding dedup", lambda: _cross_scan_finding_dedup(db, org_id)
        )

    # 9.5. Asset relationship inference (DNS → cloud workload)
    if org_id and scan_id:
        results["asset_relationships"] = _step(
            db, "Asset relationship inference",
            lambda: _infer_asset_relationships(db, org_id, scan_id),
        )

    # 9.55. Inventory-derived edges (netconn, AD trusts, domain membership,
    # shared sessions, runs-as principals) — feeds attack-path BFS.
    if org_id:
        results["inventory_edges"] = _step(
            db, "Inventory graph edges",
            lambda: _extract_inventory_edges(db, org_id, scan_id),
        )

    # 9.56. Unified-edge materialization from inventory (Phase 2 of the
    # Cross-Scan Chain Coordinator). Emits asset_to_asset_port /
    # user_to_asset / asset_to_asset_auth using the closed taxonomy in
    # `models.asset_edges`. Complementary to step 9.55 — both write to
    # `asset_relationships`; the Coordinator and the new blast-radius
    # read path consume the unified families.
    if org_id:
        results["inventory_unified_edges"] = _step(
            db, "Inventory unified edges",
            lambda: _materialize_inventory_unified_edges(db, org_id, scan_id),
        )

    # 9.6. Cross-finding correlation — dispatched as a background job
    # (CVE corroboration + attack-path BFS + up to 50 LLM narrations).
    # Runs async so multi-scan ingests don't serialise on one slow run,
    # and debounces per-org so EASM's batch polling doesn't cause thrash.
    if org_id:
        results["finding_correlation"] = _step(
            db, "Cross-finding correlation (dispatched)",
            lambda: _correlate_findings(db, org_id),
        )

    # 9.65. Chain Coordinator (Phase 3) — dispatched as a background job
    # alongside correlation. Reads the unified edge graph, enumerates
    # hypotheses, dispatches probes, and emits ValidatedChain findings
    # on closure. Same per-org debounce shape as correlation so a
    # multi-scan ingest collapses to a single tick.
    if org_id:
        results["chain_coordinator"] = _step(
            db, "Chain coordinator (dispatched)",
            lambda: _run_chain_coordinator(db, org_id, scan_id),
        )

    # 10. EASM enrichment
    if org_id:
        results["easm"] = _step(
            db, "EASM enrichment", lambda: _easm_enrich(db, org_id, scan_id)
        )

    # 11. Auto VM scan for EASM-discovered assets
    if org_id and scan_id:
        results["auto_vm_scan"] = _step(
            db, "Auto VM scan (EASM→VM)",
            lambda: _auto_vm_scan_for_easm(db, org_id, scan_id),
        )

    # 12. Security control validation (requires matched_ttps from step 7)
    if org_id:
        results["control_assessment"] = _step(
            db, "Control assessment",
            lambda: _run_control_assessment(db, org_id, scan_id),
        )

    # 12.5. LLM vulnerability validation — detect false positives in critical/high Nuclei findings
    if org_id:
        results["llm_validation"] = _step(
            db, "LLM vulnerability validation",
            lambda: _llm_validate_findings(db, org_id, scan_id),
        )

    # 12.6. Finding prioritization — populate priority_score / effort /
    # owner / remediation for every finding in the scan. Runs after all
    # enrichment steps so KEV / EPSS / exploit maturity / TTPs feed into
    # the score. Idempotent — safe to re-run. This is the single authority
    # for prioritization; every ingestion path (file upload, VM scanner,
    # integrations) leaves priority_score at 0.0 on insert and this step
    # fills it in.
    results["prioritize"] = _step(
        db, "Finding prioritization",
        lambda: _prioritize_findings(db, scan_id, org_id),
    )

    # 12.7. Asset severity counter recomputation — scan-wide version.
    # Same purpose as the batch step: keep Asset.critical_count/high_count/etc.
    # consistent with Finding rows across scan boundaries (VM scanner, EASM,
    # integrations often link findings to assets from a different scan).
    results["severity_counts"] = _step(
        db, "Asset severity counts",
        lambda: _recompute_asset_severity_counts(db, scan_id),
    )

    # 13. Asset risk score recomputation
    results["risk_scores"] = _step(
        db, "Risk score recomputation",
        lambda: _recompute_risk_scores(db, scan_id),
    )

    # 14. Fire event-driven workflow triggers for new data
    results["workflows"] = _step(
        db, "Workflow triggers",
        lambda: _fire_data_triggers(db, scan_id, new_asset_ids, new_finding_ids),
    )

    return results


def _step(db: Session, name: str, fn):
    """Execute a pipeline step, catching and logging failures.

    Uses a savepoint so that a failure in one step doesn't roll back the
    entire transaction (and undo previous steps' work).

    Tolerates step bodies that call `db.commit()` themselves. Several pipeline
    steps (os_software_tags, tags, ownership_inference, compliance_evaluator,
    the EASM→VM trigger flag) commit their own work — that releases the
    SAVEPOINT we opened, so `nested.commit()` afterward would raise "This
    transaction is closed". Before this fix, that raise produced a misleading
    "failed (non-fatal)" warning even though the work had succeeded; in
    production it cascaded across the whole pipeline because each subsequent
    step inherited the closed-transaction state. The savepoint's isolation
    guarantee is illusory for body-commits regardless — once the body
    committed, the work is durable and can't be rolled back by us.

    Also recovers a session left in a closed-transaction state by an
    upstream caller (e.g. a transient Cloud SQL proxy connection drop)
    so the step can still run on a fresh transaction.
    """
    # Defensive recovery: if a previous step (or upstream code) left the
    # session in a closed-transaction state, reset it before doing anything.
    if not db.is_active:
        try:
            db.rollback()
        except Exception:
            logger.warning("%s: pre-step session rollback failed", name)

    nested = None
    try:
        nested = db.begin_nested()  # SAVEPOINT
        result = fn()
        # Only commit the savepoint if it's still active. A body that called
        # `db.commit()` will have released it already; commiting again raises
        # "This transaction is closed".
        if nested.is_active:
            nested.commit()
        return result
    except Exception as e:
        if nested is not None and nested.is_active:
            try:
                nested.rollback()  # roll back only this step's changes
            except Exception:
                # Savepoint not usable (e.g. test fixtures) — full rollback
                try:
                    db.rollback()
                except Exception:
                    pass
        else:
            # Either begin_nested itself raised, or the savepoint was already
            # released (body committed and then we hit a real error after).
            # Either way, roll the outer session back so the next step can
            # open a fresh savepoint instead of inheriting broken state.
            try:
                db.rollback()
            except Exception:
                pass
        logger.warning("%s failed (non-fatal): %s", name, e)
        return None


# ── Individual pipeline steps ──────────────────────────────────────────


def _drop_superseded_run(db, scan_id):
    """Delete Finding/Asset rows from the scan's previous run at finalize.

    VM rescans mint a new `current_run_id` and write alongside the prior
    run's rows. Once the new run completes successfully we drop anything
    tagged with a stale run_id. A failed rescan takes the opposite path
    (_rollback_failed_run in vm_scanner) so the prior run is preserved.

    Open tickets on superseded findings are logged then cascade-deleted
    via the FindingTicket FK (ON DELETE CASCADE). If the underlying vuln
    isn't detected by the latest scan, the remediation work is done.
    """
    from models.models import Scan, Finding, Asset, FindingTicket

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return {"findings_deleted": 0, "assets_deleted": 0}
    meta = scan.raw_metadata or {}
    current_run_id = meta.get("current_run_id")
    if not current_run_id:
        return {"findings_deleted": 0, "assets_deleted": 0}

    stale_finding_ids = [
        fid for (fid,) in db.query(Finding.id).filter(
            Finding.scan_id == scan_id,
            Finding.scan_run_id.isnot(None),
            Finding.scan_run_id != current_run_id,
        ).all()
    ]

    tickets_auto_resolved = 0
    findings_deleted = 0
    if stale_finding_ids:
        tickets_auto_resolved = db.query(FindingTicket).filter(
            FindingTicket.finding_id.in_(stale_finding_ids),
        ).delete(synchronize_session=False)
        if tickets_auto_resolved:
            logger.info(
                "Auto-resolved %d tickets on superseded findings (scan_id=%s)",
                tickets_auto_resolved, scan_id,
            )
        findings_deleted = db.query(Finding).filter(
            Finding.id.in_(stale_finding_ids),
        ).delete(synchronize_session=False)

    assets_deleted = db.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.scan_run_id.isnot(None),
        Asset.scan_run_id != current_run_id,
    ).delete(synchronize_session=False)

    if findings_deleted or assets_deleted:
        logger.info(
            "Dropped superseded run rows (scan_id=%s): findings=%d assets=%d",
            scan_id, findings_deleted, assets_deleted,
        )
    return {
        "findings_deleted": findings_deleted,
        "assets_deleted": assets_deleted,
        "tickets_auto_resolved": tickets_auto_resolved,
    }


def _run_os_software_tags(db, scan_id):
    import services.os_software_tags as os_sw_tags
    return os_sw_tags.run_os_software_auto_tags(db, scan_id)


def _run_auto_tag_rules(db, scan_id):
    import services.tags as tag_engine
    results = tag_engine.run_all_auto_tag_rules(db, scan_id=scan_id)
    if results:
        applied = {k: v for k, v in results.items() if v}
        if applied:
            logger.info("Auto-tag results: %s", applied)
    return results


def _run_ownership_rules(db, scan_id):
    import services.tags as tag_engine
    results = tag_engine.run_all_ownership_rules(db, scan_id=scan_id)
    if results:
        applied = {k: v for k, v in results.items() if v}
        if applied:
            logger.info("Ownership rule results: %s", applied)
    return results


def _run_ownership_inference(db, scan_id):
    import services.ownership_inference as ownership_inference
    stats = ownership_inference.infer_asset_ownership(db, scan_id)
    if stats["updated"]:
        logger.info("Ownership inference: %s", stats)
    return stats


def _apply_global_exceptions(db, scan_id):
    from models.models import FindingException
    from services.exception_engine import apply_exception_to_findings

    active = db.query(FindingException).filter(FindingException.is_active == True).all()
    now = datetime.utcnow()
    applied = 0
    for exc in active:
        if exc.expires_at and exc.expires_at < now:
            exc.is_active = False
            continue
        applied += apply_exception_to_findings(db, exc, scan_id=scan_id)
    if applied:
        logger.info("Applied %d global exceptions", applied)
        db.flush()
    return applied


def _run_compliance_eval(db, scan_id, org_id, *, new_finding_ids=None):
    """Wrapper around services.compliance_evaluator.evaluate so the
    post-ingest pipeline can call it with the same lambda signature as
    every other step. Non-fatal on import or runtime errors — compliance
    state is best-effort, never gates ingestion.
    """
    from services.compliance_evaluator import evaluate as _eval
    result = _eval(
        db,
        scan_id=scan_id,
        new_finding_ids=new_finding_ids,
        org_id=org_id,
    )
    if result.get("evaluated"):
        logger.info(
            "Compliance eval: %d rule matches across %d controls",
            result["evaluated"], result.get("controls_touched", 0),
        )
    return result



def _run_control_assessment(db, org_id, scan_id):
    import services.control_assessment as control_assessment
    result = control_assessment.assess_findings(db, org_id, scan_id=scan_id)
    if result["assessed"]:
        logger.info(
            "Control assessment: %d assessed, %d mitigated, %d partial, %d not mitigated",
            result["assessed"], result["mitigated"], result["partial"], result["not_mitigated"],
        )
    return result


def _aggregate_solutions(db, scan_id):
    import services.solution_aggregator as solution_aggregator
    result = solution_aggregator.aggregate_solutions(db, scan_id=scan_id)
    if result["created"]:
        logger.info(
            "Aggregated solutions: %d groups, %d findings linked",
            result["created"], result["findings_linked"],
        )
    return result


def _enrich_threat_intel(db, scan_id):
    import threat_intel.threat_intel_sync as ti_sync
    result = ti_sync.enrich_findings_from_threat_intel(db, scan_id=scan_id)
    if result["enriched"]:
        logger.info("Threat intel enrichment: %d findings enriched", result["enriched"])
    return result


def _emit_kev_cve_edges(db, scan_id, org_id):
    from services.asset_edges import write_kev_cve_edges_for_scan
    written = write_kev_cve_edges_for_scan(db, org_id=org_id, scan_id=scan_id)
    if written:
        logger.info("KEV cve_on_asset edges: %d upserted for scan %s", written, scan_id)
    return {"edges_upserted": written}


def _match_ttps(db, scan_id):
    import threat_intel.ttp_matcher as ttp_matcher
    result = ttp_matcher.match_findings_to_ttps(db, scan_id=scan_id)
    logger.info("TTP matching: %d findings matched to ATT&CK techniques", result["matched"])
    return result


def _compute_sla(db, scan_id):
    from models.models import SLAConfig
    from services.sla_engine import ensure_sla_defaults, recalculate_sla_for_scan

    ensure_sla_defaults(db)
    configs = db.query(SLAConfig).all()
    updated = recalculate_sla_for_scan(db, scan_id, configs)
    if updated:
        logger.info("SLA computed for %d findings", updated)
    return updated


def _cross_scan_dedup(db, org_id):
    import services.dedup as dedup_engine
    from models.entity_registry import ENTITY_MODEL_MAP

    cfg = dedup_engine.load_config_for_org(db, org_id)
    if not cfg.get("enabled") or not cfg.get("apply_on_upload"):
        return None
    asset_cfg = cfg.get("assets", {})
    # Per-type config: assets is a dict of {type: {enabled, ...}} — no top-level "enabled".
    # Only skip if it's a legacy flat config with enabled=False.
    if dedup_engine._is_legacy_asset_config(asset_cfg):
        if not asset_cfg.get("enabled") or asset_cfg.get("scope", "cross_scan") != "cross_scan":
            return None

    result = dedup_engine.run_cross_scan_asset_dedup(db, org_id, cfg, ENTITY_MODEL_MAP)
    if result.get("removed"):
        logger.info("Cross-scan dedup: merged %d duplicate asset(s)", result["removed"])
    return result


def _cross_scan_finding_dedup(db, org_id):
    """Apply the org's resolved findings-dedup rule across all its findings.

    Scanners (VM scanner, EASM, Nessus parser, integration pulls) emit
    raw findings into the table. This step is the single place where the
    configurable dedup engine decides which duplicates to keep/merge.
    """
    import services.dedup as dedup_engine

    cfg = dedup_engine.load_config_for_org(db, org_id)
    if not cfg.get("enabled") or not cfg.get("apply_on_upload"):
        return None

    result = dedup_engine.run_cross_scan_finding_dedup(db, org_id, cfg)
    if result.get("removed") or result.get("merged"):
        logger.info(
            "Cross-scan finding dedup: removed=%d merged=%d (strategy=%s)",
            result.get("removed", 0), result.get("merged", 0), result.get("strategy"),
        )
    return result


def _infer_asset_relationships(db, org_id, scan_id):
    from services.asset_relationship_engine import infer_dns_to_cloud_relationships
    return infer_dns_to_cloud_relationships(db, org_id, scan_id)


def _easm_enrich(db, org_id, scan_id):
    from models.models import Organization
    from services.easm import enrich_assets_from_easm
    from core.database import SessionLocal
    import asyncio

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org or not org.easm_org_id:
        return None

    # enrich_assets_from_easm is async — bridge to sync context.
    # IMPORTANT: use a dedicated session so the caller's session isn't
    # accessed concurrently or after the request context closes.
    async def _enrich_with_own_session():
        enrich_db = SessionLocal()
        try:
            enrich_org = enrich_db.query(Organization).filter(Organization.id == org_id).first()
            await enrich_assets_from_easm(enrich_db, enrich_org, scan_id)
        except Exception:
            logger.exception("EASM enrichment failed for scan %s", scan_id)
        finally:
            enrich_db.close()

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_enrich_with_own_session())
    except RuntimeError:
        asyncio.run(_enrich_with_own_session())
    return True


def _auto_vm_scan_for_easm(db, org_id, scan_id):
    """Mark an EASM scan for follow-up VM scanning.

    The actual VM scan dispatch happens in the `process_pending_easm_vm_triggers`
    sweeper (apscheduler, every 60s). We only persist the intent here.

    Why durable handoff and not in-process: the previous implementation used
    `loop.create_task()` to fire-and-forget the dispatch on the API event loop.
    On Cloud Run, liveness-probe timeouts and rolling deploys regularly tear
    down the API instance mid-finalize, killing any background task before
    `start_vm_scan` reaches the VM scanner. Persisting a flag survives container
    death — the next instance's sweeper picks it up.
    """
    from models.models import Scan

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.source_type != "easm":
        return None

    domain = (scan.raw_metadata or {}).get("domain")
    if not domain:
        return None

    # Per-scan opt-out: same flag the audit auto-trigger honors. When the
    # operator unticked "Run automated follow-up scans" at EASM scan creation,
    # skip queueing the VM follow-up too — keeping the audit and VM rails
    # consistent on a single user-facing toggle.
    if (scan.raw_metadata or {}).get("suppress_auto_followup"):
        return {"queued": False, "domain": domain, "suppressed": True}

    md = dict(scan.raw_metadata or {})
    if md.get("needs_auto_vm_scan"):
        # Already pending — sweeper will handle it.
        return {"queued": True, "domain": domain, "already_pending": True}

    md["needs_auto_vm_scan"] = True
    scan.raw_metadata = md
    db.commit()
    return {"queued": True, "domain": domain}


def _prioritize_findings(db, scan_id, org_id, new_finding_ids=None):
    """Compute and persist priority_score, effort_level, owner_suggestion,
    and remediation_steps for findings in this scan.

    This is the single prioritization authority for the whole platform.
    Every ingestion path (file upload, VM/Nuclei scanner, EASM, integration
    builder, agent findings) inserts raw Finding rows with priority_score
    defaulting to 0.0 — this step fills them in using the finding's
    enriched state (intel, KEV, EPSS, exploit maturity) and the asset's
    inventory context (compensating controls, reachability).

    Idempotent: re-running over the same rows produces the same score.
    Scope:
      - new_finding_ids set → only those rows (used by finalize_batch).
      - None → all findings in the scan (used by finalize_scan).
    """
    from pathlib import Path
    from models.models import (
        Finding, Asset, InventorySecurityControl, InventoryNetConn,
    )
    from services.prioritizer import compute_priority_score
    import core.risk_config as risk_engine
    from parsers.parser import load_intel_json

    cfg = risk_engine.load_config_for_org(db, org_id) if org_id else risk_engine.load_config()
    intel_path = Path(__file__).parent.parent / "data" / "intel.json"
    intel = load_intel_json(str(intel_path)) if intel_path.exists() else {}

    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if new_finding_ids:
        q = q.filter(Finding.id.in_(new_finding_ids))
    findings = q.all()
    if not findings:
        return {"updated": 0, "total": 0}

    asset_ids = {f.asset_id for f in findings if f.asset_id is not None}
    assets = {
        a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    } if asset_ids else {}

    # Build per-asset inventory context once and reuse across this asset's findings.
    inv_cache: dict[int, dict] = {}

    def _inv_for(asset_id: int, asset) -> dict:
        if asset_id in inv_cache:
            return inv_cache[asset_id]
        av = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset_id,
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).first()
        fw = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset_id,
            InventorySecurityControl.control_type == "firewall",
            InventorySecurityControl.is_enabled == True,
        ).first()
        netconns = db.query(InventoryNetConn.local_port, InventoryNetConn.state).filter(
            InventoryNetConn.asset_id == asset_id,
            InventoryNetConn.local_port.isnot(None),
        ).all()
        listening_ports, established_ports = set(), set()
        for row in netconns:
            if row.local_port is None:
                continue
            state = (row.state or "").upper()
            if state in ("LISTEN", "LISTENING"):
                listening_ports.add(row.local_port)
            elif state == "ESTABLISHED":
                established_ports.add(row.local_port)
        is_internet_facing = False
        if asset is not None:
            if getattr(asset, "is_internet_facing", False):
                is_internet_facing = True
            else:
                env = (asset.environment_tag or "").lower()
                if env in ("external", "dmz"):
                    is_internet_facing = True
                elif asset.ip and not asset.ip.startswith((
                    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.",
                )):
                    is_internet_facing = True
        ctx = {
            "has_av":                  av is not None if av is not None else None,
            "has_firewall":            fw is not None if fw is not None else None,
            "established_connections": len(established_ports),
            "listening_ports":         listening_ports,
            "established_ports":       established_ports,
            "is_internet_facing":      is_internet_facing,
        }
        inv_cache[asset_id] = ctx
        return ctx

    updated = 0
    for f in findings:
        asset = assets.get(f.asset_id)
        inv_ctx = _inv_for(f.asset_id, asset) if asset else {}
        finding_dict = {
            "plugin_id":        f.plugin_id,
            "plugin_name":      f.plugin_name,
            "plugin_family":    f.plugin_family,
            "severity":         f.severity,
            "port":              f.port,
            "cvss2_score":      f.cvss2_score,
            "cvss3_score":      f.cvss3_score,
            "cvss4_score":      f.cvss4_score,
            "vpr_score":        f.vpr_score,
            "cves":             f.cves or [],
            "exploit_available": f.exploit_available,
            "exploit_maturity":  f.exploit_maturity,
            "zero_day":          f.zero_day,
            "is_kev":            f.is_kev or False,
            "epss_score":        f.epss_score,
            "ransomware_linked": f.ransomware_linked or False,
            "trending_in_news":  f.trending_in_news or False,
            "solution":          f.solution,
            "synopsis":          f.synopsis,
            "asset_os":          (asset.os if asset else "") or "",
        }
        pdata = compute_priority_score(
            finding_dict,
            asset_criticality=(asset.criticality if asset else 5) or 5,
            intel=intel,
            risk_cfg=cfg,
            asset_inventory=inv_ctx,
        )
        f.priority_score    = pdata["priority_score"]
        f.effort_level      = pdata["effort_level"]
        f.owner_suggestion  = pdata["owner_suggestion"]
        f.remediation_steps = pdata["remediation_steps"]
        updated += 1

    if updated:
        db.flush()
        logger.info(
            "Prioritization: %d finding(s) scored for scan %d", updated, scan_id
        )
    return {"updated": updated, "total": len(findings)}


def _recompute_asset_severity_counts(db, scan_id, new_finding_ids=None):
    """Recount Finding.severity per asset and write back the stored counter
    columns (critical_count/high_count/medium_count/low_count/info_count).

    Scope of *which assets* to recount:
      - If new_finding_ids is provided → the distinct asset_ids on those rows
        (batch mode — called from finalize_batch).
      - Otherwise → every asset that has a finding in this scan, unioned
        with assets whose scan_id == scan_id (scan-wide mode).

    For each asset in scope, the count is computed across *all* findings
    linked to that asset, regardless of scan_id. This is deliberate: VM
    scanner and other streaming ingestors link new findings to pre-existing
    assets (from an earlier EASM scan, say), and the per-scan recount in
    app.py misses those. Recounting over all findings is idempotent.
    """
    from models.models import Asset, Finding
    from sqlalchemy import func as sa_func

    if new_finding_ids:
        asset_ids = [
            r[0] for r in db.query(Finding.asset_id)
            .filter(Finding.id.in_(new_finding_ids))
            .filter(Finding.asset_id.isnot(None))
            .distinct().all()
        ]
    else:
        finding_asset_ids = [
            r[0] for r in db.query(Finding.asset_id)
            .filter(Finding.scan_id == scan_id)
            .filter(Finding.asset_id.isnot(None))
            .distinct().all()
        ]
        scan_asset_ids = [
            r[0] for r in db.query(Asset.id)
            .filter(Asset.scan_id == scan_id).all()
        ]
        asset_ids = list(set(finding_asset_ids) | set(scan_asset_ids))

    if not asset_ids:
        return {"updated": 0, "total": 0}

    rows = (
        db.query(Finding.asset_id, Finding.severity, sa_func.count(Finding.id))
        .filter(Finding.asset_id.in_(asset_ids))
        .group_by(Finding.asset_id, Finding.severity)
        .all()
    )
    count_map: dict[int, dict[int, int]] = {}
    for asset_id, sev, cnt in rows:
        count_map.setdefault(asset_id, {})[sev] = cnt

    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    updated = 0
    for asset in assets:
        counts = count_map.get(asset.id, {})
        new_c = counts.get(4, 0)
        new_h = counts.get(3, 0)
        new_m = counts.get(2, 0)
        new_l = counts.get(1, 0)
        new_i = counts.get(0, 0)
        if (
            asset.critical_count != new_c
            or asset.high_count != new_h
            or asset.medium_count != new_m
            or asset.low_count != new_l
            or asset.info_count != new_i
        ):
            asset.critical_count = new_c
            asset.high_count = new_h
            asset.medium_count = new_m
            asset.low_count = new_l
            asset.info_count = new_i
            updated += 1
    if updated:
        db.flush()
        logger.info(
            "Severity counts: %d asset(s) updated (scan %s)", updated, scan_id
        )
    return {"updated": updated, "total": len(assets)}


def _recompute_risk_scores(db, scan_id):
    """Recompute risk scores for every asset in a scan using the full formula."""
    from models.models import Asset, Finding, InventorySecurityControl, InventoryNetConn
    from core import risk_config as risk_engine

    cfg = risk_engine.load_config()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    updated = 0
    for asset in assets:
        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        findings_dicts = [
            {
                "severity":          f.severity,
                "port":              f.port,
                "exploit_available": f.exploit_available,
                "exploit_maturity":  f.exploit_maturity,
                "vpr_score":         f.vpr_score,
                "zero_day":          f.zero_day,
                "is_kev":            f.is_kev or False,
                "epss_score":        f.epss_score,
                "ransomware_linked": f.ransomware_linked or False,
                "trending_in_news":  f.trending_in_news or False,
            }
            for f in findings
        ]
        # Build inventory context for compensating controls + reachability
        av = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset.id,
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).first()
        fw = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset.id,
            InventorySecurityControl.control_type == "firewall",
            InventorySecurityControl.is_enabled == True,
        ).first()
        netconns = db.query(InventoryNetConn.local_port, InventoryNetConn.state).filter(
            InventoryNetConn.asset_id == asset.id,
            InventoryNetConn.local_port.isnot(None),
        ).all()
        listening_ports = set()
        established_ports = set()
        for row in netconns:
            if row.local_port is None:
                continue
            state = (row.state or "").upper()
            if state in ("LISTEN", "LISTENING"):
                listening_ports.add(row.local_port)
            elif state == "ESTABLISHED":
                established_ports.add(row.local_port)

        is_internet_facing = False
        if asset.is_internet_facing:
            is_internet_facing = True
        else:
            env = (asset.environment_tag or "").lower()
            if env in ("external", "dmz"):
                is_internet_facing = True
            elif asset.ip and not asset.ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.")):
                is_internet_facing = True

        inv_ctx = {
            "has_av":                  av is not None if av is not None else None,
            "has_firewall":            fw is not None if fw is not None else None,
            "established_connections": len(established_ports),
            "listening_ports":         listening_ports,
            "established_ports":       established_ports,
            "is_internet_facing":      is_internet_facing,
        }
        new_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 5,
            inventory=inv_ctx,
            cfg=cfg,
        )
        if asset.risk_score != new_score:
            asset.risk_score = new_score
            updated += 1
    if updated:
        db.flush()
        logger.info("Risk scores: %d asset(s) updated for scan %d", updated, scan_id)
    return {"updated": updated, "total_assets": len(assets)}


def _fire_data_triggers(db, scan_id, new_asset_ids, new_finding_ids):
    """Fire workflow triggers for newly ingested data."""
    import services.workflow_engine as workflow_engine

    fired = 0

    # on_upload — always fire for the scan
    fired += workflow_engine.fire_event_workflows(
        db, "on_upload", {"scan_id": scan_id}
    )

    # on_new_asset — fire if any assets were newly inserted
    if new_asset_ids:
        from models.models import Asset
        assets = db.query(Asset).filter(Asset.id.in_(new_asset_ids)).all()
        asset_dicts = [
            {
                "id": a.id,
                "is_internet_facing": getattr(a, "is_internet_facing", False),
                "criticality": a.criticality,
            }
            for a in assets
        ]
        fired += workflow_engine.fire_event_workflows(
            db, "on_new_asset", {"asset_ids": new_asset_ids, "assets": asset_dicts}
        )

    # on_new_finding — fire if any findings were newly inserted
    if new_finding_ids:
        from models.models import Finding
        findings = db.query(Finding).filter(Finding.id.in_(new_finding_ids)).all()
        finding_dicts = [
            {
                "id": f.id,
                "severity": f.severity,
                "exploit_available": f.exploit_available,
            }
            for f in findings
        ]
        fired += workflow_engine.fire_event_workflows(
            db, "on_new_finding", {"finding_ids": new_finding_ids, "findings": finding_dicts}
        )

    return {"workflows_fired": fired}


def _correlate_findings(db, org_id):
    """Kick off cross-finding correlation as a *background job*.

    Correlation runs CVE corroboration + attack-path BFS + up to 50 LLM
    narration calls. Running inline blocked the post-ingest response for
    30-60s and starved the APScheduler on connection-pool checkouts.

    Dispatched via job_manager with per-org debounce: if a correlation
    job is already pending/running, or finished within the last minute
    for this org, skip. That absorbs EASM's multi-batch polling and
    multi-scan uploads without triggering redundant runs.

    Returns {dispatched, reason?, job_id?} for pipeline logging.
    """
    from datetime import datetime, timedelta
    from services.job_manager import dispatch, list_jobs
    from core.database import SessionLocal

    job_name = f"correlation_run_org{org_id}"
    debounce = timedelta(seconds=60)
    now = datetime.utcnow()

    # Scan recent jobs for the same org. The registry is in-memory and
    # bounded, so this is O(small).
    for j in list_jobs(limit=50):
        if j.get("name") != job_name:
            continue
        status = j.get("status")
        if status in ("pending", "running"):
            logger.info(
                "org=%d correlation already %s (job=%s) — skipping dispatch",
                org_id, status, j.get("job_id"),
            )
            return {"dispatched": False, "reason": "already_running"}
        completed_at = j.get("completed_at")
        if completed_at:
            try:
                ts = datetime.fromisoformat(completed_at)
                if now - ts < debounce:
                    logger.info(
                        "org=%d correlation ran %.0fs ago — skipping dispatch",
                        org_id, (now - ts).total_seconds(),
                    )
                    return {"dispatched": False, "reason": "debounced"}
            except (ValueError, TypeError):
                pass
        # Only consider the most recent job for this org.
        break

    def _run():
        # Dedicated session — the caller's request-scoped session closes
        # the moment post_ingest returns.
        bg_db = SessionLocal()
        try:
            from services.finding_correlator import correlate_findings
            return correlate_findings(bg_db, org_id)
        finally:
            bg_db.close()

    job = dispatch(job_name, _run, timeout=900)
    logger.info("org=%d correlation dispatched as job=%s", org_id, job.id)
    return {"dispatched": True, "job_id": job.id}


def _run_chain_coordinator(db, org_id, scan_id):
    """Dispatch a single Chain Coordinator tick as a background job.

    Mirrors `_correlate_findings`: per-org debounce so EASM's multi-batch
    polling and overlapping scan uploads collapse to one tick. Coordinator
    reads the unified edge graph directly — it does not block on the
    correlation job's output, and the two can run concurrently.

    Returns {dispatched, reason?, job_id?} for pipeline logging.
    """
    from datetime import datetime, timedelta
    from services.job_manager import dispatch, list_jobs
    from core.database import SessionLocal

    job_name = f"chain_coordinator_org{org_id}"
    debounce = timedelta(seconds=60)
    now = datetime.utcnow()

    for j in list_jobs(limit=50):
        if j.get("name") != job_name:
            continue
        status = j.get("status")
        if status in ("pending", "running"):
            logger.info(
                "org=%d chain_coordinator already %s (job=%s) — skipping dispatch",
                org_id, status, j.get("job_id"),
            )
            return {"dispatched": False, "reason": "already_running"}
        completed_at = j.get("completed_at")
        if completed_at:
            try:
                ts = datetime.fromisoformat(completed_at)
                if now - ts < debounce:
                    logger.info(
                        "org=%d chain_coordinator ran %.0fs ago — skipping dispatch",
                        org_id, (now - ts).total_seconds(),
                    )
                    return {"dispatched": False, "reason": "debounced"}
            except (ValueError, TypeError):
                pass
        break

    def _run():
        bg_db = SessionLocal()
        try:
            from services.chain_coordinator import tick
            return tick(bg_db, org_id=org_id, scan_id=scan_id)
        finally:
            bg_db.close()

    job = dispatch(job_name, _run, timeout=600)
    logger.info("org=%d chain_coordinator dispatched as job=%s", org_id, job.id)
    return {"dispatched": True, "job_id": job.id}


def _extract_inventory_edges(db, org_id, scan_id):
    """Materialize AssetRelationship edges from Inventory* tables."""
    from services.inventory_graph_extractor import extract_inventory_edges
    return extract_inventory_edges(db, org_id, scan_id)


def _materialize_inventory_unified_edges(db, org_id, scan_id):
    """Materialize unified-taxonomy edges (Phase 2)."""
    from services.inventory_edge_materializer import materialize_inventory_edges
    return materialize_inventory_edges(db, org_id=org_id, scan_id=scan_id)


def _llm_validate_findings(db, org_id, scan_id):
    """LLM vulnerability validation: detect false positives in critical/high Nuclei findings."""
    from services.llm_vuln_validator import validate_findings
    return validate_findings(db, org_id, scan_id=scan_id)

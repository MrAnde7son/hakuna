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
    """
    results = {}

    # 1. Auto-tag rules
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

    # 5. Solution aggregation
    results["solutions"] = _step(
        db, "Solution aggregation", lambda: _aggregate_solutions(db, scan_id)
    )

    # 6. Threat intel enrichment
    results["threat_intel"] = _step(
        db, "Threat intel enrichment", lambda: _enrich_threat_intel(db, scan_id)
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

    # 10. EASM enrichment
    if org_id:
        results["easm"] = _step(
            db, "EASM enrichment", lambda: _easm_enrich(db, org_id, scan_id)
        )

    # 11. Fire event-driven workflow triggers for new data
    results["workflows"] = _step(
        db, "Workflow triggers",
        lambda: _fire_data_triggers(db, scan_id, new_asset_ids, new_finding_ids),
    )

    return results


def _step(db: Session, name: str, fn):
    """Execute a pipeline step, catching and logging failures."""
    try:
        return fn()
    except Exception as e:
        db.rollback()
        logger.warning("%s failed (non-fatal): %s", name, e)
        return None


# ── Individual pipeline steps ──────────────────────────────────────────


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
    # import lazily to avoid circular deps
    from app import _apply_exception_to_findings

    active = db.query(FindingException).filter(FindingException.is_active == True).all()
    now = datetime.utcnow()
    applied = 0
    for exc in active:
        if exc.expires_at and exc.expires_at < now:
            exc.is_active = False
            continue
        applied += _apply_exception_to_findings(db, exc, scan_id=scan_id)
    if applied:
        logger.info("Applied %d global exceptions", applied)
        db.flush()
    return applied


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


def _match_ttps(db, scan_id):
    import threat_intel.ttp_matcher as ttp_matcher
    result = ttp_matcher.match_findings_to_ttps(db, scan_id=scan_id)
    logger.info("TTP matching: %d findings matched to ATT&CK techniques", result["matched"])
    return result


def _compute_sla(db, scan_id):
    from models.models import SLAConfig
    from app import _ensure_sla_defaults, _recalculate_sla_for_scan

    _ensure_sla_defaults(db)
    configs = db.query(SLAConfig).all()
    updated = _recalculate_sla_for_scan(db, scan_id, configs)
    if updated:
        logger.info("SLA computed for %d findings", updated)
    return updated


def _cross_scan_dedup(db, org_id):
    import services.dedup as dedup_engine

    cfg = dedup_engine.load_config()
    if not cfg.get("enabled") or not cfg.get("apply_on_upload"):
        return None
    asset_cfg = cfg.get("assets", {})
    if not asset_cfg.get("enabled") or asset_cfg.get("scope", "cross_scan") != "cross_scan":
        return None

    from app import ENTITY_MODEL_MAP
    result = dedup_engine.run_cross_scan_asset_dedup(db, org_id, cfg, ENTITY_MODEL_MAP)
    if result.get("removed"):
        logger.info("Cross-scan dedup: merged %d duplicate asset(s)", result["removed"])
    return result


def _easm_enrich(db, org_id, scan_id):
    from models.models import Organization
    from services.easm import enrich_assets_from_easm
    import asyncio

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org or not org.easm_org_id:
        return None

    # enrich_assets_from_easm is async — bridge to sync context
    try:
        loop = asyncio.get_running_loop()
        # Already in an async context (FastAPI) — schedule as a task
        loop.create_task(enrich_assets_from_easm(db, org, scan_id))
    except RuntimeError:
        # No running loop — run directly
        asyncio.run(enrich_assets_from_easm(db, org, scan_id))
    return True


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

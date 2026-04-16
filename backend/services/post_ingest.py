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

    # Threat intel + TTP enrichment — local to findings in this scan
    results["threat_intel"] = _step(
        db, "Threat intel enrichment (batch)", lambda: _enrich_threat_intel(db, scan_id)
    )
    results["ttp"] = _step(
        db, "TTP matching (batch)", lambda: _match_ttps(db, scan_id)
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

    # 5b. Solution aggregation
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

    # 9.6. Cross-finding correlation — link findings across scanners (Nessus + Nuclei)
    # for same CVEs, generate attack paths through the knowledge graph.
    if org_id:
        results["finding_correlation"] = _step(
            db, "Cross-finding correlation",
            lambda: _correlate_findings(db, org_id),
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

    Uses a savepoint so that a failure in one step doesn't roll back
    the entire transaction (and undo previous steps' work).
    """
    # Try savepoint-based isolation first
    nested = None
    try:
        nested = db.begin_nested()  # SAVEPOINT
        result = fn()
        nested.commit()
        return result
    except Exception as e:
        if nested is not None:
            try:
                nested.rollback()  # roll back only this step's changes
            except Exception:
                # Savepoint not usable (e.g. test fixtures) — full rollback
                try:
                    db.rollback()
                except Exception:
                    pass
        logger.warning("%s failed (non-fatal): %s", name, e)
        return None


# ── Individual pipeline steps ──────────────────────────────────────────


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
    """Trigger a VM scan on high-value assets when an EASM scan completes."""
    from models.models import Scan, Organization
    from core.database import SessionLocal
    import asyncio

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan or scan.source_type != "easm":
        return None

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return None

    domain = (scan.raw_metadata or {}).get("domain")
    if not domain:
        return None

    from services.vm_scanner import trigger_vm_scan_for_easm_assets

    # Use a dedicated session so the caller's session isn't accessed
    # concurrently or after the request context closes.
    async def _trigger_with_own_session():
        vm_db = SessionLocal()
        try:
            vm_org = vm_db.query(Organization).filter(Organization.id == org_id).first()
            await trigger_vm_scan_for_easm_assets(vm_db, vm_org, scan_id, domain)
        except Exception:
            logger.exception("Auto VM scan trigger failed for scan %s", scan_id)
        finally:
            vm_db.close()

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_trigger_with_own_session())
    except RuntimeError:
        asyncio.run(_trigger_with_own_session())
    return {"triggered": True, "domain": domain}


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
    """Cross-finding correlation: CVE-based linking + attack path generation."""
    from services.finding_correlator import correlate_findings
    return correlate_findings(db, org_id)


def _llm_validate_findings(db, org_id, scan_id):
    """LLM vulnerability validation: detect false positives in critical/high Nuclei findings."""
    from services.llm_vuln_validator import validate_findings
    return validate_findings(db, org_id, scan_id=scan_id)

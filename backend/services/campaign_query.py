"""
Campaign Query Engine
---------------------
Translates a list of condition dicts into a filtered set of (asset, findings[]).
Delegates all condition evaluation to rule_engine (unified condition engine).

Old campaign condition format {type, value} is auto-migrated via rule_engine.migrate_campaign_condition().
New format: {field, op, value} — see rule_engine.CONDITION_CATALOG for all supported conditions.
"""

from sqlalchemy.orm import Session
from models.models import Asset, Finding

import services.rule_engine as engine

# Unified catalog — exposed here for backward compat with existing API endpoint
CONDITION_CATALOG = engine.CONDITION_CATALOG


def _resolve_sbom_finding_ids(db, sbom_conds, asset_id, scan_id):
    """Return set of finding IDs matching product/cpe SBOM conditions for an asset.

    Tenant isolation is inherited from asset_id — the caller is expected to
    have already scoped asset_id to the org.
    """
    from models.models import SBOMComponent, SBOMVulnerability
    q = (
        db.query(SBOMVulnerability.finding_id)
        .join(SBOMComponent, SBOMVulnerability.component_id == SBOMComponent.id)
        .filter(SBOMComponent.asset_id == asset_id)
        .filter(SBOMVulnerability.finding_id.isnot(None))
    )
    if scan_id:
        q = q.filter(SBOMComponent.scan_id == scan_id)
    for cond in sbom_conds:
        sub = cond["field"].split(".")[-1]
        col = SBOMComponent.name if sub == "product" else SBOMComponent.cpe
        op = cond.get("op", "eq")
        val = str(cond.get("value") or "")
        if op == "eq":
            q = q.filter(col.ilike(val))
        elif op == "neq":
            q = q.filter(~col.ilike(val))
        elif op == "contains":
            q = q.filter(col.ilike(f"%{val}%"))
        elif op == "not_contains":
            q = q.filter(~col.ilike(f"%{val}%"))
    return {r[0] for r in q.all()}


def run_query(db: Session, conditions: list, logic: str, scan_id, org_ids=None) -> list:
    """
    Execute a campaign query against the database.
    Returns a list of dicts: {asset, findings, matched_conditions}

    org_ids scopes the query to the caller's tenant(s). Pass None only from
    trusted contexts that intentionally span all orgs.

    Accepts both old-style {type, value} conditions (auto-migrated) and
    new-style {field, op, value} conditions.
    """
    if not conditions:
        return []

    # Migrate any old-format conditions
    migrated = engine.migrate_conditions(conditions, mode="campaign")

    matching_assets = engine.get_matching_assets(migrated, logic, db, scan_id, org_ids=org_ids)

    results = []
    for asset in matching_assets:
        asset_dict = {
            "ip": asset.ip, "hostname": asset.hostname, "fqdn": asset.fqdn,
            "os": asset.os, "netbios_name": asset.netbios_name,
            "environment_tag": asset.environment_tag,
            "criticality": asset.criticality or 5,
            "risk_score": asset.risk_score or 0.0,
            "critical_count": asset.critical_count or 0,
            "high_count": asset.high_count or 0,
            "medium_count": asset.medium_count or 0,
            "low_count": asset.low_count or 0,
            "info_count": asset.info_count or 0,
            "source_systems": asset.source_systems or [],
            "custom_fields": asset.custom_fields or {},
        }

        # Gather matched condition labels for display
        matched_conds = []
        for orig, migr in zip(conditions, migrated):
            if engine.evaluate_condition(
                migr, asset_dict=asset_dict, db=db,
                asset_id=asset.id, scan_id=scan_id,
            ):
                # Use the original type/field as label key
                matched_conds.append(orig.get("type") or orig.get("field") or "")

        # Gather findings that match the campaign conditions.
        # If there are finding-level conditions, return only findings matching those.
        # Otherwise fall back to severity >= 1 (exclude pure info).
        f_q = db.query(Finding).filter(Finding.asset_id == asset.id)
        if scan_id:
            f_q = f_q.filter(Finding.scan_id == scan_id)
        all_findings = f_q.order_by(Finding.priority_score.desc()).all()

        finding_conds = [c for c in migrated if c.get("field", "").startswith("finding.")]
        # Separate SBOM-based conditions (product/cpe) which need a DB join
        sbom_conds = [c for c in finding_conds if c.get("field", "").split(".")[-1] in ("product", "cpe")]
        row_conds = [c for c in finding_conds if c not in sbom_conds]
        if finding_conds:
            # For SBOM conditions, resolve matching finding IDs via the join
            sbom_finding_ids = None
            if sbom_conds:
                sbom_finding_ids = _resolve_sbom_finding_ids(db, sbom_conds, asset.id, scan_id)
            findings = []
            for f in all_findings:
                row_match = not row_conds or any(engine._eval_finding_row(c, f) for c in row_conds)
                sbom_match = not sbom_conds or (sbom_finding_ids is not None and f.id in sbom_finding_ids)
                if row_match and sbom_match:
                    findings.append(f)
        else:
            findings = [f for f in all_findings if (f.severity or 0) >= 1]

        results.append({
            "asset": asset,
            "findings": findings,
            "matched_conditions": matched_conds,
        })

    # Sort by sum of top-5 finding priority scores
    def asset_priority(r):
        scores = sorted([f.priority_score or 0 for f in r["findings"]], reverse=True)
        return sum(scores[:5])

    results.sort(key=asset_priority, reverse=True)
    return results

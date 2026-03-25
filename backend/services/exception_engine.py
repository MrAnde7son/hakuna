"""
Exception engine — applies finding exceptions (accepted risk, false positive,
compensating control, severity override) to matching findings.

Extracted from app.py for proper dependency direction.
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import (
    Asset, Finding, FindingException, Tag, TagAssignment,
)

logger = logging.getLogger(__name__)


SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _check_scope_tags(db: Session, asset_id: int, scope_tags: list) -> bool:
    """Check if an asset matches any of the scope tags."""
    rows = (
        db.query(Tag.category, Tag.value)
        .join(TagAssignment, TagAssignment.tag_id == Tag.id)
        .filter(TagAssignment.asset_id == asset_id)
        .all()
    )
    asset_tags = {f"{r.category}:{r.value}".lower() for r in rows}
    return any(t.lower() in asset_tags for t in scope_tags)


def apply_exception_to_findings(
    db: Session,
    exc: FindingException,
    scan_id: Optional[int] = None,
) -> int:
    """Apply a single exception to all matching findings. Returns count of affected findings."""
    import services.rule_engine as engine

    q = db.query(Finding)
    if exc.plugin_id:
        q = q.filter(Finding.plugin_id == exc.plugin_id)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)

    # Asset-level scope: IP or tags (need join for either)
    if exc.asset_ip:
        q = q.join(Asset, Finding.asset_id == Asset.id)
        q = q.filter(Asset.ip == exc.asset_ip)

    conditions = exc.conditions or []
    logic = exc.condition_logic or "AND"
    scope_tags = exc.scope_tags or []
    findings = q.all()
    count = 0
    now = datetime.utcnow()

    for f in findings:
        # Check scope_tags if set
        if scope_tags and not _check_scope_tags(db, f.asset_id, scope_tags):
            continue

        # If conditions are set, evaluate them against the finding + its asset
        if conditions:
            parent_asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            asset_dict = {
                "ip": parent_asset.ip, "hostname": parent_asset.hostname,
                "fqdn": parent_asset.fqdn, "os": parent_asset.os,
                "netbios_name": parent_asset.netbios_name,
                "environment_tag": parent_asset.environment_tag,
                "criticality": parent_asset.criticality or 5,
                "risk_score": parent_asset.risk_score or 0.0,
                "critical_count": parent_asset.critical_count or 0,
                "high_count": parent_asset.high_count or 0,
                "medium_count": parent_asset.medium_count or 0,
                "low_count": parent_asset.low_count or 0,
                "info_count": parent_asset.info_count or 0,
            } if parent_asset else {}

            # Split conditions: finding.* evaluated per-finding, rest per-asset
            finding_conds = [c for c in conditions if c.get("field", "").startswith("finding.")]
            asset_conds = [c for c in conditions if not c.get("field", "").startswith("finding.")]

            finding_match = all(engine._eval_finding_row(c, f) for c in finding_conds) if finding_conds else True
            asset_match = engine.evaluate_conditions(
                asset_conds, logic, asset_dict=asset_dict,
                db=db, asset_id=f.asset_id, scan_id=f.scan_id,
            ) if asset_conds else True

            if logic == "AND":
                if not (finding_match and asset_match):
                    continue
            else:  # OR
                if not (finding_match or asset_match):
                    continue

        f.exception_id = exc.id
        f.status_changed_at = now

        if exc.exception_type == "severity_override" and exc.override_severity is not None:
            # Severity override: change severity instead of workflow status
            f.severity = exc.override_severity
            f.severity_label = SEVERITY_LABELS.get(exc.override_severity, "Info")
        else:
            f.workflow_status = exc.exception_type  # accepted_risk / false_positive / compensating_control

        count += 1
    return count

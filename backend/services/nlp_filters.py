"""
Shared NLP filter application — single source of truth for translating
parsed NLP filters into SQLAlchemy query conditions for Asset and Finding.
"""

from sqlalchemy import cast, Text, or_, func, desc
from sqlalchemy.orm import Session


def apply_asset_nlp_filters(query, af: dict, db: Session = None):
    """Apply parsed NLP asset_filters to a SQLAlchemy Asset query."""
    from models.models import Asset, TagAssignment, Tag

    if af.get("min_critical") is not None:
        query = query.filter(Asset.critical_count >= int(af["min_critical"]))
    if af.get("min_high") is not None:
        query = query.filter(Asset.high_count >= int(af["min_high"]))
    if af.get("min_risk") is not None:
        query = query.filter(Asset.risk_score >= float(af["min_risk"]))
    if af.get("max_risk") is not None:
        query = query.filter(Asset.risk_score <= float(af["max_risk"]))
    if af.get("criticality") is not None:
        query = query.filter(Asset.criticality >= int(af["criticality"]))
    if af.get("environment"):
        query = query.filter(Asset.environment_tag.ilike(f"%{af['environment']}%"))
    if af.get("asset_status"):
        query = query.filter(Asset.asset_status == af["asset_status"])
    if af.get("is_internet_facing"):
        query = query.filter(Asset.is_internet_facing == True)
    if af.get("search"):
        pat = f"%{af['search']}%"
        query = query.filter(or_(
            Asset.hostname.ilike(pat), Asset.ip.ilike(pat),
            Asset.fqdn.ilike(pat), Asset.os.ilike(pat),
        ))
    if af.get("source"):
        query = query.filter(cast(Asset.source_systems, Text).ilike(f'%"{af["source"]}"%'))
    if af.get("exclude_source"):
        query = query.filter(~cast(Asset.source_systems, Text).ilike(f'%"{af["exclude_source"]}"%'))
    if af.get("tags") and db is not None:
        tag_list = [t.strip() for t in af["tags"].split(",")]
        tag_subq = db.query(TagAssignment.asset_id).join(Tag, TagAssignment.tag_id == Tag.id).filter(
            TagAssignment.asset_id.isnot(None),
            or_(*[Tag.value.ilike(f"%{t}%") for t in tag_list])
        )
        query = query.filter(Asset.id.in_(tag_subq))
    return query


def apply_finding_nlp_filters(query, ff: dict, db: Session = None):
    """Apply parsed NLP finding_filters to a SQLAlchemy Finding query."""
    from models.models import Finding, TagAssignment, Tag

    if ff.get("severity") is not None:
        query = query.filter(Finding.severity == int(ff["severity"]))
    elif ff.get("severity_list"):
        query = query.filter(Finding.severity.in_([int(s) for s in ff["severity_list"]]))
    if ff.get("has_exploit"):
        query = query.filter(Finding.exploit_available == True)
    if ff.get("is_kev"):
        query = query.filter(Finding.is_kev == True)
    if ff.get("ransomware_linked"):
        query = query.filter(Finding.ransomware_linked == True)
    if ff.get("trending_in_news"):
        query = query.filter(Finding.trending_in_news == True)
    if ff.get("zero_day"):
        query = query.filter(Finding.zero_day == True)
    if ff.get("is_regression"):
        query = query.filter(Finding.is_regression == True)
    if ff.get("auto_resolved"):
        query = query.filter(Finding.auto_resolved == True)
    if ff.get("min_epss") is not None:
        query = query.filter(Finding.epss_score >= float(ff["min_epss"]))
    if ff.get("min_cvss") is not None:
        query = query.filter(or_(
            Finding.cvss3_score >= float(ff["min_cvss"]),
            Finding.cvss2_score >= float(ff["min_cvss"]),
        ))
    if ff.get("min_vpr") is not None:
        query = query.filter(Finding.vpr_score >= float(ff["min_vpr"]))
    if ff.get("min_priority") is not None:
        query = query.filter(Finding.priority_score >= float(ff["min_priority"]))
    if ff.get("sla_status"):
        query = query.filter(Finding.sla_status == ff["sla_status"])
    if ff.get("effort_level"):
        query = query.filter(Finding.effort_level == ff["effort_level"])
    if ff.get("workflow_status"):
        wf_val = ff["workflow_status"]
        if wf_val == "excepted":
            query = query.filter(Finding.exception_id.isnot(None))
        else:
            query = query.filter(Finding.workflow_status == wf_val)
    if ff.get("plugin_family"):
        query = query.filter(Finding.plugin_family.ilike(f"%{ff['plugin_family']}%"))
    if ff.get("cve"):
        query = query.filter(cast(Finding.cves, Text).ilike(f"%{ff['cve']}%"))
    if ff.get("port"):
        query = query.filter(Finding.port == ff["port"])
    if ff.get("has_ttps"):
        query = query.filter(Finding.matched_ttps.isnot(None), cast(Finding.matched_ttps, Text) != "[]")
    if ff.get("tactic"):
        query = query.filter(cast(Finding.matched_ttps, Text).ilike(f"%{ff['tactic']}%"))
    if ff.get("technique_id"):
        query = query.filter(cast(Finding.matched_ttps, Text).ilike(f"%{ff['technique_id']}%"))
    if ff.get("search"):
        pat = f"%{ff['search']}%"
        query = query.filter(
            Finding.plugin_name.ilike(pat) |
            Finding.synopsis.ilike(pat) |
            Finding.plugin_id.ilike(pat)
        )
    if ff.get("source"):
        query = query.filter(cast(Finding.source_systems, Text).ilike(f'%"{ff["source"]}"%'))
    if ff.get("exclude_source"):
        query = query.filter(~cast(Finding.source_systems, Text).ilike(f'%"{ff["exclude_source"]}"%'))
    if ff.get("tags") and db is not None:
        tag_list = [t.strip() for t in ff["tags"].split(",")]
        tag_subq = db.query(TagAssignment.finding_id).join(Tag, TagAssignment.tag_id == Tag.id).filter(
            TagAssignment.finding_id.isnot(None),
            or_(*[Tag.value.ilike(f"%{t}%") for t in tag_list])
        )
        query = query.filter(Finding.id.in_(tag_subq))
    return query


def severity_breakdown_grouped(query) -> dict:
    """Single GROUP BY query for severity counts instead of 5 separate COUNTs."""
    from models.models import Finding
    sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    rows = query.order_by(None).with_entities(Finding.severity, func.count()).group_by(Finding.severity).all()
    breakdown = {label: 0 for label in sev_labels.values()}
    for sev_int, count in rows:
        label = sev_labels.get(sev_int)
        if label:
            breakdown[label] = count
    return breakdown

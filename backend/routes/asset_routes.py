"""
Asset endpoints — CRUD, relationships, graph, risk breakdown, sources.
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Body
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_, cast, Text

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids, apply_scan_org_filter
from core.builtin_team_roles import user_owner_scopes, apply_owner_scope_to_assets
import core.risk_config as risk_engine
import services.dedup as dedup_engine
import services.tags as tag_engine
from services.asset_classifier import _is_private_ip
from models.models import (
    Asset, Finding, Scan, AssetRelationship, AssetObservation, FindingObservation,
    InventoryComputer, InventoryService, InventoryDatabaseInstance,
    InventorySecurityControl, InventoryNetConn, User,
)

router = APIRouter()


# ─── Helper: sort ────────────────────────────────────────────────────────────

def _json_text_at(col, key: str):
    """Return a SQL expression that extracts a JSON string value at `key` from a JSON column.

    Portable: uses json_extract on SQLite and the ->> operator on Postgres.
    """
    from core.database import engine as _engine
    if _engine.dialect.name == "postgresql":
        return col.op("->>")(key)
    return func.json_extract(col, f"$.{key}")


def _apply_sort(q, model, sort_by: str, order: str, default_attr):
    """Apply ORDER BY to a query, falling back to default_attr if sort_by is invalid.

    Supports `custom_fields.<key>` sort via the JSON column — works on both
    SQLite (json_extract) and Postgres (->> operator).
    """
    col = None
    if sort_by and sort_by.startswith("custom_fields.") and hasattr(model, "custom_fields"):
        key = sort_by.split(".", 1)[1]
        if key:
            col = _json_text_at(model.custom_fields, key)
    if col is None:
        col = getattr(model, sort_by, None)
    if col is None:
        col = default_attr
    return q.order_by(desc(col) if order == "desc" else col)


def _apply_custom_field_filters(q, model, request: Request):
    """Apply `cf_<key>=<value>` query params as JSON contains filters."""
    if not hasattr(model, "custom_fields"):
        return q
    for param, value in request.query_params.multi_items():
        if not param.startswith("cf_") or not value:
            continue
        key = param[3:]
        if not key:
            continue
        q = q.filter(_json_text_at(model.custom_fields, key).ilike(f"%{value}%"))
    return q


# ─── Helper: Domain Controller resolution ────────────────────────────────────

_COMPUTER_TO_ASSET_FIELD_MAP = {
    "fqdn":        ("dns_hostname", ["fqdn"]),
    "hostname":    ("computer_name", ["hostname"]),
    "netbios_name": ("computer_name", ["netbios_name"]),
}


def _resolve_dc_asset_ids(db, scan_id=None, restrict_to_asset_ids=None) -> set:
    """Return IDs of Asset records that ARE Domain Controllers.

    InventoryComputer.asset_id is the SOURCE asset that ran the AD enumeration plugin,
    not the DC itself.  We resolve the actual DC asset by matching computer name/fqdn
    against Asset fields using the same key fields as the asset dedup config.
    """
    dedup_cfg = dedup_engine.load_config()
    key_fields = dedup_cfg.get("assets", {}).get("key_fields", ["ip", "fqdn"])
    match_pairs = [
        _COMPUTER_TO_ASSET_FIELD_MAP[f]
        for f in key_fields
        if f in _COMPUTER_TO_ASSET_FIELD_MAP
    ]
    if not any(af[0] == "computer_name" for af in match_pairs):
        match_pairs.append(("computer_name", ["hostname", "netbios_name"]))

    q = db.query(
        InventoryComputer.asset_id,
        InventoryComputer.computer_name,
        InventoryComputer.dns_hostname,
    ).filter(InventoryComputer.is_domain_controller == True)
    if scan_id:
        q = q.filter(InventoryComputer.scan_id == scan_id)
    elif restrict_to_asset_ids:
        q = q.filter(InventoryComputer.asset_id.in_(restrict_to_asset_ids))
    dc_computers = q.all()
    if not dc_computers:
        return set()

    from collections import defaultdict
    comp_field_map = {"dns_hostname": lambda row: row[2], "computer_name": lambda row: row[1]}
    all_conditions = []
    for dc_row in dc_computers:
        for comp_field, asset_fields in match_pairs:
            val = comp_field_map.get(comp_field, lambda r: None)(dc_row)
            if not val:
                continue
            vl = val.lower()
            for af in asset_fields:
                col = getattr(Asset, af, None)
                if col is not None:
                    all_conditions.append(func.lower(col) == vl)

    result = set()
    if not all_conditions:
        return result
    aq = db.query(Asset.id).filter(or_(*all_conditions))
    if restrict_to_asset_ids:
        aq = aq.filter(Asset.id.in_(restrict_to_asset_ids))
    elif scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    for row in aq.all():
        result.add(row[0])
    return result


# ─── Helper: Server Role Detection ───────────────────────────────────────────

_ROLE_SERVICE_PATTERNS = {
    "web_server":  ["iis", "w3svc", "apache", "httpd", "nginx", "tomcat", "kestrel", "lighttpd"],
    "dns_server":  ["dns", "named", "bind", "dnsmasq", "unbound"],
    "mail_server": ["exchange", "smtp", "imap", "pop3", "postfix", "sendmail", "exim", "dovecot"],
    "database":    ["mssql", "sqlserver", "mysql", "mysqld", "postgres", "postgresql", "oracle",
                    "mongodb", "mariadb", "redis", "db2"],
    "ftp_server":  ["ftp", "vsftpd", "proftpd", "filezilla"],
}


def _compute_server_roles(db, asset_ids: list, scan_id: Optional[int] = None) -> dict:
    """Returns {asset_id: [role, ...]} for all given asset IDs.

    Roles are derived from:
    - Running services (InventoryService) matched against _ROLE_SERVICE_PATTERNS
    - InventoryDatabaseInstance records (database role)
    """
    if not asset_ids:
        return {}
    result: dict = {aid: [] for aid in asset_ids}

    from sqlalchemy import or_, func as sqlfunc
    svc_q = db.query(InventoryService.asset_id,
                     InventoryService.service_name,
                     InventoryService.display_name).filter(
        InventoryService.asset_id.in_(asset_ids),
        InventoryService.is_running == True,
    )
    if scan_id:
        svc_q = svc_q.filter(InventoryService.scan_id == scan_id)
    for aid, svc_name, disp_name in svc_q.all():
        combined = f"{(svc_name or '').lower()} {(disp_name or '').lower()}"
        for role, patterns in _ROLE_SERVICE_PATTERNS.items():
            if any(p in combined for p in patterns):
                if role not in result[aid]:
                    result[aid].append(role)

    db_q = db.query(InventoryDatabaseInstance.asset_id).filter(
        InventoryDatabaseInstance.asset_id.in_(asset_ids)
    )
    if scan_id:
        db_q = db_q.filter(InventoryDatabaseInstance.scan_id == scan_id)
    for (aid,) in db_q.distinct().all():
        if aid in result and "database" not in result[aid]:
            result[aid].append("database")

    return result


def _resolve_role_asset_ids(db, role: str, scan_id: Optional[int] = None,
                             restrict_to_asset_ids=None) -> set:
    """Returns set of asset_ids that have the given server role."""
    from sqlalchemy import or_, func as sqlfunc
    matched: set = set()
    patterns = _ROLE_SERVICE_PATTERNS.get(role, [])

    if patterns:
        svc_q = db.query(InventoryService.asset_id).filter(
            InventoryService.is_running == True
        )
        if scan_id:
            svc_q = svc_q.filter(InventoryService.scan_id == scan_id)
        if restrict_to_asset_ids is not None:
            svc_q = svc_q.filter(InventoryService.asset_id.in_(restrict_to_asset_ids))
        conditions = []
        for p in patterns:
            conditions.append(sqlfunc.lower(InventoryService.service_name).contains(p))
            conditions.append(sqlfunc.lower(InventoryService.display_name).contains(p))
        svc_q = svc_q.filter(or_(*conditions))
        for (aid,) in svc_q.all():
            matched.add(aid)

    if role == "database":
        db_q = db.query(InventoryDatabaseInstance.asset_id)
        if scan_id:
            db_q = db_q.filter(InventoryDatabaseInstance.scan_id == scan_id)
        if restrict_to_asset_ids is not None:
            db_q = db_q.filter(InventoryDatabaseInstance.asset_id.in_(restrict_to_asset_ids))
        for (aid,) in db_q.distinct().all():
            matched.add(aid)

    return matched


# ─── Helper: Asset inventory context for risk scoring ─────────────────────────

def _get_asset_inventory_context(db: Session, asset_id: int, asset: "Asset | None" = None) -> dict:
    """Build inventory context dict for risk scoring."""
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
    est_count = len(established_ports)
    is_internet_facing = False
    if asset is not None:
        if asset.is_internet_facing:
            is_internet_facing = True
        else:
            env = (asset.environment_tag or "").lower()
            if env in ("external", "dmz"):
                is_internet_facing = True
            elif asset.ip and not _is_private_ip(asset.ip):
                is_internet_facing = True
    return {
        "has_av":                  av is not None if av is not None else None,
        "has_firewall":            fw is not None if fw is not None else None,
        "established_connections": est_count,
        "listening_ports":         listening_ports,
        "established_ports":       established_ports,
        "is_internet_facing":      is_internet_facing,
    }


# ─── Helper: Asset → dict ────────────────────────────────────────────────────

def _asset_to_dict(a: Asset) -> dict:
    # Include manual ownership if present
    own = a.ownership[0] if a.ownership else None
    return {
        "id": a.id,
        "scan_id": a.scan_id,
        "ip": a.ip,
        "hostname": a.hostname,
        "fqdn": a.fqdn,
        "os": a.os,
        "netbios_name": a.netbios_name,
        "mac_address": a.mac_address,
        "scan_start": a.scan_start,
        "scan_end": a.scan_end,
        "criticality": a.criticality,
        "environment_tag": a.environment_tag,
        "environment_confirmed": bool(a.environment_confirmed),
        "business_context": a.business_context,
        "business_context_confirmed": bool(a.business_context_confirmed),
        "biz_num_users": a.biz_num_users,
        "biz_revenue_impact": a.biz_revenue_impact,
        "scanner_ip": a.scanner_ip,
        "is_internet_facing": a.is_internet_facing or False,
        "internet_facing_confidence": a.internet_facing_confidence,
        "internet_facing_methods": a.internet_facing_methods or [],
        "is_credentialed": a.is_credentialed or False,
        "last_auth_run": a.last_auth_run,
        "risk_score": a.risk_score,
        "critical_count": a.critical_count,
        "high_count": a.high_count,
        "medium_count": a.medium_count,
        "low_count": a.low_count,
        "info_count": a.info_count,
        # Inferred ownership
        "inferred_primary_user": a.inferred_primary_user,
        "inferred_admin_contacts": a.inferred_admin_contacts or [],
        "inferred_team": a.inferred_team,
        "owner_confidence": a.owner_confidence or "low",
        # Lifecycle tracking
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "times_seen": a.times_seen or 1,
        "asset_status": a.asset_status or "active",
        "stale_since": a.stale_since.isoformat() if a.stale_since else None,
        # Manual ownership (if set)
        "ownership": {
            "owner_name": own.owner_name,
            "owner_email": own.owner_email,
            "owner_role": own.owner_role,
            "team": own.team,
            "notes": own.notes,
        } if own else None,
        # EASM enrichment data
        "easm_data": a.easm_data,
        # Multi-source provenance
        "source_systems": a.source_systems or [],
        # Multi-type asset identity
        "asset_type": a.asset_type or "host",
        "asset_identity": a.asset_identity or {},
        "asset_attributes": a.asset_attributes or {},
        # User-defined custom fields
        "custom_fields": a.custom_fields or {},
        "user_edited_fields": a.user_edited_fields or [],
    }


# ─────────────────────────────────────────────
# Assets
# ─────────────────────────────────────────────

@router.get("/api/assets")
def list_assets(
    request: Request,
    scan_id: Optional[int] = None,
    min_risk: Optional[float] = None,
    max_risk: Optional[float] = None,
    environment: Optional[str] = None,
    criticality: Optional[int] = None,
    search: Optional[str] = None,
    min_critical: Optional[int] = None,
    min_high: Optional[int] = None,
    has_findings: Optional[bool] = None,
    server_role: Optional[str] = None,
    asset_status: Optional[str] = None,
    source: Optional[str] = None,
    min_sources: Optional[int] = None,
    first_seen_after: Optional[str] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    asset_type: Optional[str] = None,
    credentialed: Optional[bool] = None,
    sort_by: str = "risk_score",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    # Team-scoped RBAC: if the user's access comes entirely through built-in team
    # roles, narrow results to the teams they're assigned to.
    q = apply_owner_scope_to_assets(q, user_owner_scopes(db, current_user.id))
    if first_seen_after:
        try:
            q = q.filter(Asset.first_seen > datetime.fromisoformat(first_seen_after))
        except ValueError:
            pass
    if scan_id:
        # VM scans may attach findings to existing assets (different scan_id) via dedup.
        # Use the same union approach as the scan list endpoint so all relevant assets appear.
        target_scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if target_scan and target_scan.source_type == "vm_scanner":
            # Materialize to a list first to avoid accidental subquery correlation
            # when the outer query has a JOIN to Scan (SQLAlchemy may correlate the
            # Finding.scan_id subquery against the joined scans table).
            finding_asset_ids = [
                r[0] for r in db.query(Finding.asset_id)
                .filter(Finding.scan_id == scan_id).distinct().all()
            ]
            q = q.filter(or_(Asset.scan_id == scan_id, Asset.id.in_(finding_asset_ids)))
        else:
            q = q.filter(Asset.scan_id == scan_id)
    if min_risk is not None:
        q = q.filter(Asset.risk_score >= min_risk)
    if max_risk is not None:
        q = q.filter(Asset.risk_score <= max_risk)
    if environment:
        q = q.filter(Asset.environment_tag == environment)
    if criticality is not None:
        q = q.filter(Asset.criticality == criticality)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    if credentialed is not None:
        q = q.filter(Asset.is_credentialed == credentialed)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            Asset.hostname.ilike(pattern),
            Asset.ip.ilike(pattern),
            Asset.fqdn.ilike(pattern),
            Asset.os.ilike(pattern),
            cast(Asset.asset_identity, Text).ilike(pattern),
        ))
    if min_critical is not None:
        q = q.filter(Asset.critical_count >= min_critical)
    if min_high is not None:
        q = q.filter(Asset.high_count >= min_high)
    if has_findings is True:
        q = q.filter((Asset.critical_count + Asset.high_count + Asset.medium_count + Asset.low_count) > 0)
    if asset_status:
        q = q.filter(Asset.asset_status == asset_status)
    if source:
        q = q.filter(cast(Asset.source_systems, Text).ilike(f'%"{source}"%'))
    if min_sources is not None:
        q = q.filter(func.json_array_length(Asset.source_systems) >= min_sources)
    # Custom field filters: ?cf_<key>=<value>
    q = _apply_custom_field_filters(q, Asset, request)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, expand_children, db)
        q = tag_engine.apply_asset_tag_filter(q, id_sets, tag_logic, db)
    q = _apply_sort(q, Asset, sort_by, order, Asset.risk_score)

    # Apply server_role filter (subquery into service/db tables)
    if server_role:
        role_ids = _resolve_role_asset_ids(db, server_role, scan_id=scan_id)
        if not role_ids:
            return {"total": 0, "page": page, "page_size": page_size, "assets": []}
        q = q.filter(Asset.id.in_(role_ids))

    total = q.count()
    if page_size == 0:
        assets = q.all()
    else:
        assets = q.offset((page - 1) * page_size).limit(page_size).all()
    asset_ids = [a.id for a in assets]
    tag_map = tag_engine.get_asset_tags(asset_ids, db)
    # Batch-fetch DC status: match by hostname/fqdn (not by source asset_id)
    dc_asset_ids = _resolve_dc_asset_ids(db, restrict_to_asset_ids=asset_ids) if asset_ids else set()
    # Batch-compute server roles from services + DB instances
    server_roles_map = _compute_server_roles(db, asset_ids, scan_id=scan_id)
    result = []
    for a in assets:
        d = _asset_to_dict(a)
        d["tags"] = tag_map.get(a.id, [])
        d["is_domain_controller"] = a.id in dc_asset_ids
        roles = server_roles_map.get(a.id, [])
        if a.id in dc_asset_ids and "domain_controller" not in roles:
            roles = ["domain_controller"] + roles
        d["server_roles"] = roles
        result.append(d)
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "assets": result}


@router.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    query = apply_scan_org_filter(query, org_ids)
    asset = query.first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return _asset_to_dict(asset)


@router.get("/api/assets/{asset_id}/sources")
def get_asset_sources(asset_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return per-source observation snapshots for a deduplicated asset."""
    query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    query = apply_scan_org_filter(query, org_ids)
    if not query.first():
        raise HTTPException(404, "Asset not found")
    observations = (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset_id)
        .order_by(AssetObservation.last_seen.desc())
        .all()
    )
    return [
        {
            "id": obs.id,
            "source_system": obs.source_system,
            "raw_fields": obs.raw_fields or {},
            "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
            "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
            "times_seen": obs.times_seen,
        }
        for obs in observations
    ]


@router.get("/api/assets/{asset_id}/relationships")
def get_asset_relationships(asset_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return all relationship edges for an asset (both outbound and inbound)."""
    query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    query = apply_scan_org_filter(query, org_ids)
    if not query.first():
        raise HTTPException(404, "Relationship not found")

    def _rel_asset_summary(a: Asset) -> dict:
        return {
            "id": a.id, "hostname": a.hostname, "fqdn": a.fqdn, "ip": a.ip,
            "asset_type": a.asset_type, "asset_identity": a.asset_identity or {},
        }

    outbound = db.query(AssetRelationship).filter(AssetRelationship.source_asset_id == asset_id).all()
    inbound = db.query(AssetRelationship).filter(AssetRelationship.target_asset_id == asset_id).all()
    results = []
    for rel in outbound:
        target = db.query(Asset).filter(Asset.id == rel.target_asset_id).first()
        results.append({
            "id": rel.id, "direction": "outbound", "relationship_type": rel.relationship_type,
            "confidence": rel.confidence, "source_detail": rel.source_detail or {},
            "related_asset": _rel_asset_summary(target) if target else None,
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
        })
    for rel in inbound:
        source = db.query(Asset).filter(Asset.id == rel.source_asset_id).first()
        results.append({
            "id": rel.id, "direction": "inbound", "relationship_type": rel.relationship_type,
            "confidence": rel.confidence, "source_detail": rel.source_detail or {},
            "related_asset": _rel_asset_summary(source) if source else None,
            "created_at": rel.created_at.isoformat() if rel.created_at else None,
        })
    return results


@router.get("/api/assets/{asset_id}/siem-events")
def get_asset_siem_events(
    asset_id: int,
    page: int = 1,
    page_size: int = 25,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return SIEM events linked to this asset, plus open alert count."""
    from models.models import SIEMEvent, Alert

    query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    query = apply_scan_org_filter(query, org_ids)
    if not query.first():
        raise HTTPException(404, "Asset not found")

    # Events
    eq = db.query(SIEMEvent).filter(SIEMEvent.asset_id == asset_id)
    if severity:
        eq = eq.filter(SIEMEvent.severity == severity)
    total = eq.count()
    events = eq.order_by(SIEMEvent.event_time.desc()).offset((page - 1) * page_size).limit(page_size).all()

    # Alert summary for this asset
    alert_count = db.query(Alert).filter(
        Alert.asset_id == asset_id,
        Alert.status == "open",
        Alert.suppressed == False,
    ).count()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "alert_count": alert_count,
        "events": [
            {
                "id": ev.id,
                "event_time": ev.event_time.isoformat() if ev.event_time else None,
                "source_system": ev.source_system,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "message": (ev.message or "")[:300],
                "source_ip": ev.source_ip,
                "dest_ip": ev.dest_ip,
                "user_name": ev.user_name,
                "host_name": ev.host_name,
                "action": ev.action,
                "outcome": ev.outcome,
            }
            for ev in events
        ],
    }


@router.get("/api/assets/{asset_id}/alerts")
def get_asset_alerts(
    asset_id: int,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return SIEM alerts linked to this asset."""
    from models.models import Alert, DetectionRule

    query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    query = apply_scan_org_filter(query, org_ids)
    if not query.first():
        raise HTTPException(404, "Asset not found")

    aq = db.query(Alert).filter(Alert.asset_id == asset_id)
    if status:
        aq = aq.filter(Alert.status == status)
    alerts = aq.order_by(Alert.fired_at.desc()).limit(50).all()

    rule_ids = {a.rule_id for a in alerts if a.rule_id}
    rules = {r.id: r for r in db.query(DetectionRule).filter(DetectionRule.id.in_(rule_ids)).all()} if rule_ids else {}

    return [
        {
            "id": a.id,
            "rule_name": rules.get(a.rule_id, None) and rules[a.rule_id].name,
            "severity": a.severity,
            "status": a.status,
            "event_count": a.event_count,
            "fired_at": a.fired_at.isoformat() if a.fired_at else None,
            "entity_type": a.entity_type,
            "entity_value": a.entity_value,
            "suppressed": a.suppressed,
        }
        for a in alerts
    ]


@router.get("/api/asset-graph")
def get_asset_graph(
    asset_ids: str, depth: int = 1,
    collapsed: str = None,
    db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """BFS traversal from seed assets returning nodes + edges for graph visualization.

    Supports expand/collapse: pass `collapsed=1,5,12` to hide the subtrees rooted
    at those asset IDs. Collapsed nodes are included but marked with `_collapsed: true`
    and their children are excluded. The frontend can re-request with updated collapsed
    list to expand/collapse interactively.
    """
    depth = min(depth, 3)
    try:
        seed_ids = {int(x.strip()) for x in asset_ids.split(",") if x.strip()}
    except ValueError:
        raise HTTPException(400, "asset_ids must be comma-separated integers")

    collapsed_ids: set[int] = set()
    if collapsed:
        try:
            collapsed_ids = {int(x.strip()) for x in collapsed.split(",") if x.strip()}
        except ValueError:
            pass

    # Collect nodes and edges via BFS
    visited_ids: set[int] = set()
    edge_ids: set[int] = set()
    frontier = seed_ids.copy()

    for _ in range(depth + 1):
        if not frontier:
            break
        new_frontier: set[int] = set()
        for aid in frontier:
            if aid in visited_ids:
                continue
            visited_ids.add(aid)
            # If this node is collapsed, include it but don't expand its children
            if aid in collapsed_ids and aid not in seed_ids:
                continue
            rels = db.query(AssetRelationship).filter(
                (AssetRelationship.source_asset_id == aid) | (AssetRelationship.target_asset_id == aid)
            ).all()
            for rel in rels:
                edge_ids.add(rel.id)
                if rel.source_asset_id not in visited_ids:
                    new_frontier.add(rel.source_asset_id)
                if rel.target_asset_id not in visited_ids:
                    new_frontier.add(rel.target_asset_id)
        frontier = new_frontier

    # Fetch nodes with org filtering — use blast radius node format for compatibility
    nodes = {}
    if visited_ids:
        asset_query = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id.in_(visited_ids))
        asset_query = apply_scan_org_filter(asset_query, org_ids)
        for a in asset_query.all():
            nid = f"asset-{a.id}"
            # Count hidden children for collapsed nodes
            child_count = 0
            if a.id in collapsed_ids:
                child_count = db.query(AssetRelationship).filter(
                    (AssetRelationship.source_asset_id == a.id) | (AssetRelationship.target_asset_id == a.id)
                ).count()
            nodes[nid] = {
                "id": nid, "type": "asset",
                "data": {
                    "label": a.hostname or a.fqdn or a.ip or f"Asset {a.id}",
                    "ip": a.ip, "hostname": a.hostname, "fqdn": a.fqdn,
                    "os": a.os, "asset_type": a.asset_type,
                    "asset_identity": a.asset_identity or {},
                    "is_internet_facing": a.is_internet_facing or False,
                    "environment_tag": a.environment_tag,
                    "risk_score": a.risk_score, "criticality": a.criticality,
                    "_collapsed": a.id in collapsed_ids,
                    "_hidden_children": child_count if a.id in collapsed_ids else 0,
                },
            }

    # Filter edges to only include edges between org-visible nodes
    visible_ids = {int(nid.split("-", 1)[1]) for nid in nodes}
    edges = []
    if edge_ids:
        for rel in db.query(AssetRelationship).filter(AssetRelationship.id.in_(edge_ids)).all():
            if rel.source_asset_id in visible_ids and rel.target_asset_id in visible_ids:
                edges.append({
                    "id": f"e-rel-{rel.id}",
                    "source": f"asset-{rel.source_asset_id}",
                    "target": f"asset-{rel.target_asset_id}",
                    "type": rel.relationship_type,
                    "data": {
                        "label": rel.relationship_type.replace("_", " ").title(),
                        "confidence": rel.confidence,
                        "source_detail": rel.source_detail or {},
                    },
                })

    return {"nodes": list(nodes.values()), "edges": edges}


@router.post("/api/asset-relationships")
def create_asset_relationship(
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Manually create a relationship edge between two assets."""
    src_id = body.get("source_asset_id")
    tgt_id = body.get("target_asset_id")
    rel_type = body.get("relationship_type", "resolves_to")

    if not src_id or not tgt_id:
        raise HTTPException(400, "source_asset_id and target_asset_id are required")
    if src_id == tgt_id:
        raise HTTPException(400, "Cannot create self-referencing relationship")

    # Verify both assets exist and are org-accessible
    for aid in (src_id, tgt_id):
        q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == aid)
        q = apply_scan_org_filter(q, org_ids)
        if not q.first():
            raise HTTPException(404, f"Asset {aid} not found")

    src_asset = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == src_id).first()
    org_id = db.query(Scan.org_id).filter(Scan.id == src_asset.scan_id).scalar()

    rel = AssetRelationship(
        org_id=org_id, source_asset_id=src_id, target_asset_id=tgt_id,
        relationship_type=rel_type, confidence=body.get("confidence", "high"),
        source_detail=body.get("source_detail", {"manual": True}),
    )
    db.add(rel)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(409, "Relationship already exists")
    db.refresh(rel)
    return {"id": rel.id, "source_asset_id": src_id, "target_asset_id": tgt_id, "relationship_type": rel_type}


@router.delete("/api/asset-relationships/{rel_id}")
def delete_asset_relationship(
    rel_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Delete a relationship edge."""
    rel = db.query(AssetRelationship).filter(AssetRelationship.id == rel_id).first()
    if not rel:
        raise HTTPException(404, "Relationship not found")
    # Verify org access via source asset
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == rel.source_asset_id)
    q = apply_scan_org_filter(q, org_ids)
    if not q.first():
        raise HTTPException(404, "Relationship not found")
    db.delete(rel)
    db.commit()
    return {"deleted": True}


@router.get("/api/findings/{finding_id}/sources")
def get_finding_sources(finding_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return per-source observation snapshots for a deduplicated finding."""
    query = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.id == finding_id)
    query = apply_scan_org_filter(query, org_ids)
    if not query.first():
        raise HTTPException(404, "Finding not found")
    observations = (
        db.query(FindingObservation)
        .filter(FindingObservation.finding_id == finding_id)
        .order_by(FindingObservation.last_seen.desc())
        .all()
    )
    return [
        {
            "id": obs.id,
            "source_system": obs.source_system,
            "raw_fields": obs.raw_fields or {},
            "first_seen": obs.first_seen.isoformat() if obs.first_seen else None,
            "last_seen": obs.last_seen.isoformat() if obs.last_seen else None,
            "times_seen": obs.times_seen,
        }
        for obs in observations
    ]


@router.get("/api/assets/{asset_id}/risk-breakdown")
def get_asset_risk_breakdown(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    findings = db.query(Finding).filter(Finding.asset_id == asset_id).all()
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
    inv = _get_asset_inventory_context(db, asset_id, asset=asset)
    components = risk_engine.compute_asset_risk_score(
        findings_dicts,
        asset_criticality=asset.criticality or 5,
        inventory=inv,
        return_components=True,
    )
    # Human-readable details for controls and reachability
    if inv.get("has_av") or inv.get("has_firewall"):
        controls_detail = "AV/Firewall present"
    elif inv.get("has_av") is False and inv.get("has_firewall") is False:
        controls_detail = "No AV or Firewall"
    else:
        controls_detail = "Unknown"
    if inv.get("is_internet_facing"):
        reach_detail = "Internet-facing"
    elif inv.get("established_ports") or inv.get("listening_ports"):
        port_count = len(inv.get("listening_ports", set())) + len(inv.get("established_ports", set()))
        reach_detail = f"{port_count} ports tracked"
    else:
        reach_detail = "No port data"
    return {
        **components,
        "controls_detail":     controls_detail,
        "reachability_detail": reach_detail,
    }


@router.patch("/api/assets/{asset_id}")
def update_asset(
    asset_id: int,
    criticality: Optional[int] = None,
    environment_tag: Optional[str] = None,
    environment_confirmed: Optional[bool] = None,
    business_context: Optional[str] = None,
    business_context_confirmed: Optional[bool] = None,
    biz_num_users: Optional[int] = None,
    biz_revenue_impact: Optional[str] = None,
    custom_fields: Optional[dict] = Body(None, embed=True),
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Asset.id == asset_id)
    q = apply_scan_org_filter(q, org_ids)
    asset = q.first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if criticality is not None:
        asset.criticality = max(1, min(10, criticality))
    if environment_tag is not None:
        asset.environment_tag = environment_tag
        asset.environment_confirmed = True  # editing always confirms
    if environment_confirmed is not None:
        asset.environment_confirmed = environment_confirmed
    if business_context is not None:
        asset.business_context = business_context
        asset.business_context_confirmed = True  # editing always confirms
    if business_context_confirmed is not None:
        asset.business_context_confirmed = business_context_confirmed
    if biz_num_users is not None:
        asset.biz_num_users = biz_num_users
    if biz_revenue_impact is not None:
        asset.biz_revenue_impact = biz_revenue_impact
    if custom_fields:
        _apply_manual_custom_fields(db, asset, custom_fields, "asset")
    db.commit()
    return _asset_to_dict(asset)


def _apply_manual_custom_fields(db: Session, entity, payload: dict, entity_type: str):
    """Merge manual custom field values into entity.custom_fields + user_edited_fields.

    Rejects attempts to set computed (mapping/formula) fields — those come from
    ingest only. Keys not defined are silently ignored.
    """
    from models.models import CustomFieldDefinition
    from services.custom_field_resolver import _coerce_value

    # Resolve org_id from the entity's scan
    scan = db.query(Scan).filter(Scan.id == entity.scan_id).first()
    org_id = scan.org_id if scan else None
    if not org_id:
        return

    defs = db.query(CustomFieldDefinition).filter(
        CustomFieldDefinition.org_id == org_id,
        CustomFieldDefinition.entity_type == entity_type,
        CustomFieldDefinition.is_active.is_(True),
    ).all()
    def_map = {d.key: d for d in defs}

    current = dict(entity.custom_fields or {})
    edited = list(entity.user_edited_fields or [])
    for key, raw_value in payload.items():
        definition = def_map.get(key)
        if not definition:
            raise HTTPException(400, f"Unknown custom field '{key}'")
        if definition.source_type != "manual":
            raise HTTPException(400, f"custom field '{key}' is computed and cannot be set manually")
        if raw_value is None:
            current.pop(key, None)
        else:
            current[key] = _coerce_value(raw_value, definition.data_type)
        marker = f"custom_fields.{key}"
        if marker not in edited:
            edited.append(marker)
    entity.custom_fields = current
    entity.user_edited_fields = edited

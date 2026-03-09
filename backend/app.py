"""
Nessus Remediation Platform — FastAPI backend
"""
import os
import json
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from database import get_db, init_db
from models import (
    Scan, Asset, Finding, AutomateClick,
    InventoryUser, InventoryGroup, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool,
    Campaign, CampaignFinding, FindingOwnership, AssetOwnership,
    Workflow, WorkflowNode, WorkflowEdge, WorkflowExecution, WorkflowExecutionLog,
)
from parser import detect_and_parse, load_intel_json
from prioritizer import compute_priority_score
from inventory_extractor import extract_inventory_from_findings
import dedup as dedup_engine
import risk_config as risk_engine
import campaign_query as cq
import tags as tag_engine
import rule_engine
import workflow_engine
from models import Tag, TagAssignment, AutoTagRule, SLAConfig
from threat_intel_routes import router as threat_intel_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _apply_sort(q, model, sort_by: str, order: str, default_attr):
    """Apply ORDER BY to a query, falling back to default_attr if sort_by is invalid."""
    col = getattr(model, sort_by, None)
    if col is None:
        col = default_attr
    return q.order_by(desc(col) if order == "desc" else col)

app = FastAPI(title="Nessus Remediation Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(threat_intel_router)

INTEL_PATH = Path(__file__).parent.parent / "intel.json"

# Maps dedup entity_type → (Model, list_fields, bool_fields) for DB-level dedup
ENTITY_MODEL_MAP: dict = {}  # populated after models are imported (below)


@app.on_event("startup")
def startup():
    init_db()
    logger.info("Database initialized")
    # Build ENTITY_MODEL_MAP after models are loaded
    ENTITY_MODEL_MAP.update({
        "assets":            (Asset,                    [],                    []),
        "findings":          (Finding,                  ["cves"],              []),
        "users":             (InventoryUser,            ["spns", "member_of"], ["is_local_admin", "is_domain_admin", "is_privileged", "is_disabled", "password_never_expires", "never_logged_in", "never_changed_password"]),
        "groups":            (InventoryGroup,           ["members"],           ["is_privileged"]),
        "computers":         (InventoryComputer,        [],                    ["is_domain_controller", "is_disabled"]),
        "services":          (InventoryService,         [],                    ["is_running"]),
        "software":          (InventorySoftware,        [],                    []),
        "shares":            (InventoryShare,           ["acl"],               ["is_writeable", "is_default_share"]),
        "netconns":          (InventoryNetConn,         [],                    []),
        "patches":           (InventoryPatch,           ["cves"],              []),
        "security_controls": (InventorySecurityControl, [],                   ["is_enabled", "is_up_to_date"]),
        "password_policies": (InventoryPasswordPolicy,  [],                   ["complexity_enabled", "reversible_encryption", "is_weak"]),
        "logged_on":         (InventoryLoggedOn,        [],                    []),
        "scheduled_tasks":   (InventoryScheduledTask,   [],                   ["is_enabled"]),
        "env_vars":          (InventoryEnvVar,           [],                   ["is_sensitive"]),
        "certificates":      (InventoryCertificate,      ["subject_alt_names"], ["is_expired", "is_ca", "is_self_signed"]),
    })


# ─────────────────────────────────────────────
# Upload & Ingest
# ─────────────────────────────────────────────

@app.post("/api/upload")
async def upload_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload and parse a Nessus scan (HTML, .nessus XML, or CSV)."""
    fname = (file.filename or "").lower()
    allowed = (".html", ".htm", ".nessus", ".csv")
    if not any(fname.endswith(ext) for ext in allowed):
        raise HTTPException(400, f"Unsupported file type. Accepted: {', '.join(allowed)}")

    content = await file.read()

    # Load CVE intel
    intel = load_intel_json(str(INTEL_PATH)) if INTEL_PATH.exists() else {}

    # Detect format and parse
    try:
        parsed = detect_and_parse(content, file.filename)
    except Exception as e:
        logger.exception("Parse error")
        raise HTTPException(500, f"Parse error: {e}")

    # Create Scan record
    scan_data = parsed["scan"]
    scan = Scan(
        filename=file.filename,
        scan_name=scan_data.get("scan_name") or file.filename,
        scan_date=scan_data.get("scan_date"),
        scan_type=scan_data.get("scan_type"),
        scanner_ip=scan_data.get("scanner_ip"),
        nessus_version=scan_data.get("nessus_version"),
        policy_used=scan_data.get("policy_used"),
    )
    db.add(scan)
    db.flush()

    # Load configs once (used throughout the upload)
    risk_cfg = risk_engine.load_config()
    dedup_cfg = dedup_engine.load_config()

    # Within-scan asset dedup: collapse duplicate hosts before creating DB records
    parsed_assets = parsed["assets"]
    if dedup_cfg.get("enabled") and dedup_cfg.get("apply_on_upload"):
        asset_dcfg = dedup_cfg.get("assets", {})
        if asset_dcfg.get("enabled"):
            before = len(parsed_assets)
            parsed_assets = dedup_engine.dedup_records(
                parsed_assets,
                asset_dcfg.get("key_fields", ["ip"]),
                asset_dcfg.get("strategy", "merge"),
            )
            if len(parsed_assets) < before:
                logger.info(f"Within-scan asset dedup: {before} → {len(parsed_assets)} assets")

    # Create Asset records
    asset_map = {}  # hostname/ip → Asset (populated with both keys for reliable lookup)
    for asset_data in parsed_assets:
        # Determine criticality: auto-rules if configured, else default 3
        auto_crit = None
        if risk_cfg.get("auto_apply_rules_on_upload"):
            auto_crit = risk_engine.evaluate_criticality_rules(asset_data, risk_cfg)

        asset = Asset(
            scan_id=scan.id,
            ip=asset_data.get("ip"),
            hostname=asset_data.get("hostname"),
            fqdn=asset_data.get("fqdn"),
            os=asset_data.get("os"),
            netbios_name=asset_data.get("netbios_name"),
            mac_address=asset_data.get("mac_address"),
            scan_start=asset_data.get("scan_start"),
            scan_end=asset_data.get("scan_end"),
            criticality=auto_crit if auto_crit is not None else 3,
            critical_count=asset_data.get("critical_count", 0),
            high_count=asset_data.get("high_count", 0),
            medium_count=asset_data.get("medium_count", 0),
            low_count=asset_data.get("low_count", 0),
            info_count=asset_data.get("info_count", 0),
        )
        db.add(asset)
        db.flush()
        # Register both hostname and IP so finding lookup works after dedup merges
        if asset_data.get("hostname"):
            asset_map[asset_data["hostname"]] = asset
        if asset_data.get("ip"):
            asset_map[asset_data["ip"]] = asset
        if not asset_data.get("hostname") and not asset_data.get("ip"):
            # Fallback: use whichever key exists
            key = asset_data.get("hostname") or asset_data.get("ip")
            if key:
                asset_map[key] = asset

    # Create Finding records
    for finding_data in parsed["findings"]:
        host_key = finding_data.get("host_name")
        asset = asset_map.get(host_key)
        if not asset:
            # Try fuzzy match
            for k, a in asset_map.items():
                if k and host_key and (k in host_key or host_key in k):
                    asset = a
                    break
        if not asset:
            # Create a placeholder asset
            asset = Asset(scan_id=scan.id, hostname=host_key, ip=host_key)
            db.add(asset)
            db.flush()
            asset_map[host_key] = asset

        # Compute priority (risk_cfg passed for configurable weights;
        # asset_inventory not available yet at upload time — defaults to neutral)
        priority_data = compute_priority_score(
            finding_data,
            asset_criticality=asset.criticality,
            intel=intel,
            risk_cfg=risk_cfg,
        )

        finding = Finding(
            scan_id=scan.id,
            asset_id=asset.id,
            plugin_id=finding_data.get("plugin_id"),
            plugin_name=finding_data.get("plugin_name"),
            plugin_family=finding_data.get("plugin_family"),
            plugin_pub_date=finding_data.get("plugin_pub_date"),
            plugin_mod_date=finding_data.get("plugin_mod_date"),
            severity=finding_data.get("severity", 0),
            severity_label=finding_data.get("severity_label", "Info"),
            risk_factor=finding_data.get("risk_factor"),
            cvss2_score=finding_data.get("cvss2_score"),
            cvss2_vector=finding_data.get("cvss2_vector"),
            cvss3_score=finding_data.get("cvss3_score"),
            cvss3_vector=finding_data.get("cvss3_vector"),
            vpr_score=finding_data.get("vpr_score"),
            cves=finding_data.get("cves", []),
            references=finding_data.get("references", {}),
            synopsis=finding_data.get("synopsis"),
            description=finding_data.get("description"),
            solution=finding_data.get("solution"),
            see_also=finding_data.get("see_also", []),
            port=finding_data.get("port"),
            protocol=finding_data.get("protocol"),
            vulnerability_state=finding_data.get("vulnerability_state"),
            plugin_output=finding_data.get("plugin_output"),
            exploit_available=finding_data.get("exploit_available", False),
            exploit_maturity=finding_data.get("exploit_maturity"),
            zero_day=finding_data.get("zero_day", False),
            priority_score=priority_data["priority_score"],
            effort_level=priority_data["effort_level"],
            owner_suggestion=priority_data["owner_suggestion"],
            remediation_steps=priority_data["remediation_steps"],
        )
        db.add(finding)

    db.flush()
    db.commit()

    # ── Extract structured inventory from Info-level plugin outputs ──
    # Build a flat list of finding dicts enriched with asset context
    findings_for_inventory = []
    for f in db.query(Finding).filter(Finding.scan_id == scan.id).all():
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        findings_for_inventory.append({
            "plugin_id": f.plugin_id,
            "plugin_output": f.plugin_output,
            "asset_id": f.asset_id,
            "scan_id": f.scan_id,
            "asset_hostname": asset.hostname if asset else "",
            "port": f.port,
            "protocol": f.protocol,
        })

    inventory = extract_inventory_from_findings(findings_for_inventory)

    # Apply configurable dedup to inventory records before inserting
    inventory = dedup_engine.dedup_inventory(inventory, dedup_cfg)

    MODEL_MAP = {
        "users": (InventoryUser, ["scan_id", "asset_id", "source_plugin", "user_type",
                                   "username", "domain", "sid", "rid", "dn", "uac",
                                   "spns", "member_of", "password_last_set", "date_joined",
                                   "is_local_admin", "is_domain_admin", "is_privileged",
                                   "is_disabled", "password_never_expires", "never_logged_in",
                                   "never_changed_password", "last_logon_host"]),
        "groups": (InventoryGroup, ["scan_id", "asset_id", "source_plugin",
                                     "group_name", "domain", "sid", "dn",
                                     "description", "members", "is_privileged"]),
        "services": (InventoryService, ["scan_id", "asset_id", "source_plugin",
                                         "service_name", "display_name", "is_running"]),
        "netconns": (InventoryNetConn, ["scan_id", "asset_id", "source_plugin",
                                         "proto", "state", "local_addr", "local_port",
                                         "remote_addr", "remote_port", "pid"]),
        "scheduled_tasks": (InventoryScheduledTask, ["scan_id", "asset_id", "source_plugin",
                                                       "task_uri", "author", "run_as_sid",
                                                       "run_as_user", "command", "arguments",
                                                       "trigger_type", "logon_type", "is_enabled"]),
        "patches": (InventoryPatch, ["scan_id", "asset_id", "source_plugin",
                                      "kb_id", "vuln_count", "description", "cves"]),
        "logged_on": (InventoryLoggedOn, ["scan_id", "asset_id", "source_plugin",
                                           "sid", "domain", "username"]),
        "shares": (InventoryShare, ["scan_id", "asset_id", "source_plugin",
                                     "share_name", "share_type", "comment", "path",
                                     "max_users", "acl", "is_writeable", "is_default_share"]),
        "software": (InventorySoftware, ["scan_id", "asset_id", "source_plugin",
                                          "name", "version", "installed_on", "vendor"]),
        "security_controls": (InventorySecurityControl, ["scan_id", "asset_id", "source_plugin",
                                                          "control_type", "product_name", "vendor",
                                                          "version", "is_enabled", "is_up_to_date",
                                                          "signature_date", "details"]),
        "computers": (InventoryComputer, ["scan_id", "asset_id", "source_plugin",
                                           "computer_name", "dns_hostname", "os", "os_version",
                                           "sid", "dn", "is_domain_controller", "is_disabled",
                                           "uac", "date_joined"]),
        "password_policies": (InventoryPasswordPolicy, ["scan_id", "asset_id", "source_plugin",
                                                         "domain", "min_length", "history_count",
                                                         "max_age_days", "min_age_days",
                                                         "complexity_enabled", "reversible_encryption",
                                                         "lockout_threshold", "lockout_duration_mins",
                                                         "lockout_window_mins", "is_weak"]),
        "env_vars": (InventoryEnvVar, ["scan_id", "asset_id", "source_plugin",
                                        "name", "value", "scope", "is_sensitive"]),
        "certificates": (InventoryCertificate, [
            "scan_id", "asset_id", "source_plugin",
            "subject_cn", "subject_o", "subject_ou", "subject_c", "subject_email",
            "issuer_cn", "issuer_o", "issuer_ou", "issuer_c",
            "serial_number", "not_before", "not_after",
            "is_expired", "days_until_expiry",
            "signature_algorithm", "key_algorithm", "key_bits",
            "subject_alt_names", "is_ca", "is_self_signed",
            "port", "protocol",
        ]),
        "ai_tools": (InventoryAITool, [
            "scan_id", "asset_id", "source_plugin",
            "tool_name", "category",
        ]),
    }

    inv_counts = {}
    for key, (Model, fields) in MODEL_MAP.items():
        records = inventory.get(key, [])
        for rec in records:
            obj = Model(**{f: rec.get(f) for f in fields if f in rec})
            db.add(obj)
        inv_counts[key] = len(records)
        if records:
            db.commit()

    logger.info(f"Inventory extracted: { {k: v for k, v in inv_counts.items() if v} }")

    # ── Recompute asset risk scores using full formula (findings + inventory) ──
    _recompute_risk_for_scan(db, scan.id, risk_cfg)

    # ── Apply auto-tag rules to newly imported scan ──
    tag_results = tag_engine.run_all_auto_tag_rules(db, scan_id=scan.id)
    if tag_results:
        logger.info(f"Auto-tag results: { {k: v for k, v in tag_results.items() if v} }")

    total_findings = len(parsed["findings"])
    total_assets = len(asset_map)
    logger.info(f"Ingested scan '{file.filename}': {total_assets} assets, {total_findings} findings")

    return {
        "scan_id": scan.id,
        "scan_name": scan.scan_name,
        "assets": total_assets,
        "findings": total_findings,
        "message": "Scan uploaded and processed successfully",
    }


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.created_at)).all()
    result = []
    for s in scans:
        asset_count = db.query(func.count(Asset.id)).filter(Asset.scan_id == s.id).scalar()
        finding_count = db.query(func.count(Finding.id)).filter(Finding.scan_id == s.id).scalar()
        result.append({
            "id": s.id,
            "filename": s.filename,
            "scan_name": s.scan_name,
            "scan_date": s.scan_date,
            "scan_type": s.scan_type,
            "nessus_version": s.nessus_version,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "asset_count": asset_count,
            "finding_count": finding_count,
        })
    return result


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    # Inventory models have no ORM cascade from Scan, so delete them explicitly
    for InvModel in [
        InventoryUser, InventoryGroup, InventoryService, InventoryNetConn,
        InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    ]:
        db.query(InvModel).filter(InvModel.scan_id == scan_id).delete(synchronize_session=False)
    db.delete(scan)  # cascades to Asset → Finding → AutomateClick via ORM
    db.commit()
    return {"message": "Scan deleted"}


# ─────────────────────────────────────────────
# Assets
# ─────────────────────────────────────────────

@app.get("/api/assets")
def list_assets(
    scan_id: Optional[int] = None,
    min_risk: Optional[float] = None,
    max_risk: Optional[float] = None,
    environment: Optional[str] = None,
    criticality: Optional[int] = None,
    search: Optional[str] = None,
    min_critical: Optional[int] = None,
    min_high: Optional[int] = None,
    has_findings: Optional[bool] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    sort_by: str = "risk_score",
    order: str = "desc",
    db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if scan_id:
        q = q.filter(Asset.scan_id == scan_id)
    if min_risk is not None:
        q = q.filter(Asset.risk_score >= min_risk)
    if max_risk is not None:
        q = q.filter(Asset.risk_score <= max_risk)
    if environment:
        q = q.filter(Asset.environment_tag == environment)
    if criticality is not None:
        q = q.filter(Asset.criticality == criticality)
    if search:
        pattern = f"%{search}%"
        from sqlalchemy import or_
        q = q.filter(or_(
            Asset.hostname.ilike(pattern),
            Asset.ip.ilike(pattern),
            Asset.fqdn.ilike(pattern),
            Asset.os.ilike(pattern),
        ))
    if min_critical is not None:
        q = q.filter(Asset.critical_count >= min_critical)
    if min_high is not None:
        q = q.filter(Asset.high_count >= min_high)
    if has_findings is True:
        q = q.filter((Asset.critical_count + Asset.high_count + Asset.medium_count + Asset.low_count) > 0)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, expand_children, db)
        q = tag_engine.apply_asset_tag_filter(q, id_sets, tag_logic, db)
    q = _apply_sort(q, Asset, sort_by, order, Asset.risk_score)

    assets = q.all()
    asset_ids = [a.id for a in assets]
    tag_map = tag_engine.get_asset_tags(asset_ids, db)
    result = []
    for a in assets:
        d = _asset_to_dict(a)
        d["tags"] = tag_map.get(a.id, [])
        result.append(d)
    return result


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return _asset_to_dict(asset)


@app.patch("/api/assets/{asset_id}")
def update_asset(
    asset_id: int,
    criticality: Optional[int] = None,
    environment_tag: Optional[str] = None,
    business_context: Optional[str] = None,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if criticality is not None:
        asset.criticality = max(1, min(5, criticality))
    if environment_tag is not None:
        asset.environment_tag = environment_tag
    if business_context is not None:
        asset.business_context = business_context
    db.commit()
    return _asset_to_dict(asset)


def _asset_to_dict(a: Asset) -> dict:
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
        "business_context": a.business_context,
        "risk_score": a.risk_score,
        "critical_count": a.critical_count,
        "high_count": a.high_count,
        "medium_count": a.medium_count,
        "low_count": a.low_count,
        "info_count": a.info_count,
    }


# ─────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────

@app.get("/api/findings")
def list_findings(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    severity: Optional[int] = None,
    plugin_family: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    sla_status: Optional[str] = None,
    effort_level: Optional[str] = None,
    search: Optional[str] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    sort_by: str = "priority_score",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if severity is not None:
        q = q.filter(Finding.severity == severity)
    if plugin_family:
        q = q.filter(Finding.plugin_family == plugin_family)
    if has_exploit is not None:
        q = q.filter(Finding.exploit_available == has_exploit)
    if sla_status:
        q = q.filter(Finding.sla_status == sla_status)
    if effort_level:
        q = q.filter(Finding.effort_level == effort_level)
    if search:
        q = q.filter(
            Finding.plugin_name.ilike(f"%{search}%") |
            Finding.synopsis.ilike(f"%{search}%") |
            Finding.plugin_id.ilike(f"%{search}%")
        )
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, expand_children, db)
        q = tag_engine.apply_finding_tag_filter(q, id_sets, tag_logic, db)

    # Sort
    sort_col = getattr(Finding, sort_by, Finding.priority_score)
    if order == "desc":
        q = q.order_by(desc(sort_col))
    else:
        q = q.order_by(sort_col)

    total = q.count()
    findings = q.offset((page - 1) * page_size).limit(page_size).all()

    finding_ids = [f.id for f in findings]
    tag_map = tag_engine.get_finding_tags(finding_ids, db)
    result = []
    for f in findings:
        d = _finding_to_dict(f, db)
        d["tags"] = tag_map.get(f.id, [])
        result.append(d)

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": result,
    }


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return _finding_to_dict(finding, db, include_full=True)


def _finding_to_dict(f: Finding, db: Session, include_full: bool = False) -> dict:
    asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    base = {
        "id": f.id,
        "scan_id": f.scan_id,
        "asset_id": f.asset_id,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "asset_os": asset.os if asset else None,
        "plugin_id": f.plugin_id,
        "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "risk_factor": f.risk_factor,
        "cvss2_score": f.cvss2_score,
        "cvss3_score": f.cvss3_score,
        "vpr_score": f.vpr_score,
        "cves": f.cves or [],
        "synopsis": f.synopsis,
        "port": f.port,
        "protocol": f.protocol,
        "vulnerability_state": f.vulnerability_state,
        "exploit_available": f.exploit_available,
        "exploit_maturity": f.exploit_maturity,
        "zero_day": f.zero_day,
        "priority_score": f.priority_score,
        "effort_level": f.effort_level,
        "owner_suggestion": f.owner_suggestion,
        # SLA tracking
        "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "sla_status": f.sla_status or "n/a",
        # When the vulnerability was observed (from Nessus, not upload time)
        "sla_observed_date": asset.scan_start if asset else None,
    }
    if include_full:
        base.update({
            "description": f.description,
            "solution": f.solution,
            "see_also": f.see_also or [],
            "references": f.references or {},
            "plugin_output": f.plugin_output,
            "cvss2_vector": f.cvss2_vector,
            "cvss3_vector": f.cvss3_vector,
            "plugin_pub_date": f.plugin_pub_date,
            "plugin_mod_date": f.plugin_mod_date,
            "remediation_steps": f.remediation_steps,
        })
    return base


# ─────────────────────────────────────────────
# Remediation Queue
# ─────────────────────────────────────────────

@app.get("/api/remediation-queue")
def get_remediation_queue(
    scan_id: Optional[int] = None,
    effort: Optional[str] = None,
    owner: Optional[str] = None,
    min_severity: int = 2,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Return prioritized remediation queue (non-info findings, sorted by priority)."""
    q = db.query(Finding).filter(Finding.severity >= min_severity)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if effort:
        q = q.filter(Finding.effort_level == effort)
    if owner:
        q = q.filter(Finding.owner_suggestion == owner)
    q = q.order_by(desc(Finding.priority_score))

    findings = q.limit(limit).all()
    return [_finding_to_dict(f, db) for f in findings]


# ─────────────────────────────────────────────
# Reports & Summary
# ─────────────────────────────────────────────

@app.get("/api/reports/summary")
def get_summary(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Return summary statistics for the dashboard."""
    asset_q = db.query(Asset)
    finding_q = db.query(Finding)

    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    total_assets = asset_q.count()
    total_findings = finding_q.count()

    # Severity breakdown
    severity_counts = {}
    for sev in range(5):
        severity_counts[sev] = finding_q.filter(Finding.severity == sev).count()

    # Top plugin families
    family_counts = (
        db.query(Finding.plugin_family, func.count(Finding.id).label("count"))
        .filter(Finding.severity >= 1)
    )
    if scan_id:
        family_counts = family_counts.filter(Finding.scan_id == scan_id)
    family_counts = (
        family_counts
        .group_by(Finding.plugin_family)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )

    # Top risky assets
    top_assets = asset_q.order_by(desc(Asset.risk_score)).limit(5).all()

    # Effort breakdown
    effort_counts = {}
    for effort in ("quick_win", "medium", "complex"):
        effort_counts[effort] = finding_q.filter(Finding.effort_level == effort, Finding.severity >= 1).count()

    # Owner breakdown
    owner_counts = (
        db.query(Finding.owner_suggestion, func.count(Finding.id).label("count"))
        .filter(Finding.severity >= 1)
    )
    if scan_id:
        owner_counts = owner_counts.filter(Finding.scan_id == scan_id)
    owner_counts = (
        owner_counts
        .group_by(Finding.owner_suggestion)
        .order_by(desc("count"))
        .all()
    )

    # Exploit availability
    exploit_count = finding_q.filter(Finding.exploit_available == True).count()
    high_priority_count = finding_q.filter(Finding.priority_score >= 7.0).count()

    return {
        "total_assets": total_assets,
        "total_findings": total_findings,
        "severity_breakdown": {
            "critical": severity_counts.get(4, 0),
            "high": severity_counts.get(3, 0),
            "medium": severity_counts.get(2, 0),
            "low": severity_counts.get(1, 0),
            "info": severity_counts.get(0, 0),
        },
        "top_plugin_families": [
            {"family": row[0] or "Unknown", "count": row[1]} for row in family_counts
        ],
        "top_risky_assets": [_asset_to_dict(a) for a in top_assets],
        "effort_breakdown": effort_counts,
        "owner_breakdown": [
            {"owner": row[0] or "Unknown", "count": row[1]} for row in owner_counts
        ],
        "exploit_count": exploit_count,
        "high_priority_count": high_priority_count,
    }


@app.get("/api/reports/plugin-families")
def get_plugin_families(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Return all unique plugin families for filter dropdowns."""
    q = db.query(Finding.plugin_family).distinct()
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    families = [row[0] for row in q.all() if row[0]]
    return sorted(families)


@app.get("/api/reports/trending")
def get_trending(db: Session = Depends(get_db)):
    """Return per-scan summary for trend view."""
    scans = db.query(Scan).order_by(Scan.created_at).all()
    result = []
    for s in scans:
        counts = {}
        for sev in range(5):
            counts[sev] = db.query(func.count(Finding.id)).filter(
                Finding.scan_id == s.id, Finding.severity == sev
            ).scalar()
        result.append({
            "scan_id": s.id,
            "scan_name": s.scan_name,
            "scan_date": s.scan_date or s.created_at.isoformat(),
            "critical": counts[4],
            "high": counts[3],
            "medium": counts[2],
            "low": counts[1],
            "info": counts[0],
        })
    return result


# ─────────────────────────────────────────────
# Automate Click Tracking
# ─────────────────────────────────────────────

@app.post("/api/automate-click")
def log_automate_click(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

    click = AutomateClick(
        finding_id=finding_id,
        plugin_id=finding.plugin_id,
        plugin_name=finding.plugin_name,
        asset_ip=asset.ip if asset else None,
    )
    db.add(click)
    db.commit()
    return {"message": "Click logged", "finding_id": finding_id}


@app.get("/api/automate-clicks")
def get_automate_clicks(db: Session = Depends(get_db)):
    """Return top requested automations."""
    results = (
        db.query(
            AutomateClick.plugin_id,
            AutomateClick.plugin_name,
            func.count(AutomateClick.id).label("click_count"),
        )
        .group_by(AutomateClick.plugin_id, AutomateClick.plugin_name)
        .order_by(desc("click_count"))
        .limit(20)
        .all()
    )
    return [
        {"plugin_id": r[0], "plugin_name": r[1], "click_count": r[2]}
        for r in results
    ]


# ─────────────────────────────────────────────
# Inventory API
# ─────────────────────────────────────────────

def _asset_lookup(db: Session, asset_ids) -> dict:
    """Return {asset_id: {"hostname": ..., "ip": ..., "environment_tag": ...}} for a set of asset IDs."""
    if not asset_ids:
        return {}
    assets = db.query(Asset.id, Asset.hostname, Asset.ip, Asset.environment_tag).filter(Asset.id.in_(asset_ids)).all()
    return {a.id: {"hostname": a.hostname, "ip": a.ip, "environment_tag": a.environment_tag} for a in assets}


def _asset_label(info: dict) -> str:
    """Return a human-readable label from asset info dict."""
    if not info:
        return "—"
    return info.get("hostname") or info.get("ip") or "—"

@app.get("/api/inventory/users")
def list_inventory_users(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    user_type: Optional[str] = None,
    is_admin: Optional[bool] = None,
    is_domain_admin: Optional[bool] = None,
    is_privileged: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "username",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryUser)
    if scan_id:
        q = q.filter(InventoryUser.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryUser.asset_id == asset_id)
    if user_type:
        q = q.filter(InventoryUser.user_type == user_type)
    if is_admin is not None:
        q = q.filter(InventoryUser.is_local_admin == is_admin)
    if is_domain_admin is not None:
        q = q.filter(InventoryUser.is_domain_admin == is_domain_admin)
    if is_privileged is not None:
        q = q.filter(InventoryUser.is_privileged == is_privileged)
    if search:
        q = q.filter(
            InventoryUser.username.ilike(f"%{search}%") |
            InventoryUser.domain.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryUser, sort_by, order, InventoryUser.username)
    users = q.all()
    assets = _asset_lookup(db, {u.asset_id for u in users})
    return [_inv_user_to_dict(u, assets) for u in users]


@app.get("/api/inventory/groups")
def list_inventory_groups(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_privileged: Optional[bool] = None,
    sort_by: str = "group_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryGroup)
    if scan_id:
        q = q.filter(InventoryGroup.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryGroup.asset_id == asset_id)
    if is_privileged is not None:
        q = q.filter(InventoryGroup.is_privileged == is_privileged)
    q = _apply_sort(q, InventoryGroup, sort_by, order, InventoryGroup.group_name)
    groups = q.all()
    assets = _asset_lookup(db, {g.asset_id for g in groups})
    return [_inv_group_to_dict(g, assets) for g in groups]


@app.get("/api/inventory/services")
def list_inventory_services(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "display_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryService)
    if scan_id:
        q = q.filter(InventoryService.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryService.asset_id == asset_id)
    if search:
        q = q.filter(
            InventoryService.service_name.ilike(f"%{search}%") |
            InventoryService.display_name.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryService, sort_by, order, InventoryService.display_name)
    services = q.all()
    assets = _asset_lookup(db, {s.asset_id for s in services})
    return [{
        "id": s.id,
        "scan_id": s.scan_id,
        "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "service_name": s.service_name,
        "display_name": s.display_name,
        "is_running": s.is_running,
        "source_plugin": s.source_plugin,
    } for s in services]


@app.get("/api/inventory/netconns")
def list_inventory_netconns(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    state: Optional[str] = None,
    sort_by: str = "local_port",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryNetConn)
    if scan_id:
        q = q.filter(InventoryNetConn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryNetConn.asset_id == asset_id)
    if state:
        q = q.filter(InventoryNetConn.state.ilike(state))
    q = _apply_sort(q, InventoryNetConn, sort_by, order, InventoryNetConn.local_port)
    conns = q.all()
    assets = _asset_lookup(db, {c.asset_id for c in conns})
    return [{
        "id": c.id,
        "scan_id": c.scan_id,
        "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "proto": c.proto,
        "state": c.state,
        "local_addr": c.local_addr,
        "local_port": c.local_port,
        "remote_addr": c.remote_addr,
        "remote_port": c.remote_port,
        "pid": c.pid,
        "source_plugin": c.source_plugin,
    } for c in conns]


@app.get("/api/inventory/scheduled-tasks")
def list_inventory_tasks(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "task_uri",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryScheduledTask)
    if scan_id:
        q = q.filter(InventoryScheduledTask.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryScheduledTask.asset_id == asset_id)
    q = _apply_sort(q, InventoryScheduledTask, sort_by, order, InventoryScheduledTask.task_uri)
    tasks = q.all()
    assets = _asset_lookup(db, {t.asset_id for t in tasks})
    return [{
        "id": t.id,
        "scan_id": t.scan_id,
        "asset_id": t.asset_id,
        "asset_label": _asset_label(assets.get(t.asset_id)),
        "asset_ip": (assets.get(t.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(t.asset_id) or {}).get("environment_tag"),
        "task_uri": t.task_uri,
        "author": t.author,
        "run_as_sid": t.run_as_sid,
        "run_as_user": t.run_as_user,
        "command": t.command,
        "arguments": t.arguments,
        "trigger_type": t.trigger_type,
        "logon_type": t.logon_type,
        "is_enabled": t.is_enabled,
        "source_plugin": t.source_plugin,
    } for t in tasks]


@app.get("/api/inventory/patches")
def list_inventory_patches(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "vuln_count",
    order: str = "desc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryPatch)
    if scan_id:
        q = q.filter(InventoryPatch.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryPatch.asset_id == asset_id)
    q = _apply_sort(q, InventoryPatch, sort_by, order, InventoryPatch.vuln_count)
    patches = q.all()
    assets = _asset_lookup(db, {p.asset_id for p in patches})
    return [{
        "id": p.id,
        "scan_id": p.scan_id,
        "asset_id": p.asset_id,
        "asset_label": _asset_label(assets.get(p.asset_id)),
        "asset_ip": (assets.get(p.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(p.asset_id) or {}).get("environment_tag"),
        "kb_id": p.kb_id,
        "vuln_count": p.vuln_count,
        "description": p.description,
        "cves": p.cves or [],
        "source_plugin": p.source_plugin,
    } for p in patches]


@app.get("/api/inventory/logged-on")
def list_inventory_logged_on(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "username",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryLoggedOn)
    if scan_id:
        q = q.filter(InventoryLoggedOn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryLoggedOn.asset_id == asset_id)
    q = _apply_sort(q, InventoryLoggedOn, sort_by, order, InventoryLoggedOn.username)
    entries = q.all()
    assets = _asset_lookup(db, {e.asset_id for e in entries})
    return [{
        "id": e.id,
        "scan_id": e.scan_id,
        "asset_id": e.asset_id,
        "asset_label": _asset_label(assets.get(e.asset_id)),
        "asset_ip": (assets.get(e.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(e.asset_id) or {}).get("environment_tag"),
        "sid": e.sid,
        "domain": e.domain,
        "username": e.username,
        "source_plugin": e.source_plugin,
    } for e in entries]


@app.get("/api/inventory/summary")
def get_inventory_summary(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """
    Cross-entity summary for attack path analysis.
    Returns counts + high-value entities (privileged users, domain admins,
    kerberoastable accounts, lateral movement paths via shared admins, etc.)
    """
    def _q(Model):
        q = db.query(Model)
        if scan_id:
            q = q.filter(Model.scan_id == scan_id)
        return q

    # Counts
    total_users = _q(InventoryUser).count()
    total_groups = _q(InventoryGroup).count()
    total_services = _q(InventoryService).count()
    total_netconns = _q(InventoryNetConn).count()
    total_tasks = _q(InventoryScheduledTask).count()
    total_patches = _q(InventoryPatch).count()
    total_shares = _q(InventoryShare).count()
    total_software = _q(InventorySoftware).count()
    total_controls = _q(InventorySecurityControl).count()
    total_computers = _q(InventoryComputer).count()
    total_certs = _q(InventoryCertificate).count()
    expired_certs = _q(InventoryCertificate).filter(InventoryCertificate.is_expired == True).count()
    expiring_soon = _q(InventoryCertificate).filter(
        InventoryCertificate.is_expired == False,
        InventoryCertificate.days_until_expiry != None,
        InventoryCertificate.days_until_expiry <= 30,
    ).count()
    self_signed_certs = _q(InventoryCertificate).filter(InventoryCertificate.is_self_signed == True).count()

    # Privileged users
    domain_admins = _q(InventoryUser).filter(InventoryUser.is_domain_admin == True).all()
    local_admins = _q(InventoryUser).filter(InventoryUser.is_local_admin == True).all()

    # Kerberoastable: non-computer accounts with SPNs
    kerberoastable = [
        u for u in _q(InventoryUser).filter(InventoryUser.user_type == "service_account").all()
        if u.spns
    ]

    # Weak-password-policy users
    never_expires = _q(InventoryUser).filter(InventoryUser.password_never_expires == True).count()
    never_changed = _q(InventoryUser).filter(InventoryUser.never_changed_password == True).count()

    # Active established connections (lateral movement paths)
    established = _q(InventoryNetConn).filter(
        InventoryNetConn.state.in_(["established", "ESTABLISHED"])
    ).all()

    # Hosts with local admin overlap (users who are local admin on multiple assets)
    # Group local_admin users by (username, domain) → list of asset_ids
    admin_records = _q(InventoryUser).filter(InventoryUser.is_local_admin == True).all()
    admin_map: dict[str, list[int]] = {}
    for u in admin_records:
        key = f"{u.domain}\\{u.username}".lower()
        admin_map.setdefault(key, [])
        if u.asset_id not in admin_map[key]:
            admin_map[key].append(u.asset_id)
    lateral_admin_paths = [
        {"account": k, "asset_ids": v}
        for k, v in admin_map.items()
        if len(v) > 1
    ]

    # Currently logged-on users
    logged_on = _q(InventoryLoggedOn).all()
    logged_on_assets = _asset_lookup(db, {e.asset_id for e in logged_on})

    # Missing patches with highest vuln counts
    top_patches = _q(InventoryPatch).order_by(desc(InventoryPatch.vuln_count)).limit(10).all()
    patch_assets = _asset_lookup(db, {p.asset_id for p in top_patches})

    # Writeable shares (lateral movement vector)
    writeable_shares = _q(InventoryShare).filter(InventoryShare.is_writeable == True).count()
    # Hosts without AV
    hosts_with_av = set(
        r.asset_id for r in _q(InventorySecurityControl).filter(
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).all()
    )
    # Weak password policies
    weak_policies = _q(InventoryPasswordPolicy).filter(InventoryPasswordPolicy.is_weak == True).count()
    # Domain controllers
    domain_controllers = _q(InventoryComputer).filter(InventoryComputer.is_domain_controller == True).all()

    return {
        "counts": {
            "users": total_users,
            "groups": total_groups,
            "services": total_services,
            "netconns": total_netconns,
            "scheduled_tasks": total_tasks,
            "missing_patches": total_patches,
            "shares": total_shares,
            "software": total_software,
            "security_controls": total_controls,
            "computers": total_computers,
            "certificates": total_certs,
        },
        "attack_surface": {
            "domain_admins": [_inv_user_to_dict(u) for u in domain_admins],
            "local_admins_count": len(local_admins),
            "kerberoastable_accounts": [_inv_user_to_dict(u) for u in kerberoastable],
            "password_never_expires_count": never_expires,
            "never_changed_password_count": never_changed,
            "lateral_movement_paths": lateral_admin_paths,
            "established_connections": len(established),
            "logged_on_users": [
                {
                    "asset_id": e.asset_id,
                    "asset_label": _asset_label(logged_on_assets.get(e.asset_id)),
                    "domain": e.domain,
                    "username": e.username,
                }
                for e in logged_on
            ],
            "top_missing_patches": [
                {
                    "kb_id": p.kb_id,
                    "asset_id": p.asset_id,
                    "asset_label": _asset_label(patch_assets.get(p.asset_id)),
                    "vuln_count": p.vuln_count,
                }
                for p in top_patches
            ],
            "writeable_shares": writeable_shares,
            "hosts_with_av": len(hosts_with_av),
            "weak_password_policies": weak_policies,
            "domain_controllers": [
                {"computer_name": c.computer_name, "asset_id": c.asset_id, "os": c.os}
                for c in domain_controllers
            ],
            "expired_certs": expired_certs,
            "expiring_soon_certs": expiring_soon,
            "self_signed_certs": self_signed_certs,
        },
    }


@app.get("/api/inventory/shares")
def list_inventory_shares(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_writeable: Optional[bool] = None,
    sort_by: str = "share_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryShare)
    if scan_id:
        q = q.filter(InventoryShare.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryShare.asset_id == asset_id)
    if is_writeable is not None:
        q = q.filter(InventoryShare.is_writeable == is_writeable)
    q = _apply_sort(q, InventoryShare, sort_by, order, InventoryShare.share_name)
    shares = q.all()
    assets = _asset_lookup(db, {s.asset_id for s in shares})
    return [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "share_name": s.share_name, "share_type": s.share_type,
        "comment": s.comment, "path": s.path, "max_users": s.max_users,
        "acl": s.acl or [], "is_writeable": s.is_writeable,
        "is_default_share": s.is_default_share, "source_plugin": s.source_plugin,
    } for s in shares]


@app.get("/api/inventory/software")
def list_inventory_software(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventorySoftware)
    if scan_id:
        q = q.filter(InventorySoftware.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySoftware.asset_id == asset_id)
    if search:
        q = q.filter(InventorySoftware.name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventorySoftware, sort_by, order, InventorySoftware.name)
    software = q.all()
    assets = _asset_lookup(db, {s.asset_id for s in software})
    return [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "name": s.name, "version": s.version, "installed_on": s.installed_on,
        "vendor": s.vendor, "source_plugin": s.source_plugin,
    } for s in software]


@app.get("/api/inventory/security-controls")
def list_inventory_security_controls(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    control_type: Optional[str] = None,
    sort_by: str = "product_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventorySecurityControl)
    if scan_id:
        q = q.filter(InventorySecurityControl.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySecurityControl.asset_id == asset_id)
    if control_type:
        q = q.filter(InventorySecurityControl.control_type == control_type)
    q = _apply_sort(q, InventorySecurityControl, sort_by, order, InventorySecurityControl.product_name)
    controls = q.all()
    assets = _asset_lookup(db, {c.asset_id for c in controls})
    return [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "control_type": c.control_type, "product_name": c.product_name,
        "vendor": c.vendor, "version": c.version, "is_enabled": c.is_enabled,
        "is_up_to_date": c.is_up_to_date, "signature_date": c.signature_date,
        "details": c.details or {}, "source_plugin": c.source_plugin,
    } for c in controls]


@app.get("/api/inventory/computers")
def list_inventory_computers(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_dc: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "computer_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryComputer)
    if scan_id:
        q = q.filter(InventoryComputer.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryComputer.asset_id == asset_id)
    if is_dc is not None:
        q = q.filter(InventoryComputer.is_domain_controller == is_dc)
    if search:
        q = q.filter(
            InventoryComputer.computer_name.ilike(f"%{search}%") |
            InventoryComputer.dns_hostname.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryComputer, sort_by, order, InventoryComputer.computer_name)
    computers = q.all()
    assets = _asset_lookup(db, {c.asset_id for c in computers})
    return [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "computer_name": c.computer_name, "dns_hostname": c.dns_hostname,
        "os": c.os, "os_version": c.os_version, "sid": c.sid, "dn": c.dn,
        "is_domain_controller": c.is_domain_controller, "is_disabled": c.is_disabled,
        "uac": c.uac, "date_joined": c.date_joined, "source_plugin": c.source_plugin,
    } for c in computers]


@app.get("/api/inventory/password-policies")
def list_inventory_password_policies(
    scan_id: Optional[int] = None,
    sort_by: str = "domain",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryPasswordPolicy)
    if scan_id:
        q = q.filter(InventoryPasswordPolicy.scan_id == scan_id)
    q = _apply_sort(q, InventoryPasswordPolicy, sort_by, order, InventoryPasswordPolicy.domain)
    policies = q.all()
    assets = _asset_lookup(db, {p.asset_id for p in policies})
    return [{
        "id": p.id, "scan_id": p.scan_id, "asset_id": p.asset_id,
        "asset_label": _asset_label(assets.get(p.asset_id)),
        "asset_ip": (assets.get(p.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(p.asset_id) or {}).get("environment_tag"),
        "domain": p.domain, "min_length": p.min_length,
        "history_count": p.history_count, "max_age_days": p.max_age_days,
        "min_age_days": p.min_age_days, "complexity_enabled": p.complexity_enabled,
        "reversible_encryption": p.reversible_encryption,
        "lockout_threshold": p.lockout_threshold,
        "lockout_duration_mins": p.lockout_duration_mins,
        "lockout_window_mins": p.lockout_window_mins,
        "is_weak": p.is_weak, "source_plugin": p.source_plugin,
    } for p in policies]


@app.get("/api/inventory/env-vars")
def list_inventory_env_vars(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    scope: Optional[str] = None,
    sensitive_only: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryEnvVar)
    if scan_id:
        q = q.filter(InventoryEnvVar.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryEnvVar.asset_id == asset_id)
    if scope:
        q = q.filter(InventoryEnvVar.scope == scope)
    if sensitive_only:
        q = q.filter(InventoryEnvVar.is_sensitive == True)
    if search:
        q = q.filter(
            InventoryEnvVar.name.ilike(f"%{search}%") |
            InventoryEnvVar.value.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryEnvVar, sort_by, order, InventoryEnvVar.name)
    rows = q.all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "name": r.name, "value": r.value, "scope": r.scope,
        "is_sensitive": r.is_sensitive, "source_plugin": r.source_plugin,
    } for r in rows]


@app.get("/api/inventory/certificates")
def list_inventory_certificates(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    expired_only: Optional[bool] = None,
    expiring_days: Optional[int] = None,   # certs expiring within N days
    self_signed_only: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "not_after",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryCertificate)
    if scan_id:
        q = q.filter(InventoryCertificate.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryCertificate.asset_id == asset_id)
    if expired_only:
        q = q.filter(InventoryCertificate.is_expired == True)
    if expiring_days is not None:
        q = q.filter(
            InventoryCertificate.is_expired == False,
            InventoryCertificate.days_until_expiry != None,
            InventoryCertificate.days_until_expiry <= expiring_days,
        )
    if self_signed_only:
        q = q.filter(InventoryCertificate.is_self_signed == True)
    if search:
        q = q.filter(
            InventoryCertificate.subject_cn.ilike(f"%{search}%") |
            InventoryCertificate.issuer_cn.ilike(f"%{search}%") |
            InventoryCertificate.subject_o.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryCertificate, sort_by, order, InventoryCertificate.not_after)
    rows = q.all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "subject_cn": r.subject_cn, "subject_o": r.subject_o,
        "subject_ou": r.subject_ou, "subject_c": r.subject_c,
        "subject_email": r.subject_email,
        "issuer_cn": r.issuer_cn, "issuer_o": r.issuer_o,
        "issuer_c": r.issuer_c,
        "serial_number": r.serial_number,
        "not_before": r.not_before, "not_after": r.not_after,
        "is_expired": r.is_expired, "days_until_expiry": r.days_until_expiry,
        "signature_algorithm": r.signature_algorithm,
        "key_algorithm": r.key_algorithm, "key_bits": r.key_bits,
        "subject_alt_names": r.subject_alt_names or [],
        "is_ca": r.is_ca, "is_self_signed": r.is_self_signed,
        "port": r.port, "protocol": r.protocol,
        "source_plugin": r.source_plugin,
    } for r in rows]


@app.get("/api/inventory/ai-tools")
def list_inventory_ai_tools(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "tool_name",
    order: str = "asc",
    db: Session = Depends(get_db),
):
    q = db.query(InventoryAITool)
    if scan_id:
        q = q.filter(InventoryAITool.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryAITool.asset_id == asset_id)
    if category:
        q = q.filter(InventoryAITool.category == category)
    if search:
        q = q.filter(InventoryAITool.tool_name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventoryAITool, sort_by, order, InventoryAITool.tool_name)
    rows = q.all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "tool_name": r.tool_name, "category": r.category,
        "source_plugin": r.source_plugin,
    } for r in rows]


def _inv_user_to_dict(u: InventoryUser, assets: dict = None) -> dict:
    info = assets.get(u.asset_id) if assets else None
    return {
        "id": u.id,
        "scan_id": u.scan_id,
        "asset_id": u.asset_id,
        "asset_label": _asset_label(info),
        "asset_ip": (info or {}).get("ip"),
        "asset_env": (info or {}).get("environment_tag"),
        "username": u.username,
        "domain": u.domain,
        "sid": u.sid,
        "rid": u.rid,
        "dn": u.dn,
        "user_type": u.user_type,
        "is_local_admin": u.is_local_admin,
        "is_domain_admin": u.is_domain_admin,
        "is_privileged": u.is_privileged,
        "is_disabled": u.is_disabled,
        "password_never_expires": u.password_never_expires,
        "never_logged_in": u.never_logged_in,
        "never_changed_password": u.never_changed_password,
        "spns": u.spns or [],
        "member_of": u.member_of or [],
        "uac": u.uac,
        "password_last_set": u.password_last_set,
        "date_joined": u.date_joined,
        "last_logon_host": u.last_logon_host,
        "source_plugin": u.source_plugin,
    }


def _inv_group_to_dict(g: InventoryGroup, assets: dict = None) -> dict:
    info = assets.get(g.asset_id) if assets else None
    return {
        "id": g.id,
        "scan_id": g.scan_id,
        "asset_id": g.asset_id,
        "asset_label": _asset_label(info),
        "asset_ip": (info or {}).get("ip"),
        "asset_env": (info or {}).get("environment_tag"),
        "group_name": g.group_name,
        "domain": g.domain,
        "sid": g.sid,
        "dn": g.dn,
        "description": g.description,
        "members": g.members or [],
        "is_privileged": g.is_privileged,
        "source_plugin": g.source_plugin,
    }


# ─────────────────────────────────────────────
# Risk Score Helpers
# ─────────────────────────────────────────────

def _get_asset_inventory_context(db: Session, asset_id: int) -> dict:
    """Build inventory context dict for risk scoring."""
    # Compensating controls
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
    # Established connections
    est_count = db.query(func.count(InventoryNetConn.id)).filter(
        InventoryNetConn.asset_id == asset_id,
        InventoryNetConn.state.in_(["ESTABLISHED", "established"]),
    ).scalar() or 0
    return {
        "has_av":                  av is not None if av is not None else None,
        "has_firewall":            fw is not None if fw is not None else None,
        "established_connections": est_count,
    }


def _recompute_risk_for_scan(db: Session, scan_id: int, cfg: Optional[dict] = None):
    """Recompute risk scores for every asset in a scan using the full formula."""
    if cfg is None:
        cfg = risk_engine.load_config()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    for asset in assets:
        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        findings_dicts = [
            {
                "severity":         f.severity,
                "exploit_available": f.exploit_available,
                "exploit_maturity":  f.exploit_maturity,
                "vpr_score":         f.vpr_score,
                "zero_day":          f.zero_day,
            }
            for f in findings
        ]
        inv_ctx = _get_asset_inventory_context(db, asset.id)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 3,
            inventory=inv_ctx,
            cfg=cfg,
        )
    db.commit()


# ─────────────────────────────────────────────
# Deduplication Config & On-Demand Run
# ─────────────────────────────────────────────

@app.get("/api/dedup/config")
def get_dedup_config():
    """Return the current deduplication configuration."""
    return dedup_engine.load_config()


@app.put("/api/dedup/config")
async def save_dedup_config(request: Request):
    """Save a new deduplication configuration."""
    body = await request.json()
    dedup_engine.save_config(body)
    return {"message": "Config saved"}


class RunDedupBody(BaseModel):
    entity_type: str
    scan_id: Optional[int] = None


@app.post("/api/dedup/run")
def run_dedup(body: RunDedupBody, db: Session = Depends(get_db)):
    """Run dedup on-demand for a given entity type."""
    cfg = dedup_engine.load_config()
    result = dedup_engine.run_db_dedup(db, body.entity_type, body.scan_id, cfg, ENTITY_MODEL_MAP)
    return result


# ─────────────────────────────────────────────
# Risk Config & Recalculate
# ─────────────────────────────────────────────

@app.get("/api/risk/config")
def get_risk_config():
    """Return the current risk scoring configuration."""
    return risk_engine.load_config()


@app.put("/api/risk/config")
async def save_risk_config(request: Request):
    """Save risk scoring configuration."""
    body = await request.json()
    risk_engine.save_config(body)
    return {"message": "Risk config saved"}


class RecalculateBody(BaseModel):
    scan_id: Optional[int] = None
    apply_criticality_rules: bool = False
    recalculate_findings: bool = False


@app.post("/api/risk/recalculate")
def recalculate_risk(body: RecalculateBody, db: Session = Depends(get_db)):
    """Recompute risk scores (and optionally criticality + finding priorities) for all or one scan."""
    cfg = risk_engine.load_config()
    intel = load_intel_json(str(INTEL_PATH)) if INTEL_PATH.exists() else {}

    asset_q = db.query(Asset)
    if body.scan_id:
        asset_q = asset_q.filter(Asset.scan_id == body.scan_id)
    assets = asset_q.all()

    # Preload tags for all assets in this batch (avoids N+1 queries)
    asset_ids = [a.id for a in assets]
    tag_rows = (
        db.query(TagAssignment.asset_id, Tag.category, Tag.value)
        .join(Tag, Tag.id == TagAssignment.tag_id)
        .filter(TagAssignment.asset_id.in_(asset_ids))
        .all()
    ) if asset_ids else []
    asset_tags_map: dict[int, list[str]] = {}
    for row in tag_rows:
        asset_tags_map.setdefault(row.asset_id, []).append(f"{row.category}:{row.value}")

    updated_assets = 0
    updated_findings = 0
    for asset in assets:
        # Re-apply criticality rules if requested
        if body.apply_criticality_rules:
            asset_dict = {
                "ip": asset.ip, "hostname": asset.hostname, "fqdn": asset.fqdn,
                "os": asset.os, "netbios_name": asset.netbios_name,
                "environment_tag": asset.environment_tag,
                # Numeric fields for rule evaluation
                "critical_count": asset.critical_count or 0,
                "high_count":     asset.high_count or 0,
                "medium_count":   asset.medium_count or 0,
                "low_count":      asset.low_count or 0,
                "info_count":     asset.info_count or 0,
                "risk_score":     asset.risk_score or 0.0,
                # Tags as "category:value" strings
                "tags": asset_tags_map.get(asset.id, []),
            }
            new_crit = risk_engine.evaluate_criticality_rules(asset_dict, cfg)
            if new_crit is not None:
                asset.criticality = new_crit

        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        findings_dicts = [
            {
                "severity":          f.severity,
                "exploit_available": f.exploit_available,
                "exploit_maturity":  f.exploit_maturity,
                "vpr_score":         f.vpr_score,
                "zero_day":          f.zero_day,
            }
            for f in findings
        ]
        inv_ctx = _get_asset_inventory_context(db, asset.id)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 3,
            inventory=inv_ctx,
            cfg=cfg,
        )
        updated_assets += 1

        # Optionally recompute finding priority scores
        if body.recalculate_findings:
            for f in findings:
                finding_dict = {
                    "plugin_id":        f.plugin_id,
                    "plugin_name":      f.plugin_name,
                    "plugin_family":    f.plugin_family,
                    "severity":         f.severity,
                    "cvss2_score":      f.cvss2_score,
                    "cvss3_score":      f.cvss3_score,
                    "vpr_score":        f.vpr_score,
                    "cves":             f.cves or [],
                    "exploit_available": f.exploit_available,
                    "exploit_maturity":  f.exploit_maturity,
                    "zero_day":          f.zero_day,
                    "solution":          f.solution,
                    "synopsis":          f.synopsis,
                }
                priority_data = compute_priority_score(
                    finding_dict,
                    asset_criticality=asset.criticality or 3,
                    intel=intel,
                    risk_cfg=cfg,
                    asset_inventory=inv_ctx,
                )
                f.priority_score  = priority_data["priority_score"]
                f.effort_level    = priority_data["effort_level"]
                f.owner_suggestion = priority_data["owner_suggestion"]
                f.remediation_steps = priority_data["remediation_steps"]
                updated_findings += 1

    db.commit()
    return {"updated_assets": updated_assets, "updated_findings": updated_findings, "scan_id": body.scan_id}


# ─────────────────────────────────────────────
# Ownership Endpoints
# ─────────────────────────────────────────────

class OwnershipBody(BaseModel):
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None


@app.patch("/api/assets/{asset_id}/ownership")
def set_asset_ownership(asset_id: int, body: OwnershipBody, db: Session = Depends(get_db)):
    """Set or update ownership for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    own = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset_id).first()
    if not own:
        own = AssetOwnership(asset_id=asset_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    db.commit()
    return {"ok": True, "asset_id": asset_id, "owner_name": own.owner_name}


@app.patch("/api/findings/{finding_id}/ownership")
def set_finding_ownership(finding_id: int, body: OwnershipBody, db: Session = Depends(get_db)):
    """Set or update ownership for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    own = db.query(FindingOwnership).filter(FindingOwnership.finding_id == finding_id).first()
    if not own:
        own = FindingOwnership(finding_id=finding_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    db.commit()
    return {"ok": True, "finding_id": finding_id, "owner_name": own.owner_name}


# ─────────────────────────────────────────────
# Campaign Endpoints
# ─────────────────────────────────────────────

class CampaignCreateBody(BaseModel):
    name: str
    description: Optional[str] = None
    scan_id: Optional[int] = None
    query: list = []
    query_logic: str = "AND"


class CampaignUpdateBody(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    query: Optional[list] = None
    query_logic: Optional[str] = None


class CampaignFindingUpdateBody(BaseModel):
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None


def _serialize_finding(f: Finding, asset: Asset = None) -> dict:
    """Minimal finding dict for campaign results."""
    own = f.ownership[0] if f.ownership else None
    return {
        "id": f.id,
        "plugin_id": f.plugin_id,
        "plugin_name": f.plugin_name,
        "plugin_family": f.plugin_family,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "cvss2_score": f.cvss2_score,
        "cvss3_score": f.cvss3_score,
        "vpr_score": f.vpr_score,
        "priority_score": f.priority_score,
        "effort_level": f.effort_level,
        "owner_suggestion": f.owner_suggestion,
        "synopsis": f.synopsis,
        "solution": f.solution,
        "remediation_steps": f.remediation_steps,
        "cves": f.cves or [],
        "exploit_available": f.exploit_available,
        "zero_day": f.zero_day,
        "port": f.port,
        "protocol": f.protocol,
        "asset_id": f.asset_id,
        "asset_ip": asset.ip if asset else None,
        "asset_hostname": (asset.hostname or asset.fqdn or asset.ip) if asset else None,
        "ownership": {
            "owner_name": own.owner_name,
            "owner_email": own.owner_email,
            "owner_role": own.owner_role,
            "team": own.team,
            "notes": own.notes,
        } if own else None,
    }


def _group_findings_by_owner(campaign_findings: list) -> list:
    """
    Group campaign findings by effective owner (campaign override > finding ownership > owner_suggestion).
    Returns list of {owner_key, owner_name, owner_role, team, findings[]}.
    """
    groups = {}
    for cf in campaign_findings:
        f = cf.finding
        asset = f.asset if f else None

        # Effective owner: campaign-level override > finding-level ownership > suggestion
        if cf.owner_role:
            owner_key = cf.owner_role
            owner_name = cf.owner_name or cf.owner_role
            owner_role = cf.owner_role
            team = cf.team
        elif f and f.ownership:
            own = f.ownership[0]
            owner_key = own.owner_role or own.owner_name or "Unassigned"
            owner_name = own.owner_name or owner_key
            owner_role = own.owner_role
            team = own.team
        else:
            owner_key = (f.owner_suggestion if f else None) or "Unassigned"
            owner_name = owner_key
            owner_role = owner_key
            team = None

        if owner_key not in groups:
            groups[owner_key] = {
                "owner_key": owner_key,
                "owner_name": owner_name,
                "owner_role": owner_role,
                "team": team,
                "findings": [],
                "critical_count": 0,
                "high_count": 0,
                "exploit_count": 0,
            }

        fd = _serialize_finding(f, asset)
        fd["campaign_status"] = cf.status
        fd["campaign_finding_id"] = cf.id
        fd["campaign_owner"] = {
            "owner_name": cf.owner_name,
            "owner_email": cf.owner_email,
            "owner_role": cf.owner_role,
            "team": cf.team,
            "notes": cf.notes,
        }
        groups[owner_key]["findings"].append(fd)
        if f:
            if f.severity >= 4:
                groups[owner_key]["critical_count"] += 1
            elif f.severity >= 3:
                groups[owner_key]["high_count"] += 1
            if f.exploit_available:
                groups[owner_key]["exploit_count"] += 1

    # Sort findings within each group by priority_score desc
    for g in groups.values():
        g["findings"].sort(key=lambda x: x.get("priority_score") or 0, reverse=True)

    # Sort groups: critical first
    return sorted(groups.values(), key=lambda g: (g["critical_count"] + g["high_count"]), reverse=True)


@app.get("/api/rule-engine/catalog")
def get_rule_engine_catalog():
    """Return the unified condition catalog used by all rule systems."""
    return rule_engine.CONDITION_CATALOG


@app.get("/api/campaigns/condition-catalog")
def get_condition_catalog():
    """Return condition catalog for campaign queries (proxies to unified catalog)."""
    return rule_engine.CONDITION_CATALOG


@app.post("/api/campaigns/preview")
def preview_campaign_query(body: CampaignCreateBody, db: Session = Depends(get_db)):
    """Run a query and return matching assets + finding counts without saving."""
    results = cq.run_query(db, body.query, body.query_logic, body.scan_id)
    return {
        "asset_count": len(results),
        "finding_count": sum(len(r["findings"]) for r in results),
        "assets": [
            {
                "asset_id": r["asset"].id,
                "ip": r["asset"].ip,
                "hostname": r["asset"].hostname or r["asset"].fqdn,
                "criticality": r["asset"].criticality,
                "environment_tag": r["asset"].environment_tag,
                "risk_score": r["asset"].risk_score,
                "finding_count": len(r["findings"]),
                "critical_count": sum(1 for f in r["findings"] if f.severity >= 4),
                "matched_conditions": r["matched_conditions"],
            }
            for r in results
        ]
    }


@app.post("/api/campaigns")
def create_campaign(body: CampaignCreateBody, db: Session = Depends(get_db)):
    """Create a new remediation campaign."""
    campaign = Campaign(
        name=body.name,
        description=body.description,
        scan_id=body.scan_id,
        query=body.query,
        query_logic=body.query_logic,
        status="draft",
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@app.get("/api/campaigns")
def list_campaigns(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """List all campaigns, optionally filtered by scan."""
    q = db.query(Campaign)
    if scan_id:
        q = q.filter((Campaign.scan_id == scan_id) | (Campaign.scan_id == None))
    campaigns = q.order_by(Campaign.created_at.desc()).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "description": c.description,
            "status": c.status,
            "scan_id": c.scan_id,
            "query": c.query,
            "query_logic": c.query_logic,
            "finding_count": c.finding_count,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "last_run_at": c.last_run_at.isoformat() if c.last_run_at else None,
        }
        for c in campaigns
    ]


@app.get("/api/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Get a campaign with its findings grouped by owner."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    owner_groups = _group_findings_by_owner(campaign.findings)
    total_findings = sum(len(g["findings"]) for g in owner_groups)
    total_critical = sum(g["critical_count"] for g in owner_groups)
    total_exploit = sum(g["exploit_count"] for g in owner_groups)

    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "status": campaign.status,
        "scan_id": campaign.scan_id,
        "query": campaign.query,
        "query_logic": campaign.query_logic,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "last_run_at": campaign.last_run_at.isoformat() if campaign.last_run_at else None,
        "finding_count": total_findings,
        "critical_count": total_critical,
        "exploit_count": total_exploit,
        "owner_groups": owner_groups,
    }


@app.patch("/api/campaigns/{campaign_id}")
def update_campaign(campaign_id: int, body: CampaignUpdateBody, db: Session = Depends(get_db)):
    """Update campaign metadata or query."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    if body.name is not None:
        campaign.name = body.name
    if body.description is not None:
        campaign.description = body.description
    if body.status is not None:
        campaign.status = body.status
    if body.query is not None:
        campaign.query = body.query
    if body.query_logic is not None:
        campaign.query_logic = body.query_logic
    db.commit()
    return {"ok": True, "id": campaign.id}


@app.delete("/api/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Delete a campaign and its finding associations."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    db.delete(campaign)
    db.commit()
    return {"ok": True}


@app.post("/api/campaigns/{campaign_id}/run")
def run_campaign(campaign_id: int, db: Session = Depends(get_db)):
    """Execute the campaign query and populate its findings."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    # Clear previous results
    db.query(CampaignFinding).filter(CampaignFinding.campaign_id == campaign_id).delete()

    # Run query
    results = cq.run_query(db, campaign.query or [], campaign.query_logic or "AND", campaign.scan_id)

    # Populate findings
    added = 0
    for r in results:
        for finding in r["findings"]:
            cf = CampaignFinding(
                campaign_id=campaign_id,
                finding_id=finding.id,
            )
            db.add(cf)
            added += 1

    campaign.finding_count = added
    campaign.last_run_at = datetime.utcnow()
    if campaign.status == "draft":
        campaign.status = "active"
    db.commit()

    return {"ok": True, "finding_count": added, "asset_count": len(results)}


@app.patch("/api/campaigns/{campaign_id}/findings/{cf_id}")
def update_campaign_finding(
    campaign_id: int, cf_id: int, body: CampaignFindingUpdateBody, db: Session = Depends(get_db)
):
    """Update ownership or status for a finding within a campaign."""
    cf = db.query(CampaignFinding).filter(
        CampaignFinding.id == cf_id,
        CampaignFinding.campaign_id == campaign_id
    ).first()
    if not cf:
        raise HTTPException(404, "Campaign finding not found")
    if body.owner_name is not None:
        cf.owner_name = body.owner_name
    if body.owner_email is not None:
        cf.owner_email = body.owner_email
    if body.owner_role is not None:
        cf.owner_role = body.owner_role
    if body.team is not None:
        cf.team = body.team
    if body.notes is not None:
        cf.notes = body.notes
    if body.status is not None:
        cf.status = body.status
    db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────
# Blast Radius / Attack Path
# ─────────────────────────────────────────────

@app.get("/api/blast-radius")
def get_blast_radius(
    scan_id: int = Query(...),
    asset_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Compute blast radius for a specific asset using inventory data."""
    from sqlalchemy import or_

    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.scan_id == scan_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")

    all_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    asset_map = {a.id: a for a in all_assets}
    ip_to_asset_id = {a.ip: a.id for a in all_assets if a.ip}

    nodes: dict = {}
    edges: list = []
    seen_edge_ids: set = set()

    def _asset_dc(aid):
        return db.query(InventoryComputer).filter(
            InventoryComputer.asset_id == aid,
            InventoryComputer.scan_id == scan_id,
            InventoryComputer.is_domain_controller == True,
        ).first() is not None

    def _asset_av(aid):
        return db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == aid,
            InventorySecurityControl.scan_id == scan_id,
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).first() is not None

    def _asset_share(aid):
        return db.query(InventoryShare).filter(
            InventoryShare.asset_id == aid,
            InventoryShare.scan_id == scan_id,
            InventoryShare.is_writeable == True,
        ).first() is not None

    def _asset_node_data(a):
        return {
            "label": a.ip or a.hostname or f"Asset {a.id}",
            "ip": a.ip, "hostname": a.hostname, "os": a.os,
            "risk_score": a.risk_score, "criticality": a.criticality,
            "critical_count": a.critical_count, "high_count": a.high_count,
            "medium_count": a.medium_count,
            "is_dc": _asset_dc(a.id),
            "has_av": _asset_av(a.id),
            "has_writeable_share": _asset_share(a.id),
        }

    def add_node(nid, ntype, data):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "data": data}

    def add_edge(eid, source, target, etype, label):
        if eid not in seen_edge_ids:
            seen_edge_ids.add(eid)
            edges.append({"id": eid, "source": source, "target": target,
                          "type": etype, "data": {"label": label}})

    def _user_node_data(u):
        return {
            "label": u.username or "unknown",
            "username": u.username, "domain": u.domain,
            "user_type": u.user_type,
            "is_domain_admin": u.is_domain_admin,
            "is_local_admin": u.is_local_admin,
            "is_privileged": u.is_privileged,
            "kerberoastable": bool(u.spns),
            "spns": u.spns or [],
            "password_never_expires": u.password_never_expires,
            "member_of": u.member_of or [],
        }

    start_nid = f"asset-{asset_id}"
    add_node(start_nid, "asset", {**_asset_node_data(asset), "_start": True})

    visited_assets = {asset_id}
    queue = [asset_id]

    for hop in range(2):
        next_queue = []
        for cur_id in queue:
            cur = asset_map.get(cur_id)
            if not cur:
                continue

            # 1. Established network connections to other known assets
            for conn in db.query(InventoryNetConn).filter(
                InventoryNetConn.asset_id == cur_id,
                InventoryNetConn.scan_id == scan_id,
                InventoryNetConn.state.in_(["ESTABLISHED", "established"]),
            ).all():
                if not conn.remote_addr or conn.remote_addr not in ip_to_asset_id:
                    continue
                dst_id = ip_to_asset_id[conn.remote_addr]
                if dst_id == cur_id:
                    continue
                dst = asset_map.get(dst_id)
                if not dst:
                    continue
                add_node(f"asset-{dst_id}", "asset", _asset_node_data(dst))
                add_edge(
                    f"e-net-{cur_id}-{dst_id}-{conn.remote_port}",
                    f"asset-{cur_id}", f"asset-{dst_id}",
                    "network_connection", f":{conn.remote_port}",
                )
                if dst_id not in visited_assets:
                    visited_assets.add(dst_id)
                    next_queue.append(dst_id)

            # 2. Privileged users currently logged on (credential exposure)
            for logon in db.query(InventoryLoggedOn).filter(
                InventoryLoggedOn.asset_id == cur_id,
                InventoryLoggedOn.scan_id == scan_id,
            ).all():
                if not logon.username:
                    continue
                user = db.query(InventoryUser).filter(
                    InventoryUser.scan_id == scan_id,
                    InventoryUser.username == logon.username,
                    or_(
                        InventoryUser.is_domain_admin == True,
                        InventoryUser.is_local_admin == True,
                        InventoryUser.is_privileged == True,
                    ),
                ).first()
                if not user:
                    continue
                unid = f"user-{user.id}"
                add_node(unid, "user", _user_node_data(user))
                add_edge(f"e-logon-{cur_id}-{user.id}",
                         f"asset-{cur_id}", unid, "credential_exposure", "Logged On")

            # 3. Admin accounts declared on this asset
            for user in db.query(InventoryUser).filter(
                InventoryUser.asset_id == cur_id,
                InventoryUser.scan_id == scan_id,
                or_(
                    InventoryUser.is_domain_admin == True,
                    InventoryUser.is_local_admin == True,
                ),
            ).all():
                unid = f"user-{user.id}"
                add_node(unid, "user", _user_node_data(user))
                etype = "domain_admin" if user.is_domain_admin else "local_admin"
                elabel = "Domain Admin" if user.is_domain_admin else "Local Admin"
                add_edge(f"e-admin-{user.id}-{cur_id}",
                         unid, f"asset-{cur_id}", etype, elabel)

                # Domain admins expose all other assets they control (1 hop)
                if user.is_domain_admin and hop == 0:
                    for other in db.query(InventoryUser).filter(
                        InventoryUser.scan_id == scan_id,
                        InventoryUser.username == user.username,
                        InventoryUser.asset_id != cur_id,
                        InventoryUser.is_domain_admin == True,
                    ).limit(5).all():
                        other_asset = asset_map.get(other.asset_id)
                        if not other_asset:
                            continue
                        add_node(f"asset-{other.asset_id}", "asset",
                                 _asset_node_data(other_asset))
                        add_edge(f"e-admin-{user.id}-{other.asset_id}",
                                 unid, f"asset-{other.asset_id}",
                                 "domain_admin", "Domain Admin")
                        if other.asset_id not in visited_assets:
                            visited_assets.add(other.asset_id)
                            next_queue.append(other.asset_id)

        queue = next_queue

    # Compute blast radius score 0–10
    reachable_asset_ids = {
        int(n["id"].split("-")[1])
        for n in nodes.values()
        if n["type"] == "asset" and n["id"] != start_nid
    }
    user_nodes = [n for n in nodes.values() if n["type"] == "user"]
    da_exposed = any(u["data"].get("is_domain_admin") for u in user_nodes)
    la_exposed = any(u["data"].get("is_local_admin") for u in user_nodes)
    dc_reachable = any(
        n["data"].get("is_dc")
        for n in nodes.values()
        if n["type"] == "asset" and n["id"] != start_nid
    )
    kerb_exposed = any(u["data"].get("kerberoastable") for u in user_nodes)

    score = min(len(reachable_asset_ids) * 1.5, 5.0)
    if dc_reachable:   score += 3.0
    if da_exposed:     score += 2.0
    elif la_exposed:   score += 1.0
    if kerb_exposed:   score += 1.0
    score = min(round(score, 1), 10.0)

    vectors = []
    for u in user_nodes:
        d = u["data"]
        if d.get("is_domain_admin"):
            vectors.append({"type": "domain_admin",
                            "label": f"Domain Admin credential on host: {d['username']}",
                            "severity": "critical"})
        elif d.get("kerberoastable"):
            vectors.append({"type": "kerberoastable",
                            "label": f"Kerberoastable account: {d['username']}",
                            "severity": "high"})
        elif d.get("is_local_admin"):
            vectors.append({"type": "local_admin",
                            "label": f"Local Admin account: {d['username']}",
                            "severity": "high"})
    for e in edges:
        if e["type"] == "credential_exposure":
            un = nodes.get(e["target"])
            if un:
                vectors.append({
                    "type": "credential_exposure",
                    "label": f"Credential exposure: {un['data'].get('username','?')} logged on",
                    "severity": "high" if un["data"].get("is_domain_admin") else "medium",
                })
        elif e["type"] == "network_connection" and e["source"] == start_nid:
            tid = int(e["target"].split("-")[1])
            ta = asset_map.get(tid)
            vectors.append({
                "type": "network_connection",
                "label": f"Established → {ta.ip or ta.hostname if ta else e['target']} {e['data']['label']}",
                "severity": "low",
            })

    return {
        "asset_id": asset_id,
        "score": score,
        "reachable_assets": len(reachable_asset_ids),
        "privileged_users": len(user_nodes),
        "da_exposed": da_exposed,
        "dc_reachable": dc_reachable,
        "kerberoastable_exposed": kerb_exposed,
        "vectors": vectors[:10],
        "nodes": list(nodes.values()),
        "edges": edges,
    }


# ─────────────────────────────────────────────
# Tags
# ─────────────────────────────────────────────

class TagCreate(BaseModel):
    category: str
    value: str
    parent_id: Optional[int] = None
    color: Optional[str] = "#6366f1"
    description: Optional[str] = None


class TagUpdate(BaseModel):
    category: Optional[str] = None
    value: Optional[str] = None
    parent_id: Optional[int] = None
    color: Optional[str] = None
    description: Optional[str] = None


class TagAssignBody(BaseModel):
    tag_ids: list
    asset_ids: Optional[list] = None
    finding_ids: Optional[list] = None


class AutoTagRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tag_id: int
    target_type: str = "asset"
    conditions: list = []
    condition_logic: str = "AND"
    is_enabled: bool = True


class AutoTagRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tag_id: Optional[int] = None
    target_type: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    is_enabled: Optional[bool] = None


@app.post("/api/tags")
def create_tag(body: TagCreate, db: Session = Depends(get_db)):
    existing = db.query(Tag).filter(Tag.category == body.category, Tag.value == body.value).first()
    if existing:
        raise HTTPException(409, f"Tag '{body.category}:{body.value}' already exists")
    if body.parent_id:
        parent = db.query(Tag).filter(Tag.id == body.parent_id).first()
        if not parent:
            raise HTTPException(404, "Parent tag not found")
    tag = Tag(
        category=body.category,
        value=body.value,
        parent_id=body.parent_id,
        color=body.color or "#6366f1",
        description=body.description,
    )
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@app.get("/api/tags")
def list_tags(
    category: Optional[str] = None,
    tree: bool = False,
    db: Session = Depends(get_db),
):
    q = db.query(Tag)
    if category:
        q = q.filter(Tag.category == category)
    q = q.order_by(Tag.category, Tag.value)
    tags = q.all()
    if tree:
        return tag_engine.build_tree(tags, db=db)
    return [tag_engine._tag_to_dict(t, db=db, include_counts=True) for t in tags]


@app.get("/api/tags/{tag_id}")
def get_tag(tag_id: int, db: Session = Depends(get_db)):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    d = tag_engine._tag_to_dict(tag, db=db, include_counts=True)
    d["ancestors"] = tag_engine.get_ancestors(tag_id, db)
    descendant_ids = tag_engine.get_descendant_ids(tag_id, db)
    d["descendant_count"] = len(descendant_ids)
    return d


@app.patch("/api/tags/{tag_id}")
def update_tag(tag_id: int, body: TagUpdate, db: Session = Depends(get_db)):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    if body.category is not None or body.value is not None:
        new_cat = body.category or tag.category
        new_val = body.value or tag.value
        conflict = db.query(Tag).filter(
            Tag.category == new_cat, Tag.value == new_val, Tag.id != tag_id
        ).first()
        if conflict:
            raise HTTPException(409, f"Tag '{new_cat}:{new_val}' already exists")
        tag.category = new_cat
        tag.value = new_val
    if body.parent_id is not None:
        if body.parent_id == tag_id:
            raise HTTPException(400, "Tag cannot be its own parent")
        tag.parent_id = body.parent_id
    if body.color is not None:
        tag.color = body.color
    if body.description is not None:
        tag.description = body.description
    db.commit()
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@app.delete("/api/tags/{tag_id}")
def delete_tag(
    tag_id: int,
    strategy: str = "reparent",  # "reparent" | "cascade"
    db: Session = Depends(get_db),
):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")

    children = db.query(Tag).filter(Tag.parent_id == tag_id).all()
    if strategy == "cascade":
        # Delete all descendants recursively
        all_desc_ids = tag_engine.get_descendant_ids(tag_id, db)
        for did in all_desc_ids:
            db.query(TagAssignment).filter(TagAssignment.tag_id == did).delete(synchronize_session=False)
            db.query(Tag).filter(Tag.id == did).delete(synchronize_session=False)
    else:
        # Reparent children to grandparent
        grandparent_id = tag.parent_id
        for child in children:
            child.parent_id = grandparent_id

    db.query(TagAssignment).filter(TagAssignment.tag_id == tag_id).delete(synchronize_session=False)
    db.delete(tag)
    db.commit()
    return {"message": "Tag deleted", "strategy": strategy}


@app.post("/api/tags/assign")
def assign_tags(body: TagAssignBody, db: Session = Depends(get_db)):
    assigned = 0
    for tag_id in (body.tag_ids or []):
        tag = db.query(Tag).filter(Tag.id == tag_id).first()
        if not tag:
            continue
        for aid in (body.asset_ids or []):
            exists = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.asset_id == aid,
            ).first()
            if not exists:
                db.add(TagAssignment(tag_id=tag_id, asset_id=aid, assigned_by="user"))
                assigned += 1
        for fid in (body.finding_ids or []):
            exists = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.finding_id == fid,
            ).first()
            if not exists:
                db.add(TagAssignment(tag_id=tag_id, finding_id=fid, assigned_by="user"))
                assigned += 1
    db.commit()
    return {"assigned": assigned}


@app.post("/api/tags/unassign")
def unassign_tags(body: TagAssignBody, db: Session = Depends(get_db)):
    removed = 0
    for tag_id in (body.tag_ids or []):
        for aid in (body.asset_ids or []):
            n = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.asset_id == aid,
            ).delete(synchronize_session=False)
            removed += n
        for fid in (body.finding_ids or []):
            n = db.query(TagAssignment).filter(
                TagAssignment.tag_id == tag_id,
                TagAssignment.finding_id == fid,
            ).delete(synchronize_session=False)
            removed += n
    db.commit()
    return {"removed": removed}


# ─────────────────────────────────────────────
# Auto-tag rules
# ─────────────────────────────────────────────

@app.get("/api/auto-tag-rules/condition-catalog")
def get_tag_condition_catalog():
    """Return condition catalog for auto-tag rules (proxies to unified catalog)."""
    return rule_engine.CONDITION_CATALOG


@app.get("/api/auto-tag-rules")
def list_auto_tag_rules(db: Session = Depends(get_db)):
    rules = db.query(AutoTagRule).order_by(AutoTagRule.id).all()
    return [_rule_to_dict(r) for r in rules]


@app.post("/api/auto-tag-rules")
def create_auto_tag_rule(body: AutoTagRuleCreate, db: Session = Depends(get_db)):
    tag = db.query(Tag).filter(Tag.id == body.tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    rule = AutoTagRule(
        name=body.name,
        description=body.description,
        tag_id=body.tag_id,
        target_type=body.target_type,
        conditions=body.conditions,
        condition_logic=body.condition_logic,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_to_dict(rule)


@app.patch("/api/auto-tag-rules/{rule_id}")
def update_auto_tag_rule(rule_id: int, body: AutoTagRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.tag_id is not None:
        tag = db.query(Tag).filter(Tag.id == body.tag_id).first()
        if not tag:
            raise HTTPException(404, "Tag not found")
        rule.tag_id = body.tag_id
    if body.target_type is not None:
        rule.target_type = body.target_type
    if body.conditions is not None:
        rule.conditions = body.conditions
    if body.condition_logic is not None:
        rule.condition_logic = body.condition_logic
    if body.is_enabled is not None:
        rule.is_enabled = body.is_enabled
    db.commit()
    return _rule_to_dict(rule)


@app.delete("/api/auto-tag-rules/{rule_id}")
def delete_auto_tag_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}


@app.post("/api/auto-tag-rules/{rule_id}/run")
def run_auto_tag_rule(
    rule_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    rule = db.query(AutoTagRule).filter(AutoTagRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    count = tag_engine.run_auto_tag_rule(rule, db, scan_id=scan_id)
    return {"tagged": count, "rule_id": rule_id}


def _rule_to_dict(rule: AutoTagRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "tag_id": rule.tag_id,
        "tag_label": f"{rule.tag.category}:{rule.tag.value}" if rule.tag else None,
        "tag_color": rule.tag.color if rule.tag else None,
        "target_type": rule.target_type,
        "conditions": rule_engine.migrate_conditions(rule.conditions or [], mode="autotag"),
        "condition_logic": rule.condition_logic,
        "is_enabled": rule.is_enabled,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "last_run_at": rule.last_run_at.isoformat() if rule.last_run_at else None,
        "last_run_count": rule.last_run_count,
    }


# ─────────────────────────────────────────────
# SLA / MTTR Tracking
# ─────────────────────────────────────────────

# Default SLA windows (days) per severity
_SLA_DEFAULTS = {
    4: {"label": "Critical", "days": 7,   "warn": 2,  "enabled": True},
    3: {"label": "High",     "days": 30,  "warn": 7,  "enabled": True},
    2: {"label": "Medium",   "days": 90,  "warn": 14, "enabled": True},
    1: {"label": "Low",      "days": 180, "warn": 30, "enabled": True},
    0: {"label": "Info",     "days": 365, "warn": 30, "enabled": False},
}


def _ensure_sla_defaults(db: Session):
    """Seed SLAConfig rows with defaults if they don't exist yet."""
    for sev, d in _SLA_DEFAULTS.items():
        if not db.query(SLAConfig).filter(SLAConfig.severity == sev).first():
            db.add(SLAConfig(
                severity=sev,
                severity_label=d["label"],
                days_to_remediate=d["days"],
                warn_days_before=d["warn"],
                is_enabled=d["enabled"],
            ))
    db.commit()


_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%a %b %d %H:%M:%S %Y",
    "%a %b  %d %H:%M:%S %Y",   # single-digit day with extra space
    "%b %d, %Y",
    "%d/%m/%Y",
]


def _parse_nessus_date(s: str) -> Optional[datetime]:
    """Try common Nessus/scan date formats, return datetime or None."""
    if not s:
        return None
    s = s.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _compute_sla_status(due_date, resolved_at, warn_days: int) -> str:
    """Return sla_status string given a due date and current time."""
    if resolved_at:
        return "resolved"
    if not due_date:
        return "n/a"
    now = datetime.utcnow()
    delta = (due_date - now).total_seconds() / 86400  # days remaining
    if delta < 0:
        return "breached"
    if delta <= warn_days:
        return "at_risk"
    return "on_track"


def _recalculate_sla_for_scan(db: Session, scan_id: int, configs: list):
    """Recompute sla_due_date and sla_status for every finding in a scan.

    Base date priority (most accurate → fallback):
      1. asset.scan_start  — per-asset scan start from Nessus
      2. scan.scan_date    — scan-level date from the Nessus file
      3. scan.created_at   — upload timestamp (last resort)
    """
    from datetime import timedelta

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return 0

    cfg_map = {c.severity: c for c in configs}

    # scan-level fallback date (from Nessus file, or upload time)
    scan_fallback = _parse_nessus_date(scan.scan_date) or scan.created_at or datetime.utcnow()

    # Build per-asset observation date cache
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    asset_obs_date: dict = {}
    for a in assets:
        asset_obs_date[a.id] = _parse_nessus_date(a.scan_start) or scan_fallback

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    updated = 0
    for f in findings:
        cfg = cfg_map.get(f.severity)
        if not cfg or not cfg.is_enabled:
            f.sla_due_date = None
            f.sla_status = "n/a"
        else:
            # Use the asset's observation date so the SLA reflects when
            # this specific host was actually scanned, not the upload time.
            base_date = asset_obs_date.get(f.asset_id, scan_fallback)
            f.sla_due_date = base_date + timedelta(days=cfg.days_to_remediate)
            f.sla_status = _compute_sla_status(f.sla_due_date, f.resolved_at, cfg.warn_days_before)
        updated += 1
    db.commit()
    return updated


@app.get("/api/sla/config")
def get_sla_config(db: Session = Depends(get_db)):
    """Return SLA configuration for all severity levels."""
    _ensure_sla_defaults(db)
    rows = db.query(SLAConfig).order_by(SLAConfig.severity.desc()).all()
    return [
        {
            "id": r.id,
            "severity": r.severity,
            "severity_label": r.severity_label,
            "days_to_remediate": r.days_to_remediate,
            "warn_days_before": r.warn_days_before,
            "is_enabled": r.is_enabled,
        }
        for r in rows
    ]


class SLAConfigUpdateBody(BaseModel):
    configs: list  # [{severity, days_to_remediate, warn_days_before, is_enabled}]


@app.put("/api/sla/config")
def save_sla_config(body: SLAConfigUpdateBody, db: Session = Depends(get_db)):
    """Save SLA configuration and trigger recalculation for all scans."""
    _ensure_sla_defaults(db)
    for item in body.configs:
        sev = item.get("severity")
        row = db.query(SLAConfig).filter(SLAConfig.severity == sev).first()
        if not row:
            continue
        if "days_to_remediate" in item:
            row.days_to_remediate = int(item["days_to_remediate"])
        if "warn_days_before" in item:
            row.warn_days_before = int(item["warn_days_before"])
        if "is_enabled" in item:
            row.is_enabled = bool(item["is_enabled"])
    db.commit()

    # Recalculate SLA for all scans
    configs = db.query(SLAConfig).all()
    scans = db.query(Scan).all()
    total = 0
    for scan in scans:
        total += _recalculate_sla_for_scan(db, scan.id, configs)
    return {"ok": True, "updated_findings": total}


class SLARecalcBody(BaseModel):
    scan_id: Optional[int] = None


@app.post("/api/sla/recalculate")
def recalculate_sla(
    body: SLARecalcBody = SLARecalcBody(),
    db: Session = Depends(get_db),
):
    """Recompute sla_due_date and sla_status for findings (all scans or a specific one)."""
    scan_id = body.scan_id
    _ensure_sla_defaults(db)
    configs = db.query(SLAConfig).all()
    if scan_id:
        scans = db.query(Scan).filter(Scan.id == scan_id).all()
    else:
        scans = db.query(Scan).all()
    total = 0
    for scan in scans:
        total += _recalculate_sla_for_scan(db, scan.id, configs)
    return {"ok": True, "updated_findings": total}


@app.get("/api/sla/summary")
def get_sla_summary(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return SLA compliance stats and MTTR for a scan (or all scans)."""
    _ensure_sla_defaults(db)
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)

    # Exclude Info unless it has SLA enabled
    enabled_sevs = [
        c.severity for c in db.query(SLAConfig).filter(SLAConfig.is_enabled == True).all()
    ]
    q = q.filter(Finding.severity.in_(enabled_sevs))

    findings = q.all()

    counts = {"on_track": 0, "at_risk": 0, "breached": 0, "resolved": 0, "n/a": 0}
    breached_by_sev = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}

    # MTTR: days from observation date to resolved_at.
    # observation_date = sla_due_date - days_to_remediate (already computed using
    # asset.scan_start / scan.scan_date, so this is accurate to the Nessus data).
    mttr_by_sev: dict[int, list[float]] = {4: [], 3: [], 2: [], 1: [], 0: []}

    cfg_map = {c.severity: c for c in db.query(SLAConfig).all()}

    for f in findings:
        status = f.sla_status or "n/a"
        counts[status] = counts.get(status, 0) + 1
        if status == "breached":
            breached_by_sev[f.severity] = breached_by_sev.get(f.severity, 0) + 1
        if f.resolved_at and f.sla_due_date:
            cfg = cfg_map.get(f.severity)
            if cfg:
                from datetime import timedelta
                obs_date = f.sla_due_date - timedelta(days=cfg.days_to_remediate)
                days = (f.resolved_at - obs_date).total_seconds() / 86400
                if days >= 0:
                    mttr_by_sev[f.severity].append(days)

    avg_mttr = {}
    sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    for sev, vals in mttr_by_sev.items():
        if vals:
            avg_mttr[sev_labels[sev]] = round(sum(vals) / len(vals), 1)

    total_with_sla = sum(counts[k] for k in ("on_track", "at_risk", "breached", "resolved"))
    compliance_pct = round(
        (counts["on_track"] + counts["resolved"]) / total_with_sla * 100, 1
    ) if total_with_sla else 0

    return {
        "on_track": counts["on_track"],
        "at_risk": counts["at_risk"],
        "breached": counts["breached"],
        "resolved": counts["resolved"],
        "total_with_sla": total_with_sla,
        "compliance_pct": compliance_pct,
        "avg_mttr_days": avg_mttr,
        "breached_by_severity": {sev_labels[k]: v for k, v in breached_by_sev.items() if v > 0},
    }


@app.patch("/api/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    """Mark a finding as resolved (sets resolved_at and sla_status=resolved)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.resolved_at = datetime.utcnow()
    finding.sla_status = "resolved"
    db.commit()
    return {"ok": True, "finding_id": finding_id, "resolved_at": finding.resolved_at.isoformat()}


@app.patch("/api/findings/{finding_id}/unresolve")
def unresolve_finding(finding_id: int, db: Session = Depends(get_db)):
    """Reopen a resolved finding and recompute its SLA status."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.resolved_at = None
    # Recompute status from due date
    configs = db.query(SLAConfig).all()
    cfg_map = {c.severity: c for c in configs}
    cfg = cfg_map.get(finding.severity)
    warn = cfg.warn_days_before if cfg else 7
    finding.sla_status = _compute_sla_status(finding.sla_due_date, None, warn)
    db.commit()
    return {"ok": True, "finding_id": finding_id, "sla_status": finding.sla_status}


# ─────────────────────────────────────────────
# Workflow Engine
# ─────────────────────────────────────────────

@app.get("/api/workflows/node-catalog")
def get_node_catalog():
    """Return available node types for the workflow builder."""
    return workflow_engine.NODE_CATALOG


@app.get("/api/workflows/templates")
def get_workflow_templates():
    """Return OOTB workflow templates."""
    return {
        "templates": workflow_engine.WORKFLOW_TEMPLATES,
        "categories": workflow_engine.TEMPLATE_CATEGORIES,
    }


class WorkflowCreateFromTemplate(BaseModel):
    template_id: str
    name: Optional[str] = None
    campaign_id: Optional[int] = None


@app.post("/api/workflows/from-template")
def create_workflow_from_template(body: WorkflowCreateFromTemplate, db: Session = Depends(get_db)):
    """Create a workflow from an OOTB template."""
    try:
        wf = workflow_engine.create_workflow_from_template(
            db, body.template_id, name=body.name, campaign_id=body.campaign_id)
        d = _workflow_to_dict(wf)
        d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
        d["edges"] = [_edge_to_dict(e) for e in wf.edges]
        return d
    except ValueError as e:
        raise HTTPException(400, str(e))


class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    campaign_id: Optional[int] = None


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    campaign_id: Optional[int] = None
    status: Optional[str] = None
    is_enabled: Optional[bool] = None
    nodes: Optional[list] = None
    edges: Optional[list] = None


@app.post("/api/workflows")
def create_workflow(body: WorkflowCreate, db: Session = Depends(get_db)):
    wf = Workflow(
        name=body.name,
        description=body.description,
        campaign_id=body.campaign_id,
    )
    db.add(wf)
    db.commit()
    db.refresh(wf)
    return _workflow_to_dict(wf)


@app.get("/api/workflows")
def list_workflows(
    campaign_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Workflow).order_by(desc(Workflow.updated_at))
    if campaign_id is not None:
        q = q.filter(Workflow.campaign_id == campaign_id)
    return [_workflow_to_dict(w) for w in q.all()]


@app.get("/api/workflows/{wf_id}")
def get_workflow(wf_id: int, db: Session = Depends(get_db)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@app.patch("/api/workflows/{wf_id}")
def update_workflow(wf_id: int, body: WorkflowUpdate, db: Session = Depends(get_db)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")

    if body.name is not None:
        wf.name = body.name
    if body.description is not None:
        wf.description = body.description
    if body.campaign_id is not None:
        wf.campaign_id = body.campaign_id
    if body.status is not None:
        wf.status = body.status
    if body.is_enabled is not None:
        wf.is_enabled = body.is_enabled

    # Sync nodes
    if body.nodes is not None:
        db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf_id).delete(synchronize_session=False)
        for nd in body.nodes:
            db.add(WorkflowNode(
                workflow_id=wf_id,
                node_id=nd["node_id"],
                node_type=nd["node_type"],
                node_subtype=nd["node_subtype"],
                label=nd.get("label", ""),
                config=nd.get("config", {}),
                position_x=nd.get("position_x", 0),
                position_y=nd.get("position_y", 0),
            ))

    # Sync edges
    if body.edges is not None:
        db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf_id).delete(synchronize_session=False)
        for ed in body.edges:
            db.add(WorkflowEdge(
                workflow_id=wf_id,
                edge_id=ed["edge_id"],
                source_node_id=ed["source_node_id"],
                target_node_id=ed["target_node_id"],
                source_handle=ed.get("source_handle", "output"),
                target_handle=ed.get("target_handle", "input"),
                label=ed.get("label"),
            ))

    db.commit()
    db.refresh(wf)
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@app.delete("/api/workflows/{wf_id}")
def delete_workflow(wf_id: int, db: Session = Depends(get_db)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    db.delete(wf)
    db.commit()
    return {"message": "Workflow deleted"}


@app.post("/api/workflows/{wf_id}/execute")
def execute_workflow_endpoint(wf_id: int, db: Session = Depends(get_db)):
    """Execute a workflow manually."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    try:
        result = workflow_engine.execute_workflow(db, wf_id)
        return result
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/workflows/{wf_id}/executions")
def list_workflow_executions(wf_id: int, limit: int = 20, db: Session = Depends(get_db)):
    execs = db.query(WorkflowExecution).filter(
        WorkflowExecution.workflow_id == wf_id
    ).order_by(desc(WorkflowExecution.started_at)).limit(limit).all()
    return [_execution_to_dict(e) for e in execs]


@app.get("/api/workflows/executions/{exec_id}")
def get_workflow_execution(exec_id: int, db: Session = Depends(get_db)):
    ex = db.query(WorkflowExecution).filter(WorkflowExecution.id == exec_id).first()
    if not ex:
        raise HTTPException(404, "Execution not found")
    d = _execution_to_dict(ex)
    d["logs"] = [
        {
            "id": l.id,
            "node_id": l.node_id,
            "node_type": l.node_type,
            "node_subtype": l.node_subtype,
            "status": l.status,
            "items_in": l.items_in,
            "items_out": l.items_out,
            "output_data": l.output_data,
            "error": l.error,
            "executed_at": l.executed_at.isoformat() if l.executed_at else None,
        }
        for l in ex.logs
    ]
    return d


def _workflow_to_dict(wf: Workflow) -> dict:
    return {
        "id": wf.id,
        "campaign_id": wf.campaign_id,
        "name": wf.name,
        "description": wf.description,
        "status": wf.status,
        "is_enabled": wf.is_enabled,
        "created_at": wf.created_at.isoformat() if wf.created_at else None,
        "updated_at": wf.updated_at.isoformat() if wf.updated_at else None,
        "last_run_at": wf.last_run_at.isoformat() if wf.last_run_at else None,
        "run_count": wf.run_count,
        "node_count": len(wf.nodes),
        "edge_count": len(wf.edges),
    }


def _node_to_dict(n: WorkflowNode) -> dict:
    return {
        "node_id": n.node_id,
        "node_type": n.node_type,
        "node_subtype": n.node_subtype,
        "label": n.label,
        "config": n.config or {},
        "position_x": n.position_x,
        "position_y": n.position_y,
    }


def _edge_to_dict(e: WorkflowEdge) -> dict:
    return {
        "edge_id": e.edge_id,
        "source_node_id": e.source_node_id,
        "target_node_id": e.target_node_id,
        "source_handle": e.source_handle,
        "target_handle": e.target_handle,
        "label": e.label,
    }


def _execution_to_dict(ex: WorkflowExecution) -> dict:
    return {
        "id": ex.id,
        "workflow_id": ex.workflow_id,
        "status": ex.status,
        "trigger_type": ex.trigger_type,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "items_processed": ex.items_processed,
        "result_summary": ex.result_summary,
        "error": ex.error,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)

"""
Admin endpoints: Dedup config, Risk config, Audit Log, and Scan re-extract/redetect.
Extracted from app.py.
"""
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from core.database import get_db
from core.auth import (
    get_current_user, require_auth, get_accessible_org_ids,
    apply_scan_org_filter,
)
from core.time_utils import iso_utc
from pathlib import Path

from models.models import (
    User, Scan, Asset, Finding,
    InventoryUser, InventoryGroup, InventoryDomainTrust, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
    Tag, TagAssignment, AuditLog, AssetObservation, FindingObservation,
)
import services.dedup as dedup_engine
import core.risk_config as risk_engine
from services.blast_radius import resolve_dc_asset_ids as _resolve_dc_asset_ids
from services.prioritizer import compute_priority_score
from parsers.parser import load_intel_json

INTEL_PATH = Path(__file__).parent.parent / "data" / "intel.json"

router = APIRouter()


# ─────────────────────────────────────────────
# Dedup Config
# ─────────────────────────────────────────────

@router.get("/api/dedup/config")
def get_dedup_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Return the effective deduplication configuration for the current org.

    Equals the global config when no org override exists, otherwise the
    global deep-merged with the org's sparse override.
    """
    org_id = int(x_org_context) if x_org_context else user.org_id
    cfg = dedup_engine.load_config_for_org(db, org_id)
    cfg["is_org_override"] = dedup_engine.has_org_override(db, org_id)
    return cfg


@router.put("/api/dedup/config")
async def save_dedup_config(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Save deduplication configuration for the current org as an override.

    Platform superadmins can save the global config by posting without an
    org context and with ?scope=global.
    """
    org_id = int(x_org_context) if x_org_context else user.org_id
    body = await request.json()
    body.pop("is_org_override", None)  # strip read-only field

    scope = request.query_params.get("scope", "org")
    if scope == "global":
        if user.role != "superadmin":
            raise HTTPException(403, "Only superadmins can modify the global dedup config")
        dedup_engine.save_config(body)
        return {"message": "Global dedup config saved", "scope": "global"}

    dedup_engine.save_config_for_org(db, org_id, body)
    return {"message": "Org dedup config saved", "scope": "org", "org_id": org_id}


@router.delete("/api/dedup/config/org-override")
def delete_dedup_config_override(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Remove the org-level dedup config override, reverting to global defaults."""
    org_id = int(x_org_context) if x_org_context else user.org_id
    removed = dedup_engine.delete_config_for_org(db, org_id)
    if removed:
        return {"message": "Org dedup config override removed. Global defaults will be used."}
    return {"message": "No org-specific override existed. Already using global defaults."}


@router.get("/api/dedup/config/global")
def get_dedup_config_global(user: User = Depends(require_auth)):
    """Return the raw global dedup config (superadmin only)."""
    if user.role != "superadmin":
        raise HTTPException(403, "Only superadmins can view the global dedup config")
    return dedup_engine.load_config()


@router.get("/api/dedup/config/override")
def get_dedup_config_override_raw(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Return only this org's sparse override (empty dict if none).

    Useful for the Settings UI to render which fields are overridden vs.
    inherited from the global config.
    """
    org_id = int(x_org_context) if x_org_context else user.org_id
    return dedup_engine.load_org_override(db, org_id)


class RunDedupBody(BaseModel):
    entity_type: str
    scan_id: Optional[int] = None


@router.post("/api/dedup/run", status_code=202)
def run_dedup(
    body: RunDedupBody,
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Dispatch dedup as a background job using this org's resolved config."""
    from services.job_manager import dispatch
    from core.database import SessionLocal
    from models.entity_registry import ENTITY_MODEL_MAP

    entity_type = body.entity_type
    scan_id = body.scan_id
    org_id = int(x_org_context) if x_org_context else user.org_id

    def _run_dedup():
        db = SessionLocal()
        try:
            cfg = dedup_engine.load_config_for_org(db, org_id)
            return dedup_engine.run_db_dedup(db, entity_type, scan_id, cfg, ENTITY_MODEL_MAP)
        finally:
            db.close()

    job = dispatch(f"dedup_{entity_type}", _run_dedup)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


@router.get("/api/dedup/available-sources")
def get_available_sources(
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return distinct source_system values across assets and findings for this org."""
    q = (
        db.query(AssetObservation.source_system)
        .distinct()
    )
    if org_ids:
        q = q.filter(AssetObservation.org_id.in_(org_ids))
    asset_sources = {row[0] for row in q.all() if row[0]}

    q2 = (
        db.query(FindingObservation.source_system)
        .distinct()
    )
    if org_ids:
        q2 = q2.filter(FindingObservation.org_id.in_(org_ids))
    finding_sources = {row[0] for row in q2.all() if row[0]}

    # Also include source_systems from Asset/Finding for orgs that predate observations
    q3 = db.query(Asset.source_systems).join(Scan, Asset.scan_id == Scan.id)
    q3 = apply_scan_org_filter(q3, org_ids)
    for row in q3.all():
        if row[0] and isinstance(row[0], list):
            asset_sources.update(row[0])

    return sorted(asset_sources | finding_sources)


@router.post("/api/dedup/rollup", status_code=202)
def run_rollup(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Re-rollup all assets from their observations using this org's resolved
    source_priority config.

    Called after the user saves source_priority changes in Settings.
    """
    from services.job_manager import dispatch
    from core.database import SessionLocal

    org_id = int(x_org_context) if x_org_context else user.org_id

    def _run_rollup():
        _db = SessionLocal()
        try:
            cfg = dedup_engine.load_config_for_org(_db, org_id)
            from services.asset_observations import rollup_all_assets
            # Collect all source_priority configs across asset types
            assets_cfg = cfg.get("assets", {})
            total = 0
            for atype, tcfg in assets_cfg.items():
                if not isinstance(tcfg, dict):
                    continue
                sp = tcfg.get("source_priority")
                if sp and any(sp.values()):
                    total += rollup_all_assets(_db, sp)
            return {"rolled_up": total}
        finally:
            _db.close()

    job = dispatch("rollup_assets", _run_rollup)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


# ─────────────────────────────────────────────
# Risk Config & Recalculate
# ─────────────────────────────────────────────

@router.get("/api/risk/config")
def get_risk_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Return the risk scoring configuration (org-specific if override exists, else global)."""
    org_id = int(x_org_context) if x_org_context else user.org_id
    cfg = risk_engine.load_config_for_org(db, org_id)
    cfg["is_org_override"] = risk_engine.has_org_override(db, org_id)
    return cfg


@router.put("/api/risk/config")
async def save_risk_config(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Save risk scoring configuration for the current org."""
    org_id = int(x_org_context) if x_org_context else user.org_id
    body = await request.json()
    body.pop("is_org_override", None)  # strip read-only field
    risk_engine.save_config_for_org(db, org_id, body)
    return {"message": "Risk config saved"}


@router.delete("/api/risk/config/org-override")
def delete_risk_config_override(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Remove the org-level risk config override, reverting to global defaults."""
    org_id = int(x_org_context) if x_org_context else user.org_id
    removed = risk_engine.delete_config_for_org(db, org_id)
    if removed:
        return {"message": "Org risk config override removed. Global defaults will be used."}
    return {"message": "No org-specific override existed. Already using global defaults."}


class RecalculateBody(BaseModel):
    scan_id: Optional[int] = None
    apply_criticality_rules: bool = False
    recalculate_findings: bool = False


@router.post("/api/risk/recalculate", status_code=202)
def recalculate_risk(
    body: RecalculateBody,
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Dispatch risk recalculation as a background job. Returns job_id immediately."""
    from services.job_manager import dispatch
    from core.database import SessionLocal

    org_id = int(x_org_context) if x_org_context else user.org_id
    scan_id = body.scan_id
    apply_criticality = body.apply_criticality_rules
    recalc_findings = body.recalculate_findings

    def _run_risk_recalc():
        db = SessionLocal()
        try:
            return _risk_recalc_sync(db, org_id, scan_id, apply_criticality, recalc_findings)
        finally:
            db.close()

    job = dispatch("risk_recalculate", _run_risk_recalc)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


def _risk_recalc_sync(db, org_id, scan_id, apply_criticality, recalc_findings):
    """Synchronous risk recalculation logic (runs in background thread)."""
    cfg = risk_engine.load_config_for_org(db, org_id)
    intel = load_intel_json(str(INTEL_PATH)) if INTEL_PATH.exists() else {}

    asset_q = db.query(Asset)
    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
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

    # Batch-fetch DC asset IDs so we can enforce criticality floor
    dc_asset_ids = _resolve_dc_asset_ids(db, restrict_to_asset_ids=asset_ids) if asset_ids else set()

    updated_assets = 0
    updated_findings = 0
    for asset in assets:
        # Re-apply criticality rules if requested
        if apply_criticality:
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

        # Domain controllers get a criticality floor of 9
        if asset.id in dc_asset_ids and (asset.criticality or 5) < 9:
            asset.criticality = 9

        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()

        # Recount severity from actual findings
        sev_recount = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        for f in findings:
            sev_recount[f.severity] = sev_recount.get(f.severity, 0) + 1
        asset.critical_count = sev_recount[4]
        asset.high_count = sev_recount[3]
        asset.medium_count = sev_recount[2]
        asset.low_count = sev_recount[1]
        asset.info_count = sev_recount[0]

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
        import app as _app
        inv_ctx = _app._get_asset_inventory_context(db, asset.id, asset=asset)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 5,
            inventory=inv_ctx,
            cfg=cfg,
        )
        updated_assets += 1

        # Optionally recompute finding priority scores
        if recalc_findings:
            for f in findings:
                finding_dict = {
                    "plugin_id":        f.plugin_id,
                    "plugin_name":      f.plugin_name,
                    "plugin_family":    f.plugin_family,
                    "severity":         f.severity,
                    "port":             f.port,
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
                    "asset_os":          asset.os or "",
                    "plugin_name":       f.plugin_name,
                    "plugin_family":     f.plugin_family,
                }
                priority_data = compute_priority_score(
                    finding_dict,
                    asset_criticality=asset.criticality or 5,
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
    return {"updated_assets": updated_assets, "updated_findings": updated_findings, "scan_id": scan_id}


# ─────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────

@router.get("/api/audit-log")
def get_audit_log(
    entity_type: Optional[str] = None,
    action: Optional[str] = None,
    actor_email: Optional[str] = None,
    entity_id: Optional[int] = None,
    date_from: Optional[str] = None,   # ISO date string
    date_to: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return paginated audit log entries with optional filters."""
    q = db.query(AuditLog)
    if org_ids:
        q = q.filter((AuditLog.org_id.in_(org_ids)) | (AuditLog.org_id == None))
    if entity_type:
        q = q.filter(AuditLog.entity_type == entity_type)
    if action:
        q = q.filter(AuditLog.action == action)
    if actor_email:
        q = q.filter(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if entity_id:
        q = q.filter(AuditLog.entity_id == entity_id)
    if date_from:
        try:
            q = q.filter(AuditLog.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(AuditLog.created_at <= datetime.fromisoformat(date_to))
        except ValueError:
            pass

    total = q.count()
    entries = q.order_by(desc(AuditLog.created_at)).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "entries": [
            {
                "id": e.id,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "entity_name": e.entity_name,
                "actor_email": e.actor_email,
                "actor_display_name": e.actor_display_name,
                "changes": e.changes,
                "created_at": iso_utc(e.created_at),
            }
            for e in entries
        ],
        "entity_types": [r[0] for r in db.query(AuditLog.entity_type).distinct().all()],
        "actions": [r[0] for r in db.query(AuditLog.action).distinct().all()],
        "retention_days": 90,
    }


# ─────────────────────────────────────────────
# Scan Re-extract Inventory / Redetect Reachability
# ─────────────────────────────────────────────

@router.post("/api/scans/{scan_id}/reextract-inventory")
def reextract_inventory(scan_id: int, db: Session = Depends(get_db)):
    """Re-run inventory extraction for an existing scan (backfills missing inventory)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_for_inventory = []
    for f in db.query(Finding).filter(Finding.scan_id == scan_id).all():
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        findings_for_inventory.append({
            "plugin_id": f.plugin_id,
            "plugin_output": f.plugin_output,
            "plugin_name": f.plugin_name,
            "plugin_family": f.plugin_family,
            "severity": f.severity,
            "synopsis": f.synopsis,
            "solution": f.solution,
            "asset_id": f.asset_id,
            "scan_id": f.scan_id,
            "asset_hostname": asset.hostname if asset else "",
            "port": f.port,
            "protocol": f.protocol,
        })

    # ── Re-enrich assets with OS identification (11936) and CPE (45590) ──
    os_plugin_findings = db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.plugin_id.in_(["11936", "45590"]),
    ).all()
    _os_enrich_re: dict[int, dict[str, str]] = {}
    for f_os in os_plugin_findings:
        bucket = _os_enrich_re.setdefault(f_os.asset_id, {})
        bucket[f_os.plugin_id] = f_os.plugin_output or ""
    from services.asset_classifier import enrich_asset_from_os_plugins
    for aid, plugins in _os_enrich_re.items():
        asset = db.query(Asset).filter(Asset.id == aid).first()
        if asset:
            enrich_asset_from_os_plugins(
                asset,
                plugin_11936_output=plugins.get("11936"),
                plugin_45590_output=plugins.get("45590"),
            )

    # Use the scan's source_type to get the right inventory dispatch
    from parsers.registry import get_parser_by_source
    from parsers.inventory_extractor import extract_inventory_from_findings
    scan_parser = get_parser_by_source(scan.source_type or "nessus")
    dispatch = scan_parser.get_inventory_dispatch() if scan_parser else None
    inventory = extract_inventory_from_findings(findings_for_inventory, dispatch=dispatch)

    MODEL_MAP = {
        "users": (InventoryUser, ["scan_id", "asset_id", "source_plugin", "user_type",
                                   "username", "domain", "sid", "rid", "dn", "uac",
                                   "spns", "member_of", "password_last_set", "date_joined",
                                   "is_local_admin", "is_domain_admin", "is_privileged",
                                   "is_disabled", "password_never_expires", "never_logged_in",
                                   "never_changed_password", "last_logon_host",
                                   "identity_type", "identity_subtype", "source_systems",
                                   "department", "job_title", "manager_dn", "manager_username"]),
        "groups": (InventoryGroup, ["scan_id", "asset_id", "source_plugin",
                                     "group_name", "domain", "sid", "dn",
                                     "description", "members", "is_privileged"]),
        "services": (InventoryService, ["scan_id", "asset_id", "source_plugin",
                                         "service_name", "display_name", "is_running",
                                         "startup_type", "run_as_user"]),
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
                                          "name", "version", "installed_on", "vendor", "category"]),
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
        "processes": (InventoryProcess, [
            "scan_id", "asset_id", "source_plugin",
            "process_name", "pid", "ppid", "session_id",
            "parent_name", "depth",
        ]),
        "database_instances": (InventoryDatabaseInstance, [
            "scan_id", "asset_id", "source_plugin",
            "db_type", "instance_name", "version", "port",
            "databases", "named_pipes", "is_running",
        ]),
        "domain_trusts": (InventoryDomainTrust, [
            "scan_id", "asset_id", "source_plugin",
            "trusted_domain", "flat_name", "sid", "dn",
            "trust_direction", "trust_type", "trust_attributes",
            "is_transitive", "is_sid_filtering_enabled",
            "source_domain", "when_created",
        ]),
        "credentials": (InventoryCredential, [
            "scan_id", "asset_id", "source_plugin",
            "credential_type", "protocol", "username", "severity",
            "port", "description", "plugin_name", "remediation",
        ]),
    }

    # Delete existing inventory for this scan before re-inserting
    for Model, _ in MODEL_MAP.values():
        db.query(Model).filter(Model.scan_id == scan_id).delete()
    db.commit()

    inv_counts = {}
    for key, (Model, fields) in MODEL_MAP.items():
        records = inventory.get(key, [])
        for rec in records:
            obj = Model(**{f: rec.get(f) for f in fields if f in rec})
            db.add(obj)
        inv_counts[key] = len(records)
        if records:
            db.commit()

    # Rebuild SBOM from updated inventory
    try:
        from services.sbom_pipeline import build_sbom_from_inventory
        sbom_stats = build_sbom_from_inventory(db, scan_id)
        inv_counts["sbom_components"] = sbom_stats.get("components", 0)
        inv_counts["sbom_vulnerabilities"] = sbom_stats.get("vulnerabilities", 0)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"SBOM rebuild failed (non-fatal): {e}")

    return {"scan_id": scan_id, "extracted": {k: v for k, v in inv_counts.items() if v}}


@router.post("/api/scans/{scan_id}/redetect-reachability")
def redetect_reachability(scan_id: int, db: Session = Depends(get_db)):
    """Re-run internet-reachability detection for an existing scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    import app as _app
    stats = _app._apply_reachability_detection(db, scan_id)

    # Recompute risk if any assets were updated
    if stats["updated"]:
        from services.post_ingest import _recompute_risk_scores
        _recompute_risk_scores(db, scan_id)

    return {"scan_id": scan_id, **stats}

"""
Nessus Remediation Platform — FastAPI backend
"""
import os
import re
import json
import logging
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Query, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_

from core.database import get_db, init_db
from models.models import (
    Organization, User,
    Scan, Asset, Finding, AutomateClick,
    InventoryUser, InventoryGroup, InventoryDomainTrust, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
    Campaign, CampaignFinding, FindingOwnership, AssetOwnership,
    Workflow, WorkflowNode, WorkflowEdge, WorkflowExecution, WorkflowExecutionLog,
    Tag, TagAssignment, AutoTagRule, OwnershipRule, ExternalTagSource, ExternalTagMap,
    SLAConfig, IntegrationConfig, FindingException, ScanComparison, AuditLog, AggregatedSolution,
)
from parsers.parser import detect_and_parse, load_intel_json
from parsers.registry import detect_parser, list_parsers, init_parsers
from services.normalizer import compute_normalized_id
from services.prioritizer import compute_priority_score
from parsers.inventory_extractor import extract_inventory_from_findings, _cn_from_dn
from services.asset_classifier import classify_asset
import services.dedup as dedup_engine
import core.risk_config as risk_engine
import services.campaign_query as cq
import services.tags as tag_engine
import services.rule_engine as rule_engine
import services.workflow_engine as workflow_engine
from services.nlp_search import parse_nlp_query
import services.integrations as integ_module
import services.ownership_inference as ownership_inference
import services.solution_aggregator as solution_aggregator
from core.audit import log_audit, diff as _diff
from core.auth import (
    get_current_user, require_auth, require_role, require_permission,
    get_accessible_org_ids, apply_org_filter, apply_scan_org_filter,
)
from routes.auth_routes import router as auth_router
from routes.threat_intel_routes import router as threat_intel_router
from routes.export import router as export_router
from routes.config_portability import router as config_portability_router
from routes.agent_routes import router as agent_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _apply_sort(q, model, sort_by: str, order: str, default_attr):
    """Apply ORDER BY to a query, falling back to default_attr if sort_by is invalid."""
    col = getattr(model, sort_by, None)
    if col is None:
        col = default_attr
    return q.order_by(desc(col) if order == "desc" else col)


# Mapping from asset dedup key fields → (InventoryComputer field, Asset field(s))
# Used by _resolve_dc_asset_ids to match DC objects to their scanned assets.
_COMPUTER_TO_ASSET_FIELD_MAP = {
    "fqdn":        ("dns_hostname", ["fqdn"]),
    "hostname":    ("computer_name", ["hostname"]),
    "netbios_name": ("computer_name", ["netbios_name"]),
    # "ip" is not present on InventoryComputer — skipped
}


def _resolve_dc_asset_ids(db, scan_id=None, restrict_to_asset_ids=None) -> set:
    """Return IDs of Asset records that ARE Domain Controllers.

    InventoryComputer.asset_id is the SOURCE asset that ran the AD enumeration plugin,
    not the DC itself.  We resolve the actual DC asset by matching computer name/fqdn
    against Asset fields using the same key fields as the asset dedup config.
    """
    # Determine which fields to match on from the dedup config
    dedup_cfg = dedup_engine.load_config()
    key_fields = dedup_cfg.get("assets", {}).get("key_fields", ["ip", "fqdn"])
    match_pairs = [
        _COMPUTER_TO_ASSET_FIELD_MAP[f]
        for f in key_fields
        if f in _COMPUTER_TO_ASSET_FIELD_MAP
    ]
    # Always include hostname as fallback (computer_name ↔ hostname / netbios_name)
    if not any(af[0] == "computer_name" for af in match_pairs):
        match_pairs.append(("computer_name", ["hostname", "netbios_name"]))

    q = db.query(
        InventoryComputer.scan_id,
        InventoryComputer.computer_name,
        InventoryComputer.dns_hostname,
    ).filter(InventoryComputer.is_domain_controller == True)
    if scan_id:
        q = q.filter(InventoryComputer.scan_id == scan_id)
    elif restrict_to_asset_ids:
        scan_ids = [
            r[0] for r in db.query(Asset.scan_id)
            .filter(Asset.id.in_(restrict_to_asset_ids))
            .distinct().all()
        ]
        if scan_ids:
            q = q.filter(InventoryComputer.scan_id.in_(scan_ids))
    dc_computers = q.all()
    if not dc_computers:
        return set()

    result = set()
    comp_field_map = {"dns_hostname": lambda row: row[2], "computer_name": lambda row: row[1]}
    for dc_row in dc_computers:
        dc_scan_id = dc_row[0]
        conditions = []
        for comp_field, asset_fields in match_pairs:
            val = comp_field_map.get(comp_field, lambda r: None)(dc_row)
            if not val:
                continue
            vl = val.lower()
            for af in asset_fields:
                col = getattr(Asset, af, None)
                if col is not None:
                    conditions.append(func.lower(col) == vl)
        if not conditions:
            continue
        aq = db.query(Asset.id).filter(Asset.scan_id == dc_scan_id, or_(*conditions))
        if restrict_to_asset_ids:
            aq = aq.filter(Asset.id.in_(restrict_to_asset_ids))
        for row in aq.all():
            result.add(row[0])
    return result


# ─── Server Role Detection ────────────────────────────────────────────────────
# Maps role name → service name substrings (matched against service_name + display_name)
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

    # Service-based role detection
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

    # InventoryDatabaseInstance → database role
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


app = FastAPI(title="Nessus Remediation Platform", version="1.0.0")

_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(threat_intel_router)
app.include_router(export_router)
app.include_router(config_portability_router)
app.include_router(agent_router)

INTEL_PATH = Path(__file__).parent.parent / "intel.json"


# ─────────────────────────────────────────────────────────
# Audit Log Helper — imported from audit.py
# ─────────────────────────────────────────────────────────


# Maps dedup entity_type → (Model, list_fields, bool_fields) for DB-level dedup
ENTITY_MODEL_MAP: dict = {}  # populated after models are imported (below)


def _deferred_startup():
    """Heavy startup tasks that run in a background thread so the server
    can bind the port and pass Render's port-scan check immediately."""
    import threading
    logger.info("Deferred startup running in background thread: %s", threading.current_thread().name)
    # Start workflow scheduler for cron-based triggers
    from core.database import SessionLocal
    workflow_engine.start_scheduler(SessionLocal)
    logger.info("Workflow scheduler started")
    # Start agent scheduler for cron-based agent runs
    from agents.agent_scheduler import start_scheduler as start_agent_scheduler
    start_agent_scheduler()
    logger.info("Agent scheduler started")
    # Schedule threat intel auto-update every 24 hours
    from threat_intel.intel_updater import update_intel
    from apscheduler.schedulers.background import BackgroundScheduler as _BGScheduler
    from apscheduler.triggers.interval import IntervalTrigger as _IntervalTrigger
    _intel_scheduler = _BGScheduler()
    _intel_scheduler.add_job(update_intel, _IntervalTrigger(hours=24), id="intel_update", replace_existing=True)
    _intel_scheduler.start()
    logger.info("Intel auto-update scheduled (every 24h)")
    # Seed SLA defaults and backfill any scans that have no SLA due dates yet
    try:
        from core.database import SessionLocal as _SL
        _db = _SL()
        try:
            _ensure_sla_defaults(_db)
            _sla_configs = _db.query(SLAConfig).filter(SLAConfig.is_enabled == True).all()
            if _sla_configs:
                # Find scans that have findings without sla_due_date
                scan_ids_needing_sla = (
                    _db.query(Finding.scan_id)
                    .filter(Finding.sla_due_date == None)
                    .distinct()
                    .all()
                )
                scan_id_set = {row[0] for row in scan_ids_needing_sla}
                scans_needing_sla = _db.query(Scan).filter(Scan.id.in_(scan_id_set)).all() if scan_id_set else []
                if scans_needing_sla:
                    all_configs = _db.query(SLAConfig).all()
                    for s in scans_needing_sla:
                        _recalculate_sla_for_scan(_db, s.id, all_configs)
                    logger.info(f"SLA backfilled for {len(scans_needing_sla)} scan(s)")
        finally:
            _db.close()
    except Exception as _e:
        logger.warning(f"SLA startup seeding failed (non-fatal): {_e}")
    logger.info("Deferred startup complete")


@app.on_event("startup")
def startup():
    init_db()
    init_parsers()
    logger.info("Database initialized, parsers registered")
    # Build ENTITY_MODEL_MAP after models are loaded
    ENTITY_MODEL_MAP.update({
        "assets":            (Asset,                    ["inferred_admin_contacts"],  ["is_internet_facing", "is_credentialed"]),
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
        "processes":         (InventoryProcess,          [],                    []),
        "database_instances": (InventoryDatabaseInstance, [],                  ["is_running"]),
        "credentials":        (InventoryCredential,       [],                  []),
    })
    # Run heavy tasks (schedulers, SLA backfill) in background so the port
    # is available immediately for Render's port-scan health check.
    import threading
    threading.Thread(target=_deferred_startup, name="deferred-startup", daemon=True).start()
    logger.info("Startup complete — deferred tasks running in background")


# ─────────────────────────────────────────────
# Temporal Tracking Helpers
# ─────────────────────────────────────────────

def _parse_scan_date(scan) -> datetime:
    """Best-effort parse of scan date for temporal tracking.
    Prefers the scan_date embedded in the file so SLA starts from when
    the scan was actually run, not when it was uploaded."""
    if scan.scan_date:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%b %d, %Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(scan.scan_date, fmt)
            except (ValueError, TypeError):
                continue
    if scan.created_at:
        return scan.created_at
    return datetime.utcnow()


def _populate_temporal_fields(db: Session, scan):
    """Set first_seen, last_seen, times_seen, is_regression for each finding
    in the new scan by looking at historical findings across all other scans."""
    scan_date = _parse_scan_date(scan)

    # Build lookup of current scan findings keyed by (plugin_id, asset_ip)
    new_findings = db.query(Finding, Asset.ip).join(
        Asset, Finding.asset_id == Asset.id
    ).filter(Finding.scan_id == scan.id).all()

    if not new_findings:
        return

    # Build historical map: (plugin_id, ip) → {first_seen, last_seen, times_seen, was_resolved}
    prior_scans = db.query(Scan).filter(Scan.id != scan.id).order_by(Scan.created_at).all()
    if not prior_scans:
        # First scan ever — just set first_seen = last_seen = scan_date
        for f, ip in new_findings:
            f.first_seen = scan_date
            f.last_seen = scan_date
            f.times_seen = 1
        db.flush()
        return

    # Aggregate historical data efficiently
    # Use first_seen/last_seen from prior findings (set from actual scan dates, not upload times)
    from sqlalchemy import and_
    history_rows = db.query(
        Finding.plugin_id, Asset.ip,
        func.min(func.coalesce(Finding.first_seen, Scan.created_at)).label("earliest"),
        func.max(func.coalesce(Finding.last_seen, Scan.created_at)).label("latest"),
        func.count(Finding.id).label("cnt"),
    ).join(Asset, Finding.asset_id == Asset.id).join(
        Scan, Finding.scan_id == Scan.id
    ).filter(Finding.scan_id != scan.id).group_by(
        Finding.plugin_id, Asset.ip
    ).all()

    history = {}
    for row in history_rows:
        key = (row.plugin_id, row.ip or "")
        history[key] = {
            "first_seen": row.earliest,
            "last_seen": row.latest,
            "times_seen": row.cnt,
        }

    # Check for resolved findings that are reappearing (regression detection)
    resolved_keys = set()
    resolved_rows = db.query(Finding.plugin_id, Asset.ip).join(
        Asset, Finding.asset_id == Asset.id
    ).filter(
        Finding.scan_id != scan.id,
        Finding.workflow_status == "resolved",
    ).all()
    for row in resolved_rows:
        resolved_keys.add((row.plugin_id, row.ip or ""))

    for f, ip in new_findings:
        key = (f.plugin_id, ip or "")
        hist = history.get(key)
        if hist:
            f.first_seen = hist["first_seen"]
            f.last_seen = scan_date
            f.times_seen = hist["times_seen"] + 1
            f.is_regression = key in resolved_keys
        else:
            f.first_seen = scan_date
            f.last_seen = scan_date
            f.times_seen = 1
            f.is_regression = False

    db.flush()
    logger.info(f"Temporal tracking: {len(new_findings)} findings processed, "
                f"{sum(1 for f, _ in new_findings if f.is_regression)} regressions detected")


# ─────────────────────────────────────────────
# Delta Reconciliation (auto-resolve fixed findings, asset lifecycle)
# ─────────────────────────────────────────────

# Workflow statuses that analysts set deliberately — never auto-resolve these
_PROTECTED_STATUSES = {"accepted_risk", "false_positive", "compensating_control", "technical_debt"}


def _reconcile_findings_delta(db: Session, scan) -> dict:
    """Auto-resolve findings from prior scans that are absent in the new scan,
    per-asset (matched by IP).  Only considers assets present in BOTH the new
    scan and at least one prior scan — partial scans won't mark unrelated assets.

    Returns dict with delta stats for the upload response."""
    from sqlalchemy import and_

    scan_date = _parse_scan_date(scan)

    # Step 1: IPs in the new scan
    new_assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
    new_scan_ips = {a.ip for a in new_assets if a.ip}
    if not new_scan_ips:
        return {"auto_resolved": 0, "rescanned_assets": 0, "new_assets": 0}

    # Step 2: Which of these IPs existed in prior scans? (same org only)
    org_filter = []
    if scan.org_id:
        org_filter.append(Scan.org_id == scan.org_id)

    prior_asset_ips = {
        row.ip for row in
        db.query(Asset.ip).join(Scan, Asset.scan_id == Scan.id).filter(
            Asset.ip.in_(new_scan_ips),
            Scan.id != scan.id,
            *org_filter,
        ).distinct().all()
    }
    # Only reconcile IPs that were seen before (rescanned assets)
    rescanned_ips = new_scan_ips & prior_asset_ips
    new_ips = new_scan_ips - prior_asset_ips

    if not rescanned_ips:
        # First time seeing all these assets — just set asset lifecycle fields
        _update_asset_lifecycle(db, scan, scan_date, new_scan_ips, prior_asset_ips)
        return {"auto_resolved": 0, "rescanned_assets": 0, "new_assets": len(new_ips)}

    # Step 3: Build set of (plugin_id, ip) present in the new scan
    new_finding_keys = set()
    for plugin_id, ip in db.query(Finding.plugin_id, Asset.ip).join(
        Asset, Finding.asset_id == Asset.id
    ).filter(Finding.scan_id == scan.id).all():
        new_finding_keys.add((plugin_id, ip or ""))

    # Step 4: Find prior open findings for rescanned IPs
    prior_q = db.query(Finding).join(
        Asset, Finding.asset_id == Asset.id
    ).join(
        Scan, Finding.scan_id == Scan.id
    ).filter(
        Finding.scan_id != scan.id,
        Asset.ip.in_(rescanned_ips),
        Finding.auto_resolved == False,
        Finding.severity > 0,  # Skip Info-level
    )
    if scan.org_id:
        prior_q = prior_q.filter(Scan.org_id == scan.org_id)
    # Exclude protected workflow statuses
    prior_q = prior_q.filter(
        ~Finding.workflow_status.in_(_PROTECTED_STATUSES)
    )

    # Eager-load asset IPs to avoid N+1
    prior_findings = prior_q.all()
    # Build asset_id → ip map for these findings
    asset_ids = {f.asset_id for f in prior_findings}
    asset_ip_map = {}
    if asset_ids:
        for a_id, a_ip in db.query(Asset.id, Asset.ip).filter(Asset.id.in_(asset_ids)).all():
            asset_ip_map[a_id] = a_ip or ""

    # Step 5: Auto-resolve findings absent from new scan
    resolved_count = 0
    for f in prior_findings:
        ip = asset_ip_map.get(f.asset_id, "")
        key = (f.plugin_id, ip)
        if key not in new_finding_keys:
            f.auto_resolved = True
            f.auto_resolved_at = scan_date
            f.auto_resolved_by_scan_id = scan.id
            if f.workflow_status in ("open", "in_progress", None):
                f.workflow_status = "resolved"
                f.resolved_at = scan_date
                f.status_changed_at = scan_date
                f.sla_status = "resolved"
            resolved_count += 1

    # Step 6: Update asset lifecycle
    _update_asset_lifecycle(db, scan, scan_date, new_scan_ips, prior_asset_ips)

    db.flush()
    logger.info(f"Delta reconciliation: {resolved_count} findings auto-resolved "
                f"across {len(rescanned_ips)} rescanned assets")

    return {
        "auto_resolved": resolved_count,
        "rescanned_assets": len(rescanned_ips),
        "new_assets": len(new_ips),
    }


def _update_asset_lifecycle(db: Session, scan, scan_date: datetime,
                            new_scan_ips: set, prior_asset_ips: set):
    """Update first_seen/last_seen/status for assets based on the new scan."""

    # Assets in the new scan: set lifecycle fields
    for asset in db.query(Asset).filter(Asset.scan_id == scan.id).all():
        asset.last_seen = scan_date
        asset.asset_status = "active"
        asset.stale_since = None

        if asset.ip and asset.ip in prior_asset_ips:
            # Seen before — pull earliest first_seen from prior assets with same IP
            earliest = db.query(func.min(Asset.first_seen)).filter(
                Asset.ip == asset.ip, Asset.id != asset.id,
                Asset.first_seen.isnot(None),
            ).scalar()
            asset.first_seen = earliest or scan_date
            # Count total scans this IP has appeared in
            prior_count = db.query(func.count(func.distinct(Asset.scan_id))).filter(
                Asset.ip == asset.ip, Asset.scan_id != scan.id,
            ).scalar() or 0
            asset.times_seen = prior_count + 1
        else:
            asset.first_seen = scan_date
            asset.times_seen = 1

    # Prior assets with rescanned IPs that are NOT in the new scan:
    # mark stale if their IP was rescanned but they weren't updated
    # (This covers the case where the same IP was in a prior scan of this org)
    org_filter = []
    if scan.org_id:
        org_filter.append(Scan.org_id == scan.org_id)

    # Mark prior-scan assets for rescanned IPs — update their last_seen
    if prior_asset_ips & new_scan_ips:
        returning_ips = prior_asset_ips & new_scan_ips
        prior_assets = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(
            Asset.ip.in_(returning_ips),
            Asset.scan_id != scan.id,
            *org_filter,
        ).all()
        for pa in prior_assets:
            # Update last_seen on prior records too so queries across scans are consistent
            if not pa.last_seen or scan_date > pa.last_seen:
                pa.last_seen = scan_date

    db.flush()


# ─────────────────────────────────────────────
# Upload & Ingest
# ─────────────────────────────────────────────

@app.post("/api/upload")
async def upload_scan(file: UploadFile = File(...), db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user), x_org_context: Optional[str] = Header(None, alias="X-Org-Context")):
    """Upload and parse a vulnerability scan file (Nessus, Qualys, etc.)."""
    content = await file.read()

    # Detect the appropriate parser via the registry
    source_parser = detect_parser(content, file.filename or "")
    if not source_parser:
        supported = [ext for p in list_parsers() for ext in p["extensions"]]
        raise HTTPException(400, f"Unsupported file type. Accepted: {', '.join(supported)}")

    # Load CVE intel
    intel = load_intel_json(str(INTEL_PATH)) if INTEL_PATH.exists() else {}

    # Parse using the detected parser
    try:
        parsed = source_parser.parse(content, file.filename)
    except Exception as e:
        logger.exception("Parse error")
        raise HTTPException(500, f"Parse error: {e}")

    # Create Scan record with source provenance
    scan_data = parsed["scan"]
    # Use X-Org-Context if set (e.g. superadmin uploading into a specific org)
    effective_org_id = int(x_org_context) if x_org_context else (user.org_id if user else None)
    scan = Scan(
        org_id=effective_org_id,
        filename=file.filename,
        scan_name=scan_data.get("scan_name") or file.filename,
        scan_date=scan_data.get("scan_date"),
        scan_type=scan_data.get("scan_type"),
        scanner_ip=scan_data.get("scanner_ip"),
        nessus_version=scan_data.get("nessus_version"),
        policy_used=scan_data.get("policy_used"),
        # Multi-source provenance
        source_type=source_parser.source_type,
        source_version=scan_data.get("scanner_version") or scan_data.get("nessus_version"),
        raw_metadata=scan_data,
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
                key_mode=asset_dcfg.get("key_mode", "and"),
            )
            if len(parsed_assets) < before:
                logger.info(f"Within-scan asset dedup: {before} → {len(parsed_assets)} assets")

    # Create Asset records
    asset_map = {}  # hostname/ip → Asset (populated with both keys for reliable lookup)
    for asset_data in parsed_assets:
        # Determine criticality: auto-rules if configured, else default 5
        auto_crit = None
        if risk_cfg.get("auto_apply_rules_on_upload"):
            auto_crit = risk_engine.evaluate_criticality_rules(asset_data, risk_cfg)

        ctx = classify_asset(asset_data)
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
            is_credentialed=asset_data.get("is_credentialed", False),
            last_auth_run=asset_data.get("last_auth_run"),
            criticality=auto_crit if auto_crit is not None else 5,
            critical_count=asset_data.get("critical_count", 0),
            high_count=asset_data.get("high_count", 0),
            medium_count=asset_data.get("medium_count", 0),
            low_count=asset_data.get("low_count", 0),
            info_count=asset_data.get("info_count", 0),
            environment_tag=ctx["environment_tag"],
            business_context=ctx["business_context"],
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
        finding_data["asset_os"] = asset.os or ""
        priority_data = compute_priority_score(
            finding_data,
            asset_criticality=asset.criticality,
            intel=intel,
            risk_cfg=risk_cfg,
        )

        finding = Finding(
            scan_id=scan.id,
            asset_id=asset.id,
            # Multi-source provenance
            source_type=source_parser.source_type,
            source_vuln_id=finding_data.get("plugin_id"),
            normalized_id=compute_normalized_id(finding_data),
            # Plugin metadata
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

    # ── Recount severity per asset (covers placeholder assets created mid-loop) ──
    from sqlalchemy import func as sa_func
    sev_counts = (
        db.query(
            Finding.asset_id,
            Finding.severity,
            sa_func.count(Finding.id),
        )
        .filter(Finding.scan_id == scan.id)
        .group_by(Finding.asset_id, Finding.severity)
        .all()
    )
    count_map: dict[int, dict[int, int]] = {}
    for asset_id, sev, cnt in sev_counts:
        count_map.setdefault(asset_id, {})[sev] = cnt
    sev_key = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}
    for asset in asset_map.values():
        counts = count_map.get(asset.id, {})
        asset.critical_count = counts.get(4, 0)
        asset.high_count = counts.get(3, 0)
        asset.medium_count = counts.get(2, 0)
        asset.low_count = counts.get(1, 0)
        asset.info_count = counts.get(0, 0)

    # ── Populate temporal tracking (first_seen / last_seen / regression) ──
    _populate_temporal_fields(db, scan)

    # ── Delta reconciliation: auto-resolve findings fixed since last scan ──
    delta_stats = _reconcile_findings_delta(db, scan)

    # ── Detect internet-facing assets & credentialed scan status via scanner detection plugin ──
    import ipaddress as _ipaddress
    detection_plugin_id = source_parser.get_scanner_detection_plugin()
    plugin_19506_findings = db.query(Finding).filter(
        Finding.scan_id == scan.id, Finding.plugin_id == detection_plugin_id
    ).all() if detection_plugin_id else []
    for f19506 in plugin_19506_findings:
        output = f19506.plugin_output or ""
        asset = db.query(Asset).filter(Asset.id == f19506.asset_id).first()
        if not asset:
            continue
        # Scanner IP & internet-facing detection
        m = re.search(r"Scanner IP\s*:\s*([\d.]+)", output)
        if m:
            scanner_ip = m.group(1)
            asset.scanner_ip = scanner_ip
            try:
                addr = _ipaddress.ip_address(scanner_ip)
                asset.is_internet_facing = not addr.is_private
            except ValueError:
                asset.is_internet_facing = False
        # Credentialed scan detection (from plugin output, supplements XML host property)
        if not asset.is_credentialed:
            cred_m = re.search(r"Credentialed checks\s*:\s*(yes|no)", output, re.IGNORECASE)
            if cred_m and cred_m.group(1).lower() == "yes":
                asset.is_credentialed = True

    db.commit()

    # ── Extract structured inventory from Info-level plugin outputs ──
    # Build a flat list of finding dicts enriched with asset context
    findings_for_inventory = []
    for f in db.query(Finding).filter(Finding.scan_id == scan.id).all():
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

    inventory = extract_inventory_from_findings(
        findings_for_inventory,
        dispatch=source_parser.get_inventory_dispatch(),
    )

    # Apply configurable dedup to inventory records before inserting
    inventory = dedup_engine.dedup_inventory(inventory, dedup_cfg)

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

    # ── Boost criticality for Domain Controllers discovered in inventory ──
    dc_asset_ids = _resolve_dc_asset_ids(db, scan_id=scan.id)
    if dc_asset_ids:
        dc_assets = db.query(Asset).filter(Asset.id.in_(dc_asset_ids)).all()
        for asset in dc_assets:
            if (asset.criticality or 5) < 9:
                asset.criticality = 9
        db.commit()
        logger.info(f"Boosted criticality to 9 (Critical) for {len(dc_assets)} domain controller(s)")

    # ── Recompute asset risk scores using full formula (findings + inventory) ──
    _recompute_risk_for_scan(db, scan.id, risk_cfg)

    # ── Detect security controls from services + software (catalog matching) ──
    try:
        from parsers.inventory_extractor import detect_security_controls_from_inventory
        sc_count = detect_security_controls_from_inventory(db, scan.id)
        if sc_count:
            logger.info(f"Security catalog: {sc_count} controls detected for scan {scan.id}")
    except Exception as e:
        db.rollback()
        logger.warning(f"Security catalog detection failed (non-fatal): {e}")

    # ── Apply auto-tag rules to newly imported scan ──
    tag_results = tag_engine.run_all_auto_tag_rules(db, scan_id=scan.id)
    if tag_results:
        logger.info(f"Auto-tag results: { {k: v for k, v in tag_results.items() if v} }")

    # ── Apply ownership rules to newly imported scan ──
    ownership_results = tag_engine.run_all_ownership_rules(db, scan_id=scan.id)
    if ownership_results:
        logger.info(f"Ownership rule results: { {k: v for k, v in ownership_results.items() if v} }")

    # ── Infer asset ownership from inventory data ──
    own_stats = ownership_inference.infer_asset_ownership(db, scan.id)
    if own_stats["updated"]:
        logger.info(f"Ownership inference: {own_stats}")

    # ── Apply global exceptions to new scan findings ──
    try:
        active_exceptions = db.query(FindingException).filter(FindingException.is_active == True).all()
        exc_applied = 0
        now = datetime.utcnow()
        for exc in active_exceptions:
            if exc.expires_at and exc.expires_at < now:
                exc.is_active = False
                continue
            exc_applied += _apply_exception_to_findings(db, exc, scan_id=scan.id)
        if exc_applied:
            logger.info(f"Applied {exc_applied} global exceptions to new scan")
            db.flush()
    except Exception as e:
        db.rollback()
        logger.warning(f"Exception application failed (non-fatal): {e}")

    # ── Aggregate solutions by root cause ──
    try:
        agg_result = solution_aggregator.aggregate_solutions(db, scan_id=scan.id)
        if agg_result["created"]:
            logger.info(f"Aggregated solutions: {agg_result['created']} groups, {agg_result['findings_linked']} findings linked")
    except Exception as e:
        db.rollback()
        logger.warning(f"Solution aggregation failed (non-fatal): {e}")

    # ── Enrich findings with threat intel (KEV, EPSS, ransomware, trending) ──
    try:
        import threat_intel.threat_intel_sync as _ti_sync
        enrich_result = _ti_sync.enrich_findings_from_threat_intel(db, scan_id=scan.id)
        if enrich_result["enriched"]:
            logger.info(f"Threat intel enrichment: {enrich_result['enriched']} findings enriched")
    except Exception as e:
        db.rollback()
        logger.warning(f"Threat intel enrichment failed (non-fatal): {e}")

    # ── Match findings to MITRE ATT&CK TTPs (keyword + plugin ID + family) ──
    try:
        import threat_intel.ttp_matcher as _ttp_matcher
        ttp_result = _ttp_matcher.match_findings_to_ttps(db, scan_id=scan.id)
        logger.info(f"TTP matching: {ttp_result['matched']} findings matched to ATT&CK techniques")
    except Exception as e:
        db.rollback()
        logger.warning(f"TTP matching failed (non-fatal): {e}")

    # ── Compute SLA due dates for all findings in this scan ──
    try:
        _ensure_sla_defaults(db)
        sla_configs = db.query(SLAConfig).all()
        sla_updated = _recalculate_sla_for_scan(db, scan.id, sla_configs)
        if sla_updated:
            logger.info(f"SLA computed for {sla_updated} findings")
    except Exception as e:
        db.rollback()
        logger.warning(f"SLA computation failed (non-fatal): {e}")

    # ── Cross-scan asset dedup: merge duplicate hosts from prior scans in same org ──
    if dedup_cfg.get("enabled") and dedup_cfg.get("apply_on_upload"):
        asset_dcfg = dedup_cfg.get("assets", {})
        if asset_dcfg.get("enabled") and asset_dcfg.get("scope", "cross_scan") == "cross_scan":
            try:
                cs_result = dedup_engine.run_cross_scan_asset_dedup(
                    db, effective_org_id, dedup_cfg, ENTITY_MODEL_MAP
                )
                if cs_result.get("removed"):
                    logger.info(f"Cross-scan asset dedup: merged {cs_result['removed']} duplicate asset(s)")
            except Exception as e:
                db.rollback()
                logger.warning(f"Cross-scan asset dedup failed (non-fatal): {e}")

    total_findings = len(parsed["findings"])
    total_assets = len(asset_map)
    logger.info(f"Ingested scan '{file.filename}': {total_assets} assets, {total_findings} findings")
    log_audit(db, "create", "scan", scan.id,
              entity_name=scan.scan_name or file.filename,
              changes={"filename": file.filename, "assets": total_assets, "findings": total_findings},
              actor=user)
    db.commit()

    return {
        "scan_id": scan.id,
        "scan_name": scan.scan_name,
        "assets": total_assets,
        "findings": total_findings,
        "delta": delta_stats,
        "message": "Scan uploaded and processed successfully",
    }


# ─────────────────────────────────────────────
# Health check (no auth — used by Render)
# ─────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {"status": "ok"}


# ─────────────────────────────────────────────
# Sources (parser registry)
# ─────────────────────────────────────────────

@app.get("/api/sources")
def get_sources():
    """Return all registered scanner source types and their supported file extensions."""
    return list_parsers()


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scans = q.order_by(desc(Scan.created_at)).all()
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
            "source_type": s.source_type or "nessus",
            "source_version": s.source_version,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "asset_count": asset_count,
            "finding_count": finding_count,
        })
    return result


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    q = apply_org_filter(db.query(Scan), Scan, org_ids)
    scan = q.filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    # Inventory models have no ORM cascade from Scan, so delete them explicitly
    for InvModel in [
        InventoryUser, InventoryGroup, InventoryService, InventoryNetConn,
        InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
        InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
    ]:
        db.query(InvModel).filter(InvModel.scan_id == scan_id).delete(synchronize_session=False)
    # Remove scan comparisons referencing this scan
    db.query(ScanComparison).filter(
        (ScanComparison.base_scan_id == scan_id) | (ScanComparison.compare_scan_id == scan_id)
    ).delete(synchronize_session=False)
    # Delete ownership & campaign rows that reference assets/findings (no ORM cascade)
    asset_subq = db.query(Asset.id).filter(Asset.scan_id == scan_id).scalar_subquery()
    finding_subq = db.query(Finding.id).filter(Finding.asset_id.in_(asset_subq)).scalar_subquery()
    db.query(AssetOwnership).filter(AssetOwnership.asset_id.in_(asset_subq)).delete(synchronize_session=False)
    db.query(FindingOwnership).filter(FindingOwnership.finding_id.in_(finding_subq)).delete(synchronize_session=False)
    db.query(CampaignFinding).filter(CampaignFinding.finding_id.in_(finding_subq)).delete(synchronize_session=False)
    _scan_name = scan.scan_name or scan.filename
    _scan_org = scan.org_id
    db.delete(scan)  # cascades to Asset → Finding → AutomateClick via ORM
    log_audit(db, "delete", "scan", scan_id, entity_name=_scan_name, org_id=_scan_org)
    db.commit()
    return {"message": "Scan deleted"}


# ─────────────────────────────────────────────
# NLP Search
# ─────────────────────────────────────────────

@app.get("/api/search/nlp")
def nlp_search(
    q: str,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Parse a natural language query and return matching asset/finding counts + filter params."""
    parsed = parse_nlp_query(q)

    af = dict(parsed["asset_filters"])
    ff = dict(parsed["finding_filters"])

    # ── Count matching assets ──────────────────────────────────────────────────
    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    if af.get("min_critical") is not None:
        aq = aq.filter(Asset.critical_count >= af["min_critical"])
    if af.get("min_high") is not None:
        aq = aq.filter(Asset.high_count >= af["min_high"])
    if af.get("min_risk") is not None:
        aq = aq.filter(Asset.risk_score >= af["min_risk"])
    if af.get("environment"):
        aq = aq.filter(Asset.environment_tag == af["environment"])
    if af.get("search"):
        from sqlalchemy import or_
        pat = f"%{af['search']}%"
        aq = aq.filter(or_(
            Asset.hostname.ilike(pat), Asset.ip.ilike(pat),
            Asset.fqdn.ilike(pat), Asset.os.ilike(pat),
        ))
    asset_count = aq.count()

    # ── Count matching findings ────────────────────────────────────────────────
    fq = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    fq = apply_scan_org_filter(fq, org_ids)
    if scan_id:
        fq = fq.filter(Finding.scan_id == scan_id)
    if ff.get("severity") is not None:
        fq = fq.filter(Finding.severity == ff["severity"])
    if ff.get("has_exploit"):
        fq = fq.filter(Finding.exploit_available == True)
    if ff.get("is_kev"):
        fq = fq.filter(Finding.is_kev == True)
    if ff.get("ransomware_linked"):
        fq = fq.filter(Finding.ransomware_linked == True)
    if ff.get("trending_in_news"):
        fq = fq.filter(Finding.trending_in_news == True)
    if ff.get("min_epss") is not None:
        fq = fq.filter(Finding.epss_score >= ff["min_epss"])
    if ff.get("effort_level"):
        fq = fq.filter(Finding.effort_level == ff["effort_level"])
    if ff.get("sla_status"):
        fq = fq.filter(Finding.sla_status == ff["sla_status"])
    if ff.get("cve"):
        fq = fq.filter(Finding.cves.ilike(f"%{ff['cve']}%"))
    if ff.get("plugin_family"):
        fq = fq.filter(Finding.plugin_family == ff["plugin_family"])
    if ff.get("min_cvss") is not None:
        fq = fq.filter(
            (Finding.cvss3_base_score >= ff["min_cvss"]) |
            (Finding.cvss2_base_score >= ff["min_cvss"])
        )
    if ff.get("min_priority") is not None:
        fq = fq.filter(Finding.priority_score >= ff["min_priority"])
    if ff.get("port"):
        fq = fq.filter(Finding.port == ff["port"])
    if ff.get("search"):
        fq = fq.filter(
            Finding.plugin_name.ilike(f"%{ff['search']}%") |
            Finding.synopsis.ilike(f"%{ff['search']}%") |
            Finding.plugin_id.ilike(f"%{ff['search']}%")
        )
    finding_count = fq.count()

    return {
        **parsed,
        "asset_count": asset_count,
        "finding_count": finding_count,
    }


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
    server_role: Optional[str] = None,
    asset_status: Optional[str] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    sort_by: str = "risk_score",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    if asset_status:
        q = q.filter(Asset.asset_status == asset_status)
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
    environment_confirmed: Optional[bool] = None,
    business_context: Optional[str] = None,
    business_context_confirmed: Optional[bool] = None,
    biz_num_users: Optional[int] = None,
    biz_revenue_impact: Optional[str] = None,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
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
    db.commit()
    return _asset_to_dict(asset)


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
    }


# ─────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────

@app.get("/api/findings")
def list_findings(
    request: Request,
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    severity: Optional[int] = None,
    plugin_family: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    is_kev: Optional[bool] = None,
    ransomware_linked: Optional[bool] = None,
    trending_in_news: Optional[bool] = None,
    min_epss: Optional[float] = None,
    sla_status: Optional[str] = None,
    effort_level: Optional[str] = None,
    auto_resolved: Optional[bool] = None,
    cve: Optional[str] = None,
    search: Optional[str] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    expand_children: bool = False,
    # ATT&CK / threat-intel filters
    has_ttps: Optional[bool] = None,
    tactic: Optional[str] = None,
    technique_id: Optional[str] = None,
    threat_group_id: Optional[int] = None,
    sort_by: str = "priority_score",
    order: str = "desc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    if is_kev is not None:
        q = q.filter(Finding.is_kev == is_kev)
    if ransomware_linked is not None:
        q = q.filter(Finding.ransomware_linked == ransomware_linked)
    if trending_in_news is not None:
        q = q.filter(Finding.trending_in_news == trending_in_news)
    if min_epss is not None:
        q = q.filter(Finding.epss_score >= min_epss)
    if sla_status:
        q = q.filter(Finding.sla_status == sla_status)
    if request.query_params.get("workflow_status"):
        ws = request.query_params["workflow_status"]
        if ws == "excepted":
            q = q.filter(Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"]))
        else:
            q = q.filter(Finding.workflow_status == ws)
    if request.query_params.get("has_exception") == "true":
        q = q.filter(Finding.exception_id != None)
    elif request.query_params.get("has_exception") == "false":
        q = q.filter(Finding.exception_id == None)
    if effort_level:
        q = q.filter(Finding.effort_level == effort_level)
    if auto_resolved is not None:
        q = q.filter(Finding.auto_resolved == auto_resolved)
    if cve:
        # Partial match within JSON-serialized cves array (case-insensitive)
        q = q.filter(Finding.cves.ilike(f"%{cve}%"))
    if request.query_params.get("port"):
        q = q.filter(Finding.port == request.query_params["port"])
    if request.query_params.get("min_priority"):
        q = q.filter(Finding.priority_score >= float(request.query_params["min_priority"]))
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
    # ATT&CK / threat-intel filters (JSON text search on matched_ttps column)
    if has_ttps is True:
        q = q.filter(Finding.matched_ttps.isnot(None), Finding.matched_ttps != "[]", Finding.matched_ttps != "null")
    elif has_ttps is False:
        q = q.filter(or_(Finding.matched_ttps == None, Finding.matched_ttps == "[]", Finding.matched_ttps == "null"))
    if tactic:
        q = q.filter(Finding.matched_ttps.ilike(f'%"tactic": "{tactic}"%'))
    if technique_id:
        q = q.filter(Finding.matched_ttps.ilike(f'%"{technique_id}"%'))
    if threat_group_id:
        # Resolve TTPs linked to this group, then filter findings with any of those technique_ids
        from models.threat_intel_models import ThreatGroupTTP as _TGTTP, TTP as _TTP
        group_ttps = (
            db.query(_TTP.technique_id)
            .join(_TGTTP, _TTP.id == _TGTTP.ttp_id)
            .filter(_TGTTP.group_id == threat_group_id)
            .all()
        )
        group_technique_ids = [row.technique_id for row in group_ttps]
        if group_technique_ids:
            q = q.filter(or_(*[Finding.matched_ttps.ilike(f'%"{tid}"%') for tid in group_technique_ids]))
        else:
            # Group has no TTPs — return empty
            q = q.filter(False)

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


def _review_status(review_by) -> Optional[str]:
    if not review_by:
        return None
    days_until = (review_by - datetime.utcnow()).days
    if days_until < 0:
        return "overdue"
    elif days_until <= 30:
        return "upcoming"
    return "ok"


def _infer_finding_context(f: Finding, asset: Optional[Asset], db: Session) -> dict:
    """Auto-infer validated context + business context from existing data."""
    inferred = {}

    # ── Reachability ──
    if asset:
        inferred["ctx_reachability"] = "internet_facing" if asset.is_internet_facing else "internal_only"

    # ── Exploitability ──
    if f.exploit_available:
        mat = (f.exploit_maturity or "").lower()
        if mat in ("weaponized", "functional", "high"):
            inferred["ctx_exploitability"] = "easily_exploitable"
        else:
            inferred["ctx_exploitability"] = "requires_conditions"
    elif f.epss_score is not None:
        inferred["ctx_exploitability"] = "easily_exploitable" if f.epss_score >= 0.5 else (
            "requires_conditions" if f.epss_score >= 0.1 else "not_exploitable"
        )
    else:
        inferred["ctx_exploitability"] = "unknown"

    # ── Accessibility ──
    port_str = str(f.port or "")
    public_ports = {"80", "443", "8080", "8443"}
    auth_families = {"Windows", "Databases", "RPC", "SMB"}
    family = f.plugin_family or ""
    if port_str in public_ports:
        inferred["ctx_accessibility"] = "public"
    elif any(af in family for af in auth_families):
        inferred["ctx_accessibility"] = "authenticated_only"
    else:
        inferred["ctx_accessibility"] = "unknown"

    # ── Compensating Control (from exception detail + security controls on asset) ──
    cc_parts = []
    if f.exception_id:
        exc = db.query(FindingException).filter(FindingException.id == f.exception_id).first()
        if exc and exc.compensating_control_detail:
            cc_parts.append(exc.compensating_control_detail)
    if asset:
        controls = db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == asset.id,
            InventorySecurityControl.scan_id == f.scan_id,
            InventorySecurityControl.is_enabled == True,
        ).all()
        if controls:
            lines = []
            for ctrl in controls:
                desc = ctrl.control_type.upper()
                if ctrl.product_name:
                    desc += f": {ctrl.product_name}"
                if ctrl.vendor:
                    desc += f" ({ctrl.vendor})"
                if ctrl.is_up_to_date is False:
                    desc += " [outdated]"
                lines.append(desc)
            cc_parts.append("Active security controls on host: " + "; ".join(lines))
    if cc_parts:
        inferred["ctx_compensating_control"] = "\n".join(cc_parts)

    # ── Business context (from asset-level fields) ──
    if asset:
        if asset.business_context:
            inferred["biz_function"] = asset.business_context
        # No. of Users: use asset.biz_num_users if set, else infer from InventoryLoggedOn
        if asset.biz_num_users is not None:
            inferred["biz_num_users"] = asset.biz_num_users
        else:
            user_count = db.query(InventoryLoggedOn).filter(
                InventoryLoggedOn.asset_id == asset.id,
                InventoryLoggedOn.scan_id == f.scan_id,
            ).count()
            if user_count:
                inferred["biz_num_users"] = user_count
        # Revenue Impact: use asset.biz_revenue_impact if set, else infer from criticality
        if asset.biz_revenue_impact:
            inferred["biz_revenue_impact"] = asset.biz_revenue_impact
        elif asset.criticality:
            c = asset.criticality
            inferred["biz_revenue_impact"] = (
                "critical" if c >= 9 else
                "high" if c >= 7 else
                "medium" if c >= 5 else
                "low" if c >= 3 else
                "none"
            )

    return inferred


def _finding_to_dict(f: Finding, db: Session, include_full: bool = False) -> dict:
    asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
    # Resolve effective owner through the full chain
    resolved = ownership_inference.resolve_finding_owner(f, asset, db)
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
        # Multi-source provenance
        "source_type": f.source_type or "nessus",
        "source_vuln_id": f.source_vuln_id,
        "normalized_id": f.normalized_id,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "risk_factor": f.risk_factor,
        "cvss2_score": f.cvss2_score,
        "cvss3_score": f.cvss3_score,
        "cvss4_score": f.cvss4_score,
        "vpr_score": f.vpr_score,
        "cves": f.cves or [],
        "synopsis": f.synopsis,
        "port": f.port,
        "protocol": f.protocol,
        "vulnerability_state": f.vulnerability_state,
        "exploit_available": f.exploit_available,
        "exploit_maturity": f.exploit_maturity,
        "zero_day": f.zero_day,
        "is_kev": f.is_kev or False,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "ransomware_linked": f.ransomware_linked or False,
        "trending_in_news": f.trending_in_news or False,
        "matched_ttps": f.matched_ttps or [],
        "priority_score": f.priority_score,
        "effort_level": f.effort_level,
        "owner_suggestion": f.owner_suggestion,
        # Resolved ownership (full chain)
        "resolved_owner": resolved,
        # SLA tracking
        "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "sla_status": f.sla_status or "n/a",
        # When the vulnerability was observed (from scanner, not upload time)
        "sla_observed_date": asset.scan_start if asset else None,
        # Workflow status
        "workflow_status": f.workflow_status or "open",
        "workflow_assigned_to": f.workflow_assigned_to,
        "workflow_notes": f.workflow_notes,
        "status_changed_at": f.status_changed_at.isoformat() if f.status_changed_at else None,
        "exception_id": f.exception_id,
        # Aggregated solution
        "aggregated_solution_id": f.aggregated_solution_id,
        # Temporal tracking
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "times_seen": f.times_seen or 1,
        "is_regression": f.is_regression or False,
        # Delta tracking
        "auto_resolved": f.auto_resolved or False,
        "auto_resolved_at": f.auto_resolved_at.isoformat() if f.auto_resolved_at else None,
        "auto_resolved_by_scan_id": f.auto_resolved_by_scan_id,
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
            "cvss4_vector": f.cvss4_vector,
            "plugin_pub_date": f.plugin_pub_date,
            "plugin_mod_date": f.plugin_mod_date,
            "remediation_steps": f.remediation_steps,
        })
        # Validated + Business context (with auto-inference)
        inferred = _infer_finding_context(f, asset, db)
        context = {}
        # Validated context fields — manual override stored on finding
        for field in ["ctx_reachability", "ctx_exploitability", "ctx_accessibility", "ctx_compensating_control"]:
            manual = getattr(f, field)
            auto = inferred.get(field)
            context[field] = {
                "value": manual if manual is not None else auto,
                "source": "manual" if manual is not None else ("inferred" if auto is not None else None),
                "inferred": auto,
            }
        # Business context fields — manual values stored on asset, inference from scan data
        biz_manual_map = {
            "biz_function": asset.business_context if asset else None,
            "biz_num_users": asset.biz_num_users if asset else None,
            "biz_revenue_impact": asset.biz_revenue_impact if asset else None,
        }
        biz_confirmed = bool(asset.business_context_confirmed) if asset else False
        for field in ["biz_function", "biz_num_users", "biz_revenue_impact"]:
            manual = biz_manual_map[field]
            auto = inferred.get(field)
            # For biz_function: manual only if confirmed; otherwise treat as inferred
            if field == "biz_function" and manual and not biz_confirmed:
                context[field] = {"value": manual, "source": "inferred", "inferred": manual}
            elif manual is not None:
                context[field] = {"value": manual, "source": "manual", "inferred": auto}
            else:
                context[field] = {"value": auto, "source": "inferred" if auto is not None else None, "inferred": auto}
        base["context"] = context
        base["asset_id_for_biz"] = f.asset_id  # frontend needs this to PATCH the asset
        # Include aggregated solution summary if present
        if f.aggregated_solution_id:
            agg = db.query(AggregatedSolution).filter(AggregatedSolution.id == f.aggregated_solution_id).first()
            if agg:
                base["aggregated_solution"] = {
                    "id": agg.id,
                    "category": agg.category,
                    "title": agg.title,
                    "description": agg.description,
                    "finding_count": agg.finding_count,
                    "effort_level": agg.effort_level,
                }
        # Include technical debt info if this finding's exception is a tech debt
        if f.exception_id:
            exc = db.query(FindingException).filter(FindingException.id == f.exception_id).first()
            if exc and exc.exception_type == "technical_debt":
                base["technical_debt"] = {
                    "title": exc.plugin_name or f"Technical Debt #{exc.id}",
                    "reason": exc.reason,
                    "debt_category": exc.debt_category,
                    "mitigation_plan": exc.mitigation_plan,
                    "review_by": exc.review_by.isoformat() if exc.review_by else None,
                    "review_status": _review_status(exc.review_by),
                }
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
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return prioritized remediation queue (non-info findings, sorted by priority)."""
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Finding.severity >= min_severity)
    q = apply_scan_org_filter(q, org_ids)
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
def get_summary(scan_id: Optional[int] = None, tags: Optional[str] = None, tag_logic: str = "AND", db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return summary statistics for the dashboard."""
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = apply_scan_org_filter(finding_q, org_ids)

    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        asset_q = tag_engine.apply_asset_tag_filter(asset_q, id_sets, tag_logic, db)
        finding_q = tag_engine.apply_finding_tag_filter(finding_q, id_sets, tag_logic, db)

    total_assets = asset_q.count()
    total_findings = finding_q.count()

    # Exclude findings with active exceptions that have exclude_from_reports=True
    excluded_exception_ids = [
        e.id for e in db.query(FindingException.id).filter(
            FindingException.is_active == True,
            FindingException.exclude_from_reports == True,
        ).all()
    ]
    report_q = finding_q
    if excluded_exception_ids:
        report_q = finding_q.filter(
            or_(Finding.exception_id.is_(None), ~Finding.exception_id.in_(excluded_exception_ids))
        )

    # Severity breakdown (excludes report-excluded exceptions)
    severity_counts = {}
    for sev in range(5):
        severity_counts[sev] = report_q.filter(Finding.severity == sev).count()

    # Top plugin families — derived from report_q (already tag/scan/org/exception filtered)
    filtered_ids_subq = report_q.filter(Finding.severity >= 1).with_entities(Finding.id).subquery()
    family_counts = (
        db.query(Finding.plugin_family, func.count(Finding.id).label("count"))
        .filter(Finding.id.in_(filtered_ids_subq))
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
        effort_counts[effort] = report_q.filter(Finding.effort_level == effort, Finding.severity >= 1).count()

    # Owner breakdown — derived from report_q
    owner_counts = (
        db.query(Finding.owner_suggestion, func.count(Finding.id).label("count"))
        .filter(Finding.id.in_(filtered_ids_subq))
        .group_by(Finding.owner_suggestion)
        .order_by(desc("count"))
        .all()
    )

    # Exploit availability
    exploit_count = report_q.filter(Finding.exploit_available == True).count()
    high_priority_count = report_q.filter(Finding.priority_score >= 7.0).count()

    excepted_count = total_findings - report_q.count() if excluded_exception_ids else 0

    # Quick wins: top 5 critical/high findings with quick_win effort, ordered by priority
    quick_wins_q = (
        report_q.filter(
            Finding.severity >= 3,
            Finding.effort_level == "quick_win",
        )
        .order_by(desc(Finding.priority_score))
        .limit(5)
        .all()
    )
    quick_wins = []
    for f in quick_wins_q:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        quick_wins.append({
            "id": f.id,
            "plugin_name": f.plugin_name,
            "severity": f.severity,
            "priority_score": f.priority_score,
            "solution": (f.solution or "")[:200],
            "host": asset.hostname or asset.ip if asset else "—",
            "asset_id": f.asset_id,
            "plugin_family": f.plugin_family,
        })

    # Coverage / Assessment maturity
    credentialed_count = asset_q.filter(Asset.is_credentialed == True).count()
    with_auth_run = asset_q.filter(Asset.last_auth_run.isnot(None)).count()
    coverage_pct = round((credentialed_count / total_assets) * 100) if total_assets > 0 else 0

    return {
        "total_assets": total_assets,
        "total_findings": total_findings,
        "excepted_findings": excepted_count,
        "coverage": {
            "credentialed_count": credentialed_count,
            "uncredentialed_count": total_assets - credentialed_count,
            "with_auth_run": with_auth_run,
            "coverage_pct": coverage_pct,
        },
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
        "quick_wins": quick_wins,
    }


@app.get("/api/reports/risk-grade")
def get_risk_grade(
    scan_id: Optional[int] = None,
    tags: Optional[str] = None,
    tag_logic: str = "AND",
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute a composite organisation risk grade (0-100 score → A-F letter)."""
    # ── Gather summary data ──
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = apply_scan_org_filter(finding_q, org_ids)
    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        asset_q = tag_engine.apply_asset_tag_filter(asset_q, id_sets, tag_logic, db)
        finding_q = tag_engine.apply_finding_tag_filter(finding_q, id_sets, tag_logic, db)

    total_assets = asset_q.count()
    total_findings = finding_q.count()

    sev_counts = {}
    for sev in range(5):
        sev_counts[sev] = finding_q.filter(Finding.severity == sev).count()
    non_info = max(total_findings - sev_counts.get(0, 0), 1)
    critical = sev_counts.get(4, 0)
    high = sev_counts.get(3, 0)
    exploit_count = finding_q.filter(Finding.exploit_available == True).count()

    credentialed = asset_q.filter(Asset.is_credentialed == True).count()
    coverage_pct = (credentialed / total_assets * 100) if total_assets > 0 else 0

    # ── Gather SLA data ──
    _ensure_sla_defaults(db)
    sla_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    sla_q = apply_scan_org_filter(sla_q, org_ids)
    if scan_id:
        sla_q = sla_q.filter(Finding.scan_id == scan_id)
    enabled_sevs = [c.severity for c in db.query(SLAConfig).filter(SLAConfig.is_enabled == True).all()]
    sla_q = sla_q.filter(Finding.severity.in_(enabled_sevs))
    sla_findings = sla_q.all()

    sla_counts = {"on_track": 0, "at_risk": 0, "breached": 0, "resolved": 0, "n/a": 0}
    cfg_map = {c.severity: c for c in db.query(SLAConfig).all()}
    mttr_vals = []
    for f in sla_findings:
        status = f.sla_status or "n/a"
        sla_counts[status] = sla_counts.get(status, 0) + 1
        if f.resolved_at and f.sla_due_date:
            cfg = cfg_map.get(f.severity)
            if cfg:
                from datetime import timedelta
                obs_date = f.sla_due_date - timedelta(days=cfg.days_to_remediate)
                days = (f.resolved_at - obs_date).total_seconds() / 86400
                if days >= 0:
                    mttr_vals.append(days)

    total_sla = sum(sla_counts[k] for k in ("on_track", "at_risk", "breached", "resolved"))
    compliance_pct = ((sla_counts["on_track"] + sla_counts["resolved"]) / total_sla * 100) if total_sla else 100
    avg_mttr = (sum(mttr_vals) / len(mttr_vals)) if mttr_vals else 0

    # ── Score components (each 0-100, higher = better) ──
    # 1. Severity mix: penalise critical/high ratio
    crit_high_ratio = (critical + high) / non_info if non_info else 0
    severity_score = max(0, 100 - crit_high_ratio * 200)  # 50% crit+high → 0

    # 2. SLA compliance (already 0-100)
    sla_score = compliance_pct

    # 3. Remediation velocity: MTTR < 7d = 100, >90d = 0
    if avg_mttr <= 0:
        velocity_score = 100  # no data or instant
    else:
        velocity_score = max(0, min(100, 100 - (avg_mttr - 7) * (100 / 83)))

    # 4. Assessment coverage (already 0-100)
    coverage_score = coverage_pct

    # 5. Exploit exposure: % of non-info findings that are exploitable
    exploit_ratio = exploit_count / non_info if non_info else 0
    exploit_score = max(0, 100 - exploit_ratio * 300)  # 33% exploitable → 0

    # ── Weighted composite ──
    composite = (
        severity_score * 0.25 +
        sla_score * 0.25 +
        velocity_score * 0.20 +
        coverage_score * 0.15 +
        exploit_score * 0.15
    )
    composite = max(0, min(100, round(composite, 1)))

    # ── Letter grade ──
    if composite >= 90:
        grade, grade_color = "A", "#16a34a"
    elif composite >= 80:
        grade, grade_color = "B", "#65a30d"
    elif composite >= 70:
        grade, grade_color = "C", "#d97706"
    elif composite >= 60:
        grade, grade_color = "D", "#ea580c"
    else:
        grade, grade_color = "F", "#dc2626"

    return {
        "score": composite,
        "grade": grade,
        "grade_color": grade_color,
        "components": {
            "severity_mix": round(severity_score, 1),
            "sla_compliance": round(sla_score, 1),
            "remediation_velocity": round(velocity_score, 1),
            "assessment_coverage": round(coverage_score, 1),
            "exploit_exposure": round(exploit_score, 1),
        },
        "weights": {
            "severity_mix": 0.25,
            "sla_compliance": 0.25,
            "remediation_velocity": 0.20,
            "assessment_coverage": 0.15,
            "exploit_exposure": 0.15,
        },
    }


@app.get("/api/reports/plugin-families")
def get_plugin_families(scan_id: Optional[int] = None, tags: Optional[str] = None, tag_logic: str = "AND", db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return all unique plugin families for filter dropdowns."""
    q = db.query(Finding.plugin_family).join(Scan, Finding.scan_id == Scan.id).distinct()
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if tags:
        pairs = tag_engine.parse_tag_filter(tags)
        id_sets = tag_engine.resolve_tag_ids(pairs, False, db)
        q = tag_engine.apply_finding_tag_filter(q, id_sets, tag_logic, db)
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


@app.get("/api/reports/metrics-timeline")
def get_metrics_timeline(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return per-scan metrics for a configurable timeline widget.
    Each scan gets a snapshot of: severity counts, total findings/assets,
    exploit counts, SLA stats, workflow status breakdown, MTTR, and risk scores."""
    from sqlalchemy import case as sa_case
    scans = apply_org_filter(db.query(Scan), Scan, org_ids).order_by(Scan.created_at).all()
    result = []
    sev_labels = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

    for s in scans:
        findings_q = db.query(Finding).filter(Finding.scan_id == s.id)
        assets_q = db.query(Asset).filter(Asset.scan_id == s.id)

        total_findings = findings_q.count()
        total_assets = assets_q.count()

        # Severity counts
        sev_counts = {}
        for sev in range(5):
            sev_counts[sev_labels[sev]] = findings_q.filter(Finding.severity == sev).count()

        # Exploitable
        exploit_count = findings_q.filter(Finding.exploit_available == True).count()

        # SLA stats
        sla_on_track = findings_q.filter(Finding.sla_status == "on_track").count()
        sla_at_risk = findings_q.filter(Finding.sla_status == "at_risk").count()
        sla_breached = findings_q.filter(Finding.sla_status == "breached").count()
        sla_resolved = findings_q.filter(Finding.sla_status == "resolved").count()
        total_with_sla = sla_on_track + sla_at_risk + sla_breached + sla_resolved
        sla_compliance = round(((sla_on_track + sla_resolved) / total_with_sla * 100) if total_with_sla else 0, 1)

        # Workflow status
        ws_open = findings_q.filter((Finding.workflow_status == "open") | (Finding.workflow_status == None)).count()
        ws_in_progress = findings_q.filter(Finding.workflow_status == "in_progress").count()
        ws_resolved = findings_q.filter(Finding.workflow_status == "resolved").count()
        ws_excepted = findings_q.filter(Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"])).count()
        ws_tech_debt = findings_q.filter(Finding.workflow_status == "technical_debt").count()

        # MTTR for resolved findings in this scan
        resolved_findings = findings_q.filter(Finding.resolved_at != None, Finding.sla_due_date != None).all()
        if resolved_findings:
            mttrs = []
            for f in resolved_findings:
                scan_obj = db.query(Scan).filter(Scan.id == f.scan_id).first()
                if scan_obj and scan_obj.created_at and f.resolved_at:
                    days = (f.resolved_at - scan_obj.created_at).total_seconds() / 86400
                    if days >= 0:
                        mttrs.append(days)
            avg_mttr = round(sum(mttrs) / len(mttrs), 1) if mttrs else None
        else:
            avg_mttr = None

        # Average risk score across assets
        risk_scores = [a.risk_score for a in assets_q.all() if a.risk_score is not None and a.risk_score > 0]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0
        max_risk = round(max(risk_scores), 2) if risk_scores else 0

        # Non-info findings (actionable)
        actionable = total_findings - sev_counts["info"]

        result.append({
            "scan_id": s.id,
            "scan_name": s.scan_name or s.filename,
            "scan_date": s.scan_date or (s.created_at.isoformat() if s.created_at else None),
            # Severity
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
            # Totals
            "total_findings": total_findings,
            "actionable_findings": actionable,
            "total_assets": total_assets,
            "exploit_count": exploit_count,
            # SLA
            "sla_on_track": sla_on_track,
            "sla_at_risk": sla_at_risk,
            "sla_breached": sla_breached,
            "sla_resolved": sla_resolved,
            "sla_compliance_pct": sla_compliance,
            # Workflow
            "workflow_open": ws_open,
            "workflow_in_progress": ws_in_progress,
            "workflow_resolved": ws_resolved,
            "workflow_excepted": ws_excepted,
            "workflow_technical_debt": ws_tech_debt,
            # Risk
            "avg_risk_score": avg_risk,
            "max_risk_score": max_risk,
            # MTTR
            "avg_mttr_days": avg_mttr,
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
    identity_type: Optional[str] = None,
    identity_subtype: Optional[str] = None,
    department: Optional[str] = None,
    has_manager: Optional[bool] = None,
    is_admin: Optional[bool] = None,
    is_domain_admin: Optional[bool] = None,
    is_privileged: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "username",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryUser).join(Scan, InventoryUser.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryUser.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryUser.asset_id == asset_id)
    if user_type:
        q = q.filter(InventoryUser.user_type == user_type)
    if identity_type:
        q = q.filter(InventoryUser.identity_type == identity_type)
    if identity_subtype:
        q = q.filter(InventoryUser.identity_subtype == identity_subtype)
    if department:
        q = q.filter(InventoryUser.department.ilike(f"%{department}%"))
    if has_manager is not None:
        if has_manager:
            q = q.filter(InventoryUser.manager_username.isnot(None))
        else:
            q = q.filter(InventoryUser.manager_username.is_(None))
    if is_admin is not None:
        if is_admin:
            q = q.filter(InventoryUser.is_local_admin == True)
        else:
            # "Non-admin" means not a local admin AND not a domain admin
            q = q.filter(InventoryUser.is_local_admin == False, InventoryUser.is_domain_admin == False)
    if is_domain_admin is not None:
        q = q.filter(InventoryUser.is_domain_admin == is_domain_admin)
    if is_privileged is not None:
        q = q.filter(InventoryUser.is_privileged == is_privileged)
    if search:
        q = q.filter(
            InventoryUser.username.ilike(f"%{search}%") |
            InventoryUser.domain.ilike(f"%{search}%") |
            InventoryUser.department.ilike(f"%{search}%") |
            InventoryUser.job_title.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryUser, sort_by, order, InventoryUser.username)
    total = q.count()
    if page_size == 0:
        users = q.all()
    else:
        users = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {u.asset_id for u in users})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "users": [_inv_user_to_dict(u, assets) for u in users]}


@app.get("/api/inventory/users/org-tree")
def get_user_org_tree(
    scan_id: int,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return a hierarchical org tree built from the manager attribute of human AD users."""
    q = db.query(InventoryUser).join(Scan, InventoryUser.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    q = q.filter(InventoryUser.scan_id == scan_id)
    q = q.filter(InventoryUser.identity_type == "human")
    users = q.all()
    assets = _asset_lookup(db, {u.asset_id for u in users})

    # Build lookup by username (lowercase) for tree construction
    by_name = {}
    for u in users:
        udict = _inv_user_to_dict(u, assets)
        udict["children"] = []
        key = (u.username or "").lower()
        if key not in by_name:
            by_name[key] = udict
        else:
            # Merge source_systems from duplicate
            existing = by_name[key]
            for s in udict.get("source_systems") or []:
                if s not in existing["source_systems"]:
                    existing["source_systems"].append(s)

    # Link children to parents
    roots = []
    for key, node in by_name.items():
        mgr = (node.get("manager_username") or "").lower()
        if mgr and mgr in by_name and mgr != key:
            by_name[mgr]["children"].append(node)
        else:
            roots.append(node)

    return {"roots": roots, "total_users": len(by_name), "total_with_manager": sum(1 for n in by_name.values() if n.get("manager_username"))}


@app.get("/api/inventory/groups")
def list_inventory_groups(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_privileged: Optional[bool] = None,
    sort_by: str = "group_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryGroup).join(Scan, InventoryGroup.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryGroup.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryGroup.asset_id == asset_id)
    if is_privileged is not None:
        q = q.filter(InventoryGroup.is_privileged == is_privileged)
    q = _apply_sort(q, InventoryGroup, sort_by, order, InventoryGroup.group_name)
    total = q.count()
    if page_size == 0:
        groups = q.all()
    else:
        groups = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {g.asset_id for g in groups})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "groups": [_inv_group_to_dict(g, assets) for g in groups]}


@app.get("/api/inventory/services")
def list_inventory_services(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "display_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryService).join(Scan, InventoryService.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    total = q.count()
    if page_size == 0:
        services = q.all()
    else:
        services = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in services})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "services": [{
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
    } for s in services]}


@app.get("/api/inventory/netconns")
def list_inventory_netconns(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "local_port",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryNetConn).join(Scan, InventoryNetConn.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryNetConn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryNetConn.asset_id == asset_id)
    if state:
        q = q.filter(InventoryNetConn.state.ilike(state))
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryNetConn.local_addr.ilike(s),
            InventoryNetConn.remote_addr.ilike(s),
            InventoryNetConn.proto.ilike(s),
        ))
    q = _apply_sort(q, InventoryNetConn, sort_by, order, InventoryNetConn.local_port)
    total = q.count()
    if page_size == 0:
        conns = q.all()
    else:
        conns = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in conns})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "netconns": [{
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
    } for c in conns]}


@app.get("/api/inventory/scheduled-tasks")
def list_inventory_tasks(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    trigger_type: Optional[str] = None,
    sort_by: str = "task_uri",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryScheduledTask).join(Scan, InventoryScheduledTask.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryScheduledTask.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryScheduledTask.asset_id == asset_id)
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryScheduledTask.task_uri.ilike(s),
            InventoryScheduledTask.author.ilike(s),
            InventoryScheduledTask.command.ilike(s),
            InventoryScheduledTask.run_as_user.ilike(s),
        ))
    if trigger_type:
        q = q.filter(InventoryScheduledTask.trigger_type.ilike(trigger_type))
    q = _apply_sort(q, InventoryScheduledTask, sort_by, order, InventoryScheduledTask.task_uri)
    total = q.count()
    if page_size == 0:
        tasks = q.all()
    else:
        tasks = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {t.asset_id for t in tasks})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "tasks": [{
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
    } for t in tasks]}


@app.get("/api/inventory/patches")
def list_inventory_patches(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "vuln_count",
    order: str = "desc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryPatch).join(Scan, InventoryPatch.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryPatch.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryPatch.asset_id == asset_id)
    q = _apply_sort(q, InventoryPatch, sort_by, order, InventoryPatch.vuln_count)
    total = q.count()
    if page_size == 0:
        patches = q.all()
    else:
        patches = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {p.asset_id for p in patches})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "patches": [{
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
    } for p in patches]}


@app.get("/api/inventory/logged-on")
def list_inventory_logged_on(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "username",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryLoggedOn).join(Scan, InventoryLoggedOn.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryLoggedOn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryLoggedOn.asset_id == asset_id)
    q = _apply_sort(q, InventoryLoggedOn, sort_by, order, InventoryLoggedOn.username)
    total = q.count()
    if page_size == 0:
        entries = q.all()
    else:
        entries = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {e.asset_id for e in entries})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "logged_on": [{
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
    } for e in entries]}


@app.get("/api/inventory/summary")
def get_inventory_summary(scan_id: Optional[int] = None, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """
    Cross-entity summary for attack path analysis.
    Returns counts + high-value entities (privileged users, domain admins,
    kerberoastable accounts, lateral movement paths via shared admins, etc.)
    """
    def _q(Model):
        q = db.query(Model).join(Scan, Model.scan_id == Scan.id)
        q = apply_scan_org_filter(q, org_ids)
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
    total_processes = _q(InventoryProcess).count()
    total_certs = _q(InventoryCertificate).count()
    total_logged_on = _q(InventoryLoggedOn).count()
    total_env_vars = _q(InventoryEnvVar).count()
    total_password_policies = _q(InventoryPasswordPolicy).count()
    total_ai_tools = _q(InventoryAITool).count()
    total_credentials = _q(InventoryCredential).count()
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
    admin_map = {}
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
    # Sensitive env vars
    sensitive_env_vars = _q(InventoryEnvVar).filter(InventoryEnvVar.is_sensitive == True).count()
    # Domain controllers
    domain_controllers = _q(InventoryComputer).filter(InventoryComputer.is_domain_controller == True).all()
    # Database servers
    db_instance_count = _q(InventoryDatabaseInstance).count()

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
            "processes": total_processes,
            "logged_on": total_logged_on,
            "env_vars": total_env_vars,
            "password_policies": total_password_policies,
            "ai_tools": total_ai_tools,
            "database_instances": db_instance_count,
            "credentials": total_credentials,
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
            "sensitive_env_vars": sensitive_env_vars,
            "credential_exposures": total_credentials,
            "default_accounts": _q(InventoryCredential).filter(InventoryCredential.credential_type == "default_account").count(),
            "cleartext_credentials": _q(InventoryCredential).filter(InventoryCredential.credential_type == "cleartext").count(),
            "brute_forceable": _q(InventoryCredential).filter(InventoryCredential.credential_type == "brute_forceable").count(),
        },
    }


@app.get("/api/inventory/shares")
def list_inventory_shares(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_writeable: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "share_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryShare).join(Scan, InventoryShare.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryShare.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryShare.asset_id == asset_id)
    if is_writeable is not None:
        q = q.filter(InventoryShare.is_writeable == is_writeable)
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryShare.share_name.ilike(s),
            InventoryShare.comment.ilike(s),
            InventoryShare.path.ilike(s),
        ))
    q = _apply_sort(q, InventoryShare, sort_by, order, InventoryShare.share_name)
    total = q.count()
    if page_size == 0:
        shares = q.all()
    else:
        shares = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in shares})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "shares": [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "share_name": s.share_name, "share_type": s.share_type,
        "comment": s.comment, "path": s.path, "max_users": s.max_users,
        "acl": s.acl or [], "is_writeable": s.is_writeable,
        "is_default_share": s.is_default_share, "source_plugin": s.source_plugin,
    } for s in shares]}


@app.get("/api/inventory/software")
def list_inventory_software(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    category: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventorySoftware).join(Scan, InventorySoftware.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySoftware.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySoftware.asset_id == asset_id)
    if search:
        q = q.filter(InventorySoftware.name.ilike(f"%{search}%"))
    if category:
        if category == "Uncategorized":
            q = q.filter(InventorySoftware.category.is_(None))
        else:
            q = q.filter(InventorySoftware.category == category)
    q = _apply_sort(q, InventorySoftware, sort_by, order, InventorySoftware.name)
    total = q.count()
    if page_size == 0:
        software = q.all()
    else:
        software = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in software})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "software": [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "name": s.name, "version": s.version, "installed_on": s.installed_on,
        "vendor": s.vendor, "category": s.category, "source_plugin": s.source_plugin,
    } for s in software]}


@app.get("/api/inventory/security-controls")
def list_inventory_security_controls(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    control_type: Optional[str] = None,
    sort_by: str = "product_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventorySecurityControl).join(Scan, InventorySecurityControl.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySecurityControl.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySecurityControl.asset_id == asset_id)
    if control_type:
        q = q.filter(InventorySecurityControl.control_type == control_type)
    q = _apply_sort(q, InventorySecurityControl, sort_by, order, InventorySecurityControl.product_name)
    total = q.count()
    if page_size == 0:
        controls = q.all()
    else:
        controls = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in controls})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "controls": [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "control_type": c.control_type, "product_name": c.product_name,
        "vendor": c.vendor, "version": c.version, "is_enabled": c.is_enabled,
        "is_up_to_date": c.is_up_to_date, "signature_date": c.signature_date,
        "details": c.details or {}, "source_plugin": c.source_plugin,
    } for c in controls]}


@app.get("/api/inventory/security-coverage")
def get_security_coverage(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """
    Security control coverage matrix.
    Returns per-category coverage across assets and a per-asset control list.
    """
    from threat_intel.security_tool_catalog import SECURITY_TOOL_CATALOG
    from collections import defaultdict

    # Reverse map: control_type → canonical category name (from catalog)
    CT_TO_CAT = {}
    for _entry in SECURITY_TOOL_CATALOG:
        ct = _entry["control_type"]
        if ct not in CT_TO_CAT:
            CT_TO_CAT[ct] = _entry["category"]

    q = db.query(InventorySecurityControl).join(Scan, InventorySecurityControl.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySecurityControl.scan_id == scan_id)
    controls = q.all()

    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    all_assets = aq.all()
    total_assets = len(all_assets)

    asset_map = {
        a.id: {
            "asset_id": a.id,
            "asset_label": f"{a.ip or ''}" + (f" | {a.hostname}" if a.hostname else ""),
            "asset_ip": a.ip,
            "asset_env": a.environment_tag,
            "controls": [],
        }
        for a in all_assets
    }

    for c in controls:
        if c.asset_id not in asset_map:
            continue
        asset_map[c.asset_id]["controls"].append({
            "product_name": c.product_name,
            "vendor": c.vendor,
            "control_type": c.control_type,
            "category": (c.details or {}).get("category") or CT_TO_CAT.get(c.control_type, c.control_type),
            "is_enabled": c.is_enabled,
            "detection_method": (c.details or {}).get("detection_method", "plugin"),
            "source_plugin": c.source_plugin,
        })

    # Build unique category catalog (preserve insertion order by category first seen)
    CATALOG_CATEGORIES = {}
    for entry in SECURITY_TOOL_CATALOG:
        cat = entry["category"]
        if cat not in CATALOG_CATEGORIES:
            CATALOG_CATEGORIES[cat] = entry["control_type"]

    cat_to_assets = defaultdict(set)
    cat_to_products = defaultdict(set)
    for c in controls:
        cat = (c.details or {}).get("category") or CT_TO_CAT.get(c.control_type, c.control_type)
        cat_to_assets[cat].add(c.asset_id)
        if c.product_name:
            cat_to_products[cat].add(c.product_name)

    categories = []
    for cat, ct in CATALOG_CATEGORIES.items():
        covered = len(cat_to_assets.get(cat, set()))
        categories.append({
            "name": cat,
            "control_type": ct,
            "total_assets": total_assets,
            "covered_assets": covered,
            "coverage_pct": round(covered / total_assets * 100, 1) if total_assets else 0,
            "products": sorted(cat_to_products.get(cat, set())),
        })
    categories.sort(key=lambda x: x["coverage_pct"])

    if total_assets:
        per_asset_pct = [
            len({ctrl["category"] for ctrl in a["controls"]}) / len(CATALOG_CATEGORIES) * 100
            for a in asset_map.values()
        ]
        avg_coverage = round(sum(per_asset_pct) / len(per_asset_pct), 1)
    else:
        avg_coverage = 0.0

    missing_categories = [c["name"] for c in categories if c["covered_assets"] == 0]

    return {
        "categories": categories,
        "assets": sorted(asset_map.values(), key=lambda a: (a["asset_ip"] or "")),
        "summary": {
            "total_assets": total_assets,
            "avg_coverage_pct": avg_coverage,
            "total_categories": len(CATALOG_CATEGORIES),
            "categories_with_coverage": len([c for c in categories if c["covered_assets"] > 0]),
            "missing_categories": missing_categories,
        },
    }


@app.post("/api/scans/{scan_id}/detect-security-controls")
def rerun_security_control_detection(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Re-run catalog-based security control detection for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.query(InventorySecurityControl).filter(
        InventorySecurityControl.scan_id == scan_id,
        InventorySecurityControl.source_plugin == "catalog",
    ).delete(synchronize_session=False)
    db.commit()
    from parsers.inventory_extractor import detect_security_controls_from_inventory
    count = detect_security_controls_from_inventory(db, scan_id)
    return {"scan_id": scan_id, "detected": count}


@app.get("/api/inventory/computers")
def list_inventory_computers(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_dc: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "computer_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryComputer).join(Scan, InventoryComputer.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    total = q.count()
    if page_size == 0:
        computers = q.all()
    else:
        computers = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in computers})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "computers": [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "computer_name": c.computer_name, "dns_hostname": c.dns_hostname,
        "os": c.os, "os_version": c.os_version, "sid": c.sid, "dn": c.dn,
        "is_domain_controller": c.is_domain_controller, "is_disabled": c.is_disabled,
        "uac": c.uac, "date_joined": c.date_joined, "source_plugin": c.source_plugin,
    } for c in computers]}


@app.get("/api/inventory/password-policies")
def list_inventory_password_policies(
    scan_id: Optional[int] = None,
    sort_by: str = "domain",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryPasswordPolicy).join(Scan, InventoryPasswordPolicy.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryPasswordPolicy.scan_id == scan_id)
    q = _apply_sort(q, InventoryPasswordPolicy, sort_by, order, InventoryPasswordPolicy.domain)
    total = q.count()
    if page_size == 0:
        policies = q.all()
    else:
        policies = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {p.asset_id for p in policies})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "policies": [{
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
    } for p in policies]}


@app.get("/api/inventory/env-vars")
def list_inventory_env_vars(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    scope: Optional[str] = None,
    sensitive_only: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryEnvVar).join(Scan, InventoryEnvVar.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "env_vars": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "name": r.name, "value": r.value, "scope": r.scope,
        "is_sensitive": r.is_sensitive, "source_plugin": r.source_plugin,
    } for r in rows]}


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
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryCertificate).join(Scan, InventoryCertificate.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "certificates": [{
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
    } for r in rows]}


@app.get("/api/inventory/databases")
def list_inventory_databases(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    db_type: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "db_type",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryDatabaseInstance).join(Scan, InventoryDatabaseInstance.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryDatabaseInstance.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryDatabaseInstance.asset_id == asset_id)
    if db_type:
        q = q.filter(InventoryDatabaseInstance.db_type == db_type)
    if search:
        q = q.filter(
            InventoryDatabaseInstance.instance_name.ilike(f"%{search}%") |
            InventoryDatabaseInstance.version.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryDatabaseInstance, sort_by, order, InventoryDatabaseInstance.db_type)
    total = q.count()
    if page_size == 0:
        instances = q.all()
    else:
        instances = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {i.asset_id for i in instances})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "databases": [{
        "id": i.id, "scan_id": i.scan_id, "asset_id": i.asset_id,
        "asset_label": _asset_label(assets.get(i.asset_id)),
        "asset_ip": (assets.get(i.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(i.asset_id) or {}).get("environment_tag"),
        "db_type": i.db_type, "instance_name": i.instance_name,
        "version": i.version, "port": i.port,
        "databases": i.databases or [], "named_pipes": i.named_pipes or [],
        "is_running": i.is_running, "source_plugin": i.source_plugin,
    } for i in instances]}


@app.get("/api/inventory/domain-trusts")
def list_inventory_domain_trusts(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    trust_direction: Optional[str] = None,
    sort_by: str = "trusted_domain",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryDomainTrust).join(Scan, InventoryDomainTrust.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryDomainTrust.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryDomainTrust.asset_id == asset_id)
    if trust_direction:
        q = q.filter(InventoryDomainTrust.trust_direction == trust_direction)
    q = _apply_sort(q, InventoryDomainTrust, sort_by, order, InventoryDomainTrust.trusted_domain)
    total = q.count()
    if page_size == 0:
        trusts = q.all()
    else:
        trusts = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {t.asset_id for t in trusts})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "domain_trusts": [{
        "id": t.id, "scan_id": t.scan_id, "asset_id": t.asset_id,
        "asset_label": _asset_label(assets.get(t.asset_id)),
        "asset_ip": (assets.get(t.asset_id) or {}).get("ip"),
        "trusted_domain": t.trusted_domain, "flat_name": t.flat_name,
        "sid": t.sid, "dn": t.dn,
        "trust_direction": t.trust_direction, "trust_type": t.trust_type,
        "trust_attributes": t.trust_attributes,
        "is_transitive": t.is_transitive, "is_sid_filtering_enabled": t.is_sid_filtering_enabled,
        "source_domain": t.source_domain, "when_created": t.when_created,
        "source_plugin": t.source_plugin,
    } for t in trusts]}


@app.get("/api/inventory/ai-tools")
def list_inventory_ai_tools(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "tool_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryAITool).join(Scan, InventoryAITool.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryAITool.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryAITool.asset_id == asset_id)
    if category:
        q = q.filter(InventoryAITool.category == category)
    if search:
        q = q.filter(InventoryAITool.tool_name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventoryAITool, sort_by, order, InventoryAITool.tool_name)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "ai_tools": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "tool_name": r.tool_name, "category": r.category,
        "source_plugin": r.source_plugin,
    } for r in rows]}


@app.get("/api/inventory/credentials")
def list_inventory_credentials(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    credential_type: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity",
    order: str = "desc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryCredential).join(Scan, InventoryCredential.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryCredential.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryCredential.asset_id == asset_id)
    if credential_type:
        q = q.filter(InventoryCredential.credential_type == credential_type)
    if protocol:
        q = q.filter(InventoryCredential.protocol == protocol)
    if severity:
        q = q.filter(InventoryCredential.severity == severity)
    if search:
        q = q.filter(
            InventoryCredential.plugin_name.ilike(f"%{search}%") |
            InventoryCredential.username.ilike(f"%{search}%") |
            InventoryCredential.protocol.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryCredential, sort_by, order, InventoryCredential.severity)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "credentials": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "credential_type": r.credential_type, "protocol": r.protocol,
        "username": r.username, "severity": r.severity, "port": r.port,
        "description": r.description, "plugin_name": r.plugin_name,
        "source_plugin": r.source_plugin, "remediation": r.remediation,
    } for r in rows]}


@app.get("/api/inventory/processes")
def list_inventory_processes(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    session_id: Optional[int] = None,
    sort_by: str = "process_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(InventoryProcess).join(Scan, InventoryProcess.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryProcess.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryProcess.asset_id == asset_id)
    if session_id is not None:
        q = q.filter(InventoryProcess.session_id == session_id)
    if search:
        q = q.filter(InventoryProcess.process_name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventoryProcess, sort_by, order, InventoryProcess.process_name)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "processes": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "process_name": r.process_name, "pid": r.pid, "ppid": r.ppid,
        "session_id": r.session_id, "parent_name": r.parent_name,
        "depth": r.depth, "source_plugin": r.source_plugin,
    } for r in rows]}


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
        "identity_type": u.identity_type or "unknown",
        "identity_subtype": u.identity_subtype,
        "source_systems": u.source_systems or [],
        "department": u.department,
        "job_title": u.job_title,
        "manager_dn": u.manager_dn,
        "manager_username": u.manager_username,
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
    # Port-level reachability data
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
    return {
        "has_av":                  av is not None if av is not None else None,
        "has_firewall":            fw is not None if fw is not None else None,
        "established_connections": est_count,
        "listening_ports":         listening_ports,
        "established_ports":       established_ports,
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
        inv_ctx = _get_asset_inventory_context(db, asset.id)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 5,
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

    # Batch-fetch DC asset IDs so we can enforce criticality floor
    dc_asset_ids = _resolve_dc_asset_ids(db, restrict_to_asset_ids=asset_ids) if asset_ids else set()

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
        inv_ctx = _get_asset_inventory_context(db, asset.id)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 5,
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
def set_asset_ownership(asset_id: int, body: OwnershipBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Set or update ownership for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    own = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset_id).first()
    _old_own = {"owner_name": own.owner_name if own else None, "owner_email": own.owner_email if own else None, "owner_role": own.owner_role if own else None, "team": own.team if own else None}
    if not own:
        own = AssetOwnership(asset_id=asset_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    _new_own = {"owner_name": own.owner_name, "owner_email": own.owner_email, "owner_role": own.owner_role, "team": own.team}
    log_audit(db, "update", "asset_ownership", asset_id,
              entity_name=asset.ip or asset.hostname,
              changes=_diff(_old_own, _new_own), actor=user)
    db.commit()
    return {"ok": True, "asset_id": asset_id, "owner_name": own.owner_name}


@app.patch("/api/findings/{finding_id}/ownership")
def set_finding_ownership(finding_id: int, body: OwnershipBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Set or update ownership for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    own = db.query(FindingOwnership).filter(FindingOwnership.finding_id == finding_id).first()
    _old_fown = {"owner_name": own.owner_name if own else None, "owner_role": own.owner_role if own else None, "team": own.team if own else None}
    if not own:
        own = FindingOwnership(finding_id=finding_id)
        db.add(own)
    own.owner_name = body.owner_name
    own.owner_email = body.owner_email
    own.owner_role = body.owner_role
    own.team = body.team
    own.notes = body.notes
    _new_fown = {"owner_name": own.owner_name, "owner_role": own.owner_role, "team": own.team}
    log_audit(db, "update", "finding_ownership", finding_id,
              entity_name=finding.plugin_name,
              changes=_diff(_old_fown, _new_fown), actor=user)
    db.commit()
    return {"ok": True, "finding_id": finding_id, "owner_name": own.owner_name}


@app.post("/api/scans/{scan_id}/infer-ownership")
def rerun_ownership_inference(scan_id: int, db: Session = Depends(get_db)):
    """Re-run ownership inference for a scan (e.g. after inventory update)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    stats = ownership_inference.infer_asset_ownership(db, scan_id)
    return stats


@app.post("/api/assets/{asset_id}/confirm-owner")
def confirm_inferred_owner(asset_id: int, db: Session = Depends(get_db)):
    """Promote inferred ownership to a manual AssetOwnership record."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    if not asset.inferred_primary_user and not asset.inferred_team:
        raise HTTPException(400, "No inferred ownership to confirm")

    own = db.query(AssetOwnership).filter(AssetOwnership.asset_id == asset_id).first()
    if not own:
        own = AssetOwnership(asset_id=asset_id)
        db.add(own)
    own.owner_name = own.owner_name or asset.inferred_primary_user
    own.owner_role = own.owner_role or asset.inferred_team
    own.team = own.team or asset.inferred_team
    db.commit()
    return {"ok": True, "asset_id": asset_id, "owner_name": own.owner_name, "owner_role": own.owner_role}


@app.get("/api/scans/{scan_id}/ownership-summary")
def get_ownership_summary(scan_id: int, db: Session = Depends(get_db)):
    """Summary of ownership coverage for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    total = len(assets)
    manual = 0
    inferred_high = 0
    inferred_medium = 0
    inferred_low = 0
    team_counts = {}

    for a in assets:
        own = a.ownership[0] if a.ownership else None
        if own and (own.owner_name or own.owner_role):
            manual += 1
            team = own.team or own.owner_role or "Unknown"
        elif a.inferred_team or a.inferred_primary_user:
            conf = a.owner_confidence or "low"
            if conf == "high":
                inferred_high += 1
            elif conf == "medium":
                inferred_medium += 1
            else:
                inferred_low += 1
            team = a.inferred_team or "Unknown"
        else:
            inferred_low += 1
            team = "Unassigned"
        team_counts[team] = team_counts.get(team, 0) + 1

    return {
        "total_assets": total,
        "manual_ownership": manual,
        "inferred_high": inferred_high,
        "inferred_medium": inferred_medium,
        "inferred_low": inferred_low,
        "unassigned": total - manual - inferred_high - inferred_medium,
        "team_breakdown": [{"team": k, "count": v} for k, v in sorted(team_counts.items(), key=lambda x: -x[1])],
    }


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
        "cvss4_score": f.cvss4_score,
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
        "is_kev": f.is_kev or False,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "ransomware_linked": f.ransomware_linked or False,
        "trending_in_news": f.trending_in_news or False,
        "matched_ttps": f.matched_ttps or [],
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
    Group campaign findings by effective owner.
    Resolution: campaign override > finding ownership > asset ownership > inferred > plugin family.
    Returns list of {owner_key, owner_name, owner_role, team, findings[]}.
    """
    groups = {}
    for cf in campaign_findings:
        f = cf.finding
        if f is None:
            continue  # skip orphaned campaign findings whose finding was deleted
        asset = f.asset if f else None

        # Campaign-level override always wins
        if cf.owner_role:
            owner_key = cf.owner_role
            owner_name = cf.owner_name or cf.owner_role
            owner_role = cf.owner_role
            team = cf.team
        elif f:
            # Use the full resolution chain from ownership_inference
            resolved = ownership_inference.resolve_finding_owner(f, asset, None)
            owner_role = resolved["owner_role"] or "Unassigned"
            owner_name = resolved["owner_name"] or owner_role
            owner_key = owner_role
            team = resolved["owner_team"]
        else:
            owner_key = "Unassigned"
            owner_name = "Unassigned"
            owner_role = "Unassigned"
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


class AdvancedSearchBody(BaseModel):
    query: list = []
    query_logic: str = "AND"
    scan_id: Optional[int] = None
    type: str = "finding"   # "finding" | "asset"
    page: int = 1
    page_size: int = 50


@app.post("/api/search/advanced")
def advanced_search(body: AdvancedSearchBody, db: Session = Depends(get_db)):
    """Run a rule-engine query and return findings or assets in table format."""
    results = cq.run_query(db, body.query, body.query_logic, body.scan_id)

    if body.type == "asset":
        asset_ids = [r["asset"].id for r in results]
        tag_map = tag_engine.get_asset_tags(asset_ids, db)
        dc_asset_ids = _resolve_dc_asset_ids(db, restrict_to_asset_ids=asset_ids) if asset_ids else set()
        assets_out = []
        for r in results:
            a = r["asset"]
            d = _asset_to_dict(a)
            d["tags"] = tag_map.get(a.id, [])
            d["is_domain_controller"] = a.id in dc_asset_ids
            assets_out.append(d)
        total = len(assets_out)
        start = (body.page - 1) * body.page_size
        return {"total": total, "page": body.page, "page_size": body.page_size, "assets": assets_out[start:start + body.page_size]}

    # findings mode — flatten all findings from all matched assets
    all_findings = []
    for r in results:
        all_findings.extend(r["findings"])
    # deduplicate (same finding can only appear once since each asset is unique)
    all_findings.sort(key=lambda f: f.priority_score or 0, reverse=True)
    total = len(all_findings)
    start = (body.page - 1) * body.page_size
    page_findings = all_findings[start:start + body.page_size]

    finding_ids = [f.id for f in page_findings]
    tag_map = tag_engine.get_finding_tags(finding_ids, db)
    findings_out = []
    for f in page_findings:
        d = _finding_to_dict(f, db)
        d["tags"] = tag_map.get(f.id, [])
        findings_out.append(d)
    return {"total": total, "page": body.page, "page_size": body.page_size, "findings": findings_out}


@app.post("/api/campaigns")
def create_campaign(body: CampaignCreateBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Create a new remediation campaign."""
    campaign = Campaign(
        org_id=user.org_id if user else None,
        name=body.name,
        description=body.description,
        scan_id=body.scan_id,
        query=body.query,
        query_logic=body.query_logic,
        status="draft",
    )
    db.add(campaign)
    db.flush()
    log_audit(db, "create", "campaign", campaign.id,
              entity_name=campaign.name,
              changes={"name": campaign.name, "description": campaign.description, "status": campaign.status},
              actor=user)
    db.commit()
    db.refresh(campaign)
    return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@app.get("/api/campaigns")
def list_campaigns(scan_id: Optional[int] = None, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """List all campaigns, optionally filtered by scan."""
    q = apply_org_filter(db.query(Campaign), Campaign, org_ids)
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
def update_campaign(campaign_id: int, body: CampaignUpdateBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update campaign metadata or query."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    _old_c = {"name": campaign.name, "status": campaign.status, "description": campaign.description}
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
    _new_c = {"name": campaign.name, "status": campaign.status, "description": campaign.description}
    log_audit(db, "update", "campaign", campaign.id,
              entity_name=campaign.name, changes=_diff(_old_c, _new_c), actor=user)
    db.commit()
    return {"ok": True, "id": campaign.id}


@app.delete("/api/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Delete a campaign and its finding associations."""
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")
    _c_name, _c_org = campaign.name, campaign.org_id
    db.delete(campaign)
    log_audit(db, "delete", "campaign", campaign_id, entity_name=_c_name, actor=user, org_id=_c_org)
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

    # If the referenced scan was deleted, clear the stale scan_id so the query searches all scans
    scan_id = campaign.scan_id
    if scan_id and not db.query(Scan).filter(Scan.id == scan_id).first():
        campaign.scan_id = None
        scan_id = None

    # Run query
    results = cq.run_query(db, campaign.query or [], campaign.query_logic or "AND", scan_id)

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

# AD domain-level groups → grants access to Domain Controllers
_AD_ACCESS_GROUPS = {
    "remote desktop users":       ("rdp_access",   "RDP Access"),
    "administrators":             ("local_admin",   "Admin (AD Group)"),
    "distributed com users":      ("dcom_access",   "DCOM Access"),
    "dcom users":                 ("dcom_access",   "DCOM Access"),
    "power users":                ("power_user",    "Power User"),
    "remote management users":    ("winrm_access",  "WinRM Access"),
    "domain admins":              ("domain_admin",  "Domain Admin"),
    "enterprise admins":          ("domain_admin",  "Enterprise Admin"),
}

# Local Windows groups → grants access to that specific machine
_LOCAL_ACCESS_GROUPS = {
    "administrators":             ("local_admin",   "Local Admin"),
    "remote desktop users":       ("rdp_access",    "RDP Access"),
    "distributed com users":      ("dcom_access",   "DCOM Access"),
    "dcom users":                 ("dcom_access",   "DCOM Access"),
    "power users":                ("power_user",    "Power User"),
    "remote management users":    ("winrm_access",  "WinRM Access"),
}

# Linux/Unix groups → grants access to that specific machine
_LINUX_ACCESS_GROUPS = {
    "sudo":       ("sudo_access",    "Sudo Access"),
    "wheel":      ("sudo_access",    "Sudo Access"),
    "docker":     ("docker_access",  "Docker Access"),
    "sshusers":   ("ssh_access",     "SSH Access"),
    "ssh":        ("ssh_access",     "SSH Access"),
    "adm":        ("admin_read",     "Admin Read"),
}

_LINUX_OS_HINTS = ("linux", "unix", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "bsd")


@app.get("/api/blast-radius/bulk")
def get_blast_radius_bulk(
    scan_id: int = Query(...),
    db: Session = Depends(get_db),
):
    """Compute blast radius scores for ALL assets in a scan in one pass."""
    from sqlalchemy import or_

    all_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    if not all_assets:
        return {}

    asset_map = {a.id: a for a in all_assets}
    ip_to_asset_id = {a.ip: a.id for a in all_assets if a.ip}

    # Pre-fetch all inventory data for this scan in bulk
    all_conns = db.query(InventoryNetConn).filter(
        InventoryNetConn.scan_id == scan_id,
        InventoryNetConn.state.in_(["ESTABLISHED", "established"]),
    ).all()
    conns_by_asset = {}
    for c in all_conns:
        conns_by_asset.setdefault(c.asset_id, []).append(c)

    all_logons = db.query(InventoryLoggedOn).filter(
        InventoryLoggedOn.scan_id == scan_id,
    ).all()
    logons_by_asset = {}
    for lo in all_logons:
        logons_by_asset.setdefault(lo.asset_id, []).append(lo)

    all_priv_users = db.query(InventoryUser).filter(
        InventoryUser.scan_id == scan_id,
        or_(
            InventoryUser.is_domain_admin == True,
            InventoryUser.is_local_admin == True,
            InventoryUser.is_privileged == True,
        ),
    ).all()
    priv_users_by_name = {}
    for u in all_priv_users:
        if u.username:
            priv_users_by_name.setdefault(u.username, []).append(u)

    admin_users = db.query(InventoryUser).filter(
        InventoryUser.scan_id == scan_id,
        or_(
            InventoryUser.is_domain_admin == True,
            InventoryUser.is_local_admin == True,
        ),
    ).all()
    admins_by_asset = {}
    for u in admin_users:
        admins_by_asset.setdefault(u.asset_id, []).append(u)

    dc_asset_ids = _resolve_dc_asset_ids(db, scan_id=scan_id)

    # Pre-fetch group data for group-membership access paths
    all_groups = db.query(InventoryGroup).filter(InventoryGroup.scan_id == scan_id).all()
    groups_by_asset: dict[int, list] = {}
    for g in all_groups:
        groups_by_asset.setdefault(g.asset_id, []).append(g)

    # Pre-fetch all users indexed by username (lowercase) for member resolution
    all_users_scan = db.query(InventoryUser).filter(InventoryUser.scan_id == scan_id).all()
    users_by_name = {}
    for u in all_users_scan:
        if u.username:
            users_by_name.setdefault(u.username.lower(), []).append(u)
    users_by_asset: dict[int, list] = {}
    for u in all_users_scan:
        users_by_asset.setdefault(u.asset_id, []).append(u)

    results = {}

    for asset in all_assets:
        asset_id = asset.id
        reachable = set()
        da_exposed = False
        la_exposed = False
        kerb_exposed = False
        group_access_exposed = False
        seen_users = set()

        # 1. Network connections to other known assets
        for conn in conns_by_asset.get(asset_id, []):
            if conn.remote_addr and conn.remote_addr in ip_to_asset_id:
                dst_id = ip_to_asset_id[conn.remote_addr]
                if dst_id != asset_id:
                    reachable.add(dst_id)

        # 2. Privileged users logged on
        for logon in logons_by_asset.get(asset_id, []):
            if not logon.username:
                continue
            for u in priv_users_by_name.get(logon.username, []):
                if u.id in seen_users:
                    continue
                seen_users.add(u.id)
                if u.is_domain_admin:
                    da_exposed = True
                if u.is_local_admin:
                    la_exposed = True
                if u.spns:
                    kerb_exposed = True

        # 3. Admin accounts on this asset
        for u in admins_by_asset.get(asset_id, []):
            if u.id in seen_users:
                continue
            seen_users.add(u.id)
            if u.is_domain_admin:
                da_exposed = True
                # DA exposes other assets they're on
                for other in priv_users_by_name.get(u.username, []):
                    if other.asset_id != asset_id and other.is_domain_admin:
                        reachable.add(other.asset_id)
            if u.is_local_admin:
                la_exposed = True
            if u.spns:
                kerb_exposed = True

        # 4. AD group memberships → DC access
        # Users on this asset whose member_of includes sensitive AD groups
        cur_os_lower = (asset.os or "").lower()
        is_linux = any(h in cur_os_lower for h in _LINUX_OS_HINTS)
        for u in users_by_asset.get(asset_id, []):
            for group_entry in (u.member_of or []):
                cn = _cn_from_dn(group_entry) if "=" in group_entry else group_entry.strip()
                if "\\" in cn:
                    cn = cn.split("\\", 1)[1]
                cn_lower = cn.lower().strip()
                if cn_lower in _AD_ACCESS_GROUPS:
                    etype, _ = _AD_ACCESS_GROUPS[cn_lower]
                    if etype == "domain_admin":
                        da_exposed = True
                    else:
                        group_access_exposed = True
                    # Access to all DC assets
                    for dc_id in dc_asset_ids:
                        if dc_id != asset_id:
                            reachable.add(dc_id)

        # 5. Local / Linux group membership → access to this asset (affects reachable for
        #    accounts on other assets that are members of groups on this one)
        local_groups_map = _LINUX_ACCESS_GROUPS if is_linux else _LOCAL_ACCESS_GROUPS
        for group in groups_by_asset.get(asset_id, []):
            group_lower = (group.group_name or "").lower().strip()
            if group_lower not in local_groups_map:
                continue
            etype, _ = local_groups_map[group_lower]
            for member_raw in (group.members or []):
                cn = _cn_from_dn(member_raw) if "=" in member_raw else member_raw.strip()
                if "\\" in cn:
                    cn = cn.split("\\", 1)[1]
                if not cn or cn.endswith("$"):
                    continue
                matched = users_by_name.get(cn.lower(), [])
                for mu in matched:
                    if mu.asset_id != asset_id:
                        # This user (from another asset) can reach this asset
                        # We mark this asset as reachable from mu's asset
                        pass  # handled on the other asset's pass
                    if mu.id not in seen_users:
                        seen_users.add(mu.id)
                        if etype == "local_admin":
                            la_exposed = True
                        else:
                            group_access_exposed = True

        dc_reachable = bool(reachable & dc_asset_ids)

        score = min(len(reachable) * 1.5, 5.0)
        if dc_reachable:              score += 3.0
        if da_exposed:                score += 2.0
        elif la_exposed:              score += 1.0
        if kerb_exposed:              score += 1.0
        if group_access_exposed:      score += 0.5
        score = min(round(score, 1), 10.0)

        results[str(asset_id)] = {
            "asset_id": asset_id,
            "score": score,
            "reachable_assets": len(reachable),
            "da_exposed": da_exposed,
            "dc_reachable": dc_reachable,
            "group_access_exposed": group_access_exposed,
        }

    return results


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

    # Pre-compute DC asset IDs for group membership paths
    dc_asset_ids = [a.id for a in all_assets if _asset_dc(a.id)]

    # Pre-index all scan users by username (lowercase) for fast member resolution
    all_scan_users = db.query(InventoryUser).filter(InventoryUser.scan_id == scan_id).all()
    users_by_name_idx = {}
    for u in all_scan_users:
        if u.username:
            users_by_name_idx.setdefault(u.username.lower(), []).append(u)

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

            # 4. AD group memberships → DC access
            # If a user on this asset is member of RDP/DCOM/Admins/etc AD group,
            # they can reach Domain Controllers.
            cur_os_lower = (cur.os or "").lower()
            is_linux = any(h in cur_os_lower for h in _LINUX_OS_HINTS)
            for user in db.query(InventoryUser).filter(
                InventoryUser.asset_id == cur_id,
                InventoryUser.scan_id == scan_id,
            ).all():
                for group_entry in (user.member_of or []):
                    cn = _cn_from_dn(group_entry) if "=" in group_entry else group_entry.strip()
                    if "\\" in cn:
                        cn = cn.split("\\", 1)[1]
                    cn_lower = cn.lower().strip()
                    if cn_lower not in _AD_ACCESS_GROUPS:
                        continue
                    etype, elabel = _AD_ACCESS_GROUPS[cn_lower]
                    unid = f"user-{user.id}"
                    add_node(unid, "user", _user_node_data(user))
                    add_edge(f"e-account-{user.id}-{cur_id}",
                             f"asset-{cur_id}", unid,
                             "credential_exposure", "Has Account")
                    # Create edges to all DC assets
                    for dc_id in dc_asset_ids:
                        dc_asset = asset_map.get(dc_id)
                        if not dc_asset or dc_id == cur_id:
                            continue
                        add_node(f"asset-{dc_id}", "asset", _asset_node_data(dc_asset))
                        add_edge(
                            f"e-grp-dc-{user.id}-{dc_id}-{cn_lower.replace(' ', '_')}",
                            unid, f"asset-{dc_id}",
                            etype, f"{elabel} → DC",
                        )
                        if dc_id not in visited_assets:
                            visited_assets.add(dc_id)
                            next_queue.append(dc_id)

            # 5. Local / Linux group membership → access to this asset
            local_groups_map = _LINUX_ACCESS_GROUPS if is_linux else _LOCAL_ACCESS_GROUPS
            for group in db.query(InventoryGroup).filter(
                InventoryGroup.asset_id == cur_id,
                InventoryGroup.scan_id == scan_id,
            ).all():
                group_lower = (group.group_name or "").lower().strip()
                if group_lower not in local_groups_map:
                    continue
                etype, elabel = local_groups_map[group_lower]
                for member_raw in (group.members or []):
                    cn = _cn_from_dn(member_raw) if "=" in member_raw else member_raw.strip()
                    if "\\" in cn:
                        cn = cn.split("\\", 1)[1]
                    if not cn or cn.endswith("$"):
                        continue  # skip computer accounts
                    for mu in users_by_name_idx.get(cn.lower(), []):
                        munid = f"user-{mu.id}"
                        add_node(munid, "user", _user_node_data(mu))
                        add_edge(
                            f"e-grp-{mu.id}-{cur_id}-{etype}",
                            munid, f"asset-{cur_id}",
                            etype, elabel,
                        )

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

    group_access_edges = [
        e for e in edges
        if e["type"] in ("rdp_access", "dcom_access", "power_user",
                         "winrm_access", "ssh_access", "sudo_access", "docker_access")
    ]
    group_access_exposed = len(group_access_edges) > 0

    score = min(len(reachable_asset_ids) * 1.5, 5.0)
    if dc_reachable:              score += 3.0
    if da_exposed:                score += 2.0
    elif la_exposed:              score += 1.0
    if kerb_exposed:              score += 1.0
    if group_access_exposed:      score += 0.5
    score = min(round(score, 1), 10.0)

    _GROUP_ACCESS_LABELS = {
        "rdp_access":    ("RDP Access",         "high"),
        "dcom_access":   ("DCOM Access",         "medium"),
        "power_user":    ("Power User Access",   "medium"),
        "winrm_access":  ("WinRM Access",        "high"),
        "ssh_access":    ("SSH Access",          "high"),
        "sudo_access":   ("Sudo Access",         "high"),
        "docker_access": ("Docker Escape Risk",  "high"),
        "admin_read":    ("Admin Read Access",   "medium"),
    }

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
        elif e["type"] in _GROUP_ACCESS_LABELS:
            un = nodes.get(e["source"])
            ta = nodes.get(e["target"])
            if un and ta:
                alabel, aseverity = _GROUP_ACCESS_LABELS[e["type"]]
                vectors.append({
                    "type": e["type"],
                    "label": f"{alabel}: {un['data'].get('username', '?')} → {ta['data'].get('label', '?')}",
                    "severity": aseverity,
                })

    return {
        "asset_id": asset_id,
        "score": score,
        "reachable_assets": len(reachable_asset_ids),
        "privileged_users": len(user_nodes),
        "da_exposed": da_exposed,
        "dc_reachable": dc_reachable,
        "kerberoastable_exposed": kerb_exposed,
        "group_access_exposed": group_access_exposed,
        "vectors": vectors[:15],
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
    tag_id: Optional[int] = None
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
def create_tag(body: TagCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    existing = db.query(Tag).filter(Tag.category == body.category, Tag.value == body.value).first()
    if existing:
        raise HTTPException(409, f"Tag '{body.category}:{body.value}' already exists")
    if body.parent_id:
        parent = db.query(Tag).filter(Tag.id == body.parent_id).first()
        if not parent:
            raise HTTPException(404, "Parent tag not found")
    tag = Tag(
        org_id=user.org_id if user else None,
        category=body.category,
        value=body.value,
        parent_id=body.parent_id,
        color=body.color or "#6366f1",
        description=body.description,
    )
    db.add(tag)
    db.flush()
    log_audit(db, "create", "tag", tag.id,
              entity_name=f"{tag.category}:{tag.value}",
              changes={"category": tag.category, "value": tag.value, "color": tag.color},
              actor=user)
    db.commit()
    db.refresh(tag)
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@app.get("/api/tags")
def list_tags(
    category: Optional[str] = None,
    tree: bool = False,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(Tag), Tag, org_ids)
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
def update_tag(tag_id: int, body: TagUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    _old_tag = {"category": tag.category, "value": tag.value, "color": tag.color}
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
    _new_tag = {"category": tag.category, "value": tag.value, "color": tag.color}
    log_audit(db, "update", "tag", tag_id,
              entity_name=f"{tag.category}:{tag.value}",
              changes=_diff(_old_tag, _new_tag), actor=user)
    db.commit()
    return tag_engine._tag_to_dict(tag, db=db, include_counts=True)


@app.delete("/api/tags/{tag_id}")
def delete_tag(
    tag_id: int,
    strategy: str = "reparent",  # "reparent" | "cascade"
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_current_user),
):
    tag = db.query(Tag).filter(Tag.id == tag_id).first()
    if not tag:
        raise HTTPException(404, "Tag not found")
    _tag_name = f"{tag.category}:{tag.value}"
    _tag_org = tag.org_id

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
    log_audit(db, "delete", "tag", tag_id, entity_name=_tag_name, actor=user, org_id=_tag_org)
    db.commit()
    return {"message": "Tag deleted", "strategy": strategy}


@app.post("/api/tags/assign")
def assign_tags(body: TagAssignBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    from core.auth import has_tag_permission
    assigned = 0
    for tag_id in (body.tag_ids or []):
        tag = db.query(Tag).filter(Tag.id == tag_id).first()
        if not tag:
            continue
        if user and not has_tag_permission(user, tag_id, "write", db):
            raise HTTPException(status_code=403, detail=f"No write permission on tag '{tag.category}:{tag.value}'")
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
def unassign_tags(body: TagAssignBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    from core.auth import has_tag_permission
    removed = 0
    for tag_id in (body.tag_ids or []):
        if user and not has_tag_permission(user, tag_id, "write", db):
            tag = db.query(Tag).filter(Tag.id == tag_id).first()
            label = f"{tag.category}:{tag.value}" if tag else str(tag_id)
            raise HTTPException(status_code=403, detail=f"No write permission on tag '{label}'")
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
def list_auto_tag_rules(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    rules = db.query(AutoTagRule).order_by(AutoTagRule.id).all()
    return [_rule_to_dict(r) for r in rules]


@app.post("/api/auto-tag-rules")
def create_auto_tag_rule(body: AutoTagRuleCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    is_passthrough = any(c.get("op") == "passthrough" for c in (body.conditions or []))
    if body.tag_id is not None:
        tag = db.query(Tag).filter(Tag.id == body.tag_id).first()
        if not tag:
            raise HTTPException(404, "Tag not found")
    elif not is_passthrough:
        raise HTTPException(400, "tag_id is required for non-passthrough rules")
    rule = AutoTagRule(
        org_id=user.org_id if user else None,
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


@app.post("/api/auto-tag-rules/run-all")
def run_all_auto_tag_rules_endpoint(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    results = tag_engine.run_all_auto_tag_rules(db, scan_id=scan_id)
    return {"results": results, "total_tagged": sum(results.values())}


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
# Ownership Rules
# ─────────────────────────────────────────────

class OwnershipRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_type: str = "asset"
    conditions: list = []
    condition_logic: str = "AND"
    priority: int = 100
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    overwrite_existing: bool = False
    is_enabled: bool = True


class OwnershipRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    target_type: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    priority: Optional[int] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    owner_role: Optional[str] = None
    team: Optional[str] = None
    notes: Optional[str] = None
    overwrite_existing: Optional[bool] = None
    is_enabled: Optional[bool] = None


def _ownership_rule_to_dict(rule: OwnershipRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "target_type": rule.target_type,
        "conditions": rule_engine.migrate_conditions(rule.conditions or [], mode="autotag"),
        "condition_logic": rule.condition_logic,
        "priority": rule.priority,
        "owner_name": rule.owner_name,
        "owner_email": rule.owner_email,
        "owner_role": rule.owner_role,
        "team": rule.team,
        "notes": rule.notes,
        "overwrite_existing": rule.overwrite_existing,
        "is_enabled": rule.is_enabled,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "last_run_at": rule.last_run_at.isoformat() if rule.last_run_at else None,
        "last_run_count": rule.last_run_count,
    }


@app.get("/api/ownership-rules")
def list_ownership_rules(db: Session = Depends(get_db)):
    rules = db.query(OwnershipRule).order_by(OwnershipRule.priority, OwnershipRule.id).all()
    return [_ownership_rule_to_dict(r) for r in rules]


@app.post("/api/ownership-rules")
def create_ownership_rule(body: OwnershipRuleCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    rule = OwnershipRule(
        org_id=user.org_id if user else None,
        name=body.name,
        description=body.description,
        target_type=body.target_type,
        conditions=body.conditions,
        condition_logic=body.condition_logic,
        priority=body.priority,
        owner_name=body.owner_name,
        owner_email=body.owner_email,
        owner_role=body.owner_role,
        team=body.team,
        notes=body.notes,
        overwrite_existing=body.overwrite_existing,
        is_enabled=body.is_enabled,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _ownership_rule_to_dict(rule)


@app.patch("/api/ownership-rules/{rule_id}")
def update_ownership_rule(rule_id: int, body: OwnershipRuleUpdate, db: Session = Depends(get_db)):
    rule = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field in ("name", "description", "target_type", "conditions", "condition_logic",
                  "priority", "owner_name", "owner_email", "owner_role", "team",
                  "notes", "overwrite_existing", "is_enabled"):
        val = getattr(body, field)
        if val is not None:
            setattr(rule, field, val)
    db.commit()
    return _ownership_rule_to_dict(rule)


@app.delete("/api/ownership-rules/{rule_id}")
def delete_ownership_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    db.delete(rule)
    db.commit()
    return {"message": "Rule deleted"}


@app.post("/api/ownership-rules/{rule_id}/run")
def run_ownership_rule_endpoint(
    rule_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    rule = db.query(OwnershipRule).filter(OwnershipRule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    count = tag_engine.run_ownership_rule(rule, db, scan_id=scan_id)
    return {"updated": count, "rule_id": rule_id}


@app.post("/api/ownership-rules/run-all")
def run_all_ownership_rules_endpoint(
    scan_id: Optional[int] = None,
    overwrite: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    results = tag_engine.run_all_ownership_rules(db, scan_id=scan_id, overwrite=overwrite)
    return {"results": results, "total_updated": sum(results.values())}


# ─────────────────────────────────────────────
# External Tag Sources
# ─────────────────────────────────────────────

class ExternalTagSourceCreate(BaseModel):
    name: str
    source_type: str = "csv"          # csv | servicenow | api
    match_field: str = "any"          # ip | hostname | fqdn | any
    api_url: Optional[str] = None
    api_config: dict = {}
    auto_create_tags: bool = True


class ExternalTagSourceUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    match_field: Optional[str] = None
    api_url: Optional[str] = None
    api_config: Optional[dict] = None
    auto_create_tags: Optional[bool] = None


class ExternalTagMapCreate(BaseModel):
    external_tag: str
    internal_tag_id: Optional[int] = None   # null = auto-create from external_tag string


class ExternalTagMapUpdate(BaseModel):
    external_tag: Optional[str] = None
    internal_tag_id: Optional[int] = None


def _ext_source_to_dict(src: ExternalTagSource) -> dict:
    return {
        "id": src.id,
        "name": src.name,
        "source_type": src.source_type,
        "match_field": src.match_field,
        "api_url": src.api_url,
        "api_config": {k: v for k, v in (src.api_config or {}).items() if k not in ("password", "token")},
        "auto_create_tags": src.auto_create_tags,
        "created_at": src.created_at.isoformat() if src.created_at else None,
        "last_synced_at": src.last_synced_at.isoformat() if src.last_synced_at else None,
        "last_sync_count": src.last_sync_count,
        "last_sync_error": src.last_sync_error,
        "maps": [
            {
                "id": m.id,
                "external_tag": m.external_tag,
                "internal_tag_id": m.internal_tag_id,
                "internal_tag_label": f"{m.internal_tag.category}:{m.internal_tag.value}" if m.internal_tag else None,
                "internal_tag_color": m.internal_tag.color if m.internal_tag else None,
            }
            for m in (src.maps or [])
        ],
    }


@app.get("/api/external-tag-sources")
def list_external_tag_sources(db: Session = Depends(get_db)):
    sources = db.query(ExternalTagSource).order_by(ExternalTagSource.id).all()
    return [_ext_source_to_dict(s) for s in sources]


@app.post("/api/external-tag-sources")
def create_external_tag_source(body: ExternalTagSourceCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    src = ExternalTagSource(
        org_id=user.org_id if user else None,
        name=body.name,
        source_type=body.source_type,
        match_field=body.match_field,
        api_url=body.api_url,
        api_config=body.api_config,
        auto_create_tags=body.auto_create_tags,
    )
    db.add(src)
    db.commit()
    db.refresh(src)
    return _ext_source_to_dict(src)


@app.patch("/api/external-tag-sources/{source_id}")
def update_external_tag_source(source_id: int, body: ExternalTagSourceUpdate, db: Session = Depends(get_db)):
    src = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id).first()
    if not src:
        raise HTTPException(404, "Source not found")
    for field in ("name", "source_type", "match_field", "api_url", "api_config", "auto_create_tags"):
        val = getattr(body, field)
        if val is not None:
            setattr(src, field, val)
    db.commit()
    return _ext_source_to_dict(src)


@app.delete("/api/external-tag-sources/{source_id}")
def delete_external_tag_source(source_id: int, db: Session = Depends(get_db)):
    src = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id).first()
    if not src:
        raise HTTPException(404, "Source not found")
    db.delete(src)
    db.commit()
    return {"message": "Deleted"}


# ── Tag maps per source ───────────────────────────────────

@app.post("/api/external-tag-sources/{source_id}/maps")
def upsert_external_tag_map(source_id: int, body: ExternalTagMapCreate, db: Session = Depends(get_db)):
    src = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id).first()
    if not src:
        raise HTTPException(404, "Source not found")
    if body.internal_tag_id:
        if not db.query(Tag).filter(Tag.id == body.internal_tag_id).first():
            raise HTTPException(404, "Internal tag not found")
    existing = db.query(ExternalTagMap).filter(
        ExternalTagMap.source_id == source_id,
        ExternalTagMap.external_tag == body.external_tag,
    ).first()
    if existing:
        existing.internal_tag_id = body.internal_tag_id
    else:
        existing = ExternalTagMap(source_id=source_id, external_tag=body.external_tag, internal_tag_id=body.internal_tag_id)
        db.add(existing)
    db.commit()
    db.refresh(existing)
    tag = db.query(Tag).filter(Tag.id == existing.internal_tag_id).first() if existing.internal_tag_id else None
    return {
        "id": existing.id,
        "external_tag": existing.external_tag,
        "internal_tag_id": existing.internal_tag_id,
        "internal_tag_label": f"{tag.category}:{tag.value}" if tag else None,
        "internal_tag_color": tag.color if tag else None,
    }


@app.delete("/api/external-tag-sources/{source_id}/maps/{map_id}")
def delete_external_tag_map(source_id: int, map_id: int, db: Session = Depends(get_db)):
    m = db.query(ExternalTagMap).filter(ExternalTagMap.id == map_id, ExternalTagMap.source_id == source_id).first()
    if not m:
        raise HTTPException(404, "Map not found")
    db.delete(m)
    db.commit()
    return {"message": "Deleted"}


# ── Import / Sync ─────────────────────────────────────────

@app.post("/api/external-tag-sources/{source_id}/import")
async def import_external_tags(
    source_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a CSV file to apply external tags. Expected columns: identifier, tags."""
    src = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id).first()
    if not src:
        raise HTTPException(404, "Source not found")
    try:
        content = (await file.read()).decode("utf-8-sig")  # strip BOM
        rows = tag_engine.parse_csv_rows(content)
        stats = tag_engine.apply_external_tags(src, rows, db)
        return stats
    except Exception as e:
        src.last_sync_error = str(e)
        db.commit()
        raise HTTPException(400, f"Import failed: {e}")


@app.post("/api/external-tag-sources/{source_id}/sync")
def sync_external_tag_source(source_id: int, db: Session = Depends(get_db)):
    """Pull tags from a remote API source (ServiceNow, etc.) and apply them."""
    src = db.query(ExternalTagSource).filter(ExternalTagSource.id == source_id).first()
    if not src:
        raise HTTPException(404, "Source not found")
    if src.source_type == "servicenow":
        try:
            stats = tag_engine.sync_servicenow_source(src, db)
            return stats
        except Exception as e:
            src.last_sync_error = str(e)
            db.commit()
            raise HTTPException(400, f"Sync failed: {e}")
    raise HTTPException(400, f"API sync not supported for source type '{src.source_type}'. Use /import for CSV.")


# ─────────────────────────────────────────────
# SLA Tracking
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
def get_sla_config(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return SLA configuration for all severity levels."""
    _ensure_sla_defaults(db)
    rows = apply_org_filter(db.query(SLAConfig), SLAConfig, org_ids).order_by(SLAConfig.severity.desc()).all()
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
def save_sla_config(body: SLAConfigUpdateBody, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Save SLA configuration and trigger recalculation for all scans."""
    _ensure_sla_defaults(db)
    _sev_labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    for item in body.configs:
        sev = item.get("severity")
        row = db.query(SLAConfig).filter(SLAConfig.severity == sev).first()
        if not row:
            continue
        _old = {"days_to_remediate": row.days_to_remediate, "warn_days_before": row.warn_days_before, "is_enabled": row.is_enabled}
        if "days_to_remediate" in item:
            row.days_to_remediate = int(item["days_to_remediate"])
        if "warn_days_before" in item:
            row.warn_days_before = int(item["warn_days_before"])
        if "is_enabled" in item:
            row.is_enabled = bool(item["is_enabled"])
        _new = {"days_to_remediate": row.days_to_remediate, "warn_days_before": row.warn_days_before, "is_enabled": row.is_enabled}
        diff = _diff(_old, _new)
        if diff:
            log_audit(db, "update", "sla_config", row.id,
                      entity_name=_sev_labels.get(sev, str(sev)),
                      changes=diff, actor=user)
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
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return SLA compliance stats and MTTR for a scan (or all scans)."""
    _ensure_sla_defaults(db)
    q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
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
def create_workflow(body: WorkflowCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = Workflow(
        org_id=user.org_id if user else None,
        name=body.name,
        description=body.description,
        campaign_id=body.campaign_id,
    )
    db.add(wf)
    db.flush()
    log_audit(db, "create", "workflow", wf.id,
              entity_name=wf.name,
              changes={"name": wf.name, "description": wf.description},
              actor=user)
    db.commit()
    db.refresh(wf)
    return _workflow_to_dict(wf)


@app.get("/api/workflows")
def list_workflows(
    campaign_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(Workflow), Workflow, org_ids).order_by(desc(Workflow.updated_at))
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
def update_workflow(wf_id: int, body: WorkflowUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    _old_wf = {"name": wf.name, "status": wf.status, "is_enabled": wf.is_enabled, "description": wf.description}

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

    # Sync nodes — snapshot current version before overwriting
    if body.nodes is not None or body.edges is not None:
        old_nodes = [_node_to_dict(n) for n in wf.nodes]
        old_edges = [_edge_to_dict(e) for e in wf.edges]
        history = list(wf.version_history or [])
        history.append({
            "version": wf.version or 1,
            "nodes": old_nodes,
            "edges": old_edges,
            "saved_at": datetime.utcnow().isoformat(),
        })
        # Keep last 20 versions
        wf.version_history = history[-20:]
        wf.version = (wf.version or 1) + 1

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

    _new_wf = {"name": wf.name, "status": wf.status, "is_enabled": wf.is_enabled, "description": wf.description}
    log_audit(db, "update", "workflow", wf_id,
              entity_name=wf.name, changes=_diff(_old_wf, _new_wf), actor=user)
    db.commit()
    db.refresh(wf)
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@app.delete("/api/workflows/{wf_id}")
def delete_workflow(wf_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    _wf_name, _wf_org = wf.name, wf.org_id
    db.delete(wf)
    log_audit(db, "delete", "workflow", wf_id, entity_name=_wf_name, actor=user, org_id=_wf_org)
    db.commit()
    return {"message": "Workflow deleted"}


@app.get("/api/workflows/{wf_id}/versions")
def get_workflow_versions(wf_id: int, db: Session = Depends(get_db)):
    """Return version history for a workflow."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return {
        "current_version": getattr(wf, "version", 1) or 1,
        "history": list(getattr(wf, "version_history", None) or []),
    }


@app.post("/api/workflows/{wf_id}/restore/{version}")
def restore_workflow_version(wf_id: int, version: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Restore a workflow to a previous version."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    history = list(getattr(wf, "version_history", None) or [])
    snapshot = next((h for h in history if h.get("version") == version), None)
    if not snapshot:
        raise HTTPException(404, f"Version {version} not found")

    # Snapshot current state before restoring
    old_nodes = [_node_to_dict(n) for n in wf.nodes]
    old_edges = [_edge_to_dict(e) for e in wf.edges]
    history.append({
        "version": wf.version or 1,
        "nodes": old_nodes,
        "edges": old_edges,
        "saved_at": datetime.utcnow().isoformat(),
    })
    wf.version_history = history[-20:]
    wf.version = (wf.version or 1) + 1

    # Replace nodes and edges
    db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf_id).delete(synchronize_session=False)
    for nd in snapshot.get("nodes", []):
        db.add(WorkflowNode(
            workflow_id=wf_id, node_id=nd["node_id"], node_type=nd["node_type"],
            node_subtype=nd["node_subtype"], label=nd.get("label", ""),
            config=nd.get("config", {}),
            position_x=nd.get("position_x", 0), position_y=nd.get("position_y", 0),
        ))
    db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf_id).delete(synchronize_session=False)
    for ed in snapshot.get("edges", []):
        db.add(WorkflowEdge(
            workflow_id=wf_id, edge_id=ed["edge_id"],
            source_node_id=ed["source_node_id"], target_node_id=ed["target_node_id"],
            source_handle=ed.get("source_handle", "output"),
            target_handle=ed.get("target_handle", "input"), label=ed.get("label"),
        ))
    log_audit(db, "update", "workflow", wf_id,
              entity_name=wf.name, changes={"action": "restore", "restored_version": version}, actor=user)
    db.commit()
    db.refresh(wf)
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


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
        "version": getattr(wf, "version", 1) or 1,
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


# ─────────────────────────────────────────────────────────
# Integration Settings (Jira, ServiceNow, Email, Slack, Teams)
# ─────────────────────────────────────────────────────────

INTEGRATION_SCHEMAS = {
    "jira": {
        "display_name": "Jira",
        "fields": [
            {"key": "base_url", "label": "Jira Base URL", "type": "string", "placeholder": "https://yourcompany.atlassian.net"},
            {"key": "email", "label": "Email", "type": "string", "placeholder": "user@company.com"},
            {"key": "api_token", "label": "API Token", "type": "password"},
            {"key": "default_project", "label": "Default Project Key", "type": "string", "placeholder": "SEC"},
        ],
    },
    "servicenow": {
        "display_name": "ServiceNow",
        "fields": [
            {"key": "instance_url", "label": "Instance URL", "type": "string", "placeholder": "https://yourcompany.service-now.com"},
            {"key": "username", "label": "Username", "type": "string"},
            {"key": "password", "label": "Password", "type": "password"},
        ],
    },
    "email": {
        "display_name": "Email (SMTP)",
        "fields": [
            {"key": "smtp_host", "label": "SMTP Host", "type": "string", "placeholder": "smtp.gmail.com"},
            {"key": "smtp_port", "label": "SMTP Port", "type": "number", "placeholder": "587"},
            {"key": "smtp_user", "label": "Username", "type": "string"},
            {"key": "smtp_pass", "label": "Password", "type": "password"},
            {"key": "from_address", "label": "From Address", "type": "string"},
            {"key": "use_tls", "label": "Use TLS", "type": "boolean"},
        ],
    },
    "slack": {
        "display_name": "Slack",
        "fields": [
            {"key": "webhook_url", "label": "Incoming Webhook URL", "type": "string", "placeholder": "https://hooks.slack.com/services/..."},
            {"key": "default_channel", "label": "Default Channel", "type": "string", "placeholder": "#security-alerts"},
        ],
    },
    "teams": {
        "display_name": "Microsoft Teams",
        "fields": [
            {"key": "webhook_url", "label": "Incoming Webhook URL", "type": "string", "placeholder": "https://outlook.office.com/webhook/..."},
        ],
    },
    "anthropic": {
        "display_name": "Anthropic (Claude AI)",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "sk-ant-..."},
            {"key": "default_model", "label": "Default Model", "type": "select", "options": [
                "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001",
            ]},
        ],
    },
    "openai": {
        "display_name": "OpenAI (ChatGPT)",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "sk-..."},
            {"key": "default_model", "label": "Default Model", "type": "select", "options": [
                "gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "o3", "o3-mini", "o4-mini",
            ]},
        ],
    },
    "google_gemini": {
        "display_name": "Google Gemini",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "AIza..."},
            {"key": "default_model", "label": "Default Model", "type": "select", "options": [
                "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash",
            ]},
        ],
    },
    "groq": {
        "display_name": "Groq",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "gsk_..."},
            {"key": "default_model", "label": "Default Model", "type": "select", "options": [
                "llama-3.3-70b-versatile", "llama-3.1-8b-instant", "llama-3.1-70b-versatile",
                "mixtral-8x7b-32768", "gemma2-9b-it",
            ]},
        ],
    },
}


@app.get("/api/integrations")
def list_integrations(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """List all integration providers with their config status."""
    ic_q = apply_org_filter(db.query(IntegrationConfig), IntegrationConfig, org_ids)
    configs = {c.provider: c for c in ic_q.all()}
    result = []
    for provider, schema in INTEGRATION_SCHEMAS.items():
        cfg = configs.get(provider)
        result.append({
            "provider": provider,
            "display_name": schema["display_name"],
            "is_enabled": cfg.is_enabled if cfg else False,
            "is_configured": cfg is not None,
            "last_test_status": cfg.last_test_status if cfg else None,
            "last_test_at": cfg.last_test_at.isoformat() if cfg and cfg.last_test_at else None,
            "last_test_detail": cfg.last_test_detail if cfg else None,
            "updated_at": cfg.updated_at.isoformat() if cfg and cfg.updated_at else None,
            "fields": schema["fields"],
        })
    return result


@app.get("/api/integrations/{provider}")
def get_integration(provider: str, db: Session = Depends(get_db)):
    if provider not in INTEGRATION_SCHEMAS:
        raise HTTPException(404, f"Unknown provider: {provider}")
    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    schema = INTEGRATION_SCHEMAS[provider]

    # Redact password fields
    safe_config = {}
    if cfg and cfg.config:
        password_keys = {f["key"] for f in schema["fields"] if f["type"] == "password"}
        for k, v in cfg.config.items():
            if k in password_keys and v:
                safe_config[k] = "••••" + str(v)[-4:] if len(str(v)) > 4 else "••••"
            else:
                safe_config[k] = v

    return {
        "provider": provider,
        "display_name": schema["display_name"],
        "is_enabled": cfg.is_enabled if cfg else False,
        "config": safe_config,
        "fields": schema["fields"],
        "last_test_status": cfg.last_test_status if cfg else None,
        "last_test_at": cfg.last_test_at.isoformat() if cfg and cfg.last_test_at else None,
        "last_test_detail": cfg.last_test_detail if cfg else None,
    }


class IntegrationUpdate(BaseModel):
    config: dict
    is_enabled: bool = True


@app.put("/api/integrations/{provider}")
def save_integration(provider: str, data: IntegrationUpdate, db: Session = Depends(get_db)):
    if provider not in INTEGRATION_SCHEMAS:
        raise HTTPException(404, f"Unknown provider: {provider}")

    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    if not cfg:
        cfg = IntegrationConfig(
            provider=provider,
            display_name=INTEGRATION_SCHEMAS[provider]["display_name"],
        )
        db.add(cfg)

    # Merge config — don't overwrite password fields if placeholder is sent
    schema = INTEGRATION_SCHEMAS[provider]
    password_keys = {f["key"] for f in schema["fields"] if f["type"] == "password"}
    merged = dict(cfg.config or {})
    for k, v in data.config.items():
        if k in password_keys and isinstance(v, str) and v.startswith("••••"):
            continue  # keep existing password
        merged[k] = v
    cfg.config = merged
    cfg.is_enabled = data.is_enabled
    cfg.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.post("/api/integrations/{provider}/test")
def test_integration_endpoint(provider: str, db: Session = Depends(get_db)):
    if provider not in INTEGRATION_SCHEMAS:
        raise HTTPException(404, f"Unknown provider: {provider}")

    result = integ_module.test_integration(db, provider)

    # Update test status
    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    if cfg:
        cfg.last_test_at = datetime.utcnow()
        cfg.last_test_status = result.get("status", "error")
        cfg.last_test_detail = result.get("detail") or result.get("user") or result.get("host") or "ok"
        db.commit()

    return result


@app.delete("/api/integrations/{provider}")
def delete_integration(provider: str, db: Session = Depends(get_db)):
    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    if cfg:
        db.delete(cfg)
        db.commit()
    return {"status": "ok"}


# ─────────────────────────────────────────────
# Finding Workflow Status
# ─────────────────────────────────────────────

class FindingStatusUpdate(BaseModel):
    status: str  # open / in_progress / resolved / accepted_risk / false_positive
    assigned_to: Optional[str] = None
    notes: Optional[str] = None

VALID_WORKFLOW_STATUSES = {"open", "in_progress", "resolved", "accepted_risk", "false_positive"}


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: int, body: FindingStatusUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update finding workflow status."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    if body.status not in VALID_WORKFLOW_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(VALID_WORKFLOW_STATUSES)}")
    _old_status = {"status": finding.workflow_status, "assigned_to": finding.workflow_assigned_to}
    finding.workflow_status = body.status
    finding.status_changed_at = datetime.utcnow()
    if body.assigned_to is not None:
        finding.workflow_assigned_to = body.assigned_to
    if body.notes is not None:
        finding.workflow_notes = body.notes
    # Sync resolved state with SLA system
    if body.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = datetime.utcnow()
        finding.sla_status = "resolved"
    elif body.status == "open" and finding.resolved_at:
        finding.resolved_at = None
        configs = db.query(SLAConfig).all()
        cfg_map = {c.severity: c for c in configs}
        cfg = cfg_map.get(finding.severity)
        warn = cfg.warn_days_before if cfg else 7
        finding.sla_status = _compute_sla_status(finding.sla_due_date, None, warn)
    _new_status = {"status": finding.workflow_status, "assigned_to": finding.workflow_assigned_to}
    log_audit(db, "update", "finding_status", finding_id,
              entity_name=finding.plugin_name,
              changes=_diff(_old_status, _new_status), actor=user)
    db.commit()
    return {
        "ok": True, "finding_id": finding_id,
        "workflow_status": finding.workflow_status,
        "assigned_to": finding.workflow_assigned_to,
    }


class FindingContextUpdate(BaseModel):
    ctx_reachability: Optional[str] = None       # unreachable / internal_only / internet_facing / unknown
    ctx_exploitability: Optional[str] = None     # not_exploitable / requires_conditions / easily_exploitable / unknown
    ctx_accessibility: Optional[str] = None      # restricted / authenticated_only / public / unknown
    ctx_compensating_control: Optional[str] = None
    biz_function: Optional[str] = None           # saved to asset.business_context
    biz_num_users: Optional[int] = None          # saved to asset.biz_num_users
    biz_revenue_impact: Optional[str] = None     # saved to asset.biz_revenue_impact


@app.patch("/api/findings/{finding_id}/context")
def update_finding_context(finding_id: int, body: FindingContextUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Update validated context (on finding) and business context (on asset)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    changes = {}
    # Validated context → stored on finding
    for field in ["ctx_reachability", "ctx_exploitability", "ctx_accessibility", "ctx_compensating_control"]:
        val = getattr(body, field)
        if val is not None:
            old = getattr(finding, field)
            setattr(finding, field, val)
            changes[field] = {"old": old, "new": val}
    # Business context → stored on asset (shared across all findings on the asset)
    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
    if asset:
        if body.biz_function is not None:
            old = asset.business_context
            asset.business_context = body.biz_function
            asset.business_context_confirmed = True
            changes["biz_function"] = {"old": old, "new": body.biz_function}
        if body.biz_num_users is not None:
            old = asset.biz_num_users
            asset.biz_num_users = body.biz_num_users
            changes["biz_num_users"] = {"old": old, "new": body.biz_num_users}
        if body.biz_revenue_impact is not None:
            old = asset.biz_revenue_impact
            asset.biz_revenue_impact = body.biz_revenue_impact
            changes["biz_revenue_impact"] = {"old": old, "new": body.biz_revenue_impact}
    if changes:
        log_audit(db, "update", "finding_context", finding_id,
                  entity_name=finding.plugin_name, changes=changes, actor=user)
    db.commit()
    return _finding_to_dict(finding, db, include_full=True)


@app.post("/api/findings/bulk-status")
def bulk_update_finding_status(
    body: dict,
    db: Session = Depends(get_db),
):
    """Bulk update workflow status for multiple findings."""
    finding_ids = body.get("finding_ids", [])
    status = body.get("status", "open")
    assigned_to = body.get("assigned_to")
    if status not in VALID_WORKFLOW_STATUSES:
        raise HTTPException(400, f"Invalid status: {status}")
    updated = 0
    for fid in finding_ids:
        f = db.query(Finding).filter(Finding.id == fid).first()
        if f:
            f.workflow_status = status
            f.status_changed_at = datetime.utcnow()
            if assigned_to is not None:
                f.workflow_assigned_to = assigned_to
            if status == "resolved" and not f.resolved_at:
                f.resolved_at = datetime.utcnow()
                f.sla_status = "resolved"
            updated += 1
    db.commit()
    return {"ok": True, "updated": updated}


# ─────────────────────────────────────────────
# Global Exceptions / Waivers
# ─────────────────────────────────────────────

class ExceptionCreate(BaseModel):
    plugin_id: Optional[str] = None  # nullable when using conditions-only matching
    plugin_name: Optional[str] = None
    asset_ip: Optional[str] = None
    scope_tags: Optional[list] = None  # ["env:prod", "net:dmz"]
    exception_type: str = "accepted_risk"  # accepted_risk / false_positive / severity_override / compensating_control / technical_debt
    override_severity: Optional[int] = None  # 0-4, only for severity_override
    compensating_control_detail: Optional[str] = None  # description of control in place
    debt_category: Optional[str] = None  # legacy_system / business_requirement / vendor_dependency / compatibility / cost (for technical_debt)
    mitigation_plan: Optional[str] = None  # compensating controls description (for technical_debt)
    conditions: Optional[list] = None  # [{field, op, value}, ...]
    condition_logic: str = "AND"
    reason: Optional[str] = None
    approved_by: Optional[str] = None
    exclude_from_reports: bool = True  # exclude matched findings from severity counts & totals
    expires_at: Optional[str] = None  # ISO date string
    review_by: Optional[str] = None  # ISO date string — recertification reminder

class ExceptionUpdate(BaseModel):
    plugin_id: Optional[str] = None
    plugin_name: Optional[str] = None
    asset_ip: Optional[str] = None
    scope_tags: Optional[list] = None
    reason: Optional[str] = None
    approved_by: Optional[str] = None
    exception_type: Optional[str] = None
    override_severity: Optional[int] = None
    compensating_control_detail: Optional[str] = None
    debt_category: Optional[str] = None
    mitigation_plan: Optional[str] = None
    conditions: Optional[list] = None
    condition_logic: Optional[str] = None
    exclude_from_reports: Optional[bool] = None
    expires_at: Optional[str] = None
    review_by: Optional[str] = None
    is_active: Optional[bool] = None


@app.get("/api/exceptions")
def list_exceptions(
    plugin_id: Optional[str] = None,
    asset_ip: Optional[str] = None,
    exception_type: Optional[str] = None,
    active_only: bool = True,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List global exceptions/waivers."""
    q = apply_org_filter(db.query(FindingException), FindingException, org_ids)
    if active_only:
        q = q.filter(FindingException.is_active == True)
    if plugin_id:
        q = q.filter(FindingException.plugin_id == plugin_id)
    if asset_ip:
        q = q.filter((FindingException.asset_ip == asset_ip) | (FindingException.asset_ip == None))
    if exception_type:
        q = q.filter(FindingException.exception_type == exception_type)
    exceptions = q.order_by(desc(FindingException.created_at)).all()
    return [
        {
            "id": e.id, "plugin_id": e.plugin_id, "plugin_name": e.plugin_name,
            "asset_ip": e.asset_ip, "scope_tags": e.scope_tags or [],
            "exception_type": e.exception_type,
            "override_severity": e.override_severity,
            "compensating_control_detail": e.compensating_control_detail,
            "debt_category": e.debt_category,
            "mitigation_plan": e.mitigation_plan,
            "conditions": e.conditions or [],
            "condition_logic": e.condition_logic or "AND",
            "reason": e.reason, "approved_by": e.approved_by,
            "exclude_from_reports": e.exclude_from_reports if e.exclude_from_reports is not None else True,
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "review_by": e.review_by.isoformat() if e.review_by else None,
            "is_active": e.is_active,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "affected_findings": db.query(func.count(Finding.id)).filter(
                Finding.exception_id == e.id,
            ).scalar() if e.is_active else 0,
        }
        for e in exceptions
    ]


@app.get("/api/exceptions/condition-catalog")
def get_exception_condition_catalog():
    """Return the condition catalog for exception rules."""
    return rule_engine.CONDITION_CATALOG


@app.post("/api/exceptions")
def create_exception(body: ExceptionCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Create a global exception / waiver."""
    # Must have at least plugin_id or conditions
    if not body.plugin_id and not body.conditions:
        raise HTTPException(400, "Must specify plugin_id, conditions, or both")
    if body.exception_type == "severity_override" and body.override_severity is None:
        raise HTTPException(400, "override_severity is required for severity_override type")
    exc = FindingException(
        org_id=user.org_id if user else None,
        plugin_id=body.plugin_id or None,
        plugin_name=body.plugin_name,
        asset_ip=body.asset_ip or None,
        scope_tags=body.scope_tags or None,
        exception_type=body.exception_type,
        override_severity=body.override_severity if body.exception_type == "severity_override" else None,
        compensating_control_detail=body.compensating_control_detail if body.exception_type == "compensating_control" else None,
        debt_category=body.debt_category if body.exception_type == "technical_debt" else None,
        mitigation_plan=body.mitigation_plan if body.exception_type == "technical_debt" else None,
        conditions=body.conditions or None,
        condition_logic=body.condition_logic or "AND",
        reason=body.reason,
        approved_by=body.approved_by,
        exclude_from_reports=body.exclude_from_reports,
        expires_at=datetime.fromisoformat(body.expires_at) if body.expires_at else None,
        review_by=datetime.fromisoformat(body.review_by) if body.review_by else None,
    )
    db.add(exc)
    db.flush()
    # Apply to existing findings
    applied = _apply_exception_to_findings(db, exc)
    log_audit(db, "create", "exception", exc.id,
              entity_name=exc.plugin_name or exc.plugin_id,
              changes={"exception_type": exc.exception_type, "reason": exc.reason, "plugin_id": exc.plugin_id, "asset_ip": exc.asset_ip},
              actor=user)
    db.commit()
    return {"ok": True, "id": exc.id, "applied_to": applied}


@app.get("/api/exceptions/{exception_id}")
def get_exception(exception_id: int, db: Session = Depends(get_db)):
    exc = db.query(FindingException).filter(FindingException.id == exception_id).first()
    if not exc:
        raise HTTPException(404, "Exception not found")
    # Count affected findings
    q = db.query(Finding).filter(Finding.plugin_id == exc.plugin_id)
    if exc.asset_ip:
        q = q.join(Asset, Finding.asset_id == Asset.id).filter(Asset.ip == exc.asset_ip)
    affected = q.count()
    return {
        "id": exc.id, "plugin_id": exc.plugin_id, "plugin_name": exc.plugin_name,
        "asset_ip": exc.asset_ip, "scope_tags": exc.scope_tags or [],
        "exception_type": exc.exception_type,
        "override_severity": exc.override_severity,
        "compensating_control_detail": exc.compensating_control_detail,
        "debt_category": exc.debt_category,
        "mitigation_plan": exc.mitigation_plan,
        "conditions": exc.conditions or [],
        "condition_logic": exc.condition_logic or "AND",
        "reason": exc.reason, "approved_by": exc.approved_by,
        "exclude_from_reports": exc.exclude_from_reports if exc.exclude_from_reports is not None else True,
        "expires_at": exc.expires_at.isoformat() if exc.expires_at else None,
        "review_by": exc.review_by.isoformat() if exc.review_by else None,
        "is_active": exc.is_active,
        "created_at": exc.created_at.isoformat() if exc.created_at else None,
        "affected_findings": affected,
    }


@app.patch("/api/exceptions/{exception_id}")
def update_exception(exception_id: int, body: ExceptionUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    exc = db.query(FindingException).filter(FindingException.id == exception_id).first()
    if not exc:
        raise HTTPException(404, "Exception not found")
    _old_exc = {"exception_type": exc.exception_type, "reason": exc.reason, "is_active": exc.is_active, "plugin_id": exc.plugin_id, "asset_ip": exc.asset_ip, "approved_by": exc.approved_by}
    if body.plugin_id is not None:
        exc.plugin_id = body.plugin_id or None
    if body.plugin_name is not None:
        exc.plugin_name = body.plugin_name
    if body.asset_ip is not None:
        exc.asset_ip = body.asset_ip or None
    if body.scope_tags is not None:
        exc.scope_tags = body.scope_tags if body.scope_tags else None
    if body.reason is not None:
        exc.reason = body.reason
    if body.approved_by is not None:
        exc.approved_by = body.approved_by
    if body.exception_type is not None:
        exc.exception_type = body.exception_type
    if body.override_severity is not None:
        exc.override_severity = body.override_severity
    if body.compensating_control_detail is not None:
        exc.compensating_control_detail = body.compensating_control_detail
    if body.debt_category is not None:
        exc.debt_category = body.debt_category
    if body.mitigation_plan is not None:
        exc.mitigation_plan = body.mitigation_plan
    if body.conditions is not None:
        exc.conditions = body.conditions if body.conditions else None
    if body.condition_logic is not None:
        exc.condition_logic = body.condition_logic
    if body.exclude_from_reports is not None:
        exc.exclude_from_reports = body.exclude_from_reports
    if body.expires_at is not None:
        exc.expires_at = datetime.fromisoformat(body.expires_at) if body.expires_at else None
    if body.review_by is not None:
        exc.review_by = datetime.fromisoformat(body.review_by) if body.review_by else None
    if body.is_active is not None:
        exc.is_active = body.is_active
        if not body.is_active:
            # Deactivated — unlink from findings
            db.query(Finding).filter(Finding.exception_id == exc.id).update(
                {"exception_id": None, "workflow_status": "open"}, synchronize_session=False
            )
        else:
            _apply_exception_to_findings(db, exc)
    _new_exc = {"exception_type": exc.exception_type, "reason": exc.reason, "is_active": exc.is_active, "plugin_id": exc.plugin_id, "asset_ip": exc.asset_ip, "approved_by": exc.approved_by}
    log_audit(db, "update", "exception", exc.id,
              entity_name=exc.plugin_name or exc.plugin_id,
              changes=_diff(_old_exc, _new_exc), actor=user)
    db.commit()
    return {"ok": True, "id": exc.id}


@app.delete("/api/exceptions/{exception_id}")
def delete_exception(exception_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    exc = db.query(FindingException).filter(FindingException.id == exception_id).first()
    if not exc:
        raise HTTPException(404, "Exception not found")
    _exc_name = exc.plugin_name or exc.plugin_id
    _exc_org = exc.org_id
    # Unlink findings
    db.query(Finding).filter(Finding.exception_id == exc.id).update(
        {"exception_id": None, "workflow_status": "open"}, synchronize_session=False
    )
    db.delete(exc)
    log_audit(db, "delete", "exception", exception_id,
              entity_name=_exc_name, actor=user, org_id=_exc_org)
    db.commit()
    return {"ok": True}


_SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def _check_scope_tags(db: Session, asset_id: int, scope_tags: list) -> bool:
    """Check if an asset matches any of the scope tags."""
    from models.models import Tag, TagAssignment
    rows = (
        db.query(Tag.category, Tag.value)
        .join(TagAssignment, TagAssignment.tag_id == Tag.id)
        .filter(TagAssignment.asset_id == asset_id)
        .all()
    )
    asset_tags = {f"{r.category}:{r.value}".lower() for r in rows}
    return any(t.lower() in asset_tags for t in scope_tags)


def _apply_exception_to_findings(db: Session, exc: FindingException, scan_id: int = None) -> int:
    """Apply a single exception to all matching findings. Returns count of affected findings."""
    import services.rule_engine as engine

    q = db.query(Finding)
    if exc.plugin_id:
        q = q.filter(Finding.plugin_id == exc.plugin_id)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)

    # Asset-level scope: IP or tags (need join for either)
    has_asset_join = False
    if exc.asset_ip:
        q = q.join(Asset, Finding.asset_id == Asset.id)
        q = q.filter(Asset.ip == exc.asset_ip)
        has_asset_join = True

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
            f.severity_label = _SEVERITY_LABELS.get(exc.override_severity, "Info")
        else:
            f.workflow_status = exc.exception_type  # accepted_risk / false_positive / compensating_control

        count += 1
    return count


@app.post("/api/exceptions/apply-all")
def apply_all_exceptions(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Re-apply all active exceptions to findings (e.g. after a new scan upload)."""
    exceptions = db.query(FindingException).filter(
        FindingException.is_active == True
    ).all()
    now = datetime.utcnow()
    total_applied = 0
    for exc in exceptions:
        if exc.expires_at and exc.expires_at < now:
            exc.is_active = False
            continue
        total_applied += _apply_exception_to_findings(db, exc, scan_id=scan_id)
    db.commit()
    return {"ok": True, "exceptions_checked": len(exceptions), "findings_updated": total_applied}



# ─────────────────────────────────────────────
# Aggregated Solutions
# ─────────────────────────────────────────────

@app.get("/api/aggregated-solutions")
def list_aggregated_solutions(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """List aggregated solutions (root-cause grouped remediation plans)."""
    q = db.query(AggregatedSolution).join(Scan, AggregatedSolution.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(AggregatedSolution.scan_id == scan_id)
    if asset_id:
        q = q.filter(AggregatedSolution.asset_id == asset_id)
    if category:
        q = q.filter(AggregatedSolution.root_cause_type == category)
    q = q.order_by(desc(AggregatedSolution.efficiency_score))
    results = q.all()
    return [_agg_solution_to_dict(a, db) for a in results]


@app.get("/api/aggregated-solutions/{agg_id}")
def get_aggregated_solution(agg_id: int, db: Session = Depends(get_db)):
    """Get a single aggregated solution with its linked findings."""
    agg = db.query(AggregatedSolution).filter(AggregatedSolution.id == agg_id).first()
    if not agg:
        raise HTTPException(404, "Aggregated solution not found")
    result = _agg_solution_to_dict(agg, db)
    # Include full findings list
    findings = db.query(Finding).filter(Finding.aggregated_solution_id == agg.id).all()
    result["findings"] = [_finding_to_dict(f, db) for f in findings]
    return result


@app.post("/api/aggregated-solutions/rebuild")
def rebuild_aggregated_solutions(scan_id: int = Query(None), db: Session = Depends(get_db)):
    """Re-run solution aggregation on existing scans."""
    if scan_id:
        scans = db.query(Scan).filter(Scan.id == scan_id).all()
    else:
        scans = db.query(Scan).all()
    total_created = 0
    total_linked = 0
    for scan in scans:
        result = solution_aggregator.aggregate_solutions(db, scan_id=scan.id)
        total_created += result["created"]
        total_linked += result["findings_linked"]
    db.commit()
    return {"scans_processed": len(scans), "created": total_created, "findings_linked": total_linked}


def _agg_solution_to_dict(a: AggregatedSolution, db: Session) -> dict:
    # Resolve hostnames for cross-asset recommendations
    asset_hostnames = []
    if a.asset_ids:
        for aid in (a.asset_ids or [])[:10]:
            asset = db.query(Asset).filter(Asset.id == aid).first()
            if asset:
                asset_hostnames.append(asset.hostname or asset.ip or str(aid))

    return {
        "id": a.id,
        "scan_id": a.scan_id,
        # Component fingerprint
        "affected_component": a.affected_component,
        "current_version": a.current_version,
        "target_version": a.target_version,
        # Classification
        "root_cause_type": a.root_cause_type,
        "action_type": a.action_type,
        "category": a.root_cause_type,  # backward compat
        # Human-readable
        "title": a.title,
        "description": a.description,
        "action_details": a.action_details,
        "vs_alternative": a.vs_alternative,
        # Cross-asset scope
        "asset_ids": a.asset_ids or [],
        "asset_count": a.asset_count or 0,
        "asset_hostnames": asset_hostnames,
        # Findings & CVEs
        "finding_count": a.finding_count,
        "finding_ids": a.finding_ids or [],
        "cve_ids": a.cve_ids or [],
        "cve_count": len(a.cve_ids) if a.cve_ids else 0,
        # Scoring
        "severity_max": a.severity_max,
        "priority_score": a.priority_score,
        "risk_reduction": a.risk_reduction or 0,
        "efficiency_score": a.efficiency_score or 0,
        # Operational
        "effort_level": a.effort_level,
        "owner_suggestion": a.owner_suggestion,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


# ─────────────────────────────────────────────
# Cross-Scan Delta Comparison
# ─────────────────────────────────────────────

@app.get("/api/scans/compare")
def compare_scans(
    base_scan_id: int,
    compare_scan_id: int,
    db: Session = Depends(get_db),
):
    """Compare two scans and return new/fixed/recurring findings."""
    # Check if we have a cached comparison
    cached = db.query(ScanComparison).filter(
        ScanComparison.base_scan_id == base_scan_id,
        ScanComparison.compare_scan_id == compare_scan_id,
    ).first()
    if cached:
        return _format_comparison(cached, db)

    # Compute delta
    base_scan = db.query(Scan).filter(Scan.id == base_scan_id).first()
    compare_scan = db.query(Scan).filter(Scan.id == compare_scan_id).first()
    if not base_scan or not compare_scan:
        raise HTTPException(404, "Scan not found")

    result = _compute_scan_delta(db, base_scan_id, compare_scan_id)

    # Cache it
    comp = ScanComparison(
        base_scan_id=base_scan_id,
        compare_scan_id=compare_scan_id,
        new_count=result["new_count"],
        fixed_count=result["fixed_count"],
        recurring_count=result["recurring_count"],
        new_findings=result["new_findings"][:500],  # cap for storage
        fixed_findings=result["fixed_findings"][:500],
        new_by_severity=result["new_by_severity"],
        fixed_by_severity=result["fixed_by_severity"],
    )
    db.add(comp)
    db.commit()
    return _format_comparison(comp, db)


@app.get("/api/scans/delta-timeline")
def scan_delta_timeline(db: Session = Depends(get_db)):
    """Return a timeline of scan-over-scan deltas (each scan compared to previous)."""
    scans = db.query(Scan).order_by(Scan.created_at).all()
    if len(scans) < 2:
        return []

    timeline = []
    for i in range(1, len(scans)):
        base = scans[i - 1]
        current = scans[i]
        # Check cache
        cached = db.query(ScanComparison).filter(
            ScanComparison.base_scan_id == base.id,
            ScanComparison.compare_scan_id == current.id,
        ).first()
        if cached:
            delta = {
                "new_count": cached.new_count,
                "fixed_count": cached.fixed_count,
                "recurring_count": cached.recurring_count,
                "new_by_severity": cached.new_by_severity or {},
                "fixed_by_severity": cached.fixed_by_severity or {},
            }
        else:
            delta = _compute_scan_delta(db, base.id, current.id)
            # Cache
            comp = ScanComparison(
                base_scan_id=base.id, compare_scan_id=current.id,
                new_count=delta["new_count"], fixed_count=delta["fixed_count"],
                recurring_count=delta["recurring_count"],
                new_findings=delta["new_findings"][:500],
                fixed_findings=delta["fixed_findings"][:500],
                new_by_severity=delta["new_by_severity"],
                fixed_by_severity=delta["fixed_by_severity"],
            )
            db.add(comp)

        timeline.append({
            "scan_id": current.id,
            "scan_name": current.scan_name or current.filename,
            "scan_date": current.scan_date or (current.created_at.isoformat() if current.created_at else None),
            "base_scan_id": base.id,
            "base_scan_name": base.scan_name or base.filename,
            "new_count": delta["new_count"],
            "fixed_count": delta["fixed_count"],
            "recurring_count": delta["recurring_count"],
            "new_by_severity": delta.get("new_by_severity", {}),
            "fixed_by_severity": delta.get("fixed_by_severity", {}),
            "net_change": delta["new_count"] - delta["fixed_count"],
        })
    db.commit()
    return timeline


def _compute_scan_delta(db: Session, base_scan_id: int, compare_scan_id: int) -> dict:
    """Compute the set-difference between two scans' findings.
    A finding is identified by (plugin_id, asset_ip)."""
    # Build sets: {(plugin_id, asset_ip): finding_info}
    def _build_finding_set(scan_id):
        findings = db.query(Finding, Asset.ip).join(Asset, Finding.asset_id == Asset.id).filter(
            Finding.scan_id == scan_id
        ).all()
        result = {}
        for f, ip in findings:
            key = (f.plugin_id, ip or "")
            result[key] = {
                "plugin_id": f.plugin_id, "plugin_name": f.plugin_name,
                "severity": f.severity, "severity_label": f.severity_label,
                "asset_ip": ip, "cvss3_score": f.cvss3_score,
                "priority_score": f.priority_score,
            }
        return result

    base_set = _build_finding_set(base_scan_id)
    compare_set = _build_finding_set(compare_scan_id)

    base_keys = set(base_set.keys())
    compare_keys = set(compare_set.keys())

    new_keys = compare_keys - base_keys
    fixed_keys = base_keys - compare_keys
    recurring_keys = base_keys & compare_keys

    new_findings = [compare_set[k] for k in new_keys]
    fixed_findings = [base_set[k] for k in fixed_keys]

    # Severity breakdown
    new_by_sev = {}
    for f in new_findings:
        s = f.get("severity", 0)
        new_by_sev[s] = new_by_sev.get(s, 0) + 1
    fixed_by_sev = {}
    for f in fixed_findings:
        s = f.get("severity", 0)
        fixed_by_sev[s] = fixed_by_sev.get(s, 0) + 1

    # Sort by severity desc then priority
    new_findings.sort(key=lambda x: (-(x.get("severity") or 0), -(x.get("priority_score") or 0)))
    fixed_findings.sort(key=lambda x: (-(x.get("severity") or 0), -(x.get("priority_score") or 0)))

    return {
        "new_count": len(new_keys),
        "fixed_count": len(fixed_keys),
        "recurring_count": len(recurring_keys),
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "new_by_severity": new_by_sev,
        "fixed_by_severity": fixed_by_sev,
    }


def _format_comparison(comp: ScanComparison, db: Session) -> dict:
    """Format a cached ScanComparison for API response."""
    sev_labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    base = db.query(Scan).filter(Scan.id == comp.base_scan_id).first()
    compare = db.query(Scan).filter(Scan.id == comp.compare_scan_id).first()
    return {
        "base_scan": {"id": comp.base_scan_id, "name": base.scan_name if base else None,
                       "date": base.scan_date if base else None},
        "compare_scan": {"id": comp.compare_scan_id, "name": compare.scan_name if compare else None,
                          "date": compare.scan_date if compare else None},
        "new_count": comp.new_count,
        "fixed_count": comp.fixed_count,
        "recurring_count": comp.recurring_count,
        "net_change": comp.new_count - comp.fixed_count,
        "new_findings": comp.new_findings or [],
        "fixed_findings": comp.fixed_findings or [],
        "new_by_severity": {sev_labels.get(int(k), k): v for k, v in (comp.new_by_severity or {}).items()},
        "fixed_by_severity": {sev_labels.get(int(k), k): v for k, v in (comp.fixed_by_severity or {}).items()},
    }


# ─────────────────────────────────────────────
# Temporal Analytics & Remediation Velocity
# ─────────────────────────────────────────────

@app.get("/api/reports/regressions")
def get_regressions(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return findings that are regressions (were resolved, then reappeared)."""
    q = db.query(Finding).filter(Finding.is_regression == True)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    q = q.order_by(desc(Finding.severity), desc(Finding.priority_score))
    findings = q.limit(200).all()

    result = []
    for f in findings:
        asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
        result.append({
            "id": f.id,
            "plugin_id": f.plugin_id,
            "plugin_name": f.plugin_name,
            "severity": f.severity,
            "severity_label": f.severity_label,
            "asset_ip": asset.ip if asset else None,
            "asset_hostname": asset.hostname if asset else None,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "times_seen": f.times_seen,
            "priority_score": f.priority_score,
            "scan_id": f.scan_id,
        })
    return {
        "total": len(result),
        "regressions": result,
    }


@app.get("/api/reports/temporal-summary")
def get_temporal_summary(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """Return temporal health summary: zombie vulns, regression count, age distribution."""
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)

    findings = q.filter(Finding.severity > 0).all()  # Exclude Info
    now = datetime.utcnow()

    regression_count = 0
    age_buckets = {"under_30d": 0, "30_90d": 0, "90_180d": 0, "over_180d": 0}
    zombie_count = 0  # Open > 180 days
    total_with_temporal = 0

    for f in findings:
        if f.is_regression:
            regression_count += 1
        if f.first_seen:
            total_with_temporal += 1
            age_days = (now - f.first_seen).days
            if age_days < 30:
                age_buckets["under_30d"] += 1
            elif age_days < 90:
                age_buckets["30_90d"] += 1
            elif age_days < 180:
                age_buckets["90_180d"] += 1
            else:
                age_buckets["over_180d"] += 1
                if f.workflow_status in ("open", None):
                    zombie_count += 1

    return {
        "total_findings": len(findings),
        "total_with_temporal": total_with_temporal,
        "regression_count": regression_count,
        "zombie_count": zombie_count,
        "age_distribution": age_buckets,
    }


@app.get("/api/reports/remediation-velocity")
def get_remediation_velocity(
    period: str = "month",
    db: Session = Depends(get_db),
):
    """Return remediation velocity: findings resolved per time period.
    period: 'week' or 'month'"""
    from datetime import timedelta
    from collections import defaultdict

    resolved = db.query(Finding).filter(Finding.resolved_at != None).all()
    if not resolved:
        return {"period": period, "buckets": [], "total_resolved": 0, "avg_per_period": 0}

    # Group by period
    buckets = defaultdict(lambda: {"resolved": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
    for f in resolved:
        dt = f.resolved_at
        if period == "week":
            # ISO week: Monday-start
            key = f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
        else:
            key = f"{dt.year}-{dt.month:02d}"
        buckets[key]["resolved"] += 1
        sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        sev_key = sev_map.get(f.severity, "low")
        buckets[key][sev_key] += 1

    sorted_keys = sorted(buckets.keys())
    result_buckets = []
    for k in sorted_keys:
        entry = buckets[k]
        entry["period_label"] = k
        result_buckets.append(entry)

    total = len(resolved)
    avg = round(total / max(len(sorted_keys), 1), 1)

    # Compute velocity trend (last 3 periods vs prior 3)
    trend = None
    if len(sorted_keys) >= 6:
        recent = sum(buckets[k]["resolved"] for k in sorted_keys[-3:])
        prior = sum(buckets[k]["resolved"] for k in sorted_keys[-6:-3])
        if prior > 0:
            trend = round((recent - prior) / prior * 100, 1)

    return {
        "period": period,
        "buckets": result_buckets,
        "total_resolved": total,
        "avg_per_period": avg,
        "velocity_trend_pct": trend,
    }


@app.post("/api/scans/{scan_id}/backfill-temporal")
def backfill_temporal(scan_id: int, db: Session = Depends(get_db)):
    """Backfill temporal fields for an existing scan (for scans uploaded before this feature)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    _populate_temporal_fields(db, scan)
    db.commit()
    regressions = db.query(func.count(Finding.id)).filter(
        Finding.scan_id == scan_id, Finding.is_regression == True
    ).scalar()
    return {
        "ok": True,
        "scan_id": scan_id,
        "regressions_detected": regressions,
    }


@app.post("/api/scans/backfill-temporal-all")
def backfill_temporal_all(db: Session = Depends(get_db)):
    """Backfill temporal fields for ALL scans in chronological order."""
    scans = db.query(Scan).order_by(Scan.created_at).all()
    results = []
    for scan in scans:
        _populate_temporal_fields(db, scan)
        db.flush()
        regressions = db.query(func.count(Finding.id)).filter(
            Finding.scan_id == scan.id, Finding.is_regression == True
        ).scalar()
        results.append({"scan_id": scan.id, "scan_name": scan.scan_name, "regressions": regressions})
    db.commit()
    return {"ok": True, "scans_processed": len(results), "details": results}


# ── Tag-based Risk Report ─────────────────────────────────────────────────────


@app.get("/api/reports/risk-by-tags")
def get_risk_by_tags(
    category: Optional[str] = None,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Risk breakdown grouped by tag category (business unit, environment, etc.).
    Returns severity counts, avg risk score, finding density, grade, and SLA per group."""
    from collections import defaultdict

    # Get all tags, optionally filtered by category
    tag_q = apply_org_filter(db.query(Tag), Tag, org_ids)
    if category:
        tag_q = tag_q.filter(func.lower(Tag.category) == category.lower())
    tags = tag_q.all()

    # Available categories for the picker
    cat_q = apply_org_filter(db.query(Tag.category).distinct(), Tag, org_ids)
    available_categories = sorted([r[0] for r in cat_q.all() if r[0]])

    if not tags:
        return {"category": category, "groups": [], "org_avg_risk": 0, "available_categories": available_categories}

    # Get all tag assignments for assets
    ta_q = db.query(TagAssignment).filter(
        TagAssignment.tag_id.in_([t.id for t in tags]),
        TagAssignment.asset_id.isnot(None),
    )
    assignments = ta_q.all()

    # Map asset_ids per tag
    tag_assets = defaultdict(set)
    for ta in assignments:
        tag_assets[ta.tag_id].add(ta.asset_id)

    # Build scoped asset/finding queries
    asset_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    asset_q = apply_scan_org_filter(asset_q, org_ids)
    finding_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    finding_q = apply_scan_org_filter(finding_q, org_ids)
    if scan_id:
        asset_q = asset_q.filter(Asset.scan_id == scan_id)
        finding_q = finding_q.filter(Finding.scan_id == scan_id)

    # Pre-validate asset IDs in scope
    all_asset_ids = set()
    for ids in tag_assets.values():
        all_asset_ids.update(ids)
    if scan_id and all_asset_ids:
        valid_asset_ids = {a.id for a in asset_q.filter(Asset.id.in_(all_asset_ids)).all()}
    else:
        valid_asset_ids = all_asset_ids

    groups = []
    for tag in tags:
        asset_ids = tag_assets.get(tag.id, set()) & valid_asset_ids
        if not asset_ids:
            continue

        tag_findings_q = finding_q.filter(Finding.asset_id.in_(asset_ids))
        sev_counts = {}
        for sev, label in [(4, "critical"), (3, "high"), (2, "medium"), (1, "low"), (0, "info")]:
            sev_counts[label] = tag_findings_q.filter(Finding.severity == sev).count()

        total_findings = sum(sev_counts.values())
        exploit_count = tag_findings_q.filter(Finding.exploit_available == True).count()

        # SLA compliance
        sla_on = tag_findings_q.filter(Finding.sla_status == "on_track").count()
        sla_resolved = tag_findings_q.filter(Finding.sla_status == "resolved").count()
        sla_breached = tag_findings_q.filter(Finding.sla_status == "breached").count()
        sla_at_risk = tag_findings_q.filter(Finding.sla_status == "at_risk").count()
        sla_total = sla_on + sla_resolved + sla_breached + sla_at_risk
        sla_compliance = round((sla_on + sla_resolved) / sla_total * 100, 1) if sla_total else None

        # Risk scores
        risk_scores = [a.risk_score for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
                       if a.risk_score and a.risk_score > 0]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0

        # Grade
        grade = "A" if avg_risk <= 2 else "B" if avg_risk <= 4 else "C" if avg_risk <= 6 else "D" if avg_risk <= 8 else "F"

        groups.append({
            "tag_id": tag.id,
            "category": tag.category,
            "value": tag.value,
            "color": tag.color,
            "asset_count": len(asset_ids),
            "finding_count": total_findings,
            "finding_density": round(total_findings / len(asset_ids), 1),
            "severity": sev_counts,
            "avg_risk_score": avg_risk,
            "sla_compliance": sla_compliance,
            "exploit_count": exploit_count,
            "grade": grade,
        })

    # Sort by risk desc, assign rank
    groups.sort(key=lambda g: g["avg_risk_score"], reverse=True)
    for i, g in enumerate(groups):
        g["rank"] = i + 1

    # Org-wide average for benchmark comparison
    all_risk = [a.risk_score for a in asset_q.all() if a.risk_score and a.risk_score > 0]
    org_avg = round(sum(all_risk) / len(all_risk), 2) if all_risk else 0

    return {
        "category": category,
        "groups": groups,
        "org_avg_risk": org_avg,
        "available_categories": available_categories,
    }


# ─────────────────────────────────────────────────────────
# Funnel Widget
# ─────────────────────────────────────────────────────────

class FunnelStep(BaseModel):
    label: str
    filters: dict = {}

class FunnelRequest(BaseModel):
    base_entity: str = "findings"  # "findings" or "assets"
    scan_id: Optional[int] = None
    steps: List[FunnelStep] = []

@app.post("/api/reports/funnel")
def compute_funnel(
    body: FunnelRequest,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute counts for a multi-step funnel.
    Each step progressively narrows results by applying cumulative filters.
    Supports both findings-based and assets-based funnels."""
    results = []

    if body.base_entity == "findings":
        base_q = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
        base_q = apply_scan_org_filter(base_q, org_ids)
        if body.scan_id:
            base_q = base_q.filter(Finding.scan_id == body.scan_id)

        q = base_q
        for step in body.steps:
            f = step.filters
            _is_true = lambda v: v == True or v == "true"
            # Severity
            if f.get("severity") is not None and f["severity"] != "":
                q = q.filter(Finding.severity == int(f["severity"]))
            if f.get("min_severity") is not None and f["min_severity"] != "":
                q = q.filter(Finding.severity >= int(f["min_severity"]))
            # Scoring
            if f.get("min_cvss3"):
                q = q.filter(Finding.cvss3_score >= float(f["min_cvss3"]))
            if f.get("min_cvss4"):
                q = q.filter(Finding.cvss4_score >= float(f["min_cvss4"]))
            if f.get("min_vpr"):
                q = q.filter(Finding.vpr_score >= float(f["min_vpr"]))
            if f.get("min_epss"):
                q = q.filter(Finding.epss_score >= float(f["min_epss"]))
            # Threat intel
            if _is_true(f.get("is_kev")):
                q = q.filter(Finding.is_kev == True)
            if _is_true(f.get("has_exploit")):
                q = q.filter(Finding.exploit_available == True)
            if _is_true(f.get("ransomware_linked")):
                q = q.filter(Finding.ransomware_linked == True)
            if _is_true(f.get("trending_in_news")):
                q = q.filter(Finding.trending_in_news == True)
            if _is_true(f.get("zero_day")):
                q = q.filter(Finding.zero_day == True)
            if f.get("exploit_maturity"):
                q = q.filter(Finding.exploit_maturity == f["exploit_maturity"])
            # ATT&CK
            if _is_true(f.get("has_ttps")):
                q = q.filter(Finding.matched_ttps.isnot(None), Finding.matched_ttps != "[]")
            if f.get("tactic"):
                q = q.filter(Finding.matched_ttps.ilike(f'%"tactic": "{f["tactic"]}"%'))
            if f.get("technique_id"):
                q = q.filter(Finding.matched_ttps.ilike(f'%"technique_id": "{f["technique_id"]}%'))
            # Workflow & state
            if f.get("workflow_status"):
                q = q.filter(Finding.workflow_status == f["workflow_status"])
            if f.get("vulnerability_state"):
                q = q.filter(Finding.vulnerability_state == f["vulnerability_state"])
            if f.get("sla_status"):
                q = q.filter(Finding.sla_status == f["sla_status"])
            if _is_true(f.get("is_regression")):
                q = q.filter(Finding.is_regression == True)
            if _is_true(f.get("has_exception")):
                q = q.filter(Finding.exception_id.isnot(None))
            # Effort & ownership
            if f.get("effort_level"):
                q = q.filter(Finding.effort_level == f["effort_level"])
            if f.get("owner_suggestion"):
                q = q.filter(Finding.owner_suggestion == f["owner_suggestion"])
            # Plugin details
            if f.get("plugin_family"):
                q = q.filter(Finding.plugin_family.ilike(f"%{f['plugin_family']}%"))
            if f.get("plugin_name"):
                q = q.filter(Finding.plugin_name.ilike(f"%{f['plugin_name']}%"))
            if f.get("port"):
                q = q.filter(Finding.port == int(f["port"]))
            if f.get("protocol"):
                q = q.filter(Finding.protocol == f["protocol"])
            if f.get("cve"):
                q = q.filter(Finding.cves.ilike(f"%{f['cve']}%"))
            if f.get("risk_factor"):
                q = q.filter(Finding.risk_factor == f["risk_factor"])
            # Search text
            if f.get("search"):
                q = q.filter(
                    Finding.plugin_name.ilike(f"%{f['search']}%") |
                    Finding.synopsis.ilike(f"%{f['search']}%")
                )
            # Asset-level joins for findings funnel
            need_asset_join = any(f.get(k) for k in ("on_critical_assets", "on_internet_facing", "asset_min_risk"))
            if need_asset_join:
                q = q.join(Asset, Finding.asset_id == Asset.id)
            if _is_true(f.get("on_critical_assets")):
                q = q.filter(Asset.criticality >= 8)
            if _is_true(f.get("on_internet_facing")):
                q = q.filter(Asset.is_internet_facing == True)
            if f.get("asset_min_risk"):
                q = q.filter(Asset.risk_score >= float(f["asset_min_risk"]))

            count = q.count()
            results.append({"label": step.label, "count": count})

    elif body.base_entity == "assets":
        base_q = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
        base_q = apply_scan_org_filter(base_q, org_ids)
        if body.scan_id:
            base_q = base_q.filter(Asset.scan_id == body.scan_id)

        q = base_q
        # Track asset IDs for subquery-based filters
        need_asset_ids = False
        asset_ids_filter = None

        for step in body.steps:
            f = step.filters
            _is_true = lambda v: v == True or v == "true"
            # Asset properties
            if f.get("criticality") is not None and f["criticality"] != "":
                q = q.filter(Asset.criticality >= int(f["criticality"]))
            if f.get("min_risk"):
                q = q.filter(Asset.risk_score >= float(f["min_risk"]))
            if f.get("os"):
                q = q.filter(Asset.os.ilike(f"%{f['os']}%"))
            if f.get("environment"):
                q = q.filter(Asset.environment_tag == f["environment"])
            # Exposure & role
            if _is_true(f.get("is_internet_facing")):
                q = q.filter(Asset.is_internet_facing == True)
            if _is_true(f.get("is_domain_controller")):
                q = q.filter(Asset.is_domain_controller == True)
            # Service-based role detection
            _svc_role_map = {
                "is_database_server": ["mssql", "sqlserver", "mysql", "mysqld", "postgres",
                                       "postgresql", "oracle", "mongodb", "mariadb", "redis", "db2"],
                "is_web_server":  ["iis", "w3svc", "apache", "httpd", "nginx", "tomcat", "kestrel"],
                "is_dns_server":  ["dns", "named", "bind", "dnsmasq", "unbound"],
                "is_mail_server": ["exchange", "smtp", "imap", "pop3", "postfix", "sendmail", "exim"],
            }
            for role_key, patterns in _svc_role_map.items():
                if _is_true(f.get(role_key)):
                    svc_conditions = [InventoryService.service_name.ilike(f"%{p}%") for p in patterns]
                    role_ids = db.query(InventoryService.asset_id).filter(or_(*svc_conditions)).distinct().subquery()
                    q = q.filter(Asset.id.in_(db.query(role_ids)))
            # Severity counts
            if f.get("min_critical") is not None and f["min_critical"] != "":
                q = q.filter(Asset.critical_count >= int(f["min_critical"]))
            if f.get("min_high") is not None and f["min_high"] != "":
                q = q.filter(Asset.high_count >= int(f["min_high"]))
            if f.get("min_medium") is not None and f["min_medium"] != "":
                q = q.filter(Asset.medium_count >= int(f["min_medium"]))
            if _is_true(f.get("has_findings")):
                q = q.filter((Asset.critical_count + Asset.high_count + Asset.medium_count + Asset.low_count) > 0)
            # Finding-based subquery filters
            if _is_true(f.get("has_critical_cves")):
                crit_asset_ids = db.query(Finding.asset_id).filter(Finding.severity == 4).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(crit_asset_ids)))
            if _is_true(f.get("has_kev_findings")):
                kev_asset_ids = db.query(Finding.asset_id).filter(Finding.is_kev == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(kev_asset_ids)))
            if _is_true(f.get("has_exploitable")):
                exp_asset_ids = db.query(Finding.asset_id).filter(Finding.exploit_available == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(exp_asset_ids)))
            if _is_true(f.get("has_ransomware_findings")):
                rw_asset_ids = db.query(Finding.asset_id).filter(Finding.ransomware_linked == True).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(rw_asset_ids)))
            # Identity & access (inventory-based)
            if _is_true(f.get("has_domain_admin_logged_on")):
                da_usernames = db.query(InventoryUser.username).filter(
                    InventoryUser.is_domain_admin == True
                ).distinct().subquery()
                da_asset_ids = db.query(InventoryLoggedOn.asset_id).filter(
                    InventoryLoggedOn.username.in_(db.query(da_usernames))
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(da_asset_ids)))
            if _is_true(f.get("has_privileged_user")):
                priv_usernames = db.query(InventoryUser.username).filter(
                    InventoryUser.is_privileged == True
                ).distinct().subquery()
                priv_asset_ids = db.query(InventoryLoggedOn.asset_id).filter(
                    InventoryLoggedOn.username.in_(db.query(priv_usernames))
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(priv_asset_ids)))
            if _is_true(f.get("has_kerberoastable")):
                kerb_asset_ids = db.query(InventoryUser.asset_id).filter(
                    InventoryUser.spns.isnot(None), InventoryUser.spns != "[]"
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(kerb_asset_ids)))
            if _is_true(f.get("has_writeable_share")):
                share_asset_ids = db.query(InventoryShare.asset_id).filter(
                    InventoryShare.is_writeable == True
                ).distinct().subquery()
                q = q.filter(Asset.id.in_(db.query(share_asset_ids)))
            # Security controls
            if _is_true(f.get("lacks_security_controls")):
                has_ctrl_ids = db.query(InventorySecurityControl.asset_id).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_ctrl_ids)))
            if _is_true(f.get("lacks_av")):
                has_av_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "antivirus"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_av_ids)))
            if _is_true(f.get("lacks_edr")):
                has_edr_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "edr"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_edr_ids)))
            if _is_true(f.get("lacks_firewall")):
                has_fw_ids = db.query(InventorySecurityControl.asset_id).filter(
                    InventorySecurityControl.control_type == "firewall"
                ).distinct().subquery()
                q = q.filter(~Asset.id.in_(db.query(has_fw_ids)))
            # Search
            if f.get("search"):
                pattern = f"%{f['search']}%"
                q = q.filter(or_(
                    Asset.hostname.ilike(pattern),
                    Asset.ip.ilike(pattern),
                    Asset.fqdn.ilike(pattern),
                ))

            count = q.count()
            results.append({"label": step.label, "count": count})
    else:
        raise HTTPException(400, "base_entity must be 'findings' or 'assets'")

    return {"base_entity": body.base_entity, "steps": results}


# ─────────────────────────────────────────────────────────
# NLP Report Query
# ─────────────────────────────────────────────────────────

class NLPReportQueryRequest(BaseModel):
    query: str
    scan_id: Optional[int] = None

@app.post("/api/reports/nlp-query")
def nlp_report_query(
    body: NLPReportQueryRequest,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Parse a natural language query and return matching findings + assets as a structured report."""
    parsed = parse_nlp_query(body.query)
    af = parsed["asset_filters"]
    ff = parsed["finding_filters"]
    scan_id = body.scan_id

    # ── Assets ────────────────────────────────────────────
    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    if af.get("search"):
        pat = f"%{af['search']}%"
        aq = aq.filter(
            Asset.hostname.ilike(pat) | Asset.ip.ilike(pat) |
            Asset.os.ilike(pat) | Asset.fqdn.ilike(pat)
        )
    if af.get("environment"):
        aq = aq.filter(Asset.environment_tag.ilike(f"%{af['environment']}%"))
    if af.get("min_risk") is not None:
        aq = aq.filter(Asset.risk_score >= float(af["min_risk"]))
    if af.get("min_critical") is not None:
        aq = aq.filter(Asset.critical_count >= int(af["min_critical"]))
    if af.get("min_high") is not None:
        aq = aq.filter(Asset.high_count >= int(af["min_high"]))
    aq = aq.order_by(desc(Asset.risk_score))
    total_assets = aq.count()
    assets = aq.limit(20).all()

    # ── Findings ──────────────────────────────────────────
    fq = db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
    fq = apply_scan_org_filter(fq, org_ids)
    if scan_id:
        fq = fq.filter(Finding.scan_id == scan_id)
    if ff.get("severity") is not None:
        fq = fq.filter(Finding.severity == int(ff["severity"]))
    if ff.get("has_exploit"):
        fq = fq.filter(Finding.exploit_available == True)
    if ff.get("is_kev"):
        fq = fq.filter(Finding.is_kev == True)
    if ff.get("ransomware_linked"):
        fq = fq.filter(Finding.ransomware_linked == True)
    if ff.get("trending_in_news"):
        fq = fq.filter(Finding.trending_in_news == True)
    if ff.get("min_epss") is not None:
        fq = fq.filter(Finding.epss_score >= float(ff["min_epss"]))
    if ff.get("min_cvss") is not None:
        fq = fq.filter(
            or_(Finding.cvss3_score >= float(ff["min_cvss"]),
                Finding.cvss2_score >= float(ff["min_cvss"]))
        )
    if ff.get("sla_status"):
        fq = fq.filter(Finding.sla_status == ff["sla_status"])
    if ff.get("effort_level"):
        fq = fq.filter(Finding.effort_level == ff["effort_level"])
    if ff.get("plugin_family"):
        fq = fq.filter(Finding.plugin_family.ilike(f"%{ff['plugin_family']}%"))
    if ff.get("cve"):
        fq = fq.filter(Finding.cves.ilike(f"%{ff['cve']}%"))
    if ff.get("search"):
        pat = f"%{ff['search']}%"
        fq = fq.filter(
            Finding.plugin_name.ilike(pat) | Finding.synopsis.ilike(pat) |
            Finding.plugin_id.ilike(pat)
        )
    # If asset filters produced an asset set, scope findings to those assets
    if af and total_assets > 0:
        asset_ids = [a.id for a in assets]
        if len(asset_ids) < total_assets:
            # Get all matching asset IDs for scoping
            all_asset_ids = [r[0] for r in aq.with_entities(Asset.id).limit(500).all()]
            fq = fq.filter(Finding.asset_id.in_(all_asset_ids))
        else:
            fq = fq.filter(Finding.asset_id.in_(asset_ids))

    sort_col = Finding.priority_score
    if parsed.get("sort"):
        sort_field = parsed["sort"].get("sort_by", "priority_score")
        sort_col = getattr(Finding, sort_field, Finding.priority_score)
        if parsed["sort"].get("order", "desc") == "asc":
            fq = fq.order_by(sort_col)
        else:
            fq = fq.order_by(desc(sort_col))
    else:
        fq = fq.order_by(desc(sort_col))

    total_findings = fq.count()
    findings = fq.limit(50).all()

    # ── Severity breakdown ─────────────────────────────────
    sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    by_severity = {}
    for sev_int, sev_label in sev_labels.items():
        by_severity[sev_label] = fq.filter(Finding.severity == sev_int).count()

    # Reset filter chain for sev counts on the already-filtered query
    # Re-run with the same base query to get severity breakdown
    sev_breakdown = {sev_labels[s]: fq.filter(Finding.severity == s).count() for s in sev_labels}

    # ── Serialise ──────────────────────────────────────────
    def _finding(f):
        return {
            "id": f.id,
            "plugin_id": f.plugin_id,
            "plugin_name": f.plugin_name,
            "plugin_family": f.plugin_family,
            "severity": f.severity,
            "severity_label": f.severity_label or ["Info","Low","Medium","High","Critical"][f.severity],
            "cvss3_score": f.cvss3_score,
            "vpr_score": f.vpr_score,
            "priority_score": f.priority_score,
            "effort_level": f.effort_level,
            "exploit_available": f.exploit_available,
            "is_kev": f.is_kev,
            "synopsis": f.synopsis,
            "solution": f.solution,
            "asset_id": f.asset_id,
            "cves": f.cves or [],
            "sla_status": f.sla_status,
            "workflow_status": f.workflow_status,
        }

    def _asset(a):
        return {
            "id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "fqdn": a.fqdn,
            "os": a.os,
            "risk_score": a.risk_score,
            "criticality": a.criticality,
            "environment_tag": a.environment_tag,
            "critical_count": a.critical_count,
            "high_count": a.high_count,
            "medium_count": a.medium_count,
            "low_count": a.low_count,
        }

    return {
        "original_query": body.query,
        "explanation": parsed["explanation"],
        "parsed_filters": {
            "asset_filters": af,
            "finding_filters": ff,
            "sort": parsed.get("sort"),
        },
        "summary": {
            "total_findings": total_findings,
            "total_assets": total_assets,
            "by_severity": sev_breakdown,
        },
        "findings": [_finding(f) for f in findings],
        "assets": [_asset(a) for a in assets],
    }


# ─────────────────────────────────────────────────────────
# Audit Log API
# ─────────────────────────────────────────────────────────

@app.get("/api/audit-log")
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
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ],
        "entity_types": [r[0] for r in db.query(AuditLog.entity_type).distinct().all()],
        "actions": [r[0] for r in db.query(AuditLog.action).distinct().all()],
    }


@app.post("/api/scans/{scan_id}/reextract-inventory")
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

    # Use the scan's source_type to get the right inventory dispatch
    from parsers.registry import get_parser_by_source
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

    return {"scan_id": scan_id, "extracted": {k: v for k, v in inv_counts.items() if v}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


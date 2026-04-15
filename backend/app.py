"""
Hakuna Exposure Management Platform — FastAPI backend
"""
import os
import sys

# Ensure repo root is on sys.path so the hakuna package is importable
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import re
import json
import logging
import ipaddress
import uuid
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, File, UploadFile, HTTPException, Query, Request, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy import func, desc, distinct, or_, cast, Text

from core.database import get_db, init_db
from core.query_guards import set_statement_timeout, check_row_count, MAX_PAGE_SIZE
from core.limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from models.models import (
    Organization, User,
    Scan, Asset, Finding, FindingTicket, AutomateClick,
    InventoryUser, InventoryGroup, InventoryDomainTrust, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
    SBOMComponent, SBOMVulnerability, RelayAgent, AssetRelationship,
    Campaign, CampaignFinding, FindingOwnership, AssetOwnership,
    Workflow, WorkflowNode, WorkflowEdge, WorkflowExecution, WorkflowExecutionLog,
    Tag, TagAssignment, AutoTagRule, AssetTypeRule, OwnershipRule, ExternalTagSource, ExternalTagMap,
    SLAConfig, IntegrationConfig, FindingException, ScanComparison, AuditLog, AggregatedSolution,
    BenchmarkReference, AssetObservation, FindingObservation, FirewallPolicy,
)
from parsers.parser import detect_and_parse, load_intel_json
from parsers.registry import detect_parser, list_parsers, init_parsers
from services.normalizer import compute_normalized_id
from services.prioritizer import compute_priority_score
from parsers.inventory_extractor import extract_inventory_from_findings, _cn_from_dn
from services.asset_classifier import classify_asset, _is_private_ip, enrich_asset_from_os_plugins
import services.dedup as dedup_engine
import core.risk_config as risk_engine
import services.campaign_query as cq
import services.tags as tag_engine
import services.rule_engine as rule_engine
import services.asset_type_rules as asset_type_rule_engine
import services.workflow_engine as workflow_engine
from services.nlp_search import parse_nlp_query
from services.nlp_filters import apply_asset_nlp_filters, apply_finding_nlp_filters, severity_breakdown_grouped
import services.integrations as integ_module
import services.ownership_inference as ownership_inference
from services.easm import enrich_assets_from_easm
from services.asset_observations import record_observation as record_asset_observation
import services.solution_aggregator as solution_aggregator
from core.audit import log_audit, diff as _diff
from core.auth import (
    get_current_user, require_auth, require_role, require_permission,
    get_accessible_org_ids, apply_org_filter, apply_scan_org_filter,
)
from core.subscription import check_scan_limit, check_campaign_limit
from routes.auth_routes import router as auth_router
from routes.threat_intel_routes import router as threat_intel_router
from routes.export import router as export_router
from routes.config_portability import router as config_portability_router
from routes.agent_routes import router as agent_router
from routes.benchmark_routes import router as benchmark_router
from routes.easm_routes import router as easm_router
from routes.sbom_routes import router as sbom_router
from routes.vm_routes import router as vm_router
from routes.integration_builder_routes import router as integration_builder_router
from routes.discovery_routes import router as discovery_router
from routes.billing_routes import router as billing_router
from routes.copilot_routes import router as copilot_router
from routes.workflow_routes import router as workflow_router
from routes.notification_routes import router as notification_router
from routes.control_assessment_routes import router as control_assessment_router
from routes.onboarding_routes import router as onboarding_router
from routes.saml_routes import router as saml_router
from routes.relay_routes import router as relay_router, ws_router as relay_ws_router
from routes.blast_radius_routes import router as blast_radius_router
from routes.asset_routes import router as asset_router
from routes.finding_routes import router as finding_router, _finding_to_dict
from routes.report_routes import router as report_router
from routes.report_schedule_routes import router as report_schedule_router
from routes.campaign_routes import router as campaign_router
from routes.tag_routes import router as tag_router
from routes.custom_field_routes import router as custom_field_router
from routes.sla_integration_routes import router as sla_integration_router
from routes.rule_routes import router as rule_router
from routes.scan_routes import router as scan_router
from routes.admin_routes import router as admin_router
from routes.inventory_routes import router as inventory_router
from routes.siem_routes import router as siem_router
from routes.siem_ingest_routes import router as siem_ingest_router
from routes.detection_routes import router as detection_router
from routes.siem_report_routes import router as siem_report_router
from routes.graph_routes import router as graph_router
from routes.scan_planner_routes import router as scan_planner_router
from services.blast_radius import resolve_dc_asset_ids as _resolve_dc_asset_ids

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Simple TTL cache for heavy dashboard endpoints ───
import time as _time

_endpoint_cache: dict[str, tuple[float, any]] = {}
_CACHE_TTL = 30  # seconds

def _cache_get(key: str):
    """Return cached value if still valid, else None."""
    entry = _endpoint_cache.get(key)
    if entry and (_time.monotonic() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None

def _cache_set(key: str, value):
    """Store value in cache with current timestamp."""
    _endpoint_cache[key] = (_time.monotonic(), value)

def _cache_invalidate_prefix(prefix: str):
    """Invalidate all cache entries matching a prefix (call after scan upload/delete)."""
    keys_to_remove = [k for k in _endpoint_cache if k.startswith(prefix)]
    for k in keys_to_remove:
        del _endpoint_cache[k]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable public address."""
    if not ip_str:
        return False
    try:
        return not ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _apply_sort(q, model, sort_by: str, order: str, default_attr):
    """Apply ORDER BY to a query, falling back to default_attr if sort_by is invalid."""
    col = getattr(model, sort_by, None)
    if col is None:
        col = default_attr
    return q.order_by(desc(col) if order == "desc" else col)


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


_sentry_dsn = os.getenv("SENTRY_DSN")
if _sentry_dsn:
    import sentry_sdk
    sentry_sdk.init(
        dsn=_sentry_dsn,
        environment=os.getenv("ENVIRONMENT", "production"),
        send_default_pii=True,
        enable_logs=True,
        traces_sample_rate=0.2,
        profile_session_sample_rate=0.2,
        profile_lifecycle="trace",
    )

app = FastAPI(title="Hakuna Exposure Management Platform", version="1.0.0", docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/openapi.json")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global page_size guard middleware ────────────────────────────────────
# Clamp page_size query parameter to MAX_PAGE_SIZE across all endpoints.
from urllib.parse import urlencode

@app.middleware("http")
async def clamp_page_size_middleware(request: Request, call_next):
    if "page_size" in request.query_params:
        try:
            raw = int(request.query_params["page_size"])
            clamped = max(1, min(raw, MAX_PAGE_SIZE))
            if clamped != raw:
                # Rebuild query string with clamped value
                params = dict(request.query_params)
                params["page_size"] = str(clamped)
                scope = request.scope
                scope["query_string"] = urlencode(params).encode("utf-8")
        except (ValueError, TypeError):
            pass
    return await call_next(request)


app.include_router(auth_router)
app.include_router(threat_intel_router)
app.include_router(export_router)
app.include_router(config_portability_router)
app.include_router(agent_router)
app.include_router(copilot_router)
app.include_router(benchmark_router)
app.include_router(easm_router)
app.include_router(sbom_router)
app.include_router(vm_router)
app.include_router(integration_builder_router)
app.include_router(discovery_router)
app.include_router(billing_router)
app.include_router(workflow_router)
app.include_router(notification_router)
app.include_router(control_assessment_router)
app.include_router(onboarding_router)
app.include_router(saml_router)
app.include_router(relay_router)
app.include_router(relay_ws_router)
app.include_router(blast_radius_router)
app.include_router(asset_router)
app.include_router(finding_router)
app.include_router(report_router)
app.include_router(report_schedule_router)
app.include_router(campaign_router)
app.include_router(tag_router)
app.include_router(custom_field_router)
app.include_router(sla_integration_router)
app.include_router(rule_router)
app.include_router(scan_router)
app.include_router(admin_router)
app.include_router(inventory_router)
app.include_router(siem_router)
app.include_router(siem_ingest_router)
app.include_router(detection_router)
app.include_router(siem_report_router)
app.include_router(graph_router)
app.include_router(scan_planner_router)


INTEL_PATH = Path(__file__).parent / "data" / "intel.json"


# ─────────────────────────────────────────────────────────
# Audit Log Helper — imported from audit.py
# ─────────────────────────────────────────────────────────


# Maps dedup entity_type → (Model, list_fields, bool_fields) for DB-level dedup
# Canonical source: models.entity_registry — re-exported here for backward compatibility
from models.entity_registry import ENTITY_MODEL_MAP


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
    # Start integration scheduler for cron-based integration runs
    from services.integration_scheduler import start_scheduler as start_integration_scheduler
    start_integration_scheduler()
    logger.info("Integration scheduler started")
    # Start EASM scan scheduler for cron-based EASM scans
    from services.easm_scheduler import start_scheduler as start_easm_scheduler
    start_easm_scheduler()
    logger.info("EASM scan scheduler started")
    # Start report scheduler for scheduled email delivery of report PDFs
    from services.report_scheduler import start_scheduler as start_report_scheduler
    start_report_scheduler()
    logger.info("Report scheduler started")
    # Start SIEM event drain scheduler (hot → lake, every 15 min)
    try:
        from services.event_drain import start_drain_scheduler
        start_drain_scheduler()
    except Exception as exc:
        logger.error("Event drain scheduler failed to start: %s", exc)
    # Start SIEM detection engine (rule evaluator, every 1 min)
    try:
        from services.detection_engine import start_detection_scheduler
        start_detection_scheduler()
    except Exception as exc:
        logger.error("Detection engine scheduler failed to start: %s", exc)
    # Start SIEM lake maintenance + hot retention scheduler
    try:
        from services.lake_maintenance import start_maintenance_scheduler
        start_maintenance_scheduler()
    except Exception as exc:
        logger.error("Lake maintenance scheduler failed to start: %s", exc)
    # Schedule threat intel auto-update every 24 hours
    from threat_intel.intel_updater import update_intel
    from apscheduler.schedulers.background import BackgroundScheduler as _BGScheduler
    from apscheduler.triggers.interval import IntervalTrigger as _IntervalTrigger
    _intel_scheduler = _BGScheduler()
    _intel_scheduler.add_job(update_intel, _IntervalTrigger(hours=24), id="intel_update", replace_existing=True)
    # Patch catalog aggregator — daily sync at 3 AM UTC
    from threat_intel.threat_intel_sync import sync_all_patch_advisories as _sync_patches
    from apscheduler.triggers.cron import CronTrigger as _CronTrigger
    def _run_patch_catalog_sync():
        from core.database import SessionLocal as _SL
        _db = _SL()
        try:
            _sync_patches(_db)
        except Exception as _exc:
            logger.warning("Scheduled patch catalog sync failed: %s", _exc)
        finally:
            _db.close()
    _intel_scheduler.add_job(_run_patch_catalog_sync, _CronTrigger(hour=3, minute=0), id="patch_catalog_sync", replace_existing=True)
    _intel_scheduler.start()
    logger.info("Intel auto-update scheduled (every 24h) + patch catalog sync (daily 3 AM)")
    # Schedule audit log retention purge (90-day TTL, runs daily)
    from core.audit import purge_expired_audit_logs
    _audit_scheduler = _BGScheduler()
    _audit_scheduler.add_job(purge_expired_audit_logs, _IntervalTrigger(hours=24), id="audit_log_purge", replace_existing=True)
    _audit_scheduler.start()
    purge_expired_audit_logs()  # run once at startup
    logger.info("Audit log retention purge scheduled (every 24h, 90-day TTL)")
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
    # ENTITY_MODEL_MAP is now populated at import time via models.entity_registry
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

def _find_duplicate_scan(db: Session, scan_name: str, scan_date, org_id) -> Optional[Scan]:
    """Find an existing scan with matching (scan_name, scan_date, org_id)."""
    q = db.query(Scan).filter(Scan.scan_name == scan_name)
    if scan_date:
        q = q.filter(Scan.scan_date == scan_date)
    if org_id is not None:
        q = q.filter(Scan.org_id == org_id)
    else:
        q = q.filter(Scan.org_id.is_(None))
    return q.first()


def _delete_scan_cascade(db: Session, scan: Scan):
    """Delete a scan and all its dependent records (inventory, aggregations, etc.).

    Assets and findings that were deduplicated with data from other scans are
    preserved — only the observations originating from this scan are removed.
    """
    scan_id = scan.id

    # ── Scan-level child records ────────────────────────────────────────
    # SBOM records (vulns before components due to FK)
    sbom_comp_ids = [c[0] for c in db.query(SBOMComponent.id).filter(SBOMComponent.scan_id == scan_id).all()]
    if sbom_comp_ids:
        db.query(SBOMVulnerability).filter(SBOMVulnerability.component_id.in_(sbom_comp_ids)).delete(synchronize_session=False)
    db.query(SBOMComponent).filter(SBOMComponent.scan_id == scan_id).delete(synchronize_session=False)
    # Aggregated solutions — nullify FK references first to avoid constraint violation
    db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.aggregated_solution_id.isnot(None),
    ).update({"aggregated_solution_id": None}, synchronize_session=False)
    db.query(AggregatedSolution).filter(AggregatedSolution.scan_id == scan_id).delete(synchronize_session=False)
    # Inventory models
    for InvModel in [
        InventoryUser, InventoryGroup, InventoryService, InventoryNetConn,
        InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
        InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
        InventoryDomainTrust,
    ]:
        db.query(InvModel).filter(InvModel.scan_id == scan_id).delete(synchronize_session=False)
    # Scan comparisons
    db.query(ScanComparison).filter(
        (ScanComparison.base_scan_id == scan_id) | (ScanComparison.compare_scan_id == scan_id)
    ).delete(synchronize_session=False)

    # ── Remove observations that belong to this scan ────────────────────
    db.query(AssetObservation).filter(AssetObservation.scan_id == scan_id).delete(synchronize_session=False)
    db.query(FindingObservation).filter(FindingObservation.scan_id == scan_id).delete(synchronize_session=False)
    db.flush()  # ensure observation rows are gone before the survival check

    # ── Identify assets/findings that survive (have observations from other scans) ──
    all_asset_ids = {a[0] for a in db.query(Asset.id).filter(Asset.scan_id == scan_id).all()}
    surviving_asset_ids: set[int] = set()
    if all_asset_ids:
        surviving_asset_ids = {
            row[0] for row in
            db.query(AssetObservation.asset_id)
            .filter(AssetObservation.asset_id.in_(all_asset_ids))
            .distinct()
            .all()
        }

    all_finding_ids = {f[0] for f in db.query(Finding.id).filter(Finding.scan_id == scan_id).all()}
    surviving_finding_ids: set[int] = set()
    if all_finding_ids:
        surviving_finding_ids = {
            row[0] for row in
            db.query(FindingObservation.finding_id)
            .filter(FindingObservation.finding_id.in_(all_finding_ids))
            .distinct()
            .all()
        }

    # Also keep findings that belong to surviving assets even if the finding
    # itself doesn't have observations from other scans — the finding may have
    # been created by this scan but the parent asset is shared.  However, if the
    # finding has no other observations it genuinely only came from this scan, so
    # we still delete it.  (Findings on surviving assets that DO have other
    # observations are already in surviving_finding_ids.)

    # ── Reassign surviving assets to another scan ───────────────────────
    for asset_id in surviving_asset_ids:
        # Pick the most-recent observation's scan_id as the new owner
        newest_obs = (
            db.query(AssetObservation)
            .filter(AssetObservation.asset_id == asset_id)
            .order_by(AssetObservation.last_seen.desc())
            .first()
        )
        new_scan_id = newest_obs.scan_id if newest_obs and newest_obs.scan_id else None
        if new_scan_id:
            db.query(Asset).filter(Asset.id == asset_id).update(
                {"scan_id": new_scan_id}, synchronize_session=False
            )
        # Update source_systems to reflect remaining observations only
        remaining_sources = [
            row[0] for row in
            db.query(AssetObservation.source_system)
            .filter(AssetObservation.asset_id == asset_id)
            .distinct()
            .all()
        ]
        db.query(Asset).filter(Asset.id == asset_id).update(
            {"source_systems": remaining_sources}, synchronize_session=False
        )

    # ── Reassign surviving findings to another scan ─────────────────────
    for finding_id in surviving_finding_ids:
        newest_obs = (
            db.query(FindingObservation)
            .filter(FindingObservation.finding_id == finding_id)
            .order_by(FindingObservation.last_seen.desc())
            .first()
        )
        new_scan_id = newest_obs.scan_id if newest_obs and newest_obs.scan_id else None
        if new_scan_id:
            db.query(Finding).filter(Finding.id == finding_id).update(
                {"scan_id": new_scan_id}, synchronize_session=False
            )
        remaining_sources = [
            row[0] for row in
            db.query(FindingObservation.source_system)
            .filter(FindingObservation.finding_id == finding_id)
            .distinct()
            .all()
        ]
        db.query(Finding).filter(Finding.id == finding_id).update(
            {"source_systems": remaining_sources}, synchronize_session=False
        )

    db.flush()  # commit reassignments before cascade

    # ── Clean up association rows for assets/findings that WILL be deleted ──
    doomed_asset_ids = all_asset_ids - surviving_asset_ids
    doomed_finding_ids = all_finding_ids - surviving_finding_ids
    if doomed_asset_ids:
        db.query(AssetOwnership).filter(AssetOwnership.asset_id.in_(doomed_asset_ids)).delete(synchronize_session=False)
        db.query(TagAssignment).filter(TagAssignment.asset_id.in_(doomed_asset_ids)).delete(synchronize_session=False)
    if doomed_finding_ids:
        db.query(FindingOwnership).filter(FindingOwnership.finding_id.in_(doomed_finding_ids)).delete(synchronize_session=False)
        db.query(CampaignFinding).filter(CampaignFinding.finding_id.in_(doomed_finding_ids)).delete(synchronize_session=False)
        db.query(TagAssignment).filter(TagAssignment.finding_id.in_(doomed_finding_ids)).delete(synchronize_session=False)

    # ── Clear references from other tables ──────────────────────────────
    db.query(Finding).filter(Finding.auto_resolved_by_scan_id == scan_id).update(
        {"auto_resolved_by_scan_id": None}, synchronize_session=False
    )
    db.query(Campaign).filter(Campaign.scan_id == scan_id).update(
        {"scan_id": None}, synchronize_session=False
    )

    # ORM cascade deletes only assets/findings still pointing at this scan
    # (the surviving ones were already reassigned above).
    db.delete(scan)
    db.flush()


def _run_scan_ingest(
    scan_id: int,
    content: bytes,
    filename: str,
    effective_org_id: int,
    user_id: int,
    user_email: str,
    user_display_name: Optional[str],
):
    """Synchronous scan processing — runs in a thread pool with its own DB session."""
    from core.database import SessionLocal
    db = SessionLocal()

    class _AuditUser:
        def __init__(self):
            self.id = user_id
            self.email = user_email
            self.display_name = user_display_name
            self.org_id = effective_org_id

    mock_user = _AuditUser()

    try:
        # Load CVE intel
        intel = load_intel_json(str(INTEL_PATH)) if INTEL_PATH.exists() else {}

        # Detect parser
        source_parser = detect_parser(content, filename or "")
        if not source_parser:
            db.query(Scan).filter(Scan.id == scan_id).update({"status": "failed"})
            db.commit()
            return

        # Parse file
        try:
            parsed = source_parser.parse(content, filename)
        except Exception as e:
            logger.exception(f"Scan {scan_id} parse error")
            db.query(Scan).filter(Scan.id == scan_id).update({"status": "failed"})
            db.commit()
            return

        # Fetch stub scan and update with real metadata
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} missing during background processing")
            return

        scan_data = parsed["scan"]
        _scan_name = scan_data.get("scan_name") or filename
        _scan_date = scan_data.get("scan_date")

        # Duplicate scan detection (exclude this stub scan)
        dup_q = db.query(Scan).filter(
            Scan.id != scan_id,
            Scan.scan_name == _scan_name,
            Scan.org_id == effective_org_id,
        )
        if _scan_date:
            dup_q = dup_q.filter(Scan.scan_date == _scan_date)
        else:
            dup_q = dup_q.filter(Scan.scan_date.is_(None))
        existing_scan = dup_q.first()
        if existing_scan:
            logger.info(f"Replacing existing scan '{_scan_name}' (id={existing_scan.id}) with re-upload")
            _delete_scan_cascade(db, existing_scan)

        # Update stub with real scan metadata
        scan.scan_name = _scan_name
        scan.scan_date = _scan_date
        scan.scan_type = scan_data.get("scan_type")
        scan.scanner_ip = scan_data.get("scanner_ip")
        scan.nessus_version = scan_data.get("nessus_version")
        scan.policy_used = scan_data.get("policy_used")
        scan.source_type = source_parser.source_type
        scan.source_version = scan_data.get("scanner_version") or scan_data.get("nessus_version")
        scan.raw_metadata = scan_data
        db.flush()

        # Load configs once (used throughout the upload)
        risk_cfg = risk_engine.load_config_for_org(db, effective_org_id)
        dedup_cfg = dedup_engine.load_config()

        # Within-scan asset dedup: collapse duplicate hosts before creating DB records
        parsed_assets = parsed["assets"]
        if dedup_cfg.get("enabled") and dedup_cfg.get("apply_on_upload"):
            before = len(parsed_assets)
            parsed_assets = dedup_engine.dedup_asset_records(parsed_assets, dedup_cfg)
            if len(parsed_assets) < before:
                logger.info(f"Within-scan asset dedup: {before} → {len(parsed_assets)} assets")

        # Create Asset records
        asset_map = {}  # hostname/ip → Asset (populated with both keys for reliable lookup)
        for asset_data in parsed_assets:
            # Determine criticality: auto-rules if configured, else default 5
            auto_crit = None
            if risk_cfg.get("auto_apply_rules_on_upload"):
                auto_crit = risk_engine.evaluate_criticality_rules(asset_data, risk_cfg)

            # Enrich asset_data with scan-level context for classification
            asset_data["scanner_type"] = scan_data.get("scanner_type")
            asset_data["source_type"] = source_parser.source_type

            # Low-code asset-type rules: evaluate first, override parser defaults
            type_rule_result = asset_type_rule_engine.evaluate_asset_type_rules(
                asset_data, db,
                org_id=scan.org_id,
                source_type=source_parser.source_type,
            )
            if type_rule_result:
                asset_data["asset_type"] = type_rule_result["asset_type"]
                asset_data["asset_identity"] = type_rule_result["asset_identity"]
                asset_data["asset_attributes"] = {
                    **asset_data.get("asset_attributes", {}),
                    **type_rule_result["asset_attributes"],
                }

            ctx = classify_asset(asset_data)
            # Internet-facing = public IP scanned by an external/cloud scanner
            is_ext_scanner = scan_data.get("scanner_type") in ("cloud", "external")
            is_facing = _is_public_ip(asset_data.get("ip")) and is_ext_scanner
            # Criticality cascade: auto-rules → business-context baseline → default 5
            effective_crit = (
                auto_crit if auto_crit is not None
                else ctx.get("context_criticality") or 5
            )
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
                system_type=asset_data.get("system_type"),
                is_internet_facing=is_facing,
                criticality=effective_crit,
                critical_count=asset_data.get("critical_count", 0),
                high_count=asset_data.get("high_count", 0),
                medium_count=asset_data.get("medium_count", 0),
                low_count=asset_data.get("low_count", 0),
                info_count=asset_data.get("info_count", 0),
                environment_tag=ctx["environment_tag"],
                business_context=ctx["business_context"],
                source_systems=[source_parser.source_type],
                asset_type=asset_data.get("asset_type", "host"),
                asset_identity=asset_data.get("asset_identity") or {
                    k: v for k, v in {
                        "ip": asset_data.get("ip"),
                        "hostname": asset_data.get("hostname"),
                        "fqdn": asset_data.get("fqdn"),
                    }.items() if v
                },
                asset_attributes=asset_data.get("asset_attributes", {}),
            )
            db.add(asset)
            db.flush()
            # Record per-source observation
            record_asset_observation(
                db, asset_id=asset.id,
                source_system=source_parser.source_type,
                raw_fields=asset_data, scan_id=scan.id, org_id=scan.org_id,
            )
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
        _pending_finding_obs = []
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
                source_systems=[source_parser.source_type],
            )
            db.add(finding)
            _pending_finding_obs.append((finding, finding_data))

        db.flush()

        # Record per-source observations for all findings (IDs now assigned after flush)
        from services.asset_observations import record_finding_observation
        for finding, finding_data in _pending_finding_obs:
            record_finding_observation(
                db, finding_id=finding.id,
                source_system=source_parser.source_type,
                raw_fields=finding_data,
                scan_id=scan.id, org_id=scan.org_id,
            )

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
        _reconcile_findings_delta(db, scan)

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

        # ── Enrich assets with OS identification (11936) and CPE (45590) ──
        os_plugin_findings = db.query(Finding).filter(
            Finding.scan_id == scan.id,
            Finding.plugin_id.in_(["11936", "45590"]),
        ).all()
        # Group by asset_id
        _os_enrich: dict[int, dict[str, str]] = {}
        for f_os in os_plugin_findings:
            bucket = _os_enrich.setdefault(f_os.asset_id, {})
            bucket[f_os.plugin_id] = f_os.plugin_output or ""
        for aid, plugins in _os_enrich.items():
            asset = db.query(Asset).filter(Asset.id == aid).first()
            if asset:
                enrich_asset_from_os_plugins(
                    asset,
                    plugin_11936_output=plugins.get("11936"),
                    plugin_45590_output=plugins.get("45590"),
                )

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
                                              "name", "version", "installed_on", "vendor", "category",
                                              "auto_update_status"]),
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

        # ── Enhanced internet-reachability detection (uses inventory data) ──
        try:
            reachability_stats = _apply_reachability_detection(db, scan.id)
            if reachability_stats["newly_flagged"]:
                logger.info(f"Reachability detection: {reachability_stats['newly_flagged']} asset(s) newly flagged as internet-facing")
        except Exception as e:
            db.rollback()
            logger.warning(f"Reachability detection failed (non-fatal): {e}")

        # ── Risk scores now recomputed inside finalize_scan (post-ingest pipeline) ──

        # ── Detect security controls from services + software (catalog matching) ──
        try:
            from parsers.inventory_extractor import detect_security_controls_from_inventory
            sc_count = detect_security_controls_from_inventory(db, scan.id)
            if sc_count:
                logger.info(f"Security catalog: {sc_count} controls detected for scan {scan.id}")
        except Exception as e:
            db.rollback()
            logger.warning(f"Security catalog detection failed (non-fatal): {e}")

        # ── Build SBOM from inventory software + findings correlation ──
        try:
            from services.sbom_pipeline import build_sbom_from_inventory
            sbom_stats = build_sbom_from_inventory(db, scan.id)
            if sbom_stats.get("components"):
                logger.info(f"SBOM: {sbom_stats}")
        except Exception as e:
            db.rollback()
            logger.warning(f"SBOM pipeline failed (non-fatal): {e}")

        # ── Post-ingest pipeline: auto-tag, ownership, exceptions, SLA, dedup, etc. ──
        from services.post_ingest import finalize_scan
        finalize_scan(db, scan_id=scan.id, org_id=effective_org_id)

        total_findings = len(parsed["findings"])
        total_assets = len(asset_map)
        logger.info(f"Ingested scan '{filename}': {total_assets} assets, {total_findings} findings")
        log_audit(db, "create", "scan", scan.id,
                  entity_name=scan.scan_name or filename,
                  changes={"filename": filename, "assets": total_assets, "findings": total_findings},
                  actor=mock_user)

        # ── Notifications ──
        from services.notifications import create_notification
        create_notification(db, effective_org_id, "scan_complete",
            f"Scan '{scan.scan_name or filename}' completed",
            body=f"{total_assets} assets, {total_findings} findings processed",
            link=f"/findings?scan_id={scan.id}",
            entity_type="scan", entity_id=scan.id,
            metadata={"assets": total_assets, "findings": total_findings, "scan_name": scan.scan_name or filename})
        crit_high = db.query(Finding).filter(
            Finding.scan_id == scan.id, Finding.severity >= 3
        ).count()
        if crit_high > 0:
            create_notification(db, effective_org_id, "critical_findings",
                f"{crit_high} critical/high findings in '{scan.scan_name or filename}'",
                link=f"/findings?scan_id={scan.id}&severity=3,4",
                entity_type="scan", entity_id=scan.id,
                metadata={"count": crit_high, "scan_name": scan.scan_name or filename})
        new_assets = db.query(Asset).filter(
            Asset.scan_id == scan.id, Asset.times_seen == 1
        ).count()
        if new_assets > 0:
            create_notification(db, effective_org_id, "new_assets",
                f"{new_assets} new assets discovered in '{scan.scan_name or filename}'",
                link=f"/assets?scan_id={scan.id}",
                entity_type="scan", entity_id=scan.id,
                metadata={"count": new_assets, "scan_name": scan.scan_name or filename})

        scan.status = "completed"
        db.commit()
        _endpoint_cache.clear()

    except Exception as e:
        logger.exception(f"Background scan processing failed for scan {scan_id}: {e}")
        try:
            db.rollback()
            db.query(Scan).filter(Scan.id == scan_id).update({"status": "failed"})
            db.commit()
        except Exception:
            pass
    finally:
        db.close()


async def _background_process_scan(
    scan_id: int,
    content: bytes,
    filename: str,
    effective_org_id: int,
    user_id: int,
    user_email: str,
    user_display_name: Optional[str],
):
    """Async wrapper — runs _run_scan_ingest in a thread pool so the event loop stays free."""
    import asyncio
    await asyncio.to_thread(
        _run_scan_ingest, scan_id, content, filename, effective_org_id,
        user_id, user_email, user_display_name,
    )


@app.post("/api/upload", dependencies=[Depends(check_scan_limit)])
async def upload_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Upload and parse a vulnerability scan file (Nessus, Qualys, etc.)."""
    content = await file.read()
    effective_org_id = int(x_org_context) if x_org_context else user.org_id

    # Quick format validation (fast — just checks extension/header bytes)
    source_parser = detect_parser(content, file.filename or "")
    if not source_parser:
        supported = [ext for p in list_parsers() for ext in p["extensions"]]
        raise HTTPException(400, f"Unsupported file type. Accepted: {', '.join(supported)}")

    # Create stub scan record immediately so the client gets a scan_id right away
    scan = Scan(
        org_id=effective_org_id,
        filename=file.filename,
        scan_name=file.filename,  # updated with real name once parsed in background
        source_type=source_parser.source_type,
        status="processing",
    )
    db.add(scan)
    db.flush()
    scan_id = scan.id
    db.commit()

    # Schedule all heavy processing in a background thread (does NOT block the event loop)
    background_tasks.add_task(
        _background_process_scan,
        scan_id,
        content,
        file.filename,
        effective_org_id,
        user.id,
        user.email,
        getattr(user, "display_name", None),
    )

    return {
        "scan_id": scan_id,
        "scan_name": file.filename,
        "status": "processing",
        "assets": 0,
        "findings": 0,
        "delta": {},
        "message": "Scan uploaded, processing in background",
    }


# ─────────────────────────────────────────────
# Large file upload via GCS signed URL
# ─────────────────────────────────────────────

GCS_SCAN_BUCKET = os.environ.get("GCS_BUCKET")


def _get_gcs_client():
    from google.cloud import storage as gcs
    return gcs.Client()


class SignedUrlRequest(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"


@app.post("/api/upload/signed-url")
async def get_upload_signed_url(body: SignedUrlRequest, user: User = Depends(require_auth)):
    """Generate a GCS signed URL for direct browser upload (bypasses Cloud Run 32MB limit)."""
    if not GCS_SCAN_BUCKET:
        raise HTTPException(501, "GCS upload not configured (GCS_BUCKET env var missing)")

    import uuid as _uuid
    blob_name = f"uploads/{_uuid.uuid4().hex}/{body.filename}"

    client = _get_gcs_client()
    bucket = client.bucket(GCS_SCAN_BUCKET)
    blob = bucket.blob(blob_name)

    url = blob.generate_signed_url(
        version="v4",
        expiration=datetime.utcnow() + timedelta(minutes=30),
        method="PUT",
        content_type=body.content_type,
    )

    return {"url": url, "blob_name": blob_name}


class GcsIngestRequest(BaseModel):
    blob_name: str
    filename: str


@app.post("/api/upload/gcs")
async def ingest_from_gcs(body: GcsIngestRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require_auth), x_org_context: Optional[str] = Header(None, alias="X-Org-Context")):
    """Process a scan file already uploaded to GCS via signed URL."""
    if not GCS_SCAN_BUCKET:
        raise HTTPException(501, "GCS upload not configured")

    client = _get_gcs_client()
    bucket = client.bucket(GCS_SCAN_BUCKET)
    blob = bucket.blob(body.blob_name)

    if not blob.exists():
        raise HTTPException(404, "Uploaded file not found in storage")

    content = blob.download_as_bytes()

    # Build a minimal file-like object and delegate to the existing upload handler
    class _GcsFile:
        def __init__(self, filename, data):
            self.filename = filename
            self._data = data
        async def read(self):
            return self._data

    fake_file = _GcsFile(body.filename, content)
    return await upload_scan(file=fake_file, background_tasks=background_tasks, db=db, user=user, x_org_context=x_org_context)
# ─────────────────────────────────────────────
# Risk Score Helpers
# ─────────────────────────────────────────────

def _get_asset_inventory_context(db: Session, asset_id: int, asset: "Asset | None" = None) -> dict:
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
    # Internet-facing: prefer persisted flag (set by reachability detector + upload heuristics)
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


def _apply_reachability_detection(db: Session, scan_id: int) -> dict:
    """Run enhanced reachability detection for all assets in a scan."""
    from services.reachability_detector import detect_internet_reachability

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    newly_flagged = 0
    updated = 0

    for asset in assets:
        # Gather inventory data
        netconns = [
            {"state": nc.state, "remote_addr": nc.remote_addr, "local_port": nc.local_port}
            for nc in db.query(InventoryNetConn).filter(InventoryNetConn.asset_id == asset.id).all()
        ]
        certificates = [
            {
                "is_self_signed": c.is_self_signed,
                "issuer_o": c.issuer_o,
                "issuer_cn": c.issuer_cn,
                "subject_cn": c.subject_cn,
            }
            for c in db.query(InventoryCertificate).filter(InventoryCertificate.asset_id == asset.id).all()
        ]
        # Only fetch plugin_output for relevant families (performance)
        findings_q = db.query(Finding.plugin_family, Finding.plugin_output).filter(
            Finding.asset_id == asset.id,
        ).all()
        findings = [
            {"plugin_family": f.plugin_family, "plugin_output": f.plugin_output}
            for f in findings_q
        ]

        result = detect_internet_reachability(
            asset_ip=asset.ip or "",
            environment_tag=asset.environment_tag or "",
            netconns=netconns,
            certificates=certificates,
            findings=findings,
            easm_data=asset.easm_data,
        )

        if not result.is_internet_facing:
            continue

        # Only upgrade — never downgrade an existing flag
        was_flagged = asset.is_internet_facing or False
        existing_rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}.get(
            asset.internet_facing_confidence or "", 0
        )
        new_rank = {"confirmed": 4, "high": 3, "medium": 2, "low": 1}.get(
            result.confidence or "", 0
        )

        if not was_flagged or new_rank > existing_rank:
            asset.is_internet_facing = True
            asset.internet_facing_confidence = result.confidence
            # Merge methods (keep existing + add new)
            existing_methods = asset.internet_facing_methods or []
            merged = list(dict.fromkeys(existing_methods + result.methods))
            asset.internet_facing_methods = merged
            updated += 1
            if not was_flagged:
                newly_flagged += 1

    if updated:
        db.commit()

    return {"newly_flagged": newly_flagged, "updated": updated, "total_assets": len(assets)}


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
        inv_ctx = _get_asset_inventory_context(db, asset.id, asset=asset)
        asset.risk_score = risk_engine.compute_asset_risk_score(
            findings_dicts,
            asset_criticality=asset.criticality or 5,
            inventory=inv_ctx,
            cfg=cfg,
        )
    db.commit()



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
    """Seed SLAConfig rows with defaults if they don't exist yet.
    Delegates to services.sla_engine — kept here for backward compatibility."""
    from services.sla_engine import ensure_sla_defaults
    ensure_sla_defaults(db)


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
    Delegates to services.sla_engine — kept here for backward compatibility."""
    from services.sla_engine import recalculate_sla_for_scan
    return recalculate_sla_for_scan(db, scan_id, configs)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)


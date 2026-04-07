"""
SLA Tracking, Integrations (legacy), Global Exceptions/Waivers, and Aggregated Solutions routes.
Extracted from app.py.
"""
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from core.database import get_db
from core.audit import log_audit, diff as _diff
from core.auth import (
    get_current_user, get_accessible_org_ids,
    apply_org_filter, apply_scan_org_filter,
)
from models.models import (
    User, Scan, Asset, Finding,
    SLAConfig, IntegrationConfig, FindingException, AggregatedSolution,
)
import services.integrations as integ_module
import services.solution_aggregator as solution_aggregator
import services.rule_engine as rule_engine
from routes.finding_routes import _finding_to_dict

router = APIRouter()

# ─── Simple TTL cache (local — mirrors the one in app.py) ────────────────────
import time as _time

_endpoint_cache: dict = {}
_CACHE_TTL = 30  # seconds


def _cache_get(key: str):
    entry = _endpoint_cache.get(key)
    if entry and (_time.monotonic() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def _cache_set(key: str, value):
    _endpoint_cache[key] = (_time.monotonic(), value)


# ─── SLA helpers ─────────────────────────────────────────────────────────────

def _ensure_sla_defaults(db: Session):
    """Seed SLAConfig rows with defaults if they don't exist yet."""
    from services.sla_engine import ensure_sla_defaults
    ensure_sla_defaults(db)


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
    """Recompute sla_due_date and sla_status for every finding in a scan."""
    from services.sla_engine import recalculate_sla_for_scan
    return recalculate_sla_for_scan(db, scan_id, configs)


# ─────────────────────────────────────────────
# SLA Tracking
# ─────────────────────────────────────────────

class SLAConfigUpdateBody(BaseModel):
    configs: list  # [{severity, days_to_remediate, warn_days_before, is_enabled}]


class SLARecalcBody(BaseModel):
    scan_id: Optional[int] = None


@router.get("/api/sla/config")
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


@router.put("/api/sla/config")
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

    # Dispatch SLA recalculation as a background job (covers all scans)
    from services.job_manager import dispatch
    from core.database import SessionLocal

    def _run_sla_after_save():
        bg_db = SessionLocal()
        try:
            _ensure_sla_defaults(bg_db)
            cfgs = bg_db.query(SLAConfig).all()
            all_scans = bg_db.query(Scan).all()
            total = 0
            for s in all_scans:
                total += _recalculate_sla_for_scan(bg_db, s.id, cfgs)
            return {"updated_findings": total}
        finally:
            bg_db.close()

    job = dispatch("sla_recalculate_after_config_save", _run_sla_after_save)
    return {"ok": True, "job_id": job.id, "poll_url": f"/api/jobs/{job.id}/status"}


@router.post("/api/sla/recalculate", status_code=202)
def recalculate_sla(
    body: SLARecalcBody = SLARecalcBody(),
):
    """Dispatch SLA recalculation as a background job. Returns job_id immediately."""
    from services.job_manager import dispatch
    from core.database import SessionLocal

    scan_id = body.scan_id

    def _run_sla_recalc():
        db = SessionLocal()
        try:
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
        finally:
            db.close()

    job = dispatch("sla_recalculate", _run_sla_recalc)
    return {"job_id": job.id, "status": job.status.value, "poll_url": f"/api/jobs/{job.id}/status"}


@router.get("/api/sla/summary")
def get_sla_summary(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return SLA compliance stats and MTTR for a scan (or all scans)."""
    _ck = f"sla_summary:{scan_id}:{sorted(org_ids or [])}"
    cached = _cache_get(_ck)
    if cached is not None:
        return cached
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

    # Counts via SQL aggregation instead of loading all findings into memory
    from sqlalchemy import case as sa_case
    count_rows = q.with_entities(
        func.count(sa_case((Finding.sla_status == "on_track", 1))).label("on_track"),
        func.count(sa_case((Finding.sla_status == "at_risk", 1))).label("at_risk"),
        func.count(sa_case((Finding.sla_status == "breached", 1))).label("breached"),
        func.count(sa_case((Finding.sla_status == "resolved", 1))).label("resolved"),
    ).first()
    counts = {
        "on_track": count_rows.on_track,
        "at_risk": count_rows.at_risk,
        "breached": count_rows.breached,
        "resolved": count_rows.resolved,
    }

    # Breached by severity via SQL
    breached_rows = q.filter(Finding.sla_status == "breached").with_entities(
        Finding.severity, func.count(Finding.id)
    ).group_by(Finding.severity).all()
    breached_by_sev = {sev: cnt for sev, cnt in breached_rows}

    # MTTR: only load resolved findings with SLA data (small subset), not ALL findings
    cfg_map = {c.severity: c for c in db.query(SLAConfig).all()}
    mttr_findings = q.filter(
        Finding.resolved_at != None, Finding.sla_due_date != None
    ).with_entities(Finding.severity, Finding.resolved_at, Finding.sla_due_date).all()

    mttr_by_sev: dict[int, list[float]] = {4: [], 3: [], 2: [], 1: [], 0: []}
    for sev, resolved_at, sla_due_date in mttr_findings:
        cfg = cfg_map.get(sev)
        if cfg:
            from datetime import timedelta
            obs_date = sla_due_date - timedelta(days=cfg.days_to_remediate)
            days = (resolved_at - obs_date).total_seconds() / 86400
            if days >= 0:
                mttr_by_sev[sev].append(days)

    avg_mttr = {}
    sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    for sev, vals in mttr_by_sev.items():
        if vals:
            avg_mttr[sev_labels[sev]] = round(sum(vals) / len(vals), 1)

    total_with_sla = sum(counts[k] for k in ("on_track", "at_risk", "breached", "resolved"))
    compliance_pct = round(
        (counts["on_track"] + counts["resolved"]) / total_with_sla * 100, 1
    ) if total_with_sla else 0

    result = {
        "on_track": counts["on_track"],
        "at_risk": counts["at_risk"],
        "breached": counts["breached"],
        "resolved": counts["resolved"],
        "total_with_sla": total_with_sla,
        "compliance_pct": compliance_pct,
        "avg_mttr_days": avg_mttr,
        "breached_by_severity": {sev_labels[k]: v for k, v in breached_by_sev.items() if v > 0},
    }
    _cache_set(_ck, result)
    return result


@router.patch("/api/findings/{finding_id}/resolve")
def resolve_finding(finding_id: int, db: Session = Depends(get_db)):
    """Mark a finding as resolved (sets resolved_at and sla_status=resolved)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.resolved_at = datetime.utcnow()
    finding.sla_status = "resolved"
    db.commit()
    _endpoint_cache.clear()
    return {"ok": True, "finding_id": finding_id, "resolved_at": finding.resolved_at.isoformat()}


@router.patch("/api/findings/{finding_id}/unresolve")
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
    _endpoint_cache.clear()
    return {"ok": True, "finding_id": finding_id, "sla_status": finding.sla_status}


# ─────────────────────────────────────────────
# Integrations (legacy)
# ─────────────────────────────────────────────

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
            {"key": "bot_token", "label": "Bot Token (for channel creation)", "type": "password", "placeholder": "xoxb-...", "required": False},
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
    "ollama": {
        "display_name": "Ollama (Local)",
        "fields": [
            {"key": "base_url", "label": "Ollama Server URL", "type": "string", "placeholder": "http://localhost:11434"},
            {"key": "default_model", "label": "Default Model", "type": "string", "placeholder": "llama3"},
        ],
    },
    "vertex_ai": {
        "display_name": "Google Vertex AI",
        "fields": [
            {"key": "project_id", "label": "GCP Project ID", "type": "string", "placeholder": "my-gcp-project"},
            {"key": "location", "label": "Region", "type": "string", "placeholder": "us-central1"},
            {"key": "default_model", "label": "Default Model", "type": "select", "options": [
                "vertex/gemini-2.5-flash", "vertex/gemini-2.5-pro", "vertex/gemini-2.0-flash",
            ]},
        ],
    },
}


@router.get("/api/integrations")
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


@router.get("/api/integrations/{provider}")
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

    response = {
        "provider": provider,
        "display_name": schema["display_name"],
        "is_enabled": cfg.is_enabled if cfg else False,
        "config": safe_config,
        "fields": schema["fields"],
        "last_test_status": cfg.last_test_status if cfg else None,
        "last_test_at": cfg.last_test_at.isoformat() if cfg and cfg.last_test_at else None,
        "last_test_detail": cfg.last_test_detail if cfg else None,
    }
    # For email, indicate whether Brevo fallback is available
    if provider == "email":
        from services.brevo import is_configured as brevo_configured
        response["brevo_available"] = brevo_configured()
    return response


class IntegrationUpdate(BaseModel):
    config: dict
    is_enabled: bool = True


@router.put("/api/integrations/{provider}")
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


@router.post("/api/integrations/{provider}/test")
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


@router.delete("/api/integrations/{provider}")
def delete_integration(provider: str, db: Session = Depends(get_db)):
    cfg = db.query(IntegrationConfig).filter(IntegrationConfig.provider == provider).first()
    if cfg:
        db.delete(cfg)
        db.commit()
    return {"status": "ok"}


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


def _check_scope_tags(db: Session, asset_id: int, scope_tags: list) -> bool:
    """Delegates to services.exception_engine — kept here for backward compatibility."""
    from services.exception_engine import _check_scope_tags as _impl
    return _impl(db, asset_id, scope_tags)


def _apply_exception_to_findings(db: Session, exc: FindingException, scan_id: int = None) -> int:
    """Apply a single exception to all matching findings. Returns count of affected findings."""
    from services.exception_engine import apply_exception_to_findings
    return apply_exception_to_findings(db, exc, scan_id=scan_id)


@router.get("/api/exceptions")
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


@router.get("/api/exceptions/condition-catalog")
def get_exception_condition_catalog(db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """Return the condition catalog for exception rules."""
    return rule_engine.get_condition_catalog(db, org_ids)


@router.post("/api/exceptions")
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


@router.get("/api/exceptions/{exception_id}")
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


@router.patch("/api/exceptions/{exception_id}")
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


@router.delete("/api/exceptions/{exception_id}")
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


@router.post("/api/exceptions/apply-all")
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
        # Downstream impact assessment (upgrade/migrate actions only)
        "downstream_impact": a.downstream_impact,
        # Operational
        "effort_level": a.effort_level,
        "owner_suggestion": a.owner_suggestion,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.get("/api/aggregated-solutions")
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

    # Collect all unique finding IDs referenced by these solutions so the
    # frontend can compute a deduplicated risk-reduction (avoiding double-
    # counting findings that appear in more than one solution group).
    all_finding_ids = set()
    for a in results:
        for fid in (a.finding_ids or []):
            all_finding_ids.add(fid)

    finding_priority_map = {}
    total_scan_risk = 0.0
    if all_finding_ids:
        result_scan_ids = list({a.scan_id for a in results})
        scan_findings = db.query(Finding.id, Finding.priority_score).filter(
            Finding.scan_id.in_(result_scan_ids)
        ).all()
        total_scan_risk = sum(f.priority_score or 0.0 for f in scan_findings)
        finding_priority_map = {
            f.id: round(f.priority_score or 0.0, 4)
            for f in scan_findings
            if f.id in all_finding_ids
        }

    return {
        "solutions": [_agg_solution_to_dict(a, db) for a in results],
        "total_scan_risk": round(total_scan_risk, 4),
        "finding_priority_map": finding_priority_map,
    }


@router.get("/api/aggregated-solutions/{agg_id}")
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


@router.post("/api/aggregated-solutions/rebuild")
def rebuild_aggregated_solutions(
    scan_id: int = Query(None),
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Re-run solution aggregation on existing scans."""
    try:
        q = db.query(Scan)
        q = apply_scan_org_filter(q, org_ids)
        if scan_id:
            q = q.filter(Scan.id == scan_id)
        scans = q.all()
        total_created = 0
        total_linked = 0
        for scan in scans:
            result = solution_aggregator.aggregate_solutions(db, scan_id=scan.id)
            total_created += result["created"]
            total_linked += result["findings_linked"]
        db.commit()
        return {"scans_processed": len(scans), "created": total_created, "findings_linked": total_linked}
    except Exception as e:
        logging.error("Error rebuilding aggregated solutions: %s", e, exc_info=True)
        raise HTTPException(500, "Failed to rebuild aggregated solutions")

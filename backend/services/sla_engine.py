"""
SLA computation engine — extracted from app.py for proper dependency direction.

Computes SLA due dates and statuses for findings based on severity-specific
deadlines and observation timestamps.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models.models import Scan, Asset, Finding, SLAConfig

logger = logging.getLogger(__name__)


_SLA_DEFAULTS = {
    4: {"label": "Critical", "days": 15,  "warn": 5,  "enabled": True},
    3: {"label": "High",     "days": 30,  "warn": 7,  "enabled": True},
    2: {"label": "Medium",   "days": 90,  "warn": 14, "enabled": True},
    1: {"label": "Low",      "days": 180, "warn": 30, "enabled": True},
    0: {"label": "Info",     "days": 365, "warn": 30, "enabled": False},
}


_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%a %b %d %H:%M:%S %Y",
    "%a %b  %d %H:%M:%S %Y",   # single-digit day with extra space
    "%b %d, %Y",
    "%d/%m/%Y",
]


def parse_nessus_date(s: str) -> Optional[datetime]:
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


def compute_sla_status(due_date, resolved_at, warn_days: int) -> str:
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


def ensure_sla_defaults(db: Session):
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


def recalculate_sla_for_scan(db: Session, scan_id: int, configs: list):
    """Recompute sla_due_date and sla_status for every finding in a scan.

    Base date priority (most accurate → fallback):
      1. asset.scan_start  — per-asset scan start from Nessus
      2. scan.scan_date    — scan-level date from the Nessus file
      3. scan.created_at   — upload timestamp (last resort)
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return 0

    cfg_map = {c.severity: c for c in configs}

    # scan-level fallback date (from Nessus file, or upload time)
    scan_fallback = parse_nessus_date(scan.scan_date) or scan.created_at or datetime.utcnow()

    # Build per-asset observation date cache
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    asset_obs_date: dict = {}
    for a in assets:
        asset_obs_date[a.id] = parse_nessus_date(a.scan_start) or scan_fallback

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    updated = 0
    for f in findings:
        cfg = cfg_map.get(f.severity)
        if not cfg or not cfg.is_enabled:
            f.sla_due_date = None
            f.sla_status = "n/a"
        else:
            base_date = asset_obs_date.get(f.asset_id, scan_fallback)
            f.sla_due_date = base_date + timedelta(days=cfg.days_to_remediate)
            f.sla_status = compute_sla_status(f.sla_due_date, f.resolved_at, cfg.warn_days_before)
        updated += 1
    db.commit()
    return updated

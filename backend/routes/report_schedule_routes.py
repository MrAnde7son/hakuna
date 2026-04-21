"""
Report Schedule routes — CRUD + run-now for scheduled PDF report emails.

A ReportSchedule attaches an email-delivery cadence to a ReportTemplate.
The scheduler service (`services.report_scheduler`) picks up these rows on
startup and re-syncs every few minutes so API edits take effect promptly.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

# Minimal sanity check: local@domain.tld with at least one dot in the domain.
# Deliberately looser than RFC 5322 — just rejects obvious garbage like
# "not-an-email" that previously slipped through and fed bad addresses into
# scheduled delivery.
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _split_recipients(recipients: str) -> List[str]:
    return [r.strip() for r in recipients.split(",") if r.strip()]

from core.auth import require_auth, get_accessible_org_ids
from core.database import get_db
from core.time_utils import iso_utc
from models.models import ReportSchedule, ReportTemplate, User

router = APIRouter()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class ReportScheduleIn(BaseModel):
    recipients: str = Field(..., description="Comma-separated email addresses")
    frequency: str = "weekly"          # daily | weekly | monthly | custom
    day_of_week: Optional[int] = None  # 0=Mon..6=Sun
    day_of_month: Optional[int] = None # 1..28
    hour: int = 8
    minute: int = 0
    cron_expression: Optional[str] = None
    timezone: str = "UTC"
    format: str = "pdf"
    name: Optional[str] = None
    subject_template: Optional[str] = None
    body_template: Optional[str] = None
    is_enabled: bool = True


class ReportSchedulePatch(BaseModel):
    recipients: Optional[str] = None
    frequency: Optional[str] = None
    day_of_week: Optional[int] = None
    day_of_month: Optional[int] = None
    hour: Optional[int] = None
    minute: Optional[int] = None
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None
    format: Optional[str] = None
    name: Optional[str] = None
    subject_template: Optional[str] = None
    body_template: Optional[str] = None
    is_enabled: Optional[bool] = None


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _serialize(s: ReportSchedule) -> dict:
    return {
        "id": s.id,
        "org_id": s.org_id,
        "report_template_id": s.report_template_id,
        "name": s.name,
        "recipients": s.recipients,
        "subject_template": s.subject_template,
        "body_template": s.body_template,
        "format": s.format,
        "frequency": s.frequency,
        "day_of_week": s.day_of_week,
        "day_of_month": s.day_of_month,
        "hour": s.hour,
        "minute": s.minute,
        "cron_expression": s.cron_expression,
        "timezone": s.timezone,
        "is_enabled": s.is_enabled,
        "last_run_at": iso_utc(s.last_run_at),
        "last_status": s.last_status,
        "last_error": s.last_error,
        "next_run_at": iso_utc(s.next_run_at),
        "created_by": s.created_by,
        "created_at": iso_utc(s.created_at),
        "updated_at": iso_utc(s.updated_at),
    }


def _load_template_scoped(
    template_id: int,
    db: Session,
    org_ids: Optional[List[int]],
) -> ReportTemplate:
    q = db.query(ReportTemplate).filter(ReportTemplate.id == template_id)
    t = q.first()
    if not t:
        raise HTTPException(404, "Report template not found")
    # Scope check: if template is org-bound, ensure the caller can see that org.
    if t.org_id is not None and org_ids is not None and t.org_id not in org_ids:
        raise HTTPException(404, "Report template not found")
    return t


def _validate_schedule_fields(data: dict) -> None:
    freq = (data.get("frequency") or "weekly").lower()
    if freq not in {"daily", "weekly", "monthly", "custom"}:
        raise HTTPException(400, f"Unsupported frequency '{freq}'")
    if freq == "custom" and not (data.get("cron_expression") or "").strip():
        raise HTTPException(400, "cron_expression is required when frequency='custom'")
    fmt = (data.get("format") or "pdf").lower()
    if fmt != "pdf":
        raise HTTPException(400, "Only 'pdf' format is supported today")
    recipients = (data.get("recipients") or "").strip()
    if not recipients:
        raise HTTPException(400, "recipients is required")
    parsed = _split_recipients(recipients)
    if not parsed:
        raise HTTPException(400, "recipients is required")
    invalid = [r for r in parsed if not _EMAIL_RE.match(r)]
    if invalid:
        raise HTTPException(400, f"Invalid recipient email(s): {', '.join(invalid)}")
    if data.get("hour") is not None and not (0 <= int(data["hour"]) <= 23):
        raise HTTPException(400, "hour must be 0..23")
    if data.get("minute") is not None and not (0 <= int(data["minute"]) <= 59):
        raise HTTPException(400, "minute must be 0..59")
    if freq == "weekly":
        dow = data.get("day_of_week")
        if dow is not None and not (0 <= int(dow) <= 6):
            raise HTTPException(400, "day_of_week must be 0..6 (0=Mon)")
    if freq == "monthly":
        dom = data.get("day_of_month")
        if dom is not None and not (1 <= int(dom) <= 28):
            raise HTTPException(400, "day_of_month must be 1..28")


def _trigger_resync():
    """Ask the scheduler to re-read schedules without waiting for the 5min tick.
    Best-effort — if the scheduler isn't running (e.g. tests) this is a no-op.
    """
    try:
        from services.report_scheduler import sync_schedules
        sync_schedules()
    except Exception:
        # Scheduler may not be started in tests / worker processes
        pass


# ─────────────────────────────────────────────
# Per-template schedule CRUD
# ─────────────────────────────────────────────

@router.get("/api/report-templates/{template_id}/schedules")
def list_schedules_for_template(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    _load_template_scoped(template_id, db, org_ids)
    rows = (
        db.query(ReportSchedule)
        .filter(ReportSchedule.report_template_id == template_id)
        .order_by(ReportSchedule.created_at.desc())
        .all()
    )
    return [_serialize(r) for r in rows]


@router.post("/api/report-templates/{template_id}/schedules")
def create_schedule_for_template(
    template_id: int,
    body: ReportScheduleIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    template = _load_template_scoped(template_id, db, org_ids)
    data = body.model_dump()
    _validate_schedule_fields(data)

    row = ReportSchedule(
        org_id=template.org_id,
        report_template_id=template.id,
        name=data.get("name") or template.name,
        recipients=data["recipients"].strip(),
        subject_template=data.get("subject_template"),
        body_template=data.get("body_template"),
        format=data.get("format") or "pdf",
        frequency=data.get("frequency") or "weekly",
        day_of_week=data.get("day_of_week"),
        day_of_month=data.get("day_of_month"),
        hour=data.get("hour", 8),
        minute=data.get("minute", 0),
        cron_expression=data.get("cron_expression"),
        timezone=data.get("timezone") or "UTC",
        is_enabled=bool(data.get("is_enabled", True)),
        created_by=user.email if user else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    _trigger_resync()
    return _serialize(row)


# ─────────────────────────────────────────────
# All-schedules list (across templates for the tenant)
# ─────────────────────────────────────────────

@router.get("/api/report-schedules")
def list_all_schedules(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(ReportSchedule)
    if org_ids is not None:
        # Allow schedules with NULL org_id (system-wide) to be visible to any
        # authenticated user; otherwise scope strictly to accessible orgs.
        q = q.filter((ReportSchedule.org_id.in_(org_ids)) | (ReportSchedule.org_id.is_(None)))
    rows = q.order_by(ReportSchedule.created_at.desc()).all()
    return [_serialize(r) for r in rows]


def _load_schedule_scoped(
    schedule_id: int,
    db: Session,
    org_ids: Optional[List[int]],
) -> ReportSchedule:
    row = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
    if not row:
        raise HTTPException(404, "Schedule not found")
    if row.org_id is not None and org_ids is not None and row.org_id not in org_ids:
        raise HTTPException(404, "Schedule not found")
    return row


@router.get("/api/report-schedules/{schedule_id}")
def get_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    return _serialize(_load_schedule_scoped(schedule_id, db, org_ids))


@router.patch("/api/report-schedules/{schedule_id}")
def update_schedule(
    schedule_id: int,
    body: ReportSchedulePatch,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    row = _load_schedule_scoped(schedule_id, db, org_ids)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}

    # Validate the merged state
    merged = {**_serialize(row), **patch}
    _validate_schedule_fields(merged)

    for k, v in patch.items():
        setattr(row, k, v)
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    _trigger_resync()
    return _serialize(row)


@router.delete("/api/report-schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    row = _load_schedule_scoped(schedule_id, db, org_ids)
    db.delete(row)
    db.commit()
    _trigger_resync()
    return {"status": "ok"}


@router.post("/api/report-schedules/{schedule_id}/run-now")
def run_schedule_now(
    schedule_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    row = _load_schedule_scoped(schedule_id, db, org_ids)
    # Fire-and-forget so the request returns immediately; delivery result is
    # recorded on the ReportSchedule row (last_status/last_error).
    from services.report_scheduler import deliver_schedule
    background.add_task(deliver_schedule, row.id)
    return {"status": "queued", "schedule_id": row.id}

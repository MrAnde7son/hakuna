"""
Report scheduler — APScheduler-based background job that delivers scheduled
report PDFs by email on the cadence configured by each ReportSchedule row.

The scheduler re-syncs from the database periodically so changes made via
the API (enable/disable, update frequency) take effect without a server
restart. A manual re-sync can also be triggered from the CRUD routes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from core.database import SessionLocal
from models.models import ReportSchedule, ReportTemplate

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler()
_started = False

_JOB_PREFIX = "report_schedule_"
_SYNC_JOB_ID = "report_schedule_resync"


# ─────────────────────────────────────────────
# Trigger builders
# ─────────────────────────────────────────────

def _trigger_for(schedule: ReportSchedule) -> Optional[CronTrigger]:
    """Build an APScheduler CronTrigger from a ReportSchedule row.

    Returns None for invalid/unparseable configs so the job is simply
    skipped rather than crashing the whole scheduler.
    """
    freq = (schedule.frequency or "weekly").lower()
    hour = int(schedule.hour or 0)
    minute = int(schedule.minute or 0)
    tz = schedule.timezone or "UTC"

    try:
        if freq == "custom" and schedule.cron_expression:
            return CronTrigger.from_crontab(schedule.cron_expression, timezone=tz)
        if freq == "daily":
            return CronTrigger(hour=hour, minute=minute, timezone=tz)
        if freq == "weekly":
            dow = schedule.day_of_week if schedule.day_of_week is not None else 0
            # APScheduler day_of_week: 0=Mon..6=Sun — same as our stored value.
            return CronTrigger(day_of_week=int(dow), hour=hour, minute=minute, timezone=tz)
        if freq == "monthly":
            dom = schedule.day_of_month if schedule.day_of_month is not None else 1
            return CronTrigger(day=int(dom), hour=hour, minute=minute, timezone=tz)
    except Exception:
        logger.exception("Invalid schedule config for report_schedule=%s", schedule.id)
        return None

    logger.warning("Unknown frequency %r on report_schedule=%s", freq, schedule.id)
    return None


# ─────────────────────────────────────────────
# Delivery
# ─────────────────────────────────────────────

def deliver_schedule(schedule_id: int) -> dict:
    """Render the schedule's report and email it to the configured recipients.

    Safe to call from API ("Run now") or from the background scheduler.
    Always records outcome on the ReportSchedule row.
    """
    db = SessionLocal()
    try:
        schedule = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
        if not schedule:
            return {"status": "error", "detail": "schedule not found"}
        if not schedule.is_enabled:
            return {"status": "skipped", "detail": "schedule disabled"}

        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == schedule.report_template_id
        ).first()
        if not template:
            _record_outcome(db, schedule, "error", "report template missing")
            return {"status": "error", "detail": "report template missing"}

        # Render PDF
        from services.report_renderer import render_report_pdf
        try:
            pdf_bytes = render_report_pdf(db, template)
        except Exception as e:
            logger.exception("[ReportSchedule %s] render failed", schedule.id)
            _record_outcome(db, schedule, "error", f"render failed: {e}")
            return {"status": "error", "detail": str(e)}

        # Send email with PDF attachment
        from services import integrations
        safe_name = (template.name or "report").replace("/", "-").strip() or "report"
        ts = datetime.utcnow().strftime("%Y%m%d")
        filename = f"{safe_name}-{ts}.pdf"

        email_config = {
            "to": schedule.recipients,
            "subject": schedule.subject_template or f"Hakuna Report: {template.name}",
            "body_template": (
                schedule.body_template
                or f"Your scheduled Hakuna report \"{template.name}\" is attached.\n"
                   f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}."
            ),
            "attachments": [{
                "filename": filename,
                "content": pdf_bytes,
                "mime_type": "application/pdf",
            }],
        }

        try:
            result = integrations.send_email(db, email_config, [])
        except Exception as e:
            logger.exception("[ReportSchedule %s] email send failed", schedule.id)
            _record_outcome(db, schedule, "error", f"email failed: {e}")
            return {"status": "error", "detail": str(e)}

        _record_outcome(db, schedule, "success", None)
        logger.info(
            "[ReportSchedule %s] delivered '%s' to %s (%d bytes)",
            schedule.id, template.name, result.get("recipients"), len(pdf_bytes),
        )
        return {"status": "success", "recipients": result.get("recipients", []),
                "bytes": len(pdf_bytes)}
    finally:
        db.close()


def _record_outcome(db, schedule: ReportSchedule, status: str, error: Optional[str]):
    schedule.last_run_at = datetime.utcnow()
    schedule.last_status = status
    schedule.last_error = error
    # Update next_run_at based on the current trigger, best-effort.
    trigger = _trigger_for(schedule)
    if trigger:
        try:
            nxt = trigger.get_next_fire_time(None, datetime.utcnow())
            if nxt:
                schedule.next_run_at = nxt.replace(tzinfo=None)
        except Exception:
            pass
    db.commit()


# ─────────────────────────────────────────────
# Scheduler lifecycle
# ─────────────────────────────────────────────

def sync_schedules():
    """Reload all enabled ReportSchedule rows into APScheduler jobs."""
    global _scheduler, _started
    if not _started:
        return

    # Remove existing schedule jobs (but keep the re-sync job itself)
    for job in _scheduler.get_jobs():
        if job.id.startswith(_JOB_PREFIX) and job.id != _SYNC_JOB_ID:
            try:
                job.remove()
            except Exception:
                pass

    db = SessionLocal()
    try:
        schedules = db.query(ReportSchedule).filter(ReportSchedule.is_enabled == True).all()
        loaded = 0
        for s in schedules:
            trigger = _trigger_for(s)
            if not trigger:
                continue
            try:
                _scheduler.add_job(
                    deliver_schedule,
                    trigger=trigger,
                    args=[s.id],
                    id=f"{_JOB_PREFIX}{s.id}",
                    replace_existing=True,
                    name=f"Report schedule #{s.id}",
                    misfire_grace_time=600,
                    coalesce=True,
                    max_instances=1,
                )
                nxt = trigger.get_next_fire_time(None, datetime.utcnow())
                if nxt:
                    s.next_run_at = nxt.replace(tzinfo=None)
                loaded += 1
            except Exception:
                logger.exception("Failed to register schedule %s", s.id)
        db.commit()
        logger.info("Synced %d report schedule(s)", loaded)
    finally:
        db.close()


def start_scheduler():
    """Start the background scheduler and hydrate it from the DB."""
    global _scheduler, _started
    if _started:
        return
    _scheduler.start()
    _started = True

    # Periodic re-sync so edits made through the API take effect
    # without having to call sync_schedules() explicitly everywhere.
    _scheduler.add_job(
        sync_schedules,
        trigger=IntervalTrigger(minutes=5),
        id=_SYNC_JOB_ID,
        replace_existing=True,
        name="Report schedule re-sync",
    )
    sync_schedules()
    logger.info("Report scheduler started")


def stop_scheduler():
    global _scheduler, _started
    if _started:
        _scheduler.shutdown(wait=False)
        _started = False

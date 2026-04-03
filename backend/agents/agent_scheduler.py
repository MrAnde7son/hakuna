"""
Agent Scheduler — runs agents on cron schedules using APScheduler.

Lightweight background scheduler that loads schedules from the DB
and executes agent runs at the configured times.
"""
import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from core.database import SessionLocal
from models.models import Agent, AgentSchedule

logger = logging.getLogger(__name__)

_scheduler = BackgroundScheduler()
_started = False


def _run_scheduled_agent(schedule_id: int):
    """Execute a single scheduled agent run.

    Uses short-lived DB sessions: one to load schedule/agent metadata,
    a second passed to run_agent for its own queries, and a third to
    record completion.  This avoids holding a connection idle for the
    full duration of an LLM-heavy agent run (potentially 5-10+ min).
    """
    # 1. Load schedule + agent metadata, then release the connection.
    db = SessionLocal()
    try:
        schedule = db.query(AgentSchedule).filter(AgentSchedule.id == schedule_id).first()
        if not schedule or not schedule.is_enabled:
            return

        agent_id = schedule.agent_id
        input_template = schedule.input_template or ""
    except Exception:
        logger.exception(f"Scheduled agent run failed loading schedule {schedule_id}")
        return
    finally:
        db.close()

    # 2. Execute the agent with its own session.
    logger.info(f"Running scheduled agent (schedule {schedule_id}, agent {agent_id})")
    run_db = SessionLocal()
    try:
        from agents.agent_engine import run_agent
        agent = run_db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            logger.warning(f"Schedule {schedule_id}: agent {agent_id} not found")
            return

        run = run_agent(agent, input_template, run_db)
        logger.info(f"Scheduled run completed: agent={agent.name}, status={run.status}, steps={run.steps_used}")
    except Exception:
        logger.exception(f"Scheduled agent run failed (schedule {schedule_id})")
    finally:
        run_db.close()

    # 3. Record last_run_at in a short-lived session.
    ts_db = SessionLocal()
    try:
        sched = ts_db.query(AgentSchedule).filter(AgentSchedule.id == schedule_id).first()
        if sched:
            sched.last_run_at = datetime.utcnow()
            ts_db.commit()
    except Exception:
        logger.exception(f"Failed to update last_run_at for schedule {schedule_id}")
    finally:
        ts_db.close()


def sync_schedules():
    """Sync all DB schedules to APScheduler jobs."""
    global _scheduler, _started

    if not _started:
        return

    # Remove all existing agent jobs
    for job in _scheduler.get_jobs():
        if job.id.startswith("agent_schedule_"):
            job.remove()

    # Load active schedules from DB
    db = SessionLocal()
    try:
        schedules = db.query(AgentSchedule).filter(AgentSchedule.is_enabled == True).all()
        for s in schedules:
            try:
                trigger = CronTrigger.from_crontab(s.cron_expression)
                _scheduler.add_job(
                    _run_scheduled_agent,
                    trigger=trigger,
                    args=[s.id],
                    id=f"agent_schedule_{s.id}",
                    replace_existing=True,
                    name=f"Agent schedule #{s.id}",
                )
                # Update next_run_at
                next_fire = trigger.get_next_fire_time(None, datetime.now())
                if next_fire:
                    s.next_run_at = next_fire
            except Exception:
                logger.exception(f"Failed to schedule agent job {s.id}: bad cron '{s.cron_expression}'")
        db.commit()
        logger.info(f"Synced {len(schedules)} agent schedules")
    finally:
        db.close()


def start_scheduler():
    """Start the background scheduler and load initial schedules."""
    global _scheduler, _started
    if _started:
        return

    _scheduler.start()
    _started = True
    sync_schedules()
    logger.info("Agent scheduler started")


def stop_scheduler():
    """Shut down the scheduler gracefully."""
    global _scheduler, _started
    if _started:
        _scheduler.shutdown(wait=False)
        _started = False

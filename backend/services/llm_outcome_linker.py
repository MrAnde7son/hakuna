"""Outcome linker + retention cleanup for llm_interactions.

Runs on an interval (APScheduler, every 5 min). For each interaction that
has no outcome row yet, we resolve outcome signals from existing tables:
AgentRun status, AgentApproval decisions, Finding status transitions on
findings touched by the run's tool_calls, WorkflowExecution status.

The aggregated outcome_score in [-1, +1] is what the retrieval path ranks
by — so this is the signal that makes the feedback loop useful, not the
logs themselves.

Retention: interactions older than LLM_FEEDBACK_RETENTION_DAYS (default 90)
are deleted. Interactions without a linked outcome_score after 30 days are
also deleted — they're unscored and take up space without improving
retrieval quality.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from core.database import SessionLocal

logger = logging.getLogger(__name__)

_RETENTION_DAYS = int(os.environ.get("LLM_FEEDBACK_RETENTION_DAYS", "90"))
_UNSCORED_RETENTION_DAYS = int(os.environ.get("LLM_FEEDBACK_UNSCORED_RETENTION_DAYS", "30"))

_scheduler: Optional[BackgroundScheduler] = None


# ── Signal → score mapping ─────────────────────────────────────────────

def _approval_score(status: Optional[str]) -> Optional[float]:
    if status == "approved":
        return 1.0
    if status == "rejected":
        return -1.0
    if status == "expired":
        return -0.3
    return None


def _run_status_score(status: Optional[str]) -> Optional[float]:
    if status == "done":
        return 0.5
    if status == "failed":
        return -0.7
    return None


def _finding_score(status: Optional[str]) -> Optional[float]:
    if status in ("remediated", "resolved", "fixed"):
        return 1.0
    if status == "false_positive":
        return -1.0
    return None


# ── Linking logic ──────────────────────────────────────────────────────

def _link_agent_interaction(db: Session, interaction) -> tuple[dict, Optional[float]]:
    """Resolve outcome signals for a surface='agent' interaction."""
    from models.models import AgentRun, AgentApproval

    signals: dict = {}
    scores: list[float] = []

    if not interaction.agent_run_id:
        return signals, None

    run = db.query(AgentRun).filter(AgentRun.id == interaction.agent_run_id).first()
    if run:
        s = _run_status_score(run.status)
        if s is not None:
            signals["workflow_outcome"] = run.status
            scores.append(s)

    # HITL approval — the strongest explicit signal we have today.
    approval = (
        db.query(AgentApproval)
          .filter(AgentApproval.agent_run_id == interaction.agent_run_id)
          .order_by(AgentApproval.id.desc())
          .first()
    )
    if approval:
        s = _approval_score(approval.status)
        if s is not None:
            signals["approval_outcome"] = approval.status
            scores.append(s * 1.5)  # weight explicit human sign-off highest

    if not scores:
        return signals, None
    composite = max(-1.0, min(1.0, sum(scores) / len(scores)))
    return signals, composite


def _link_finding_ref_interaction(db: Session, interaction) -> tuple[dict, Optional[float]]:
    """Resolve outcome for interactions that reference a specific finding
    (surface_ref_type='finding', e.g. vuln_validator, alert_triage)."""
    from models.models import Finding

    signals: dict = {}
    if interaction.surface_ref_type != "finding" or not interaction.surface_ref_id:
        return signals, None

    try:
        fid = int(interaction.surface_ref_id)
    except (TypeError, ValueError):
        return signals, None

    finding = db.query(Finding).filter(Finding.id == fid).first()
    if not finding:
        return signals, None

    # Only score once the finding has reached a terminal state — we don't
    # want to lock in a "still_open" score for a finding that might still
    # be remediated tomorrow.
    s = _finding_score(getattr(finding, "status", None))
    if s is None:
        # Age-gate: findings open > 30d after the interaction without
        # transition are treated as mild negative signal.
        age = datetime.utcnow() - interaction.created_at
        if age > timedelta(days=30):
            signals["finding_outcome"] = "still_open_30d"
            return signals, -0.2
        return signals, None

    signals["finding_outcome"] = finding.status
    return signals, s


def _link_one(db: Session, interaction) -> bool:
    """Attempt to link a single interaction. Returns True if an outcome was
    written."""
    from models.models import LLMInteractionOutcome

    if interaction.surface == "agent":
        signals, score = _link_agent_interaction(db, interaction)
    else:
        signals, score = _link_finding_ref_interaction(db, interaction)

    if score is None:
        return False

    outcome = LLMInteractionOutcome(
        interaction_id=interaction.id,
        org_id=interaction.org_id,
        outcome_score=score,
        computed_at=datetime.utcnow(),
        **signals,
    )
    db.add(outcome)
    return True


# ── Public entry points ────────────────────────────────────────────────

def run_linker(batch_size: int = 500) -> int:
    """Link outcome signals for recent unscored interactions. Returns count linked."""
    from models.models import LLMInteraction, LLMInteractionOutcome

    db = SessionLocal()
    linked = 0
    try:
        # Candidates: interactions with no outcome row yet.
        candidates = (
            db.query(LLMInteraction)
              .outerjoin(LLMInteractionOutcome, LLMInteractionOutcome.interaction_id == LLMInteraction.id)
              .filter(LLMInteractionOutcome.id.is_(None))
              .order_by(LLMInteraction.created_at.asc())
              .limit(batch_size)
              .all()
        )
        for interaction in candidates:
            try:
                if _link_one(db, interaction):
                    linked += 1
            except Exception:
                logger.exception("llm_outcome_linker: failed to link interaction %s", interaction.id)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("llm_outcome_linker: batch failed")
    finally:
        db.close()

    if linked:
        logger.info("llm_outcome_linker: linked %d outcomes", linked)
    return linked


def run_embedding_backfill(batch_size: int = 100) -> int:
    """Populate the `embedding` pgvector column for interactions that
    don't have one yet. No-op on SQLite and when no API key is configured.

    Embedding target: the user input — that's what future `retrieve_exemplars`
    calls will compare against at query time.
    """
    from core.database import DATABASE_URL
    if not DATABASE_URL.startswith("postgresql"):
        return 0

    from services.llm_embeddings import embed_text
    from sqlalchemy import text as _sql

    db = SessionLocal()
    embedded = 0
    try:
        rows = db.execute(
            _sql("""
                SELECT id, messages
                FROM llm_interactions
                WHERE embedding IS NULL
                  AND status = 'ok'
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": batch_size},
        ).fetchall()

        for r in rows:
            try:
                msgs = r.messages or []
                user_text = ""
                for m in msgs:
                    if m.get("role") == "user":
                        user_text = str(m.get("content") or "")
                        break
                if not user_text:
                    continue
                vec = embed_text(user_text, db=db)
                if vec is None:
                    # No API key configured — bail out to avoid hammering the API
                    # once per row with a guaranteed None.
                    break
                db.execute(
                    _sql("UPDATE llm_interactions SET embedding = (:v)::vector, embedding_model = :m WHERE id = :id"),
                    {"v": vec, "m": "text-embedding-3-small", "id": r.id},
                )
                embedded += 1
            except Exception:
                logger.exception("embedding backfill failed for interaction %s", r.id)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("run_embedding_backfill: batch failed")
    finally:
        db.close()

    if embedded:
        logger.info("llm_outcome_linker: embedded %d interactions", embedded)
    return embedded


def run_retention() -> int:
    """Delete stale interaction rows. Returns count deleted."""
    from models.models import LLMInteraction, LLMInteractionOutcome

    db = SessionLocal()
    deleted = 0
    try:
        cutoff_all = datetime.utcnow() - timedelta(days=_RETENTION_DAYS)
        cutoff_unscored = datetime.utcnow() - timedelta(days=_UNSCORED_RETENTION_DAYS)

        # Hard retention: anything older than RETENTION_DAYS, outcomes and all.
        n1 = (
            db.query(LLMInteraction)
              .filter(LLMInteraction.created_at < cutoff_all)
              .delete(synchronize_session=False)
        )
        # Soft retention: unscored rows older than UNSCORED_RETENTION_DAYS.
        scored_ids = db.query(LLMInteractionOutcome.interaction_id).subquery()
        n2 = (
            db.query(LLMInteraction)
              .filter(LLMInteraction.created_at < cutoff_unscored)
              .filter(~LLMInteraction.id.in_(scored_ids))
              .delete(synchronize_session=False)
        )
        deleted = int(n1 or 0) + int(n2 or 0)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("llm_outcome_linker: retention cleanup failed")
    finally:
        db.close()

    if deleted:
        logger.info("llm_outcome_linker: deleted %d stale interactions", deleted)
    return deleted


# ── Scheduler wiring ──────────────────────────────────────────────────

def start_scheduler() -> None:
    """Register the linker + retention jobs on APScheduler."""
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        run_linker,
        IntervalTrigger(minutes=5),
        id="llm_outcome_linker",
        replace_existing=True,
        misfire_grace_time=300,
        coalesce=True,
    )
    _scheduler.add_job(
        run_retention,
        IntervalTrigger(hours=6),
        id="llm_outcome_retention",
        replace_existing=True,
        misfire_grace_time=3600,
        coalesce=True,
    )
    _scheduler.add_job(
        run_embedding_backfill,
        IntervalTrigger(minutes=15),
        id="llm_embedding_backfill",
        replace_existing=True,
        misfire_grace_time=600,
        coalesce=True,
    )
    _scheduler.start()
    logger.info("LLM outcome linker scheduler started (linker 5m / embed 15m / retention 6h)")


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None

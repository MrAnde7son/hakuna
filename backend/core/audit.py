"""
Shared audit logging helpers.
Extracted here to avoid circular imports between app.py and auth_routes.py.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models.models import AuditLog

logger = logging.getLogger(__name__)

AUDIT_LOG_RETENTION_DAYS = 90


def log_audit(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    entity_name: Optional[str] = None,
    changes: Optional[dict] = None,
    actor=None,
    org_id: Optional[int] = None,
) -> None:
    """Write a single immutable audit record. Fire-and-forget — never raises.

    `actor` may be a User (or User-like object with id/email/display_name/org_id)
    or a CollaboratorPrincipal. For collaborators we record `actor_user_id=NULL`
    and snapshot the email so the row is identifiable as an external action.
    """
    try:
        # Detect a CollaboratorPrincipal without importing core.auth (circular).
        is_collab = actor is not None and getattr(actor, "collaborator_id", None) is not None
        if is_collab:
            actor_user_id = None
            actor_email = getattr(actor, "email", None)
            actor_display_name = f"Collaborator <{actor_email}>" if actor_email else "Collaborator"
            actor_org_id = getattr(actor, "org_id", None)
        else:
            actor_user_id = getattr(actor, "id", None) if actor else None
            actor_email = getattr(actor, "email", None) if actor else None
            actor_display_name = getattr(actor, "display_name", None) if actor else None
            actor_org_id = getattr(actor, "org_id", None) if actor else None

        entry = AuditLog(
            org_id=org_id or actor_org_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            actor_display_name=actor_display_name,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            changes=changes,
        )
        db.add(entry)
        db.flush()
    except Exception as e:
        logger.warning(f"audit log write failed: {e}")


def purge_expired_audit_logs() -> int:
    """Delete audit log entries older than AUDIT_LOG_RETENTION_DAYS.

    Runs as a scheduled background job.  Returns the number of rows deleted.
    """
    from core.database import SessionLocal

    cutoff = datetime.utcnow() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
    db: Session = SessionLocal()
    try:
        count = db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete()
        db.commit()
        logger.info("Purged %d audit log entries older than %s days", count, AUDIT_LOG_RETENTION_DAYS)
        return count
    except Exception as e:
        db.rollback()
        logger.warning("Audit log purge failed: %s", e)
        return 0
    finally:
        db.close()


def diff(old: dict, new: dict) -> dict:
    """Return only the fields that changed, as {field: {old, new}}."""
    return {
        k: {"old": old.get(k), "new": new.get(k)}
        for k in set(old) | set(new)
        if old.get(k) != new.get(k)
    }

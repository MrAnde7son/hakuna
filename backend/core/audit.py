"""
Shared audit logging helpers.
Extracted here to avoid circular imports between app.py and auth_routes.py.
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from models.models import AuditLog

logger = logging.getLogger(__name__)


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
    """Write a single immutable audit record. Fire-and-forget — never raises."""
    try:
        entry = AuditLog(
            org_id=org_id or (actor.org_id if actor else None),
            actor_user_id=actor.id if actor else None,
            actor_email=actor.email if actor else None,
            actor_display_name=getattr(actor, "display_name", None) if actor else None,
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


def diff(old: dict, new: dict) -> dict:
    """Return only the fields that changed, as {field: {old, new}}."""
    return {
        k: {"old": old.get(k), "new": new.get(k)}
        for k in set(old) | set(new)
        if old.get(k) != new.get(k)
    }

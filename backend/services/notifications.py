"""
Notification generation helpers.
Pattern mirrors core/audit.py — fire-and-forget, never raises.
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from models.models import Notification

logger = logging.getLogger(__name__)


def create_notification(
    db: Session,
    org_id: int,
    category: str,
    title: str,
    body: Optional[str] = None,
    link: Optional[str] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Write a single notification record. Fire-and-forget — never raises."""
    try:
        notif = Notification(
            org_id=org_id,
            category=category,
            title=title,
            body=body,
            link=link,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_=metadata or {},
        )
        db.add(notif)
        db.flush()
    except Exception as e:
        logger.warning(f"notification write failed: {e}")

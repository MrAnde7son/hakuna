"""Event store abstraction for SIEM event querying.

Provides a simple store that queries the SIEMEvent table (hot tier).
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.models import SIEMEvent


@dataclass
class EventFilter:
    org_ids: List[int] = field(default_factory=list)
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    source_system: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    asset_id: Optional[int] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    q: Optional[str] = None
    sort_by: str = "event_time"
    order: str = "desc"


class EventRecord:
    """Thin wrapper around a SIEMEvent row for serialization."""

    def __init__(self, ev: SIEMEvent):
        self._ev = ev

    def to_dict(self) -> dict:
        ev = self._ev
        return {
            "id": ev.id,
            "org_id": ev.org_id,
            "event_time": ev.event_time.isoformat() if ev.event_time else None,
            "ingested_at": ev.ingested_at.isoformat() if ev.ingested_at else None,
            "source_system": ev.source_system,
            "source_id": ev.source_id,
            "event_type": ev.event_type,
            "event_category": ev.event_category,
            "severity": ev.severity,
            "action": ev.action,
            "outcome": ev.outcome,
            "asset_id": ev.asset_id,
            "user_name": ev.user_name,
            "source_ip": ev.source_ip,
            "dest_ip": ev.dest_ip,
            "host_name": ev.host_name,
            "message": ev.message,
            "raw": ev.raw,
            "normalized": ev.normalized,
            "dedup_hash": ev.dedup_hash,
            "integration_id": ev.integration_id,
        }


ALLOWED_SORT_COLUMNS = {
    "event_time", "ingested_at", "source_system", "severity",
    "event_type", "host_name", "user_name", "source_ip",
}


class HotEventStore:
    """Queries SIEMEvent rows from the relational DB (hot tier)."""

    def __init__(self, db: Session):
        self.db = db

    def _apply_filters(self, q, f: EventFilter):
        if f.org_ids:
            q = q.filter(SIEMEvent.org_id.in_(f.org_ids))
        if f.time_from:
            q = q.filter(SIEMEvent.event_time >= f.time_from)
        if f.time_to:
            q = q.filter(SIEMEvent.event_time <= f.time_to)
        if f.source_system:
            q = q.filter(SIEMEvent.source_system == f.source_system)
        if f.severity:
            q = q.filter(SIEMEvent.severity == f.severity)
        if f.event_type:
            q = q.filter(SIEMEvent.event_type == f.event_type)
        if f.asset_id is not None:
            q = q.filter(SIEMEvent.asset_id == f.asset_id)
        if f.host_name:
            q = q.filter(SIEMEvent.host_name.ilike(f"%{f.host_name}%"))
        if f.user_name:
            q = q.filter(SIEMEvent.user_name.ilike(f"%{f.user_name}%"))
        if f.source_ip:
            q = q.filter(SIEMEvent.source_ip == f.source_ip)
        if f.q:
            q = q.filter(SIEMEvent.message.ilike(f"%{f.q}%"))
        return q

    def _apply_sort(self, q, f: EventFilter):
        col_name = f.sort_by if f.sort_by in ALLOWED_SORT_COLUMNS else "event_time"
        col = getattr(SIEMEvent, col_name)
        q = q.order_by(col.desc() if f.order == "desc" else col.asc())
        return q

    def count(self, filters: EventFilter) -> int:
        q = self.db.query(SIEMEvent)
        q = self._apply_filters(q, filters)
        return q.count()

    def query(self, filters: EventFilter, limit: int = 50, offset: int = 0) -> List[EventRecord]:
        q = self.db.query(SIEMEvent)
        q = self._apply_filters(q, filters)
        q = self._apply_sort(q, filters)
        rows = q.offset(offset).limit(limit).all()
        return [EventRecord(r) for r in rows]

    def get_by_id(self, event_id: str, org_ids: List[int]) -> Optional[EventRecord]:
        q = self.db.query(SIEMEvent).filter(SIEMEvent.id == event_id)
        if org_ids:
            q = q.filter(SIEMEvent.org_id.in_(org_ids))
        ev = q.first()
        return EventRecord(ev) if ev else None


def get_event_store(db: Session) -> HotEventStore:
    """Factory — returns the hot-tier event store."""
    return HotEventStore(db)

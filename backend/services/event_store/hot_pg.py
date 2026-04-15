"""Postgres-backed hot tier EventStore — queries SIEMEvent ORM directly."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.models import SIEMEvent
from services.event_store.base import EventStore, EventRecord, EventFilter

logger = logging.getLogger(__name__)


def _model_to_record(ev: SIEMEvent) -> EventRecord:
    return EventRecord(
        id=ev.id,
        org_id=ev.org_id,
        event_time=ev.event_time,
        ingested_at=ev.ingested_at,
        source_system=ev.source_system,
        source_id=ev.source_id,
        event_type=ev.event_type,
        event_category=ev.event_category,
        severity=ev.severity,
        action=ev.action,
        outcome=ev.outcome,
        asset_id=ev.asset_id,
        user_name=ev.user_name,
        source_ip=ev.source_ip,
        dest_ip=ev.dest_ip,
        host_name=ev.host_name,
        message=ev.message,
        raw=ev.raw,
        normalized=ev.normalized,
        dedup_hash=ev.dedup_hash,
        integration_id=ev.integration_id,
    )


def _apply_filters(query, filters: EventFilter):
    """Apply EventFilter to a SQLAlchemy query on SIEMEvent."""
    if filters.org_ids:
        query = query.filter(SIEMEvent.org_id.in_(filters.org_ids))
    if filters.time_from:
        query = query.filter(SIEMEvent.event_time >= filters.time_from)
    if filters.time_to:
        query = query.filter(SIEMEvent.event_time <= filters.time_to)
    if filters.source_system:
        query = query.filter(SIEMEvent.source_system == filters.source_system)
    if filters.severity:
        query = query.filter(SIEMEvent.severity == filters.severity)
    if filters.event_type:
        query = query.filter(SIEMEvent.event_type == filters.event_type)
    if filters.asset_id:
        query = query.filter(SIEMEvent.asset_id == filters.asset_id)
    if filters.host_name:
        query = query.filter(SIEMEvent.host_name.ilike(f"%{filters.host_name}%"))
    if filters.user_name:
        query = query.filter(SIEMEvent.user_name.ilike(f"%{filters.user_name}%"))
    if filters.source_ip:
        query = query.filter(SIEMEvent.source_ip == filters.source_ip)
    if filters.q:
        query = query.filter(SIEMEvent.message.ilike(f"%{filters.q}%"))
    return query


def _apply_sort(query, filters: EventFilter):
    SORTABLE = {"event_time", "severity", "source_system", "ingested_at", "host_name"}
    sort_col = getattr(SIEMEvent, filters.sort_by) if filters.sort_by in SORTABLE else SIEMEvent.event_time
    if filters.order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())
    return query


class HotPgStore(EventStore):
    """Reads/writes SIEM events from the Postgres hot tier via SQLAlchemy."""

    def __init__(self, db: Session):
        self._db = db

    def write_batch(self, events: list[EventRecord]) -> int:
        objs = []
        for ev in events:
            objs.append(SIEMEvent(
                id=ev.id,
                org_id=ev.org_id,
                event_time=ev.event_time,
                ingested_at=ev.ingested_at,
                source_system=ev.source_system,
                source_id=ev.source_id,
                event_type=ev.event_type,
                event_category=ev.event_category,
                severity=ev.severity,
                action=ev.action,
                outcome=ev.outcome,
                asset_id=ev.asset_id,
                user_name=ev.user_name,
                source_ip=ev.source_ip,
                dest_ip=ev.dest_ip,
                host_name=ev.host_name,
                message=ev.message,
                raw=ev.raw,
                normalized=ev.normalized,
                dedup_hash=ev.dedup_hash,
                integration_id=ev.integration_id,
            ))
        if objs:
            self._db.bulk_save_objects(objs)
            self._db.commit()
        return len(objs)

    def query(self, filters: EventFilter, limit: int = 50, offset: int = 0) -> list[EventRecord]:
        q = self._db.query(SIEMEvent)
        q = _apply_filters(q, filters)
        q = _apply_sort(q, filters)
        rows = q.offset(offset).limit(limit).all()
        return [_model_to_record(r) for r in rows]

    def count(self, filters: EventFilter) -> int:
        q = self._db.query(SIEMEvent)
        q = _apply_filters(q, filters)
        return q.count()

    def get_by_id(self, event_id: str, org_ids: list[int]) -> Optional[EventRecord]:
        q = self._db.query(SIEMEvent).filter(SIEMEvent.id == event_id)
        if org_ids:
            q = q.filter(SIEMEvent.org_id.in_(org_ids))
        ev = q.first()
        return _model_to_record(ev) if ev else None

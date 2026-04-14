"""RoutedEventStore — picks hot vs lake tier by time range.

Queries fully within the hot window (last 72h) go to Postgres.
Older or cross-boundary queries go to Iceberg via DuckDB.
Mixed queries union both with dedup by id.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from services.event_store.base import EventStore, EventRecord, EventFilter
from services.event_store.hot_pg import HotPgStore
from services.event_store.lake_iceberg import LakeIcebergStore

logger = logging.getLogger(__name__)

HOT_RETENTION_HOURS = int(os.environ.get("SIEM_HOT_RETENTION_HOURS", "72"))


def _hot_boundary() -> datetime:
    """Cutoff timestamp: events newer than this are in the hot tier."""
    return datetime.utcnow() - timedelta(hours=HOT_RETENTION_HOURS)


def _range_is_hot_only(filters: EventFilter) -> bool:
    """True if the query time range falls entirely within the hot window."""
    boundary = _hot_boundary()
    if filters.time_from and filters.time_from >= boundary:
        return True
    if not filters.time_from and not filters.time_to:
        # No time range specified — could span both; default to hot-only
        # for performance (most common case is recent events)
        return True
    return False


def _range_is_lake_only(filters: EventFilter) -> bool:
    """True if the query time range falls entirely outside the hot window."""
    boundary = _hot_boundary()
    if filters.time_to and filters.time_to < boundary:
        return True
    return False


class RoutedEventStore(EventStore):
    """Routes queries to hot (Postgres) or lake (Iceberg) based on time range."""

    def __init__(self, db: Session, lake: Optional[LakeIcebergStore] = None):
        self._hot = HotPgStore(db)
        self._lake = lake or LakeIcebergStore()
        self._db = db

    def write_batch(self, events: list[EventRecord]) -> int:
        """Writes always go to hot tier (drain moves them to lake later)."""
        return self._hot.write_batch(events)

    def query(self, filters: EventFilter, limit: int = 50, offset: int = 0) -> list[EventRecord]:
        if _range_is_hot_only(filters):
            return self._hot.query(filters, limit, offset)

        if _range_is_lake_only(filters) and self._lake.available:
            return self._lake.query(filters, limit, offset)

        # Mixed range: query both and dedup by id
        if self._lake.available:
            return self._query_both(filters, limit, offset)

        # Lake unavailable — fall back to hot only
        return self._hot.query(filters, limit, offset)

    def count(self, filters: EventFilter) -> int:
        if _range_is_hot_only(filters):
            return self._hot.count(filters)

        if _range_is_lake_only(filters) and self._lake.available:
            return self._lake.count(filters)

        if self._lake.available:
            return self._count_both(filters)

        return self._hot.count(filters)

    def get_by_id(self, event_id: str, org_ids: list[int]) -> Optional[EventRecord]:
        # Try hot first (most common lookup)
        record = self._hot.get_by_id(event_id, org_ids)
        if record:
            return record
        # Fall back to lake
        if self._lake.available:
            return self._lake.get_by_id(event_id, org_ids)
        return None

    def _query_both(self, filters: EventFilter, limit: int, offset: int) -> list[EventRecord]:
        """Query both tiers, dedup by id, sort, and paginate."""
        # Fetch more than needed from each tier to account for dedup + pagination
        fetch_limit = limit + offset + 100

        hot_records = self._hot.query(filters, fetch_limit, 0)
        lake_records = self._lake.query(filters, fetch_limit, 0)

        # Dedup: hot tier wins on conflict (fresher data)
        seen_ids = set()
        merged = []
        for r in hot_records:
            if r.id not in seen_ids:
                seen_ids.add(r.id)
                merged.append(r)
        for r in lake_records:
            if r.id not in seen_ids:
                seen_ids.add(r.id)
                merged.append(r)

        # Sort
        reverse = filters.order != "asc"
        sort_key = filters.sort_by if filters.sort_by in {
            "event_time", "severity", "source_system", "ingested_at", "host_name"
        } else "event_time"
        merged.sort(key=lambda r: getattr(r, sort_key, "") or "", reverse=reverse)

        return merged[offset:offset + limit]

    def _count_both(self, filters: EventFilter) -> int:
        """Count across both tiers. Approximate — dedup may reduce total."""
        hot_count = self._hot.count(filters)
        lake_count = self._lake.count(filters)
        # This is an upper bound; exact dedup count would require scanning both
        return hot_count + lake_count


# Module-level singleton accessor
_lake_singleton: Optional[LakeIcebergStore] = None


def get_event_store(db: Session) -> RoutedEventStore:
    """Get a RoutedEventStore with shared lake singleton."""
    global _lake_singleton
    if _lake_singleton is None:
        _lake_singleton = LakeIcebergStore()
    return RoutedEventStore(db, _lake_singleton)

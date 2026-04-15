"""Event store package — abstraction over hot (Postgres) and cold (Iceberg) tiers."""

from services.event_store.base import EventStore, EventRecord, EventFilter
from services.event_store.hot_pg import HotPgStore
from services.event_store.router import RoutedEventStore, get_event_store

__all__ = [
    "EventStore",
    "EventRecord",
    "EventFilter",
    "HotPgStore",
    "RoutedEventStore",
    "get_event_store",
]

"""Abstract EventStore interface and shared data types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class EventRecord:
    """Flat representation of a SIEM event (shared across hot + lake tiers)."""
    id: str
    org_id: int
    event_time: datetime
    ingested_at: datetime
    source_system: str
    source_id: Optional[str] = None
    event_type: str = ""
    event_category: Optional[str] = None
    severity: str = "info"
    action: Optional[str] = None
    outcome: Optional[str] = None
    asset_id: Optional[int] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    host_name: Optional[str] = None
    message: Optional[str] = None
    raw: Optional[dict] = None
    normalized: Optional[dict] = None
    dedup_hash: str = ""
    integration_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "org_id": self.org_id,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "source_system": self.source_system,
            "source_id": self.source_id,
            "event_type": self.event_type,
            "event_category": self.event_category,
            "severity": self.severity,
            "action": self.action,
            "outcome": self.outcome,
            "asset_id": self.asset_id,
            "user_name": self.user_name,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "host_name": self.host_name,
            "message": self.message,
            "raw": self.raw,
            "normalized": self.normalized,
            "dedup_hash": self.dedup_hash,
            "integration_id": self.integration_id,
        }


@dataclass
class EventFilter:
    """Query filters for event search."""
    org_ids: list[int] = field(default_factory=list)
    time_from: Optional[datetime] = None
    time_to: Optional[datetime] = None
    source_system: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    asset_id: Optional[int] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    q: Optional[str] = None  # full-text search on message
    sort_by: str = "event_time"
    order: str = "desc"


class EventStore(ABC):
    """Abstract base for event storage backends."""

    @abstractmethod
    def write_batch(self, events: list[EventRecord]) -> int:
        """Write a batch of events. Returns count of events written."""
        ...

    @abstractmethod
    def query(self, filters: EventFilter, limit: int = 50, offset: int = 0) -> list[EventRecord]:
        """Query events matching filters with pagination."""
        ...

    @abstractmethod
    def count(self, filters: EventFilter) -> int:
        """Count events matching filters."""
        ...

    @abstractmethod
    def get_by_id(self, event_id: str, org_ids: list[int]) -> Optional[EventRecord]:
        """Fetch a single event by ID, scoped to org_ids."""
        ...

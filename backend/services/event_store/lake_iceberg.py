"""Iceberg + DuckDB-backed lake tier EventStore for cold storage queries."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Optional

from services.event_store.base import EventStore, EventRecord, EventFilter

logger = logging.getLogger(__name__)

# Iceberg table schema mirrors SIEMEvent columns
ICEBERG_NAMESPACE = "siem"
ICEBERG_TABLE = "siem.events"

# pyiceberg schema definition (used by init_lake.py)
ICEBERG_SCHEMA_FIELDS = [
    ("id", "string", True),
    ("org_id", "long", True),
    ("event_time", "timestamptz", True),
    ("ingested_at", "timestamptz", True),
    ("source_system", "string", True),
    ("source_id", "string", False),
    ("event_type", "string", True),
    ("event_category", "string", False),
    ("severity", "string", True),
    ("action", "string", False),
    ("outcome", "string", False),
    ("asset_id", "long", False),
    ("user_name", "string", False),
    ("source_ip", "string", False),
    ("dest_ip", "string", False),
    ("host_name", "string", False),
    ("message", "string", False),
    ("raw_json", "string", False),       # JSON serialized as string
    ("normalized_json", "string", False), # JSON serialized as string
    ("dedup_hash", "string", True),
    ("integration_id", "string", False),
    ("event_date", "date", True),         # partition column: date(event_time)
]


def _get_lake_config() -> dict:
    """Build pyiceberg catalog configuration from environment."""
    endpoint = os.environ.get("SIEM_LAKE_ENDPOINT", "http://localhost:9000")
    access_key = os.environ.get("SIEM_LAKE_ACCESS_KEY", "minioadmin")
    secret_key = os.environ.get("SIEM_LAKE_SECRET_KEY", "minioadmin")
    bucket = os.environ.get("SIEM_LAKE_BUCKET", "hakuna-events-dev")

    return {
        "type": "sql",
        "uri": os.environ.get("DATABASE_URL", "sqlite:///./nessus_remediation.db"),
        "warehouse": f"s3://{bucket}/warehouse",
        "s3.endpoint": endpoint,
        "s3.access-key-id": access_key,
        "s3.secret-access-key": secret_key,
        "s3.path-style-access": "true",
    }


def _get_catalog():
    """Lazily load the Iceberg catalog. Returns None if pyiceberg is unavailable."""
    try:
        from pyiceberg.catalog import load_catalog
        config = _get_lake_config()
        return load_catalog("hakuna_lake", **config)
    except ImportError:
        logger.warning("pyiceberg not installed — lake tier unavailable")
        return None
    except Exception as exc:
        logger.warning("Failed to initialize Iceberg catalog: %s", exc)
        return None


def _record_to_row(ev: EventRecord) -> dict:
    """Convert EventRecord to a flat dict suitable for Iceberg/Arrow."""
    return {
        "id": ev.id,
        "org_id": ev.org_id,
        "event_time": ev.event_time,
        "ingested_at": ev.ingested_at,
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
        "raw_json": json.dumps(ev.raw) if ev.raw else None,
        "normalized_json": json.dumps(ev.normalized) if ev.normalized else None,
        "dedup_hash": ev.dedup_hash,
        "integration_id": ev.integration_id,
        "event_date": ev.event_time.date() if ev.event_time else None,
    }


def _row_to_record(row: dict) -> EventRecord:
    """Convert a DuckDB row dict back to EventRecord."""
    raw = None
    if row.get("raw_json"):
        try:
            raw = json.loads(row["raw_json"])
        except (json.JSONDecodeError, TypeError):
            raw = None
    normalized = None
    if row.get("normalized_json"):
        try:
            normalized = json.loads(row["normalized_json"])
        except (json.JSONDecodeError, TypeError):
            normalized = None

    event_time = row.get("event_time")
    if isinstance(event_time, str):
        event_time = datetime.fromisoformat(event_time)
    ingested_at = row.get("ingested_at")
    if isinstance(ingested_at, str):
        ingested_at = datetime.fromisoformat(ingested_at)

    return EventRecord(
        id=row["id"],
        org_id=int(row["org_id"]),
        event_time=event_time,
        ingested_at=ingested_at,
        source_system=row.get("source_system", ""),
        source_id=row.get("source_id"),
        event_type=row.get("event_type", ""),
        event_category=row.get("event_category"),
        severity=row.get("severity", "info"),
        action=row.get("action"),
        outcome=row.get("outcome"),
        asset_id=int(row["asset_id"]) if row.get("asset_id") is not None else None,
        user_name=row.get("user_name"),
        source_ip=row.get("source_ip"),
        dest_ip=row.get("dest_ip"),
        host_name=row.get("host_name"),
        message=row.get("message"),
        raw=raw,
        normalized=normalized,
        dedup_hash=row.get("dedup_hash", ""),
        integration_id=row.get("integration_id"),
    )


def _build_where_clauses(filters: EventFilter) -> tuple[str, dict]:
    """Build SQL WHERE clauses and params from EventFilter."""
    clauses = []
    params = {}

    if filters.org_ids:
        placeholders = ", ".join(f"${i + 1}" for i in range(len(filters.org_ids)))
        clauses.append(f"org_id IN ({placeholders})")
        for i, oid in enumerate(filters.org_ids):
            params[f"${i + 1}"] = oid

    # For DuckDB we use simple string interpolation with parameterized queries
    # Reset param counter
    params = {}
    clauses = []
    idx = [0]

    def _add(col: str, op: str, val):
        idx[0] += 1
        clauses.append(f"{col} {op} ?")
        params[idx[0]] = val

    if filters.org_ids:
        org_list = ", ".join(str(int(o)) for o in filters.org_ids)
        clauses.append(f"org_id IN ({org_list})")

    if filters.time_from:
        _add("event_time", ">=", filters.time_from.isoformat())
    if filters.time_to:
        _add("event_time", "<=", filters.time_to.isoformat())
    if filters.source_system:
        _add("source_system", "=", filters.source_system)
    if filters.severity:
        _add("severity", "=", filters.severity)
    if filters.event_type:
        _add("event_type", "=", filters.event_type)
    if filters.asset_id:
        _add("asset_id", "=", filters.asset_id)
    if filters.host_name:
        _add("host_name", "ILIKE", f"%{filters.host_name}%")
    if filters.user_name:
        _add("user_name", "ILIKE", f"%{filters.user_name}%")
    if filters.source_ip:
        _add("source_ip", "=", filters.source_ip)
    if filters.q:
        _add("message", "ILIKE", f"%{filters.q}%")

    where = " AND ".join(clauses) if clauses else "1=1"
    ordered_params = [params[k] for k in sorted(params.keys())]
    return where, ordered_params


class LakeIcebergStore(EventStore):
    """Queries Iceberg Parquet files via DuckDB for cold-tier events."""

    def __init__(self):
        self._catalog = None
        self._table_checked = False
        self._table_available = False

    @property
    def catalog(self):
        if self._catalog is None:
            self._catalog = _get_catalog()
        return self._catalog

    @property
    def available(self) -> bool:
        if self.catalog is None:
            return False
        if not self._table_checked:
            self._table_checked = True
            self._table_available = self._load_table() is not None
        return self._table_available

    def _load_table(self):
        """Load the Iceberg table object. Returns None if unavailable."""
        if self.catalog is None:
            return None
        try:
            return self.catalog.load_table(ICEBERG_TABLE)
        except Exception as exc:
            logger.warning("Failed to load Iceberg table %s: %s", ICEBERG_TABLE, exc)
            return None

    def write_batch(self, events: list[EventRecord]) -> int:
        """Append events to the Iceberg table via pyiceberg."""
        table = self._load_table()
        if not table:
            raise RuntimeError("Lake tier unavailable — cannot write events")

        try:
            import pyarrow as pa

            rows = [_record_to_row(ev) for ev in events]
            # Build a PyArrow table from dicts
            arrow_table = pa.Table.from_pylist(rows)
            table.append(arrow_table)
            return len(events)
        except Exception as exc:
            logger.error("Failed to write %d events to lake: %s", len(events), exc)
            raise

    def query(self, filters: EventFilter, limit: int = 50, offset: int = 0) -> list[EventRecord]:
        """Query lake via DuckDB against the Iceberg table's Parquet files."""
        table = self._load_table()
        if not table:
            return []

        try:
            import duckdb

            where, params = _build_where_clauses(filters)
            sort_col = filters.sort_by if filters.sort_by in {
                "event_time", "severity", "source_system", "ingested_at", "host_name"
            } else "event_time"
            direction = "ASC" if filters.order == "asc" else "DESC"

            # Scan to Arrow and query via DuckDB
            arrow_table = table.scan().to_arrow()
            conn = duckdb.connect()
            conn.register("lake_events", arrow_table)

            sql = f"SELECT * FROM lake_events WHERE {where} ORDER BY {sort_col} {direction} LIMIT {limit} OFFSET {offset}"
            result = conn.execute(sql, params).fetchdf()
            conn.close()

            records = []
            for _, row in result.iterrows():
                records.append(_row_to_record(row.to_dict()))
            return records

        except Exception as exc:
            logger.error("Lake query failed: %s", exc)
            return []

    def count(self, filters: EventFilter) -> int:
        table = self._load_table()
        if not table:
            return 0

        try:
            import duckdb

            where, params = _build_where_clauses(filters)

            arrow_table = table.scan().to_arrow()
            conn = duckdb.connect()
            conn.register("lake_events", arrow_table)

            sql = f"SELECT COUNT(*) as cnt FROM lake_events WHERE {where}"
            result = conn.execute(sql, params).fetchone()
            conn.close()
            return result[0] if result else 0

        except Exception as exc:
            logger.error("Lake count failed: %s", exc)
            return 0

    def get_by_id(self, event_id: str, org_ids: list[int]) -> Optional[EventRecord]:
        table = self._load_table()
        if not table:
            return None

        try:
            import duckdb

            org_list = ", ".join(str(int(o)) for o in org_ids)
            arrow_table = table.scan().to_arrow()
            conn = duckdb.connect()
            conn.register("lake_events", arrow_table)

            sql = f"SELECT * FROM lake_events WHERE id = ? AND org_id IN ({org_list}) LIMIT 1"
            result = conn.execute(sql, [event_id]).fetchdf()
            conn.close()

            if result.empty:
                return None
            return _row_to_record(result.iloc[0].to_dict())

        except Exception as exc:
            logger.error("Lake get_by_id failed: %s", exc)
            return None

"""Upsert engine — insert or update assets/findings from mapped integration records."""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

from models.models import Asset, Finding

logger = logging.getLogger(__name__)

# Severity label → integer mapping used by the Finding model
SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class UpsertResult:
    action: str  # inserted | updated | skipped
    id: Optional[int] = None
    errors: List[str] = field(default_factory=list)


def upsert(db: Session, entity_type: str, mapped_record: dict, dedup_key: list,
           integration_id: str, scan_id: int = None) -> UpsertResult:
    """Upsert a single mapped record into the database."""
    if entity_type == "asset":
        return _upsert_asset(db, mapped_record, dedup_key, integration_id, scan_id)
    elif entity_type == "finding":
        return _upsert_finding(db, mapped_record, dedup_key, integration_id, scan_id)
    elif entity_type == "action":
        # Actions are always inserts (run records are append-only)
        return UpsertResult(action="skipped", errors=["Action entity push not implemented in upsert"])
    else:
        return UpsertResult(action="skipped", errors=[f"Unknown entity type: {entity_type}"])


def _upsert_asset(db: Session, record: dict, dedup_key: list, integration_id: str,
                   scan_id: int) -> UpsertResult:
    """Upsert an asset record."""
    source_system = record.get("source_system", "")
    source_id = record.get("source_id", "")

    # Build dedup filters
    existing = _find_existing(db, Asset, record, dedup_key, source_system, source_id)

    if existing:
        # Update only non-null fields, respecting user_edited_fields
        user_edited = existing.user_edited_fields or []
        updated = False
        field_mapping = {
            "hostname": "hostname", "ip_address": "ip", "fqdn": "fqdn",
            "os": "os", "environment": "environment_tag",
            "last_seen": "last_seen", "criticality": "criticality",
        }
        for src_field, db_field in field_mapping.items():
            value = record.get(src_field)
            if value is not None and db_field not in user_edited:
                setattr(existing, db_field, value)
                updated = True

        existing.last_seen = datetime.utcnow()
        existing.source_system = source_system
        if source_id:
            existing.source_id = source_id

        return UpsertResult(action="updated" if updated else "skipped", id=existing.id)
    else:
        # Insert new asset
        asset = Asset(
            scan_id=scan_id or 0,
            ip=record.get("ip_address", ""),
            hostname=record.get("hostname", ""),
            fqdn=record.get("fqdn", ""),
            os=record.get("os", ""),
            environment_tag=record.get("environment", "internal"),
            criticality=record.get("criticality", 5),
            source_id=source_id,
            source_system=source_system,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(asset)
        db.flush()
        return UpsertResult(action="inserted", id=asset.id)


def _upsert_finding(db: Session, record: dict, dedup_key: list, integration_id: str,
                     scan_id: int) -> UpsertResult:
    """Upsert a finding record."""
    source_system = record.get("source_system", "")
    source_id = record.get("source_id", "")

    # Resolve asset FK
    asset_data = record.get("asset", {})
    ip = asset_data.get("ip_address", "") if isinstance(asset_data, dict) else ""
    hostname = asset_data.get("hostname", "") if isinstance(asset_data, dict) else ""

    asset = _resolve_asset(db, ip, hostname, source_system, scan_id)

    # Build dedup filters
    existing = _find_existing_finding(db, record, dedup_key, source_system, source_id, ip)

    severity_label = record.get("severity", "info")
    severity_int = SEVERITY_MAP.get(severity_label, 0) if isinstance(severity_label, str) else severity_label

    if existing:
        user_edited = existing.user_edited_fields or []
        updated = False

        field_mapping = {
            "title": "plugin_name",
            "description": "description",
            "solution": "solution",
            "cvss_score": "cvss3_score",
            "cvss_vector": "cvss3_vector",
            "exploit_available": "exploit_available",
            "cve_id": None,  # handled separately
            "plugin_id": "plugin_id",
        }

        for src_field, db_field in field_mapping.items():
            if db_field is None:
                continue
            value = record.get(src_field)
            if value is not None and db_field not in user_edited:
                setattr(existing, db_field, value)
                updated = True

        # Handle CVE
        cve_id = record.get("cve_id")
        if cve_id and "cves" not in user_edited:
            existing.cves = [cve_id] if isinstance(cve_id, str) else cve_id
            updated = True

        # Severity — don't override if user edited
        if "severity" not in user_edited:
            existing.severity = severity_int
            existing.severity_label = severity_label if isinstance(severity_label, str) else None

        existing.last_seen = datetime.utcnow()
        existing.source_system = source_system
        if source_id:
            existing.source_id = source_id
        # Do NOT change workflow_status if user has set it

        return UpsertResult(action="updated" if updated else "skipped", id=existing.id)
    else:
        # Insert new finding
        finding = Finding(
            scan_id=scan_id or 0,
            asset_id=asset.id,
            source_type=source_system or "integration",
            source_id=source_id,
            source_system=source_system,
            plugin_id=record.get("plugin_id", ""),
            plugin_name=record.get("title", ""),
            severity=severity_int,
            severity_label=severity_label if isinstance(severity_label, str) else None,
            cvss3_score=_to_float(record.get("cvss_score")),
            cvss3_vector=record.get("cvss_vector"),
            cves=[record["cve_id"]] if record.get("cve_id") and isinstance(record["cve_id"], str) else record.get("cve_id", []),
            synopsis=record.get("description", ""),
            description=record.get("description", ""),
            solution=record.get("solution", ""),
            exploit_available=bool(record.get("exploit_available")),
            workflow_status="open",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(finding)
        db.flush()
        return UpsertResult(action="inserted", id=finding.id)


def upsert_batch(db: Session, entity_type: str, mapped_records: list, dedup_key: list,
                  integration_id: str, scan_id: int = None) -> dict:
    """Process a batch of records. Returns aggregate counts."""
    counts = {"inserted": 0, "updated": 0, "skipped": 0, "errors": []}
    for record in mapped_records:
        try:
            result = upsert(db, entity_type, record, dedup_key, integration_id, scan_id)
            counts[result.action] = counts.get(result.action, 0) + 1
            if result.errors:
                counts["errors"].extend(result.errors)
        except Exception as e:
            counts["errors"].append(str(e))
            counts["skipped"] += 1
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        counts["errors"].append(f"Batch commit failed: {e}")
    return counts


# ── Helpers ──

def _find_existing(db, model, record, dedup_key, source_system, source_id):
    """Find existing record by dedup key."""
    if not dedup_key:
        dedup_key = ["source_system", "source_id"]

    filters = []
    for key in dedup_key:
        if key == "source_system":
            filters.append(model.source_system == source_system)
        elif key == "source_id":
            filters.append(model.source_id == source_id)
        elif key == "asset.ip_address" and model == Asset:
            filters.append(model.ip == record.get("ip_address", ""))
        elif hasattr(model, key):
            filters.append(getattr(model, key) == record.get(key, ""))

    if not filters:
        return None
    return db.query(model).filter(and_(*filters)).first()


def _find_existing_finding(db, record, dedup_key, source_system, source_id, ip):
    """Find existing finding by dedup key."""
    if not dedup_key:
        dedup_key = ["source_system", "source_id", "asset.ip_address"]

    filters = []
    for key in dedup_key:
        if key == "source_system":
            filters.append(Finding.source_system == source_system)
        elif key == "source_id":
            filters.append(Finding.source_id == source_id)
        elif key == "asset.ip_address":
            # Join through asset
            filters.append(Finding.asset_id == Asset.id)
            filters.append(Asset.ip == ip)
        elif key == "plugin_id":
            filters.append(Finding.plugin_id == record.get("plugin_id", ""))

    if not filters:
        return None
    query = db.query(Finding)
    if any("asset" in str(f) for f in filters):
        query = query.join(Asset, Finding.asset_id == Asset.id)
    return query.filter(and_(*filters)).first()


def _resolve_asset(db: Session, ip: str, hostname: str, source_system: str, scan_id: int) -> Asset:
    """Find or create an asset for a finding."""
    asset = None
    if ip:
        asset = db.query(Asset).filter(Asset.ip == ip).first()
    if not asset and hostname:
        asset = db.query(Asset).filter(Asset.hostname == hostname).first()
    if not asset:
        asset = Asset(
            scan_id=scan_id or 0,
            ip=ip,
            hostname=hostname,
            source_system=source_system,
            source_id=f"auto:{ip or hostname}",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(asset)
        db.flush()
    return asset


def _to_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

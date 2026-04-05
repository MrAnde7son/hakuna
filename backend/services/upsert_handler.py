"""Upsert engine — insert or update records from mapped integration data.

Supports the original hardcoded asset/finding paths for backward compatibility,
plus a generic model-driven upsert for any model registered in the model registry.
"""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

from models.models import Asset, Finding
from integrations.model_registry import get_model_meta
from services.asset_observations import record_observation, record_finding_observation

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
    # Hardcoded paths for backward compatibility (asset/finding have special logic)
    if entity_type == "asset":
        return _upsert_asset(db, mapped_record, dedup_key, integration_id, scan_id)
    elif entity_type == "finding":
        return _upsert_finding(db, mapped_record, dedup_key, integration_id, scan_id)
    elif entity_type == "action":
        return UpsertResult(action="skipped", errors=["Action entity push not implemented in upsert"])

    # Generic model-driven upsert for any registered model
    meta = get_model_meta(entity_type)
    if meta is None:
        return UpsertResult(action="skipped", errors=[f"Unknown entity type: {entity_type}"])
    return _generic_upsert(db, meta, mapped_record, dedup_key)


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
            "asset_type": "asset_type",
            "asset_identity": "asset_identity",
            "asset_attributes": "asset_attributes",
            "is_internet_facing": "is_internet_facing",
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

        # Deep-merge easm_data (connector-specific blobs accumulate, not overwrite)
        new_easm = record.get("easm_data")
        if new_easm and isinstance(new_easm, dict) and "easm_data" not in user_edited:
            merged = dict(existing.easm_data or {})
            for k, v in new_easm.items():
                if isinstance(v, dict) and isinstance(merged.get(k), dict):
                    merged[k] = {**merged[k], **v}
                else:
                    merged[k] = v
            existing.easm_data = merged
            updated = True

        # Accumulate source provenance
        _accumulate_source(existing, source_system)

        # Side effect: create policy assignment if present
        _handle_policy_assignment(db, record, existing.id, scan_id)

        # Side effect: create asset relationships if mapped
        _handle_relationship_map(db, record, existing.id, scan_id)

        # Record per-source observation
        record_observation(
            db, asset_id=existing.id, source_system=source_system,
            raw_fields=record, scan_id=scan_id,
        )

        return UpsertResult(action="updated" if updated else "skipped", id=existing.id)
    else:
        # Evaluate asset-type rules before insert (if no type already set by mapping)
        if not record.get("asset_type") or record.get("asset_type") == "host":
            try:
                import services.asset_type_rules as asset_type_rule_engine
                # Pass all available fields — normalize_asset_data() handles
                # flattening easm_data and computing derived fingerprint signals.
                rule_data = dict(record)
                rule_data.setdefault("hostname", record.get("hostname", ""))
                rule_data.setdefault("ip", record.get("ip_address", ""))
                rule_data.setdefault("fqdn", record.get("fqdn", ""))
                rule_data.setdefault("os", record.get("os", ""))
                rule_data.setdefault("source_type", "integration")
                type_result = asset_type_rule_engine.evaluate_asset_type_rules(
                    rule_data, db, source_type="integration",
                )
                if type_result:
                    record["asset_type"] = type_result["asset_type"]
                    record["asset_identity"] = type_result["asset_identity"]
                    record["asset_attributes"] = {
                        **record.get("asset_attributes", {}),
                        **type_result["asset_attributes"],
                    }
            except Exception:
                pass  # graceful fallback — don't block upsert

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
            source_systems=[source_system] if source_system else [],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            asset_type=record.get("asset_type", "host"),
            asset_identity=record.get("asset_identity", {}),
            asset_attributes=record.get("asset_attributes", {}),
            easm_data=record.get("easm_data"),
            is_internet_facing=record.get("is_internet_facing", False),
        )
        db.add(asset)
        db.flush()

        # Side effect: create policy assignment if present
        _handle_policy_assignment(db, record, asset.id, scan_id)

        # Side effect: create asset relationships if mapped
        _handle_relationship_map(db, record, asset.id, scan_id)

        # Record per-source observation
        record_observation(
            db, asset_id=asset.id, source_system=source_system,
            raw_fields=record, scan_id=scan_id,
        )

        return UpsertResult(action="inserted", id=asset.id)


def _handle_policy_assignment(db, record, asset_id, scan_id):
    """Create SecurityControlPolicyAssignment if the record has policy data."""
    policy_external_id = record.get("_prevention_policy_id")
    if not policy_external_id:
        return

    from models.models import SecurityControlPolicy, SecurityControlPolicyAssignment, Scan

    # Find the policy by external ID
    scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    org_id = scan.org_id if scan else None
    if not org_id:
        return

    policy = db.query(SecurityControlPolicy).filter(
        SecurityControlPolicy.org_id == org_id,
        SecurityControlPolicy.policy_external_id == policy_external_id,
    ).first()
    if not policy:
        return

    # Upsert assignment
    existing_assignment = db.query(SecurityControlPolicyAssignment).filter(
        SecurityControlPolicyAssignment.policy_id == policy.id,
        SecurityControlPolicyAssignment.asset_id == asset_id,
    ).first()
    if not existing_assignment:
        groups = record.get("_host_groups", [])
        db.add(SecurityControlPolicyAssignment(
            org_id=org_id,
            policy_id=policy.id,
            asset_id=asset_id,
            assignment_source="host_group",
            source_group_id=groups[0] if groups else None,
            synced_at=datetime.utcnow(),
        ))


def _handle_relationship_map(db, record, asset_id, scan_id):
    """Create AssetRelationship edges if the record has _relationship_map entries.

    Connector JSON can define:
      {"source": "cname_target", "target": "_relationship_map",
       "transform": {"type": "expression",
                     "expr": "[{'target_hostname': value, 'relationship_type': 'resolves_to'}]"}}

    Or directly in the mapped record via field_map:
      _relationship_map: [
        {"target_hostname": "my-alb.elb.amazonaws.com", "relationship_type": "resolves_to"},
        {"target_ip": "10.0.0.5", "relationship_type": "depends_on"},
        {"target_asset_id": 42, "relationship_type": "hosts"},
      ]
    """
    rel_maps = record.get("_relationship_map")
    if not rel_maps or not isinstance(rel_maps, list):
        return

    from models.models import Asset, AssetRelationship, Scan

    scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
    org_id = scan.org_id if scan else None
    if not org_id:
        return

    for rel_spec in rel_maps:
        if not isinstance(rel_spec, dict):
            continue
        rel_type = rel_spec.get("relationship_type", "resolves_to")
        confidence = rel_spec.get("confidence", "high")

        # Resolve target asset by ID, hostname, FQDN, or IP
        target_asset = None
        if rel_spec.get("target_asset_id"):
            target_asset = db.query(Asset).filter(Asset.id == rel_spec["target_asset_id"]).first()
        else:
            # Search by hostname/fqdn/ip within this org's scans
            org_scan_ids = db.query(Scan.id).filter(Scan.org_id == org_id).scalar_subquery()
            for field in ("target_hostname", "target_fqdn", "target_ip"):
                val = rel_spec.get(field)
                if not val:
                    continue
                col_name = field.replace("target_", "")  # hostname, fqdn, ip
                col = getattr(Asset, col_name, None)
                if col is None:
                    continue
                target_asset = db.query(Asset).filter(
                    col == val, Asset.scan_id.in_(org_scan_ids),
                ).first()
                if target_asset:
                    break

        if not target_asset or target_asset.id == asset_id:
            continue

        # Idempotent edge creation
        existing = db.query(AssetRelationship).filter(
            AssetRelationship.org_id == org_id,
            AssetRelationship.source_asset_id == asset_id,
            AssetRelationship.target_asset_id == target_asset.id,
            AssetRelationship.relationship_type == rel_type,
        ).first()
        if not existing:
            db.add(AssetRelationship(
                org_id=org_id,
                source_asset_id=asset_id,
                target_asset_id=target_asset.id,
                relationship_type=rel_type,
                confidence=confidence,
                source_detail={"connector": record.get("source_system", ""), "manual": False},
            ))


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
        # Accumulate source provenance
        _accumulate_source(existing, source_system)
        # Do NOT change workflow_status if user has set it

        # Record per-source finding observation
        record_finding_observation(
            db, finding_id=existing.id, source_system=source_system,
            raw_fields=record, scan_id=scan_id,
        )

        return UpsertResult(action="updated" if updated else "skipped", id=existing.id)
    else:
        # Insert new finding
        finding = Finding(
            scan_id=scan_id or 0,
            asset_id=asset.id,
            source_type=source_system or "integration",
            source_id=source_id,
            source_system=source_system,
            source_systems=[source_system] if source_system else [],
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

        # Record per-source finding observation
        record_finding_observation(
            db, finding_id=finding.id, source_system=source_system,
            raw_fields=record, scan_id=scan_id,
        )

        return UpsertResult(action="inserted", id=finding.id)


def _generic_upsert(db: Session, meta, record: dict, dedup_key: list) -> UpsertResult:
    """Generic upsert for any registered model — uses introspected columns and dedup keys."""
    model_cls = meta.model_class
    dedup_key = dedup_key or meta.dedup_keys

    # Resolve parent FK if parent_hint exists
    if meta.parent_hint:
        _resolve_parent_fk(db, meta, record)

    # Build dedup filter
    filters = []
    for key in dedup_key:
        if hasattr(model_cls, key) and record.get(key) is not None:
            filters.append(getattr(model_cls, key) == record[key])

    if not filters:
        # No dedup possible — always insert
        return _generic_insert(db, meta, record)

    existing = db.query(model_cls).filter(and_(*filters)).first()
    if existing:
        updated = False
        for col in meta.writable_columns:
            col_name = col["name"]
            if col_name in dedup_key:
                continue
            value = _coerce(record.get(col_name), col["type"])
            if value is not None:
                setattr(existing, col_name, value)
                updated = True
        return UpsertResult(action="updated" if updated else "skipped", id=existing.id)
    else:
        return _generic_insert(db, meta, record)


def _generic_insert(db: Session, meta, record: dict) -> UpsertResult:
    """Insert a new record for a registered model."""
    obj = meta.model_class()
    for col in meta.writable_columns:
        col_name = col["name"]
        value = _coerce(record.get(col_name), col["type"])
        if value is not None:
            setattr(obj, col_name, value)
    db.add(obj)
    db.flush()
    return UpsertResult(action="inserted", id=obj.id)


def _resolve_parent_fk(db: Session, meta, record: dict):
    """Resolve a parent FK from mapped record data using the parent_hint."""
    hint = meta.parent_hint
    parent_meta = get_model_meta(hint.parent_slug)
    if parent_meta is None:
        return
    parent_cls = parent_meta.model_class
    fk_field = hint.field  # e.g. "asset_id"

    # If the FK is already set directly, skip resolution
    if record.get(fk_field):
        return

    # Try to resolve by each resolve_by field
    for resolve_field in hint.resolve_by:
        value = record.get(resolve_field)
        if value and hasattr(parent_cls, resolve_field):
            parent = db.query(parent_cls).filter(
                getattr(parent_cls, resolve_field) == value
            ).first()
            if parent:
                record[fk_field] = parent.id
                return


def upsert_batch(db: Session, entity_type: str, mapped_records: list, dedup_key: list,
                  integration_id: str, scan_id: int = None) -> dict:
    """Process a batch of records. Returns aggregate counts and new IDs."""
    counts = {"inserted": 0, "updated": 0, "skipped": 0, "errors": [],
              "new_asset_ids": [], "new_finding_ids": []}
    for record in mapped_records:
        try:
            result = upsert(db, entity_type, record, dedup_key, integration_id, scan_id)
            counts[result.action] = counts.get(result.action, 0) + 1
            if result.action == "inserted" and result.id:
                if entity_type == "asset":
                    counts["new_asset_ids"].append(result.id)
                elif entity_type == "finding":
                    counts["new_finding_ids"].append(result.id)
            if result.errors:
                counts["errors"].extend(result.errors)
        except Exception as e:
            db.rollback()
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
            source_systems=[source_system] if source_system else [],
            source_id=f"auto:{ip or hostname}",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.add(asset)
        db.flush()
    return asset


def _accumulate_source(record, source_system: str):
    """Append source_system to the record's source_systems list if not already present."""
    if not source_system:
        return
    current = record.source_systems or []
    if source_system not in current:
        record.source_systems = current + [source_system]


def _to_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _coerce(value, col_type: str):
    """Coerce a mapped value to the column's expected Python type.

    Returns None rather than raising when the value is incompatible — the record
    will be stored with that field empty rather than crashing the whole batch.
    """
    if value is None:
        return None
    if col_type == "float":
        return _to_float(value)
    if col_type == "integer":
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    if col_type == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    # string / json / datetime — pass through as-is
    return value

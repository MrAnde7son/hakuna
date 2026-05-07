"""Custom field definition routes — per-org user-defined fields on Asset/Finding.

Endpoints:
    GET    /api/custom-fields?entity_type=asset|finding
    POST   /api/custom-fields                       — create + backfill
    PUT    /api/custom-fields/{id}                  — update + backfill
    DELETE /api/custom-fields/{id}                  — delete + clear values
    POST   /api/custom-fields/preview               — resolve a def against a sample entity
    POST   /api/custom-fields/{id}/backfill         — explicit re-run
"""
import re
from typing import Optional, List, Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from datetime import datetime

from core.database import get_db
from core.auth import require_auth, get_accessible_org_ids, resolve_active_org_id
from core.time_utils import iso_utc
from models.models import (
    User, CustomFieldDefinition, Asset, Finding, Scan,
    AssetObservation, FindingObservation,
)
from services.custom_field_resolver import (
    apply_custom_fields, _coerce_value, _entity_snapshot,
)
from services.field_mapper import _resolve_path, _apply_transform

router = APIRouter()

VALID_ENTITIES = {"asset", "finding"}
VALID_DATA_TYPES = {"string", "number", "boolean", "date", "enum"}
VALID_SOURCE_TYPES = {"mapping", "formula", "manual"}
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────


class CustomFieldCreate(BaseModel):
    entity_type: str
    key: str
    label: str
    description: Optional[str] = None
    data_type: str = "string"
    enum_values: Optional[List[str]] = None
    source_type: str = "manual"
    mapping_source: Optional[str] = None
    mapping_transform: Optional[Dict[str, Any]] = None
    mapping_source_system: Optional[str] = None
    formula_expression: Optional[str] = None
    show_in_list: bool = False
    is_active: bool = True


class CustomFieldUpdate(BaseModel):
    label: Optional[str] = None
    description: Optional[str] = None
    data_type: Optional[str] = None
    enum_values: Optional[List[str]] = None
    source_type: Optional[str] = None
    mapping_source: Optional[str] = None
    mapping_transform: Optional[Dict[str, Any]] = None
    mapping_source_system: Optional[str] = None
    formula_expression: Optional[str] = None
    show_in_list: Optional[bool] = None
    is_active: Optional[bool] = None


class CustomFieldPreview(BaseModel):
    entity_type: str
    source_type: str
    data_type: str = "string"
    mapping_source: Optional[str] = None
    mapping_transform: Optional[Dict[str, Any]] = None
    formula_expression: Optional[str] = None
    sample_entity_id: Optional[int] = None        # resolve against a real row
    sample_record: Optional[Dict[str, Any]] = None # or against a literal payload


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────


def _require_org(user: User) -> int:
    if not user.org_id:
        raise HTTPException(400, "User has no org context")
    return user.org_id


def _validate_definition(payload: CustomFieldCreate | CustomFieldUpdate, existing: Optional[CustomFieldDefinition] = None):
    """Validate field-level invariants. Raises HTTPException on failure."""
    def val(name: str):
        pv = getattr(payload, name, None)
        if pv is not None:
            return pv
        return getattr(existing, name, None) if existing else None

    entity_type = val("entity_type") if existing is None else existing.entity_type
    if entity_type not in VALID_ENTITIES:
        raise HTTPException(400, f"entity_type must be one of {sorted(VALID_ENTITIES)}")

    data_type = val("data_type") or "string"
    if data_type not in VALID_DATA_TYPES:
        raise HTTPException(400, f"data_type must be one of {sorted(VALID_DATA_TYPES)}")

    source_type = val("source_type") or "manual"
    if source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(400, f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}")

    if data_type == "enum":
        ev = val("enum_values")
        if not ev or not isinstance(ev, list):
            raise HTTPException(400, "enum data_type requires non-empty enum_values")

    if source_type == "mapping" and not val("mapping_source"):
        raise HTTPException(400, "mapping source_type requires mapping_source")

    if source_type == "formula" and not val("formula_expression"):
        raise HTTPException(400, "formula source_type requires formula_expression")

    if existing is None:
        key = payload.key
        if not KEY_PATTERN.match(key or ""):
            raise HTTPException(400, "key must match [a-z][a-z0-9_]{0,63}")


def _def_to_dict(d: CustomFieldDefinition) -> dict:
    return {
        "id": d.id,
        "org_id": d.org_id,
        "entity_type": d.entity_type,
        "key": d.key,
        "label": d.label,
        "description": d.description,
        "data_type": d.data_type,
        "enum_values": d.enum_values,
        "source_type": d.source_type,
        "mapping_source": d.mapping_source,
        "mapping_transform": d.mapping_transform,
        "mapping_source_system": d.mapping_source_system,
        "formula_expression": d.formula_expression,
        "show_in_list": bool(d.show_in_list),
        "is_active": bool(d.is_active),
        "created_by": d.created_by,
        "created_at": iso_utc(d.created_at),
        "updated_at": iso_utc(d.updated_at),
    }


def _entities_query(db: Session, entity_type: str, org_id: int):
    """Scan-scoped query for all rows in an org."""
    if entity_type == "asset":
        return db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == org_id)
    return db.query(Finding).join(Scan, Finding.scan_id == Scan.id).filter(Scan.org_id == org_id)


def _latest_observation_record(db: Session, entity_type: str, entity_id: int,
                                source_system: Optional[str] = None) -> Dict[str, Any]:
    """Fetch the most recent raw_fields observation for an entity."""
    model = AssetObservation if entity_type == "asset" else FindingObservation
    fk = AssetObservation.asset_id if entity_type == "asset" else FindingObservation.finding_id
    q = db.query(model).filter(fk == entity_id)
    if source_system:
        q = q.filter(model.source_system == source_system)
    obs = q.order_by(model.last_seen.desc()).first()
    if obs and obs.raw_fields:
        return dict(obs.raw_fields)
    return {}


def _backfill(db: Session, definition: CustomFieldDefinition, batch_size: int = 500) -> int:
    """Re-resolve a single definition's value for all existing rows in its org."""
    q = _entities_query(db, definition.entity_type, definition.org_id)
    total = 0
    offset = 0
    while True:
        batch = q.offset(offset).limit(batch_size).all()
        if not batch:
            break
        for entity in batch:
            user_edited = set(entity.user_edited_fields or [])
            if f"custom_fields.{definition.key}" in user_edited:
                continue
            if definition.source_type == "manual":
                # Nothing to compute; leave existing value alone.
                continue
            if definition.source_type == "mapping":
                record = _latest_observation_record(
                    db, definition.entity_type, entity.id, definition.mapping_source_system
                )
            else:  # formula
                record = _entity_snapshot(entity)
            apply_custom_fields(entity, record, [definition])
            total += 1
        db.commit()
        offset += batch_size
    return total


def _clear_field_values(db: Session, definition: CustomFieldDefinition) -> int:
    """Remove a key from every entity.custom_fields in the org after delete."""
    q = _entities_query(db, definition.entity_type, definition.org_id)
    total = 0
    for entity in q.yield_per(500):
        current = dict(entity.custom_fields or {})
        if definition.key in current:
            current.pop(definition.key, None)
            entity.custom_fields = current
            total += 1
    db.commit()
    return total


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────


@router.get("/api/custom-fields")
def list_custom_fields(
    entity_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(CustomFieldDefinition)
    if org_ids is not None:
        q = q.filter(CustomFieldDefinition.org_id.in_(org_ids))
    if entity_type:
        if entity_type not in VALID_ENTITIES:
            raise HTTPException(400, f"entity_type must be one of {sorted(VALID_ENTITIES)}")
        q = q.filter(CustomFieldDefinition.entity_type == entity_type)
    defs = q.order_by(CustomFieldDefinition.entity_type, CustomFieldDefinition.label).all()
    return [_def_to_dict(d) for d in defs]


@router.post("/api/custom-fields")
def create_custom_field(
    body: CustomFieldCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    org_id = resolve_active_org_id(user, org_ids)
    if not org_id:
        raise HTTPException(400, "User has no org context")
    _validate_definition(body)

    existing = db.query(CustomFieldDefinition).filter(
        CustomFieldDefinition.org_id == org_id,
        CustomFieldDefinition.entity_type == body.entity_type,
        CustomFieldDefinition.key == body.key,
    ).first()
    if existing:
        raise HTTPException(409, f"custom field '{body.key}' already exists for {body.entity_type}")

    definition = CustomFieldDefinition(
        org_id=org_id,
        entity_type=body.entity_type,
        key=body.key,
        label=body.label,
        description=body.description,
        data_type=body.data_type,
        enum_values=body.enum_values,
        source_type=body.source_type,
        mapping_source=body.mapping_source,
        mapping_transform=body.mapping_transform,
        mapping_source_system=body.mapping_source_system,
        formula_expression=body.formula_expression,
        show_in_list=body.show_in_list,
        is_active=body.is_active,
        created_by=user.email if user else None,
    )
    db.add(definition)
    db.commit()
    db.refresh(definition)

    backfilled = 0
    if definition.is_active and definition.source_type != "manual":
        backfilled = _backfill(db, definition)

    payload = _def_to_dict(definition)
    payload["backfilled"] = backfilled
    return payload


@router.put("/api/custom-fields/{def_id}")
def update_custom_field(
    def_id: int,
    body: CustomFieldUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(CustomFieldDefinition).filter(CustomFieldDefinition.id == def_id)
    if org_ids is not None:
        q = q.filter(CustomFieldDefinition.org_id.in_(org_ids))
    definition = q.first()
    if not definition:
        raise HTTPException(404, "Custom field not found")

    _validate_definition(body, existing=definition)

    changed_resolver_fields = False
    for attr in (
        "label", "description", "data_type", "enum_values", "source_type",
        "mapping_source", "mapping_transform", "mapping_source_system",
        "formula_expression", "show_in_list", "is_active",
    ):
        value = getattr(body, attr)
        if value is not None:
            if attr in ("source_type", "mapping_source", "mapping_transform",
                        "formula_expression", "data_type", "mapping_source_system"):
                if getattr(definition, attr) != value:
                    changed_resolver_fields = True
            setattr(definition, attr, value)

    db.commit()
    db.refresh(definition)

    backfilled = 0
    if changed_resolver_fields and definition.is_active and definition.source_type != "manual":
        backfilled = _backfill(db, definition)

    payload = _def_to_dict(definition)
    payload["backfilled"] = backfilled
    return payload


@router.delete("/api/custom-fields/{def_id}")
def delete_custom_field(
    def_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(CustomFieldDefinition).filter(CustomFieldDefinition.id == def_id)
    if org_ids is not None:
        q = q.filter(CustomFieldDefinition.org_id.in_(org_ids))
    definition = q.first()
    if not definition:
        raise HTTPException(404, "Custom field not found")

    cleared = _clear_field_values(db, definition)
    db.delete(definition)
    db.commit()
    return {"deleted": True, "cleared_rows": cleared}


@router.post("/api/custom-fields/{def_id}/backfill")
def backfill_custom_field(
    def_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = db.query(CustomFieldDefinition).filter(CustomFieldDefinition.id == def_id)
    if org_ids is not None:
        q = q.filter(CustomFieldDefinition.org_id.in_(org_ids))
    definition = q.first()
    if not definition:
        raise HTTPException(404, "Custom field not found")
    if definition.source_type == "manual":
        raise HTTPException(400, "manual custom fields cannot be backfilled")
    processed = _backfill(db, definition)
    return {"processed": processed}


@router.post("/api/custom-fields/preview")
def preview_custom_field(
    body: CustomFieldPreview,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Resolve a tentative definition against a sample entity or record.

    Used by the UI to show a live preview while the user is editing the
    definition, before saving it.
    """
    org_id = resolve_active_org_id(user, org_ids)
    if not org_id:
        raise HTTPException(400, "User has no org context")
    if body.entity_type not in VALID_ENTITIES:
        raise HTTPException(400, f"entity_type must be one of {sorted(VALID_ENTITIES)}")
    if body.source_type not in VALID_SOURCE_TYPES:
        raise HTTPException(400, f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}")

    # Build the record surface
    record: Dict[str, Any] = {}
    merged: Dict[str, Any] = {}
    if body.sample_entity_id:
        if body.entity_type == "asset":
            entity = (
                db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
                .filter(Asset.id == body.sample_entity_id, Scan.org_id == org_id)
                .first()
            )
        else:
            entity = (
                db.query(Finding).join(Scan, Finding.scan_id == Scan.id)
                .filter(Finding.id == body.sample_entity_id, Scan.org_id == org_id)
                .first()
            )
        if not entity:
            raise HTTPException(404, "Sample entity not found")
        record = _latest_observation_record(db, body.entity_type, entity.id)
        merged = _entity_snapshot(entity)
    elif body.sample_record is not None:
        record = body.sample_record
        merged = dict(body.sample_record)

    # Resolve
    error = None
    value: Any = None
    try:
        if body.source_type == "mapping":
            if not body.mapping_source:
                raise HTTPException(400, "mapping_source required")
            raw = _resolve_path(record, body.mapping_source)
            if raw is None:
                value = None
                error = f"Source path '{body.mapping_source}' not found in sample"
            else:
                value = raw
                if body.mapping_transform:
                    transformed, err = _apply_transform(raw, body.mapping_transform, record)
                    value = transformed
                    error = err
        elif body.source_type == "formula":
            if not body.formula_expression:
                raise HTTPException(400, "formula_expression required")
            transformed, err = _apply_transform(
                None, {"type": "expression", "expr": body.formula_expression}, merged
            )
            value = transformed
            error = err
        else:
            value = None  # manual
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        error = str(e)

    coerced = _coerce_value(value, body.data_type) if value is not None else None
    return {
        "raw_value": _jsonable(value),
        "coerced_value": _jsonable(coerced),
        "error": error,
    }


def _jsonable(value: Any) -> Any:
    """Best-effort conversion to JSON-serializable value for preview responses."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, datetime):
        return iso_utc(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)

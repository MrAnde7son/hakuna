"""Custom field resolver — compute per-definition values at ingest time.

Resolves CustomFieldDefinition values for Asset and Finding rows by either:
  - mapping: walking a dot-path into the incoming source observation record
  - formula: evaluating a sandboxed expression against the merged entity dict
  - manual:  skipped at ingest (only set via PATCH endpoint)

Values are coerced by the definition's data_type and written into
entity.custom_fields[key], respecting user_edited_fields protection
(skip if `custom_fields.<key>` is in the list).
"""

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from models.models import CustomFieldDefinition
from services.field_mapper import _resolve_path, _apply_transform

logger = logging.getLogger(__name__)


def load_custom_field_defs(
    db: Session, org_id: Optional[int], entity_type: str
) -> List[CustomFieldDefinition]:
    """Load active custom field definitions for an org + entity_type."""
    if not org_id:
        return []
    return (
        db.query(CustomFieldDefinition)
        .filter(
            CustomFieldDefinition.org_id == org_id,
            CustomFieldDefinition.entity_type == entity_type,
            CustomFieldDefinition.is_active.is_(True),
        )
        .all()
    )


def apply_custom_fields(
    entity,
    record: Dict[str, Any],
    definitions: List[CustomFieldDefinition],
) -> bool:
    """Resolve and write custom field values onto entity.custom_fields.

    Respects entity.user_edited_fields — keys marked as `custom_fields.<key>`
    are left untouched. Returns True if any value was written.
    """
    if not definitions:
        return False

    user_edited = set(entity.user_edited_fields or [])
    current = dict(entity.custom_fields or {})
    updated = False

    # Merged-entity view for formula source: use the current entity's persisted
    # columns (post-mapping) plus the raw record, so formulas can reference
    # either surface.
    merged_view = _entity_snapshot(entity)
    merged_view.update({k: v for k, v in record.items() if k not in merged_view})

    for definition in definitions:
        key = definition.key
        if f"custom_fields.{key}" in user_edited:
            continue

        try:
            value = _resolve_value(definition, record, merged_view)
        except Exception as e:  # pragma: no cover — defensive
            logger.warning(
                "custom_field %s (org=%s entity=%s) resolve error: %s",
                key, definition.org_id, definition.entity_type, e,
            )
            continue

        if value is None:
            continue

        coerced = _coerce_value(value, definition.data_type)
        if coerced is None:
            continue

        if current.get(key) != coerced:
            current[key] = coerced
            updated = True

    if updated:
        entity.custom_fields = current
    return updated


def _resolve_value(
    definition: CustomFieldDefinition,
    record: Dict[str, Any],
    merged_view: Dict[str, Any],
) -> Any:
    source_type = definition.source_type or "manual"

    if source_type == "manual":
        return None

    if source_type == "mapping":
        path = definition.mapping_source
        if not path:
            return None
        value = _resolve_path(record, path)
        if value is None:
            return None
        transform = definition.mapping_transform
        if transform:
            transformed, err = _apply_transform(value, transform, record)
            if err:
                logger.debug(
                    "custom_field %s transform warning: %s", definition.key, err
                )
            return transformed
        return value

    if source_type == "formula":
        expr = definition.formula_expression
        if not expr:
            return None
        # Reuse the sandboxed `expression` transform branch from field_mapper
        # by invoking it with a noop base value and the merged view as the
        # record surface for `record.*` / attribute-style access.
        value, err = _apply_transform(
            None, {"type": "expression", "expr": expr}, merged_view
        )
        if err:
            logger.debug(
                "custom_field %s formula warning: %s", definition.key, err
            )
        return value

    return None


def _coerce_value(value: Any, data_type: str) -> Any:
    """Coerce a resolved value into the definition's declared data_type."""
    if value is None:
        return None
    try:
        if data_type == "number":
            return float(value)
        if data_type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            return str(value).strip().lower() in ("true", "1", "yes", "y", "t")
        if data_type == "date":
            # Accept ISO strings or datetime; store as ISO string for JSON compat
            if hasattr(value, "isoformat"):
                return value.isoformat()
            return str(value)
        # string / enum — pass through as str (JSON-serializable)
        if isinstance(value, (dict, list)):
            return value
        return str(value)
    except (ValueError, TypeError):
        return None


def _entity_snapshot(entity) -> Dict[str, Any]:
    """Shallow dict of an Asset/Finding's column values for formula evaluation."""
    try:
        columns = entity.__table__.columns
    except AttributeError:
        return {}
    snapshot: Dict[str, Any] = {}
    for col in columns:
        name = col.name
        try:
            snapshot[name] = getattr(entity, name)
        except Exception:
            snapshot[name] = None
    return snapshot

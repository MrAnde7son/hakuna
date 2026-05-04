"""Compliance framework YAML loader.

Reads versioned mapping YAMLs from ``backend/compliance/frameworks/<slug>/``
and idempotently upserts:
  - compliance_frameworks
  - compliance_controls
  - compliance_control_mappings
  - compliance_framework_releases  (audit trail; one row per (framework, release_tag))

A YAML is processed only when its sha256 differs from the most recent
recorded ``compliance_framework_releases.mapping_file_sha256`` for that
framework — a re-boot with unchanged YAML is a no-op.

Validation runs before any DB write: every mapping rule is fed to
rule_engine to confirm the field/op combination is recognized. A single
unknown field aborts the whole release for that framework so we never end
up with a partially-loaded rule set that would silently drop matches at
evaluation time.

Failures are logged but never raise — boot must continue even if a single
framework YAML is malformed. Sentry breadcrumbs make the failure visible.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml
from sqlalchemy.orm import Session

from models.models import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceFrameworkRelease,
    AuditLog,
)
from services.rule_engine import CONDITION_CATALOG

logger = logging.getLogger(__name__)


# Default location relative to the backend root. Tests override via
# load_all_frameworks(root=...).
_DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "compliance" / "frameworks"


# ──────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────

# Operators that are always valid regardless of field type. The compliance
# evaluator handles list-shaped values for these.
_LIST_OPS = {"in", "not_in", "contains_any", "contains_all"}
# Boolean operators valid on any boolean-shaped field.
_BOOL_OPS = {"is_true", "is_false"}


def _flatten_catalog(catalog: list) -> dict[str, set[str]]:
    """Build a {field: {ops}} map from CONDITION_CATALOG."""
    flat: dict[str, set[str]] = {}
    for group in catalog:
        for cond in group.get("conditions", []):
            field = cond.get("field")
            ops = cond.get("ops") or []
            if not field:
                continue
            flat.setdefault(field, set()).update(ops)
            # Catalog ops are the UI-exposed list; the evaluator also accepts
            # in/not_in on any string/numeric field even when the picker
            # doesn't expose them. Normalize that here.
            flat[field].update(_LIST_OPS)
    return flat


def _validate_rule(rule: dict, catalog_map: dict[str, set[str]]) -> Optional[str]:
    """Return None if the rule is valid, else a string error message.

    Validates structure (logic + conditions list) and that each condition's
    field is registered in the rule_engine catalog and supports the chosen op.
    """
    if not isinstance(rule, dict):
        return f"rule must be a dict, got {type(rule).__name__}"
    logic = (rule.get("logic") or "AND").upper()
    if logic not in ("AND", "OR"):
        return f"rule.logic must be 'AND' or 'OR', got {logic!r}"
    conditions = rule.get("conditions")
    if not isinstance(conditions, list):
        return "rule.conditions must be a list"
    for i, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            return f"conditions[{i}] must be a dict"
        field = cond.get("field")
        op = cond.get("op")
        if not field:
            return f"conditions[{i}].field is required"
        if not op:
            return f"conditions[{i}].op is required"
        if field not in catalog_map:
            return f"conditions[{i}].field={field!r} is not in rule_engine catalog"
        allowed = catalog_map[field] | _BOOL_OPS
        if op not in allowed:
            return (
                f"conditions[{i}] op={op!r} not allowed for field={field!r}; "
                f"allowed: {sorted(allowed)}"
            )
    return None


# ──────────────────────────────────────────────────────────────
# YAML discovery + parsing
# ──────────────────────────────────────────────────────────────

def _discover_yaml_files(root: Path) -> list[Path]:
    """Return the YAML file in each framework directory.

    A framework directory may carry multiple version files; we pick the
    most recent (lexicographic max) so re-loading after a release just
    drops a new file in place.
    """
    if not root.exists():
        return []
    out: list[Path] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        yamls = sorted(child.glob("*.yaml")) + sorted(child.glob("*.yml"))
        if not yamls:
            continue
        out.append(yamls[-1])
    return out


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _coerce_published_at(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    if hasattr(raw, "year"):  # date
        return datetime(raw.year, raw.month, raw.day)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


# ──────────────────────────────────────────────────────────────
# Idempotent upserts
# ──────────────────────────────────────────────────────────────

def _upsert_framework(
    db: Session,
    fw_block: dict,
    *,
    org_id: Optional[int] = None,
    created_by: Optional[int] = None,
    source: str = "builtin",
) -> ComplianceFramework:
    slug = fw_block["slug"]
    # Slug uniqueness is per-org since migration 060 — match exactly the same
    # (slug, org_id) row so a tenant import can never overwrite a builtin.
    fw = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.slug == slug,
                ComplianceFramework.org_id == org_id)
        .first()
    )
    if fw is None:
        fw = ComplianceFramework(
            slug=slug,
            name=fw_block.get("name", slug),
            version=str(fw_block.get("version", "1")),
            authority=fw_block.get("authority"),
            published_at=_coerce_published_at(fw_block.get("published_at")),
            description=fw_block.get("description"),
            categories=list(fw_block.get("categories") or []),
            mapping_schema_version=int(fw_block.get("mapping_schema_version", 1)),
            org_id=org_id,
            created_by=created_by,
            source=source,
        )
        db.add(fw)
        db.flush()
    else:
        fw.name = fw_block.get("name", fw.name)
        fw.version = str(fw_block.get("version", fw.version))
        fw.authority = fw_block.get("authority", fw.authority)
        fw.published_at = _coerce_published_at(fw_block.get("published_at")) or fw.published_at
        fw.description = fw_block.get("description", fw.description)
        fw.categories = list(fw_block.get("categories") or [])
        fw.mapping_schema_version = int(fw_block.get("mapping_schema_version",
                                                     fw.mapping_schema_version))
    return fw


def _upsert_control(db: Session, fw: ComplianceFramework, ctrl_block: dict) -> ComplianceControl:
    ref = str(ctrl_block["ref"])
    ctrl = db.query(ComplianceControl).filter_by(framework_id=fw.id, ref=ref).first()
    if ctrl is None:
        ctrl = ComplianceControl(
            framework_id=fw.id, ref=ref,
            title=ctrl_block.get("title", ref),
            description=ctrl_block.get("description"),
            parent_ref=ctrl_block.get("parent_ref"),
            domain=ctrl_block.get("domain"),
            testability=ctrl_block.get("testability") or "automated",
            default_severity_floor=ctrl_block.get("default_severity_floor"),
            canonical_guidance=ctrl_block.get("canonical_guidance"),
        )
        db.add(ctrl)
        db.flush()
    else:
        ctrl.title = ctrl_block.get("title", ctrl.title)
        ctrl.description = ctrl_block.get("description", ctrl.description)
        ctrl.parent_ref = ctrl_block.get("parent_ref", ctrl.parent_ref)
        ctrl.domain = ctrl_block.get("domain", ctrl.domain)
        ctrl.testability = ctrl_block.get("testability") or ctrl.testability
        ctrl.default_severity_floor = ctrl_block.get("default_severity_floor",
                                                     ctrl.default_severity_floor)
        ctrl.canonical_guidance = ctrl_block.get("canonical_guidance", ctrl.canonical_guidance)
    return ctrl


def _normalize_rule(when_block: dict) -> dict:
    """Strip presentation-only keys so we can hash the rule body."""
    return {
        "logic": (when_block.get("logic") or "AND").upper(),
        "conditions": copy.deepcopy(when_block.get("conditions") or []),
    }


def _upsert_mapping(db: Session, ctrl: ComplianceControl, mapping_block: dict) -> ComplianceControlMapping:
    key = mapping_block["key"]
    rule = _normalize_rule(mapping_block["when"])
    existing = (
        db.query(ComplianceControlMapping)
        .filter_by(control_id=ctrl.id, mapping_key=key)
        .first()
    )
    if existing is None:
        m = ComplianceControlMapping(
            control_id=ctrl.id,
            mapping_key=key,
            rule=rule,
            rule_version=int(mapping_block.get("rule_version", 1)),
            testability=mapping_block.get("testability"),
        )
        db.add(m)
        db.flush()
        return m
    # Bump rule_version when the rule body actually changed; control_id is
    # already part of the lookup key, so no relink is needed.
    if existing.rule != rule:
        existing.rule = rule
        existing.rule_version = (existing.rule_version or 1) + 1
    existing.testability = mapping_block.get("testability", existing.testability)
    return existing


def _delete_stale_mappings(db: Session, ctrl: ComplianceControl, keep_keys: set[str]) -> int:
    """Remove mappings under this control whose keys are absent from the new YAML."""
    if not keep_keys:
        # If the YAML lists no mappings (e.g. testability=manual_only), drop all
        # prior automated mappings cleanly.
        stale = db.query(ComplianceControlMapping).filter_by(control_id=ctrl.id).all()
    else:
        stale = (
            db.query(ComplianceControlMapping)
            .filter(ComplianceControlMapping.control_id == ctrl.id)
            .filter(~ComplianceControlMapping.mapping_key.in_(keep_keys))
            .all()
        )
    for m in stale:
        db.delete(m)
    return len(stale)


def _delete_stale_controls(db: Session, fw: ComplianceFramework, keep_refs: set[str]) -> int:
    """Remove controls under this framework absent from the new YAML.

    Cascades through control_mappings and compliance_finding_status (FK
    ON DELETE CASCADE on both) so the evaluator can't reference a control
    that no longer exists.
    """
    stale = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == fw.id)
        .filter(~ComplianceControl.ref.in_(keep_refs))
        .all() if keep_refs else
        db.query(ComplianceControl).filter_by(framework_id=fw.id).all()
    )
    for c in stale:
        db.delete(c)
    return len(stale)


def _record_release(
    db: Session,
    fw: ComplianceFramework,
    *,
    release_tag: str,
    release_notes: Optional[str],
    sha256: str,
) -> Optional[ComplianceFrameworkRelease]:
    existing = (
        db.query(ComplianceFrameworkRelease)
        .filter_by(framework_id=fw.id, release_tag=release_tag)
        .first()
    )
    if existing:
        # Update the sha if the same tag was re-published; never duplicate.
        if existing.mapping_file_sha256 != sha256:
            existing.mapping_file_sha256 = sha256
            existing.released_at = datetime.utcnow()
        return existing
    rel = ComplianceFrameworkRelease(
        framework_id=fw.id,
        release_tag=release_tag,
        release_notes=release_notes,
        mapping_file_sha256=sha256,
    )
    db.add(rel)
    db.flush()
    return rel


def _audit_log(db: Session, action: str, fw: ComplianceFramework, payload: dict) -> None:
    """Best-effort audit log write — never raise into the loader."""
    try:
        db.add(AuditLog(
            entity_type="compliance_framework_release",
            entity_id=fw.id,
            entity_name=fw.slug,
            action=action,
            changes=payload,
        ))
        db.flush()
    except Exception:
        logger.exception("compliance_loader: failed to write AuditLog (non-fatal)")


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

def load_framework_from_yaml_text(
    db: Session,
    yaml_text: str,
    *,
    org_id: int,
    created_by: Optional[int] = None,
    catalog_map: Optional[dict[str, set[str]]] = None,
) -> dict:
    """Load a tenant-imported framework from a YAML string.

    Thin wrapper around the same parse → validate → upsert path used for
    on-disk packs, with two differences:
      - org_id is required (an import always belongs to a tenant)
      - source is recorded as "imported" so the UI can label it

    Returns the same status dict as load_framework_from_path.
    """
    if not org_id:
        return {"status": "schema_error", "error": "org_id required for imported framework"}

    catalog_map = catalog_map or _flatten_catalog(CONDITION_CATALOG)
    sha256 = hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()

    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return {"status": "parse_error", "error": str(exc)}

    if not isinstance(doc, dict) or "framework" not in doc:
        return {"status": "schema_error",
                "error": "top-level YAML must contain a `framework` block"}

    fw_block = doc["framework"]
    release_block = doc.get("release") or {}
    controls_block = doc.get("controls") or []

    if not fw_block.get("slug"):
        return {"status": "schema_error", "error": "framework.slug is required"}

    for ctrl_block in controls_block:
        for mapping_block in (ctrl_block.get("mappings") or []):
            err = _validate_rule(mapping_block.get("when") or {}, catalog_map)
            if err:
                return {
                    "status": "validation_error",
                    "framework_slug": fw_block["slug"],
                    "error": (
                        f"mapping {mapping_block.get('key')!r} under control "
                        f"{ctrl_block.get('ref')!r}: {err}"
                    ),
                }

    # Existing tenant-private framework with this slug?
    existing = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.slug == fw_block["slug"],
                ComplianceFramework.org_id == org_id)
        .first()
    )
    is_new = existing is None
    if existing is not None:
        last_release = (
            db.query(ComplianceFrameworkRelease)
            .filter_by(framework_id=existing.id)
            .order_by(ComplianceFrameworkRelease.released_at.desc())
            .first()
        )
        if last_release and last_release.mapping_file_sha256 == sha256:
            return {
                "status": "skipped", "framework_slug": existing.slug,
                "release_tag": last_release.release_tag,
            }

    fw = _upsert_framework(
        db, fw_block,
        org_id=org_id, created_by=created_by, source="imported",
    )
    keep_refs: set[str] = set()
    for ctrl_block in controls_block:
        ctrl = _upsert_control(db, fw, ctrl_block)
        keep_refs.add(ctrl.ref)
        keep_keys: set[str] = set()
        for mapping_block in (ctrl_block.get("mappings") or []):
            m = _upsert_mapping(db, ctrl, mapping_block)
            keep_keys.add(m.mapping_key)
        _delete_stale_mappings(db, ctrl, keep_keys)
    _delete_stale_controls(db, fw, keep_refs)

    release_tag = release_block.get("tag") or f"sha256:{sha256[:12]}"
    _record_release(db, fw, release_tag=release_tag,
                    release_notes=release_block.get("notes"), sha256=sha256)

    status = "loaded" if is_new else "updated"
    _audit_log(db, action=f"import_{status}", fw=fw, payload={
        "release_tag": release_tag,
        "sha256": sha256,
        "controls_count": len(controls_block),
        "org_id": org_id,
        "created_by": created_by,
    })
    db.commit()

    return {
        "status": status, "framework_slug": fw.slug,
        "framework_id": fw.id, "release_tag": release_tag,
        "controls_loaded": len(controls_block),
    }


def load_framework_from_path(
    db: Session,
    path: Path,
    *,
    catalog_map: Optional[dict[str, set[str]]] = None,
) -> dict:
    """Idempotently load a single framework YAML.

    Returns a result dict so callers (boot path + tests) can assert on it
    without re-querying the DB. Status values:
      - "skipped"     — same sha256 already recorded; nothing changed
      - "loaded"      — first time we've seen this framework
      - "updated"     — sha256 changed; controls/mappings re-synced
      - "validation_error" — at least one rule failed catalog validation
      - "parse_error" — YAML invalid
      - "schema_error" — top-level YAML missing required keys
    """
    catalog_map = catalog_map or _flatten_catalog(CONDITION_CATALOG)
    sha256 = _file_sha256(path)

    try:
        with path.open("r") as fh:
            doc = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        logger.error("compliance_loader: failed to parse %s: %s", path, exc)
        return {"status": "parse_error", "path": str(path), "error": str(exc)}

    if not isinstance(doc, dict) or "framework" not in doc:
        return {
            "status": "schema_error", "path": str(path),
            "error": "top-level YAML must contain a `framework` block",
        }

    fw_block = doc["framework"]
    release_block = doc.get("release") or {}
    controls_block = doc.get("controls") or []

    if not fw_block.get("slug"):
        return {"status": "schema_error", "path": str(path), "error": "framework.slug is required"}

    # Validate every rule before touching the DB.
    for ctrl_block in controls_block:
        for mapping_block in (ctrl_block.get("mappings") or []):
            err = _validate_rule(mapping_block.get("when") or {}, catalog_map)
            if err:
                msg = (
                    f"mapping {mapping_block.get('key')!r} under control "
                    f"{ctrl_block.get('ref')!r}: {err}"
                )
                logger.error("compliance_loader: validation failed for %s — %s", path, msg)
                return {
                    "status": "validation_error", "path": str(path),
                    "framework_slug": fw_block["slug"], "error": msg,
                }

    # Short-circuit if we already loaded this exact file content.
    fw = db.query(ComplianceFramework).filter_by(slug=fw_block["slug"]).first()
    if fw is not None:
        last_release = (
            db.query(ComplianceFrameworkRelease)
            .filter_by(framework_id=fw.id)
            .order_by(ComplianceFrameworkRelease.released_at.desc())
            .first()
        )
        if last_release and last_release.mapping_file_sha256 == sha256:
            return {
                "status": "skipped", "path": str(path),
                "framework_slug": fw.slug, "release_tag": last_release.release_tag,
            }
        is_new = False
    else:
        is_new = True

    # Apply changes.
    fw = _upsert_framework(db, fw_block)
    keep_refs: set[str] = set()
    for ctrl_block in controls_block:
        ctrl = _upsert_control(db, fw, ctrl_block)
        keep_refs.add(ctrl.ref)
        keep_keys: set[str] = set()
        for mapping_block in (ctrl_block.get("mappings") or []):
            m = _upsert_mapping(db, ctrl, mapping_block)
            keep_keys.add(m.mapping_key)
        _delete_stale_mappings(db, ctrl, keep_keys)
    _delete_stale_controls(db, fw, keep_refs)

    release_tag = release_block.get("tag") or f"sha256:{sha256[:12]}"
    rel = _record_release(
        db, fw,
        release_tag=release_tag,
        release_notes=release_block.get("notes"),
        sha256=sha256,
    )

    status = "loaded" if is_new else "updated"
    _audit_log(db, action=status, fw=fw, payload={
        "release_tag": release_tag,
        "sha256": sha256,
        "controls_count": len(controls_block),
        "path": str(path),
    })
    db.commit()

    return {
        "status": status, "path": str(path),
        "framework_slug": fw.slug, "release_tag": release_tag,
        "controls_loaded": len(controls_block),
    }


def load_all_frameworks(db: Session, *, root: Optional[Path] = None) -> list[dict]:
    """Discover every framework YAML under ``root`` and load each idempotently.

    Errors on a single YAML never abort the others — each result is
    returned in the list so the caller can surface partial failures.
    """
    root = root or _DEFAULT_ROOT
    catalog_map = _flatten_catalog(CONDITION_CATALOG)
    results: list[dict] = []
    for path in _discover_yaml_files(root):
        try:
            result = load_framework_from_path(db, path, catalog_map=catalog_map)
        except Exception as exc:
            logger.exception("compliance_loader: unexpected error loading %s", path)
            db.rollback()
            result = {"status": "error", "path": str(path), "error": str(exc)}
        results.append(result)
    return results

"""Serialize a ComplianceFramework + Controls + Mappings back to YAML.

The output round-trips through services.compliance_loader.load_framework_from_yaml_text
— that's the contract: export bytes → re-import → identical framework rows.

We deliberately omit:
  - id columns (auto-assigned on load)
  - org_id, created_by, source (set by the loader from import context)
  - timestamps (created_at / updated_at)
  - rule_version (re-derived from rule body diffs on re-import)

We deliberately include:
  - everything in the YAML schema the loader validates against
  - a fresh release.tag based on export time so each export creates a
    distinguishable release record on re-import
"""

from __future__ import annotations

from datetime import datetime
from io import StringIO
from typing import Any

import yaml
from sqlalchemy.orm import Session

from models.models import (
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceFramework,
)


def _published_at_str(fw: ComplianceFramework) -> Any:
    if fw.published_at is None:
        return None
    return fw.published_at.date().isoformat()


def _rule_block(rule: dict | list | None) -> dict:
    """Normalise a stored rule body back into the YAML `when:` shape."""
    if isinstance(rule, dict):
        logic = (rule.get("logic") or "AND").upper()
        conditions = rule.get("conditions") or []
    elif isinstance(rule, list):
        logic = "AND"
        conditions = rule
    else:
        logic = "AND"
        conditions = []
    return {"logic": logic, "conditions": conditions}


def framework_to_yaml(db: Session, fw: ComplianceFramework) -> str:
    """Serialize a framework (with its controls + mappings) to a YAML string."""
    controls = (
        db.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == fw.id)
        .order_by(ComplianceControl.ref)
        .all()
    )

    control_blocks: list[dict] = []
    for ctrl in controls:
        mappings = (
            db.query(ComplianceControlMapping)
            .filter(ComplianceControlMapping.control_id == ctrl.id)
            .order_by(ComplianceControlMapping.mapping_key)
            .all()
        )
        block: dict[str, Any] = {
            "ref": ctrl.ref,
            "title": ctrl.title,
        }
        # Optional fields — only include when present so re-imports look
        # like the hand-authored YAMLs in compliance/frameworks/.
        if ctrl.description:
            block["description"] = ctrl.description
        if ctrl.parent_ref:
            block["parent_ref"] = ctrl.parent_ref
        if ctrl.domain:
            block["domain"] = ctrl.domain
        if ctrl.testability:
            block["testability"] = ctrl.testability
        if ctrl.default_severity_floor is not None:
            block["default_severity_floor"] = ctrl.default_severity_floor
        if ctrl.canonical_guidance:
            block["canonical_guidance"] = ctrl.canonical_guidance

        block["mappings"] = [
            {
                "key": m.mapping_key,
                "when": _rule_block(m.rule),
                **({"testability": m.testability} if m.testability else {}),
            }
            for m in mappings
        ]
        control_blocks.append(block)

    fw_block: dict[str, Any] = {
        "slug": fw.slug,
        "name": fw.name,
        "version": fw.version,
    }
    if fw.authority:
        fw_block["authority"] = fw.authority
    pub = _published_at_str(fw)
    if pub:
        fw_block["published_at"] = pub
    if fw.description:
        fw_block["description"] = fw.description
    if fw.categories:
        fw_block["categories"] = list(fw.categories)
    fw_block["mapping_schema_version"] = fw.mapping_schema_version

    doc = {
        "framework": fw_block,
        "release": {
            "tag": f"export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "notes": (
                f"Exported from Hakuna at "
                f"{datetime.utcnow().isoformat(timespec='seconds')}Z."
            ),
        },
        "controls": control_blocks,
    }

    buf = StringIO()
    yaml.safe_dump(
        doc, buf,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )
    return buf.getvalue()

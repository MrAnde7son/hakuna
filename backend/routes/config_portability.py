"""
Configuration portability — export/import for risk config, auto-tag rules,
report templates, and campaign workflow templates.

Envelope format:
{
    "format": "hakuna",
    "version": 1,
    "type": "<config_type>",
    "exported_at": "<ISO timestamp>",
    "data": { ... }
}
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session

from core.auth import require_auth
from core.database import get_db
from core.time_utils import iso_utc
from models.models import (
    User, Tag, AutoTagRule, ReportTemplate,
    Campaign, Workflow, WorkflowNode, WorkflowEdge,
)
import core.risk_config as rc
import services.dedup as dedup_engine

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["config-portability"])

ENVELOPE_FORMAT = "hakuna"
ENVELOPE_VERSION = 1

VALID_TYPES = {"risk_config", "auto_tag_rules", "report_template", "campaign_workflow", "dedup_config"}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _envelope(config_type: str, data: dict) -> dict:
    return {
        "format": ENVELOPE_FORMAT,
        "version": ENVELOPE_VERSION,
        "type": config_type,
        "exported_at": iso_utc(datetime.utcnow()),
        "data": data,
    }


def _validate_envelope(payload: dict, expected_type: str) -> dict:
    if payload.get("format") != ENVELOPE_FORMAT:
        raise HTTPException(400, "Invalid export file: wrong format")
    if payload.get("version", 0) > ENVELOPE_VERSION:
        raise HTTPException(400, f"Unsupported version {payload.get('version')} (max {ENVELOPE_VERSION})")
    if payload.get("type") != expected_type:
        raise HTTPException(400, f"Expected type '{expected_type}', got '{payload.get('type')}'")
    return payload.get("data", {})


async def _read_json_upload(file: UploadFile) -> dict:
    content = await file.read()
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid JSON file")


def _tag_to_export(tag: Tag, db: Session) -> dict:
    """Serialize a tag for export, using parent category:value reference."""
    parent_ref = None
    if tag.parent_id:
        parent = db.query(Tag).filter(Tag.id == tag.parent_id).first()
        if parent:
            parent_ref = f"{parent.category}:{parent.value}"
    return {
        "category": tag.category,
        "value": tag.value,
        "color": tag.color,
        "description": tag.description,
        "parent_ref": parent_ref,
    }


def _find_or_create_tag(spec: dict, db: Session, conflict: str) -> Tag:
    """Find tag by (category, value) or create it. Returns the Tag object."""
    existing = db.query(Tag).filter(
        Tag.category == spec["category"],
        Tag.value == spec["value"],
    ).first()
    if existing:
        if conflict == "overwrite":
            existing.color = spec.get("color") or existing.color
            existing.description = spec.get("description") or existing.description
        return existing
    tag = Tag(
        category=spec["category"],
        value=spec["value"],
        color=spec.get("color", "#6366f1"),
        description=spec.get("description"),
    )
    db.add(tag)
    db.flush()
    return tag


# ─────────────────────────────────────────────
# 1. Risk Config export/import
# ─────────────────────────────────────────────

@router.get("/config/export/risk_config")
def export_risk_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    org_id = int(x_org_context) if x_org_context else user.org_id
    cfg = rc.load_config_for_org(db, org_id)
    cfg.pop("is_org_override", None)
    return _envelope("risk_config", cfg)


@router.post("/config/import/risk_config")
async def import_risk_config(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    org_id = int(x_org_context) if x_org_context else user.org_id
    payload = await _read_json_upload(file)
    data = _validate_envelope(payload, "risk_config")
    rc.save_config_for_org(db, org_id, data)
    return {"status": "ok", "message": "Risk config imported successfully"}


# ─────────────────────────────────────────────
# 1b. Dedup Config export/import
# ─────────────────────────────────────────────

@router.get("/config/export/dedup_config")
def export_dedup_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
    scope: str = Query("resolved", regex="^(resolved|override|global)$"),
):
    """Export dedup config as a JSON envelope.

    scope:
      resolved  — this org's effective config (global + override merged). Default.
      override  — only this org's sparse override (empty if none).
      global    — the platform-wide global (superadmin only).
    """
    org_id = int(x_org_context) if x_org_context else user.org_id

    if scope == "global":
        if user.role != "superadmin":
            raise HTTPException(403, "Only superadmins can export the global dedup config")
        cfg = dedup_engine.load_config()
    elif scope == "override":
        cfg = dedup_engine.load_org_override(db, org_id)
    else:
        cfg = dedup_engine.load_config_for_org(db, org_id)
        cfg.pop("is_org_override", None)

    return _envelope("dedup_config", cfg)


@router.post("/config/import/dedup_config")
async def import_dedup_config(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
    scope: str = Query("org", regex="^(org|global)$"),
):
    """Import dedup config from a JSON envelope.

    scope:
      org    — installs as this org's override (default).
      global — replaces the platform-wide global (superadmin only).
    """
    org_id = int(x_org_context) if x_org_context else user.org_id
    payload = await _read_json_upload(file)
    data = _validate_envelope(payload, "dedup_config")
    data.pop("is_org_override", None)

    if scope == "global":
        if user.role != "superadmin":
            raise HTTPException(403, "Only superadmins can import the global dedup config")
        dedup_engine.save_config(data)
        return {"status": "ok", "message": "Global dedup config imported", "scope": "global"}

    dedup_engine.save_config_for_org(db, org_id, data)
    return {"status": "ok", "message": "Org dedup config imported", "scope": "org", "org_id": org_id}


# ─────────────────────────────────────────────
# 2. Auto-Tag Rules export/import
# ─────────────────────────────────────────────

@router.get("/config/export/auto_tag_rules")
def export_auto_tag_rules(db: Session = Depends(get_db)):
    rules = db.query(AutoTagRule).all()
    # Collect all tags referenced by rules
    tag_ids = {r.tag_id for r in rules}
    # Also include parent chain
    all_tag_ids = set(tag_ids)
    for tid in tag_ids:
        t = db.query(Tag).filter(Tag.id == tid).first()
        while t and t.parent_id:
            all_tag_ids.add(t.parent_id)
            t = db.query(Tag).filter(Tag.id == t.parent_id).first()

    tags = db.query(Tag).filter(Tag.id.in_(all_tag_ids)).all() if all_tag_ids else []
    # Sort tags so parents come before children (depth-first)
    tag_exports = []
    exported_ids = set()

    def _export_tag(tag):
        if tag.id in exported_ids:
            return
        if tag.parent_id and tag.parent_id not in exported_ids:
            parent = db.query(Tag).filter(Tag.id == tag.parent_id).first()
            if parent:
                _export_tag(parent)
        tag_exports.append(_tag_to_export(tag, db))
        exported_ids.add(tag.id)

    for t in tags:
        _export_tag(t)

    rule_exports = []
    for r in rules:
        tag_label = f"{r.tag.category}:{r.tag.value}" if r.tag else None
        rule_exports.append({
            "name": r.name,
            "description": r.description,
            "tag_ref": tag_label,
            "target_type": r.target_type,
            "conditions": r.conditions or [],
            "condition_logic": r.condition_logic,
            "is_enabled": r.is_enabled,
        })

    return _envelope("auto_tag_rules", {"tags": tag_exports, "rules": rule_exports})


@router.post("/config/import/auto_tag_rules")
async def import_auto_tag_rules(
    file: UploadFile = File(...),
    conflict: str = Query("skip", regex="^(skip|overwrite)$"),
    db: Session = Depends(get_db),
):
    payload = await _read_json_upload(file)
    data = _validate_envelope(payload, "auto_tag_rules")

    tags_data = data.get("tags", [])
    rules_data = data.get("rules", [])

    # Phase 1: create/find tags (parents first — they're sorted in export)
    tag_map = {}  # "category:value" → Tag object
    for spec in tags_data:
        tag = _find_or_create_tag(spec, db, conflict)
        tag_map[f"{spec['category']}:{spec['value']}"] = tag

    # Resolve parent references (second pass)
    for spec in tags_data:
        if spec.get("parent_ref"):
            tag = tag_map.get(f"{spec['category']}:{spec['value']}")
            parent = tag_map.get(spec["parent_ref"])
            if tag and parent:
                tag.parent_id = parent.id

    db.flush()

    # Phase 2: create/find rules
    created = 0
    skipped = 0
    for rspec in rules_data:
        tag_ref = rspec.get("tag_ref")
        if not tag_ref:
            skipped += 1
            continue

        # Resolve tag
        tag = tag_map.get(tag_ref)
        if not tag:
            cat, val = tag_ref.split(":", 1)
            tag = db.query(Tag).filter(Tag.category == cat, Tag.value == val).first()
        if not tag:
            skipped += 1
            continue

        existing = db.query(AutoTagRule).filter(AutoTagRule.name == rspec["name"]).first()
        if existing:
            if conflict == "overwrite":
                existing.description = rspec.get("description")
                existing.tag_id = tag.id
                existing.target_type = rspec.get("target_type", "asset")
                existing.conditions = rspec.get("conditions", [])
                existing.condition_logic = rspec.get("condition_logic", "AND")
                existing.is_enabled = rspec.get("is_enabled", True)
                created += 1
            else:
                skipped += 1
        else:
            rule = AutoTagRule(
                name=rspec["name"],
                description=rspec.get("description"),
                tag_id=tag.id,
                target_type=rspec.get("target_type", "asset"),
                conditions=rspec.get("conditions", []),
                condition_logic=rspec.get("condition_logic", "AND"),
                is_enabled=rspec.get("is_enabled", True),
            )
            db.add(rule)
            created += 1

    db.commit()
    return {"status": "ok", "imported": created, "skipped": skipped}


# ─────────────────────────────────────────────
# 3. Report Templates CRUD + export/import
# ─────────────────────────────────────────────

def _effective_org_id(user: User, x_org_context: Optional[str]) -> int:
    """The org a write should land in: the X-Org-Context header if set,
    otherwise the user's own org."""
    return int(x_org_context) if x_org_context else user.org_id


def _accessible_template_query(db: Session, user: User, x_org_context: Optional[str]):
    """Read-side scope: the user's own org plus any legacy rows with
    org_id IS NULL (which are global pre-multitenancy seeds). Superadmins
    see everything unless they pin via X-Org-Context."""
    q = db.query(ReportTemplate)
    if user.role == "superadmin" and not x_org_context:
        return q
    org_id = _effective_org_id(user, x_org_context)
    return q.filter(
        (ReportTemplate.org_id == org_id) | (ReportTemplate.org_id.is_(None))
    )


@router.get("/report-templates")
def list_report_templates(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    templates = (
        _accessible_template_query(db, user, x_org_context)
        .order_by(ReportTemplate.created_at.desc())
        .all()
    )
    return [
        {
            "id": t.id, "name": t.name, "description": t.description,
            "config": t.config, "is_default": t.is_default,
            "created_at": iso_utc(t.created_at),
            "updated_at": iso_utc(t.updated_at),
        }
        for t in templates
    ]


@router.post("/report-templates")
def create_report_template(
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    name = body.get("name")
    if not name:
        raise HTTPException(400, "name is required")
    org_id = _effective_org_id(user, x_org_context)
    # The DB-level unique index on (COALESCE(org_id, 0), name) is the source of
    # truth — this pre-check is a UX nicety so we return 409 with a readable
    # message instead of a generic IntegrityError.
    existing = (
        db.query(ReportTemplate)
        .filter(
            ReportTemplate.name == name,
            (ReportTemplate.org_id == org_id) | (ReportTemplate.org_id.is_(None)),
        )
        .first()
    )
    if existing:
        raise HTTPException(409, f"Report template '{name}' already exists")
    t = ReportTemplate(
        org_id=org_id,
        name=name,
        description=body.get("description"),
        config=body.get("config", {}),
        is_default=body.get("is_default", False),
    )
    db.add(t)
    try:
        db.commit()
    except Exception:
        # Concurrent seeders raced past the pre-check and one lost on the
        # unique index. Surface a clean 409 instead of an IntegrityError.
        db.rollback()
        raise HTTPException(409, f"Report template '{name}' already exists")
    db.refresh(t)
    return {"id": t.id, "name": t.name}


def _load_owned_template(db, user, x_org_context, template_id: int) -> ReportTemplate:
    t = (
        _accessible_template_query(db, user, x_org_context)
        .filter(ReportTemplate.id == template_id)
        .first()
    )
    if not t:
        raise HTTPException(404, "Template not found")
    return t


@router.get("/report-templates/{template_id}")
def get_report_template(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    t = _load_owned_template(db, user, x_org_context, template_id)
    return {
        "id": t.id, "name": t.name, "description": t.description,
        "config": t.config, "is_default": t.is_default,
        "created_at": iso_utc(t.created_at),
        "updated_at": iso_utc(t.updated_at),
    }


@router.patch("/report-templates/{template_id}")
def update_report_template(
    template_id: int,
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    t = _load_owned_template(db, user, x_org_context, template_id)
    for field in ("name", "description", "config", "is_default"):
        if field in body:
            setattr(t, field, body[field])
    t.updated_at = datetime.utcnow()
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(409, "Report template name already exists in this org")
    return {"status": "ok"}


@router.delete("/report-templates/{template_id}")
def delete_report_template(
    template_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    t = _load_owned_template(db, user, x_org_context, template_id)
    db.delete(t)
    db.commit()
    return {"status": "ok"}


@router.get("/config/export/report_template")
def export_report_template(
    template_id: int = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    """Export a single template by ID, or all templates if no ID given."""
    if template_id:
        t = _load_owned_template(db, user, x_org_context, template_id)
        templates = [t]
    else:
        templates = (
            _accessible_template_query(db, user, x_org_context)
            .order_by(ReportTemplate.created_at.desc())
            .all()
        )

    data = [
        {
            "name": t.name,
            "description": t.description,
            "config": t.config,
            "is_default": t.is_default,
        }
        for t in templates
    ]
    return _envelope("report_template", {"templates": data})


@router.post("/config/import/report_template")
async def import_report_template(
    file: UploadFile = File(...),
    conflict: str = Query("skip", regex="^(skip|overwrite)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    x_org_context: Optional[str] = Header(None, alias="X-Org-Context"),
):
    payload = await _read_json_upload(file)
    data = _validate_envelope(payload, "report_template")
    templates = data.get("templates", [])
    org_id = _effective_org_id(user, x_org_context)

    created = 0
    skipped = 0
    for spec in templates:
        name = spec.get("name")
        if not name:
            skipped += 1
            continue
        existing = (
            db.query(ReportTemplate)
            .filter(
                ReportTemplate.name == name,
                (ReportTemplate.org_id == org_id) | (ReportTemplate.org_id.is_(None)),
            )
            .first()
        )
        if existing:
            if conflict == "overwrite":
                existing.description = spec.get("description")
                existing.config = spec.get("config", {})
                existing.is_default = spec.get("is_default", False)
                existing.updated_at = datetime.utcnow()
                created += 1
            else:
                skipped += 1
        else:
            t = ReportTemplate(
                org_id=org_id,
                name=name,
                description=spec.get("description"),
                config=spec.get("config", {}),
                is_default=spec.get("is_default", False),
            )
            db.add(t)
            created += 1

    db.commit()
    return {"status": "ok", "imported": created, "skipped": skipped}


# ─────────────────────────────────────────────
# 4. Campaign + Workflow Template export/import
# ─────────────────────────────────────────────

@router.get("/config/export/campaign_workflow")
def export_campaign_workflow(
    campaign_id: int = Query(...),
    db: Session = Depends(get_db),
):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(404, "Campaign not found")

    workflows = db.query(Workflow).filter(Workflow.campaign_id == campaign_id).all()

    wf_exports = []
    for wf in workflows:
        nodes = db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf.id).all()
        edges = db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf.id).all()
        wf_exports.append({
            "name": wf.name,
            "description": wf.description,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type,
                    "node_subtype": n.node_subtype,
                    "label": n.label,
                    "config": n.config or {},
                    "position_x": n.position_x,
                    "position_y": n.position_y,
                }
                for n in nodes
            ],
            "edges": [
                {
                    "edge_id": e.edge_id,
                    "source_node_id": e.source_node_id,
                    "target_node_id": e.target_node_id,
                    "source_handle": e.source_handle,
                    "target_handle": e.target_handle,
                    "label": e.label,
                }
                for e in edges
            ],
        })

    data = {
        "campaign": {
            "name": campaign.name,
            "description": campaign.description,
            "query": campaign.query or [],
            "query_logic": campaign.query_logic,
        },
        "workflows": wf_exports,
    }
    return _envelope("campaign_workflow", data)


@router.post("/config/import/campaign_workflow")
async def import_campaign_workflow(
    file: UploadFile = File(...),
    conflict: str = Query("skip", regex="^(skip|overwrite)$"),
    db: Session = Depends(get_db),
):
    payload = await _read_json_upload(file)
    data = _validate_envelope(payload, "campaign_workflow")

    camp_spec = data.get("campaign", {})
    name = camp_spec.get("name")
    if not name:
        raise HTTPException(400, "Campaign name is required")

    # Check for existing campaign with same name
    existing = db.query(Campaign).filter(Campaign.name == name).first()
    if existing:
        if conflict == "skip":
            return {"status": "ok", "message": f"Campaign '{name}' already exists (skipped)", "campaign_id": existing.id}
        elif conflict == "overwrite":
            # Delete old workflows
            old_wfs = db.query(Workflow).filter(Workflow.campaign_id == existing.id).all()
            for wf in old_wfs:
                db.delete(wf)
            existing.description = camp_spec.get("description")
            existing.query = camp_spec.get("query", [])
            existing.query_logic = camp_spec.get("query_logic", "AND")
            existing.status = "draft"
            db.flush()
            campaign = existing
    else:
        campaign = Campaign(
            name=name,
            description=camp_spec.get("description"),
            query=camp_spec.get("query", []),
            query_logic=camp_spec.get("query_logic", "AND"),
            status="draft",
        )
        db.add(campaign)
        db.flush()

    # Create workflows
    wf_count = 0
    for wf_spec in data.get("workflows", []):
        wf = Workflow(
            campaign_id=campaign.id,
            name=wf_spec.get("name", "Imported Workflow"),
            description=wf_spec.get("description"),
            status="draft",
        )
        db.add(wf)
        db.flush()

        for n_spec in wf_spec.get("nodes", []):
            node = WorkflowNode(
                workflow_id=wf.id,
                node_id=n_spec["node_id"],
                node_type=n_spec["node_type"],
                node_subtype=n_spec["node_subtype"],
                label=n_spec.get("label"),
                config=n_spec.get("config", {}),
                position_x=n_spec.get("position_x", 0),
                position_y=n_spec.get("position_y", 0),
            )
            db.add(node)

        for e_spec in wf_spec.get("edges", []):
            edge = WorkflowEdge(
                workflow_id=wf.id,
                edge_id=e_spec["edge_id"],
                source_node_id=e_spec["source_node_id"],
                target_node_id=e_spec["target_node_id"],
                source_handle=e_spec.get("source_handle", "output"),
                target_handle=e_spec.get("target_handle", "input"),
                label=e_spec.get("label"),
            )
            db.add(edge)
        wf_count += 1

    db.commit()
    return {
        "status": "ok",
        "campaign_id": campaign.id,
        "campaign_name": campaign.name,
        "workflows_imported": wf_count,
    }

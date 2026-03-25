"""
Workflow routes — CRUD, execution, versioning, and node catalog.

Extracted from app.py to follow SRP: route files handle HTTP,
the workflow_engine service handles business logic.
"""

from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids, apply_org_filter
from core.audit import log_audit, diff as _diff
from models.models import (
    User, Workflow, WorkflowNode, WorkflowEdge,
    WorkflowExecution, WorkflowExecutionLog,
)
import services.workflow_engine as workflow_engine


router = APIRouter(tags=["workflows"])


# ─────────────────────────────────────────────
# Serializers
# ─────────────────────────────────────────────

def _workflow_to_dict(wf: Workflow) -> dict:
    return {
        "id": wf.id,
        "campaign_id": wf.campaign_id,
        "name": wf.name,
        "description": wf.description,
        "status": wf.status,
        "is_enabled": wf.is_enabled,
        "created_at": wf.created_at.isoformat() if wf.created_at else None,
        "updated_at": wf.updated_at.isoformat() if wf.updated_at else None,
        "last_run_at": wf.last_run_at.isoformat() if wf.last_run_at else None,
        "run_count": wf.run_count,
        "version": getattr(wf, "version", 1) or 1,
        "node_count": len(wf.nodes),
        "edge_count": len(wf.edges),
    }


def _node_to_dict(n: WorkflowNode) -> dict:
    return {
        "node_id": n.node_id,
        "node_type": n.node_type,
        "node_subtype": n.node_subtype,
        "label": n.label,
        "config": n.config or {},
        "position_x": n.position_x,
        "position_y": n.position_y,
    }


def _edge_to_dict(e: WorkflowEdge) -> dict:
    return {
        "edge_id": e.edge_id,
        "source_node_id": e.source_node_id,
        "target_node_id": e.target_node_id,
        "source_handle": e.source_handle,
        "target_handle": e.target_handle,
        "label": e.label,
    }


def _execution_to_dict(ex: WorkflowExecution) -> dict:
    return {
        "id": ex.id,
        "workflow_id": ex.workflow_id,
        "status": ex.status,
        "trigger_type": ex.trigger_type,
        "started_at": ex.started_at.isoformat() if ex.started_at else None,
        "completed_at": ex.completed_at.isoformat() if ex.completed_at else None,
        "items_processed": ex.items_processed,
        "result_summary": ex.result_summary,
        "error": ex.error,
    }


# ─────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────

class WorkflowCreateFromTemplate(BaseModel):
    template_id: str
    name: Optional[str] = None
    campaign_id: Optional[int] = None


class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    campaign_id: Optional[int] = None


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    campaign_id: Optional[int] = None
    status: Optional[str] = None
    is_enabled: Optional[bool] = None
    nodes: Optional[list] = None
    edges: Optional[list] = None


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@router.get("/api/workflows/node-catalog")
def get_node_catalog():
    """Return available node types for the workflow builder."""
    return workflow_engine.NODE_CATALOG


@router.get("/api/workflows/templates")
def get_workflow_templates():
    """Return OOTB workflow templates."""
    return {
        "templates": workflow_engine.WORKFLOW_TEMPLATES,
        "categories": workflow_engine.TEMPLATE_CATEGORIES,
    }


@router.post("/api/workflows/from-template")
def create_workflow_from_template_endpoint(body: WorkflowCreateFromTemplate, db: Session = Depends(get_db)):
    """Create a workflow from an OOTB template."""
    try:
        wf = workflow_engine.create_workflow_from_template(
            db, body.template_id, name=body.name, campaign_id=body.campaign_id)
        d = _workflow_to_dict(wf)
        d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
        d["edges"] = [_edge_to_dict(e) for e in wf.edges]
        return d
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/api/workflows")
def create_workflow(body: WorkflowCreate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = Workflow(
        org_id=user.org_id if user else None,
        name=body.name,
        description=body.description,
        campaign_id=body.campaign_id,
    )
    db.add(wf)
    db.flush()
    log_audit(db, "create", "workflow", wf.id,
              entity_name=wf.name,
              changes={"name": wf.name, "description": wf.description},
              actor=user)
    db.commit()
    db.refresh(wf)
    return _workflow_to_dict(wf)


@router.get("/api/workflows")
def list_workflows(
    campaign_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    q = apply_org_filter(db.query(Workflow), Workflow, org_ids).order_by(desc(Workflow.updated_at))
    if campaign_id is not None:
        q = q.filter(Workflow.campaign_id == campaign_id)
    return [_workflow_to_dict(w) for w in q.all()]


@router.get("/api/workflows/{wf_id}")
def get_workflow(wf_id: int, db: Session = Depends(get_db)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@router.patch("/api/workflows/{wf_id}")
def update_workflow(wf_id: int, body: WorkflowUpdate, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    _old_wf = {"name": wf.name, "status": wf.status, "is_enabled": wf.is_enabled, "description": wf.description}

    if body.name is not None:
        wf.name = body.name
    if body.description is not None:
        wf.description = body.description
    if body.campaign_id is not None:
        wf.campaign_id = body.campaign_id
    if body.status is not None:
        wf.status = body.status
    if body.is_enabled is not None:
        wf.is_enabled = body.is_enabled

    # Sync nodes — snapshot current version before overwriting
    if body.nodes is not None or body.edges is not None:
        old_nodes = [_node_to_dict(n) for n in wf.nodes]
        old_edges = [_edge_to_dict(e) for e in wf.edges]
        history = list(wf.version_history or [])
        history.append({
            "version": wf.version or 1,
            "nodes": old_nodes,
            "edges": old_edges,
            "saved_at": datetime.utcnow().isoformat(),
        })
        # Keep last 20 versions
        wf.version_history = history[-20:]
        wf.version = (wf.version or 1) + 1

    if body.nodes is not None:
        db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf_id).delete(synchronize_session=False)
        for nd in body.nodes:
            db.add(WorkflowNode(
                workflow_id=wf_id,
                node_id=nd["node_id"],
                node_type=nd["node_type"],
                node_subtype=nd["node_subtype"],
                label=nd.get("label", ""),
                config=nd.get("config", {}),
                position_x=nd.get("position_x", 0),
                position_y=nd.get("position_y", 0),
            ))

    # Sync edges
    if body.edges is not None:
        db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf_id).delete(synchronize_session=False)
        for ed in body.edges:
            db.add(WorkflowEdge(
                workflow_id=wf_id,
                edge_id=ed["edge_id"],
                source_node_id=ed["source_node_id"],
                target_node_id=ed["target_node_id"],
                source_handle=ed.get("source_handle", "output"),
                target_handle=ed.get("target_handle", "input"),
                label=ed.get("label"),
            ))

    _new_wf = {"name": wf.name, "status": wf.status, "is_enabled": wf.is_enabled, "description": wf.description}
    log_audit(db, "update", "workflow", wf_id,
              entity_name=wf.name, changes=_diff(_old_wf, _new_wf), actor=user)
    db.commit()
    db.refresh(wf)
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@router.delete("/api/workflows/{wf_id}")
def delete_workflow(wf_id: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    _wf_name, _wf_org = wf.name, wf.org_id
    db.delete(wf)
    log_audit(db, "delete", "workflow", wf_id, entity_name=_wf_name, actor=user, org_id=_wf_org)
    db.commit()
    return {"message": "Workflow deleted"}


@router.get("/api/workflows/{wf_id}/versions")
def get_workflow_versions(wf_id: int, db: Session = Depends(get_db)):
    """Return version history for a workflow."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return {
        "current_version": getattr(wf, "version", 1) or 1,
        "history": list(getattr(wf, "version_history", None) or []),
    }


@router.post("/api/workflows/{wf_id}/restore/{version}")
def restore_workflow_version(wf_id: int, version: int, db: Session = Depends(get_db), user: Optional[User] = Depends(get_current_user)):
    """Restore a workflow to a previous version."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    history = list(getattr(wf, "version_history", None) or [])
    snapshot = next((h for h in history if h.get("version") == version), None)
    if not snapshot:
        raise HTTPException(404, f"Version {version} not found")

    # Snapshot current state before restoring
    old_nodes = [_node_to_dict(n) for n in wf.nodes]
    old_edges = [_edge_to_dict(e) for e in wf.edges]
    history.append({
        "version": wf.version or 1,
        "nodes": old_nodes,
        "edges": old_edges,
        "saved_at": datetime.utcnow().isoformat(),
    })
    wf.version_history = history[-20:]
    wf.version = (wf.version or 1) + 1

    # Replace nodes and edges
    db.query(WorkflowNode).filter(WorkflowNode.workflow_id == wf_id).delete(synchronize_session=False)
    for nd in snapshot.get("nodes", []):
        db.add(WorkflowNode(
            workflow_id=wf_id, node_id=nd["node_id"], node_type=nd["node_type"],
            node_subtype=nd["node_subtype"], label=nd.get("label", ""),
            config=nd.get("config", {}),
            position_x=nd.get("position_x", 0), position_y=nd.get("position_y", 0),
        ))
    db.query(WorkflowEdge).filter(WorkflowEdge.workflow_id == wf_id).delete(synchronize_session=False)
    for ed in snapshot.get("edges", []):
        db.add(WorkflowEdge(
            workflow_id=wf_id, edge_id=ed["edge_id"],
            source_node_id=ed["source_node_id"], target_node_id=ed["target_node_id"],
            source_handle=ed.get("source_handle", "output"),
            target_handle=ed.get("target_handle", "input"), label=ed.get("label"),
        ))
    log_audit(db, "update", "workflow", wf_id,
              entity_name=wf.name, changes={"action": "restore", "restored_version": version}, actor=user)
    db.commit()
    db.refresh(wf)
    d = _workflow_to_dict(wf)
    d["nodes"] = [_node_to_dict(n) for n in wf.nodes]
    d["edges"] = [_edge_to_dict(e) for e in wf.edges]
    return d


@router.post("/api/workflows/{wf_id}/execute")
def execute_workflow_endpoint(wf_id: int, db: Session = Depends(get_db)):
    """Execute a workflow manually."""
    wf = db.query(Workflow).filter(Workflow.id == wf_id).first()
    if not wf:
        raise HTTPException(404, "Workflow not found")
    try:
        result = workflow_engine.execute_workflow(db, wf_id)
        return result
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/api/workflows/{wf_id}/executions")
def list_workflow_executions(wf_id: int, limit: int = 20, db: Session = Depends(get_db)):
    execs = db.query(WorkflowExecution).filter(
        WorkflowExecution.workflow_id == wf_id
    ).order_by(desc(WorkflowExecution.started_at)).limit(limit).all()
    return [_execution_to_dict(e) for e in execs]


@router.get("/api/workflows/executions/{exec_id}")
def get_workflow_execution(exec_id: int, db: Session = Depends(get_db)):
    ex = db.query(WorkflowExecution).filter(WorkflowExecution.id == exec_id).first()
    if not ex:
        raise HTTPException(404, "Execution not found")
    d = _execution_to_dict(ex)
    d["logs"] = [
        {
            "id": log.id,
            "node_id": log.node_id,
            "node_type": log.node_type,
            "node_subtype": log.node_subtype,
            "status": log.status,
            "items_in": log.items_in,
            "items_out": log.items_out,
            "output_data": log.output_data,
            "error": log.error,
            "executed_at": log.executed_at.isoformat() if log.executed_at else None,
        }
        for log in ex.logs
    ]
    return d

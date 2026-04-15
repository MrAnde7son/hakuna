"""Asset Knowledge Graph API routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import get_current_user, get_accessible_org_ids
from services.knowledge_graph import (
    build_clusters,
    get_asset_graph,
    get_blast_radius,
    materialize_graph_edges,
)

router = APIRouter(prefix="/api/graph", tags=["Knowledge Graph"])


@router.post("/materialize")
async def materialize(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Materialize graph edges from enrichment data. Typically called post-scan."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    stats = await materialize_graph_edges(db, org_id)
    cluster_stats = await build_clusters(db, org_id)
    return {"edges": stats, "clusters": cluster_stats}


@router.get("/")
async def get_graph(
    limit: int = 500,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get the asset knowledge graph for visualization."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    return await get_asset_graph(db, org_id, limit=limit)


@router.get("/blast-radius/{asset_id}")
async def blast_radius(
    asset_id: int,
    max_depth: int = 3,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """Get blast radius from a specific asset — BFS traversal of the graph."""
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    if max_depth > 5:
        max_depth = 5
    return await get_blast_radius(db, org_id, asset_id, max_depth=max_depth)


@router.get("/clusters")
async def list_clusters(
    cluster_type: str = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
    """List infrastructure clusters."""
    from sqlalchemy import text
    org_id = org_ids[0] if org_ids else None
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")

    query = "SELECT * FROM asset_clusters WHERE org_id = :org_id"
    params = {"org_id": org_id}
    if cluster_type:
        query += " AND cluster_type = :ctype"
        params["ctype"] = cluster_type
    query += " ORDER BY asset_count DESC LIMIT 100"

    result = await db.execute(text(query), params)
    return [
        {
            "id": row.id,
            "cluster_type": row.cluster_type,
            "label": row.label,
            "pivot_value": row.pivot_value,
            "asset_ids": row.asset_ids,
            "asset_count": row.asset_count,
        }
        for row in result.fetchall()
    ]

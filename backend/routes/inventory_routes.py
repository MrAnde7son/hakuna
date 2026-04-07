"""
Inventory API routes — extracted from app.py
Covers: users, groups, services, netconns, scheduled-tasks, patches,
logged-on, summary, shares, software, security-controls, security-coverage,
detect-security-controls, computers, password-policies, env-vars,
certificates, databases, domain-trusts, ai-tools, credentials, processes.
"""
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from core.database import get_db
from core.auth import require_role, get_accessible_org_ids, apply_scan_org_filter
from models.models import (
    Scan, Asset,
    InventoryUser, InventoryGroup, InventoryDomainTrust, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool, InventoryProcess, InventoryDatabaseInstance, InventoryCredential,
)

router = APIRouter()


# ─────────────────────────────────────────────
# Inventory helpers
# ─────────────────────────────────────────────

def _asset_lookup(db: Session, asset_ids) -> dict:
    """Return {asset_id: {"hostname": ..., "ip": ..., "environment_tag": ...}} for a set of asset IDs."""
    if not asset_ids:
        return {}
    assets = db.query(Asset.id, Asset.hostname, Asset.ip, Asset.environment_tag).filter(Asset.id.in_(asset_ids)).all()
    return {a.id: {"hostname": a.hostname, "ip": a.ip, "environment_tag": a.environment_tag} for a in assets}


def _asset_label(info: dict) -> str:
    """Return a human-readable label from asset info dict."""
    if not info:
        return "—"
    return info.get("hostname") or info.get("ip") or "—"


def _inv_user_to_dict(u: InventoryUser, assets: dict = None) -> dict:
    info = assets.get(u.asset_id) if assets else None
    return {
        "id": u.id,
        "scan_id": u.scan_id,
        "asset_id": u.asset_id,
        "asset_label": _asset_label(info),
        "asset_ip": (info or {}).get("ip"),
        "asset_env": (info or {}).get("environment_tag"),
        "username": u.username,
        "domain": u.domain,
        "sid": u.sid,
        "rid": u.rid,
        "dn": u.dn,
        "user_type": u.user_type,
        "identity_type": u.identity_type or "unknown",
        "identity_subtype": u.identity_subtype,
        "source_systems": u.source_systems or [],
        "department": u.department,
        "job_title": u.job_title,
        "manager_dn": u.manager_dn,
        "manager_username": u.manager_username,
        "is_local_admin": u.is_local_admin,
        "is_domain_admin": u.is_domain_admin,
        "is_privileged": u.is_privileged,
        "is_disabled": u.is_disabled,
        "password_never_expires": u.password_never_expires,
        "never_logged_in": u.never_logged_in,
        "never_changed_password": u.never_changed_password,
        "spns": u.spns or [],
        "member_of": u.member_of or [],
        "uac": u.uac,
        "password_last_set": u.password_last_set,
        "date_joined": u.date_joined,
        "last_logon_host": u.last_logon_host,
        "source_plugin": u.source_plugin,
    }


def _inv_group_to_dict(g: InventoryGroup, assets: dict = None) -> dict:
    info = assets.get(g.asset_id) if assets else None
    return {
        "id": g.id,
        "scan_id": g.scan_id,
        "asset_id": g.asset_id,
        "asset_label": _asset_label(info),
        "asset_ip": (info or {}).get("ip"),
        "asset_env": (info or {}).get("environment_tag"),
        "group_name": g.group_name,
        "domain": g.domain,
        "sid": g.sid,
        "dn": g.dn,
        "description": g.description,
        "members": g.members or [],
        "is_privileged": g.is_privileged,
        "source_plugin": g.source_plugin,
    }


# ─────────────────────────────────────────────
# Inventory API routes
# ─────────────────────────────────────────────

@router.get("/api/inventory/users")
def list_inventory_users(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    user_type: Optional[str] = None,
    identity_type: Optional[str] = None,
    identity_subtype: Optional[str] = None,
    department: Optional[str] = None,
    has_manager: Optional[bool] = None,
    is_admin: Optional[bool] = None,
    is_domain_admin: Optional[bool] = None,
    is_privileged: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "username",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryUser).join(Scan, InventoryUser.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryUser.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryUser.asset_id == asset_id)
    if user_type:
        q = q.filter(InventoryUser.user_type == user_type)
    if identity_type:
        q = q.filter(InventoryUser.identity_type == identity_type)
    if identity_subtype:
        q = q.filter(InventoryUser.identity_subtype == identity_subtype)
    if department:
        q = q.filter(InventoryUser.department.ilike(f"%{department}%"))
    if has_manager is not None:
        if has_manager:
            q = q.filter(InventoryUser.manager_username.isnot(None))
        else:
            q = q.filter(InventoryUser.manager_username.is_(None))
    if is_admin is not None:
        if is_admin:
            q = q.filter(InventoryUser.is_local_admin == True)
        else:
            # "Non-admin" means not a local admin AND not a domain admin
            q = q.filter(InventoryUser.is_local_admin == False, InventoryUser.is_domain_admin == False)
    if is_domain_admin is not None:
        q = q.filter(InventoryUser.is_domain_admin == is_domain_admin)
    if is_privileged is not None:
        q = q.filter(InventoryUser.is_privileged == is_privileged)
    if search:
        q = q.filter(
            InventoryUser.username.ilike(f"%{search}%") |
            InventoryUser.domain.ilike(f"%{search}%") |
            InventoryUser.department.ilike(f"%{search}%") |
            InventoryUser.job_title.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryUser, sort_by, order, InventoryUser.username)
    total = q.count()
    if page_size == 0:
        users = q.all()
    else:
        users = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {u.asset_id for u in users})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "users": [_inv_user_to_dict(u, assets) for u in users]}


@router.get("/api/inventory/users/org-tree")
def get_user_org_tree(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Return a hierarchical org tree built from the manager attribute of human AD users."""
    q = db.query(InventoryUser).join(Scan, InventoryUser.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryUser.scan_id == scan_id)
    q = q.filter(InventoryUser.identity_type == "human")
    users = q.all()
    assets = _asset_lookup(db, {u.asset_id for u in users})

    # Build lookup by username (lowercase) for tree construction
    by_name = {}
    for u in users:
        udict = _inv_user_to_dict(u, assets)
        udict["children"] = []
        key = (u.username or "").lower()
        if key not in by_name:
            by_name[key] = udict
        else:
            # Merge source_systems from duplicate
            existing = by_name[key]
            for s in udict.get("source_systems") or []:
                if s not in existing["source_systems"]:
                    existing["source_systems"].append(s)

    # Link children to parents
    roots = []
    for key, node in by_name.items():
        mgr = (node.get("manager_username") or "").lower()
        if mgr and mgr in by_name and mgr != key:
            by_name[mgr]["children"].append(node)
        else:
            roots.append(node)

    return {"roots": roots, "total_users": len(by_name), "total_with_manager": sum(1 for n in by_name.values() if n.get("manager_username"))}


@router.get("/api/inventory/groups")
def list_inventory_groups(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_privileged: Optional[bool] = None,
    sort_by: str = "group_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryGroup).join(Scan, InventoryGroup.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryGroup.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryGroup.asset_id == asset_id)
    if is_privileged is not None:
        q = q.filter(InventoryGroup.is_privileged == is_privileged)
    q = _apply_sort(q, InventoryGroup, sort_by, order, InventoryGroup.group_name)
    total = q.count()
    if page_size == 0:
        groups = q.all()
    else:
        groups = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {g.asset_id for g in groups})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "groups": [_inv_group_to_dict(g, assets) for g in groups]}


@router.get("/api/inventory/services")
def list_inventory_services(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "display_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryService).join(Scan, InventoryService.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryService.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryService.asset_id == asset_id)
    if search:
        q = q.filter(
            InventoryService.service_name.ilike(f"%{search}%") |
            InventoryService.display_name.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryService, sort_by, order, InventoryService.display_name)
    total = q.count()
    if page_size == 0:
        services = q.all()
    else:
        services = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in services})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "services": [{
        "id": s.id,
        "scan_id": s.scan_id,
        "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "service_name": s.service_name,
        "display_name": s.display_name,
        "is_running": s.is_running,
        "startup_type": s.startup_type,
        "run_as_user": s.run_as_user,
        "source_plugin": s.source_plugin,
    } for s in services]}


@router.get("/api/inventory/netconns")
def list_inventory_netconns(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    state: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "local_port",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryNetConn).join(Scan, InventoryNetConn.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryNetConn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryNetConn.asset_id == asset_id)
    if state:
        q = q.filter(InventoryNetConn.state.ilike(state))
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryNetConn.local_addr.ilike(s),
            InventoryNetConn.remote_addr.ilike(s),
            InventoryNetConn.proto.ilike(s),
        ))
    q = _apply_sort(q, InventoryNetConn, sort_by, order, InventoryNetConn.local_port)
    total = q.count()
    if page_size == 0:
        conns = q.all()
    else:
        conns = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in conns})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "netconns": [{
        "id": c.id,
        "scan_id": c.scan_id,
        "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "proto": c.proto,
        "state": c.state,
        "local_addr": c.local_addr,
        "local_port": c.local_port,
        "remote_addr": c.remote_addr,
        "remote_port": c.remote_port,
        "pid": c.pid,
        "source_plugin": c.source_plugin,
    } for c in conns]}


@router.get("/api/inventory/scheduled-tasks")
def list_inventory_tasks(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    trigger_type: Optional[str] = None,
    sort_by: str = "task_uri",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryScheduledTask).join(Scan, InventoryScheduledTask.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryScheduledTask.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryScheduledTask.asset_id == asset_id)
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryScheduledTask.task_uri.ilike(s),
            InventoryScheduledTask.author.ilike(s),
            InventoryScheduledTask.command.ilike(s),
            InventoryScheduledTask.run_as_user.ilike(s),
        ))
    if trigger_type:
        q = q.filter(InventoryScheduledTask.trigger_type.ilike(trigger_type))
    q = _apply_sort(q, InventoryScheduledTask, sort_by, order, InventoryScheduledTask.task_uri)
    total = q.count()
    if page_size == 0:
        tasks = q.all()
    else:
        tasks = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {t.asset_id for t in tasks})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "tasks": [{
        "id": t.id,
        "scan_id": t.scan_id,
        "asset_id": t.asset_id,
        "asset_label": _asset_label(assets.get(t.asset_id)),
        "asset_ip": (assets.get(t.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(t.asset_id) or {}).get("environment_tag"),
        "task_uri": t.task_uri,
        "author": t.author,
        "run_as_sid": t.run_as_sid,
        "run_as_user": t.run_as_user,
        "command": t.command,
        "arguments": t.arguments,
        "trigger_type": t.trigger_type,
        "logon_type": t.logon_type,
        "is_enabled": t.is_enabled,
        "source_plugin": t.source_plugin,
    } for t in tasks]}


@router.get("/api/inventory/patches")
def list_inventory_patches(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "vuln_count",
    order: str = "desc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryPatch).join(Scan, InventoryPatch.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryPatch.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryPatch.asset_id == asset_id)
    q = _apply_sort(q, InventoryPatch, sort_by, order, InventoryPatch.vuln_count)
    total = q.count()
    if page_size == 0:
        patches = q.all()
    else:
        patches = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {p.asset_id for p in patches})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "patches": [{
        "id": p.id,
        "scan_id": p.scan_id,
        "asset_id": p.asset_id,
        "asset_label": _asset_label(assets.get(p.asset_id)),
        "asset_ip": (assets.get(p.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(p.asset_id) or {}).get("environment_tag"),
        "kb_id": p.kb_id,
        "vuln_count": p.vuln_count,
        "description": p.description,
        "cves": p.cves or [],
        "source_plugin": p.source_plugin,
    } for p in patches]}


@router.get("/api/inventory/logged-on")
def list_inventory_logged_on(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    sort_by: str = "username",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryLoggedOn).join(Scan, InventoryLoggedOn.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryLoggedOn.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryLoggedOn.asset_id == asset_id)
    q = _apply_sort(q, InventoryLoggedOn, sort_by, order, InventoryLoggedOn.username)
    total = q.count()
    if page_size == 0:
        entries = q.all()
    else:
        entries = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {e.asset_id for e in entries})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "logged_on": [{
        "id": e.id,
        "scan_id": e.scan_id,
        "asset_id": e.asset_id,
        "asset_label": _asset_label(assets.get(e.asset_id)),
        "asset_ip": (assets.get(e.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(e.asset_id) or {}).get("environment_tag"),
        "sid": e.sid,
        "domain": e.domain,
        "username": e.username,
        "source_plugin": e.source_plugin,
    } for e in entries]}


@router.get("/api/inventory/summary")
def get_inventory_summary(scan_id: Optional[int] = None, db: Session = Depends(get_db), org_ids: Optional[List[int]] = Depends(get_accessible_org_ids)):
    """
    Cross-entity summary for attack path analysis.
    Returns counts + high-value entities (privileged users, domain admins,
    kerberoastable accounts, lateral movement paths via shared admins, etc.)
    """
    def _q(Model):
        q = db.query(Model).join(Scan, Model.scan_id == Scan.id)
        q = apply_scan_org_filter(q, org_ids)
        if scan_id:
            q = q.filter(Model.scan_id == scan_id)
        return q

    from models.models import InventoryDatabaseInstance

    # Counts
    total_users = _q(InventoryUser).count()
    total_groups = _q(InventoryGroup).count()
    total_services = _q(InventoryService).count()
    total_netconns = _q(InventoryNetConn).count()
    total_tasks = _q(InventoryScheduledTask).count()
    total_patches = _q(InventoryPatch).count()
    total_shares = _q(InventoryShare).count()
    total_software = _q(InventorySoftware).count()
    total_controls = _q(InventorySecurityControl).count()
    total_computers = _q(InventoryComputer).count()
    total_processes = _q(InventoryProcess).count()
    total_certs = _q(InventoryCertificate).count()
    total_logged_on = _q(InventoryLoggedOn).count()
    total_env_vars = _q(InventoryEnvVar).count()
    total_password_policies = _q(InventoryPasswordPolicy).count()
    total_ai_tools = _q(InventoryAITool).count()
    total_credentials = _q(InventoryCredential).count()
    expired_certs = _q(InventoryCertificate).filter(InventoryCertificate.is_expired == True).count()
    expiring_soon = _q(InventoryCertificate).filter(
        InventoryCertificate.is_expired == False,
        InventoryCertificate.days_until_expiry != None,
        InventoryCertificate.days_until_expiry <= 30,
    ).count()
    self_signed_certs = _q(InventoryCertificate).filter(InventoryCertificate.is_self_signed == True).count()

    # Privileged users
    domain_admins = _q(InventoryUser).filter(InventoryUser.is_domain_admin == True).all()
    local_admins = _q(InventoryUser).filter(InventoryUser.is_local_admin == True).all()

    # Kerberoastable: non-computer accounts with SPNs
    kerberoastable = [
        u for u in _q(InventoryUser).filter(InventoryUser.user_type == "service_account").all()
        if u.spns
    ]

    # Weak-password-policy users
    never_expires = _q(InventoryUser).filter(InventoryUser.password_never_expires == True).count()
    never_changed = _q(InventoryUser).filter(InventoryUser.never_changed_password == True).count()

    # Active established connections (lateral movement paths)
    established = _q(InventoryNetConn).filter(
        InventoryNetConn.state.in_(["established", "ESTABLISHED"])
    ).all()

    # Hosts with local admin overlap (users who are local admin on multiple assets)
    # Group local_admin users by (username, domain) → list of asset_ids
    admin_records = _q(InventoryUser).filter(InventoryUser.is_local_admin == True).all()
    admin_map = {}
    for u in admin_records:
        key = f"{u.domain}\\{u.username}".lower()
        admin_map.setdefault(key, [])
        if u.asset_id not in admin_map[key]:
            admin_map[key].append(u.asset_id)
    lateral_admin_paths = [
        {"account": k, "asset_ids": v}
        for k, v in admin_map.items()
        if len(v) > 1
    ]

    # Currently logged-on users
    logged_on = _q(InventoryLoggedOn).all()
    logged_on_assets = _asset_lookup(db, {e.asset_id for e in logged_on})

    # Missing patches with highest vuln counts
    top_patches = _q(InventoryPatch).order_by(desc(InventoryPatch.vuln_count)).limit(10).all()
    patch_assets = _asset_lookup(db, {p.asset_id for p in top_patches})

    # Writeable shares (lateral movement vector)
    writeable_shares = _q(InventoryShare).filter(InventoryShare.is_writeable == True).count()
    # Hosts without AV
    hosts_with_av = set(
        r.asset_id for r in _q(InventorySecurityControl).filter(
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).all()
    )
    # Weak password policies
    weak_policies = _q(InventoryPasswordPolicy).filter(InventoryPasswordPolicy.is_weak == True).count()
    # Sensitive env vars
    sensitive_env_vars = _q(InventoryEnvVar).filter(InventoryEnvVar.is_sensitive == True).count()
    # Domain controllers
    domain_controllers = _q(InventoryComputer).filter(InventoryComputer.is_domain_controller == True).all()
    # Database servers
    db_instance_count = _q(InventoryDatabaseInstance).count()

    return {
        "counts": {
            "users": total_users,
            "groups": total_groups,
            "services": total_services,
            "netconns": total_netconns,
            "scheduled_tasks": total_tasks,
            "missing_patches": total_patches,
            "shares": total_shares,
            "software": total_software,
            "security_controls": total_controls,
            "computers": total_computers,
            "certificates": total_certs,
            "processes": total_processes,
            "logged_on": total_logged_on,
            "env_vars": total_env_vars,
            "password_policies": total_password_policies,
            "ai_tools": total_ai_tools,
            "database_instances": db_instance_count,
            "credentials": total_credentials,
        },
        "attack_surface": {
            "domain_admins": [_inv_user_to_dict(u) for u in domain_admins],
            "local_admins_count": len(local_admins),
            "kerberoastable_accounts": [_inv_user_to_dict(u) for u in kerberoastable],
            "password_never_expires_count": never_expires,
            "never_changed_password_count": never_changed,
            "lateral_movement_paths": lateral_admin_paths,
            "established_connections": len(established),
            "logged_on_users": [
                {
                    "asset_id": e.asset_id,
                    "asset_label": _asset_label(logged_on_assets.get(e.asset_id)),
                    "domain": e.domain,
                    "username": e.username,
                }
                for e in logged_on
            ],
            "top_missing_patches": [
                {
                    "kb_id": p.kb_id,
                    "asset_id": p.asset_id,
                    "asset_label": _asset_label(patch_assets.get(p.asset_id)),
                    "vuln_count": p.vuln_count,
                }
                for p in top_patches
            ],
            "writeable_shares": writeable_shares,
            "hosts_with_av": len(hosts_with_av),
            "weak_password_policies": weak_policies,
            "domain_controllers": [
                {"computer_name": c.computer_name, "asset_id": c.asset_id, "os": c.os}
                for c in domain_controllers
            ],
            "expired_certs": expired_certs,
            "expiring_soon_certs": expiring_soon,
            "self_signed_certs": self_signed_certs,
            "sensitive_env_vars": sensitive_env_vars,
            "credential_exposures": total_credentials,
            "default_accounts": _q(InventoryCredential).filter(InventoryCredential.credential_type == "default_account").count(),
            "cleartext_credentials": _q(InventoryCredential).filter(InventoryCredential.credential_type == "cleartext").count(),
            "brute_forceable": _q(InventoryCredential).filter(InventoryCredential.credential_type == "brute_forceable").count(),
        },
    }


@router.get("/api/inventory/shares")
def list_inventory_shares(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_writeable: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "share_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryShare).join(Scan, InventoryShare.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryShare.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryShare.asset_id == asset_id)
    if is_writeable is not None:
        q = q.filter(InventoryShare.is_writeable == is_writeable)
    if search:
        s = f"%{search}%"
        q = q.filter(or_(
            InventoryShare.share_name.ilike(s),
            InventoryShare.comment.ilike(s),
            InventoryShare.path.ilike(s),
        ))
    q = _apply_sort(q, InventoryShare, sort_by, order, InventoryShare.share_name)
    total = q.count()
    if page_size == 0:
        shares = q.all()
    else:
        shares = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in shares})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "shares": [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "share_name": s.share_name, "share_type": s.share_type,
        "comment": s.comment, "path": s.path, "max_users": s.max_users,
        "acl": s.acl or [], "is_writeable": s.is_writeable,
        "is_default_share": s.is_default_share, "source_plugin": s.source_plugin,
    } for s in shares]}


@router.get("/api/inventory/software")
def list_inventory_software(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    category: Optional[str] = None,
    auto_update: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventorySoftware).join(Scan, InventorySoftware.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySoftware.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySoftware.asset_id == asset_id)
    if search:
        q = q.filter(InventorySoftware.name.ilike(f"%{search}%"))
    if category:
        if category == "Uncategorized":
            q = q.filter(InventorySoftware.category.is_(None))
        else:
            q = q.filter(InventorySoftware.category == category)
    if auto_update:
        if auto_update == "disabled":
            q = q.filter(InventorySoftware.auto_update_status == "disabled")
        elif auto_update == "enabled":
            q = q.filter(InventorySoftware.auto_update_status == "enabled")
        elif auto_update == "unknown":
            q = q.filter(InventorySoftware.auto_update_status.in_(["unknown", None]))
    q = _apply_sort(q, InventorySoftware, sort_by, order, InventorySoftware.name)
    total = q.count()
    if page_size == 0:
        software = q.all()
    else:
        software = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {s.asset_id for s in software})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "software": [{
        "id": s.id, "scan_id": s.scan_id, "asset_id": s.asset_id,
        "asset_label": _asset_label(assets.get(s.asset_id)),
        "asset_ip": (assets.get(s.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(s.asset_id) or {}).get("environment_tag"),
        "name": s.name, "version": s.version, "installed_on": s.installed_on,
        "vendor": s.vendor, "category": s.category,
        "auto_update_status": s.auto_update_status,
        "source_plugin": s.source_plugin,
    } for s in software]}


@router.get("/api/inventory/security-controls")
def list_inventory_security_controls(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    control_type: Optional[str] = None,
    sort_by: str = "product_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventorySecurityControl).join(Scan, InventorySecurityControl.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySecurityControl.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventorySecurityControl.asset_id == asset_id)
    if control_type:
        q = q.filter(InventorySecurityControl.control_type == control_type)
    q = _apply_sort(q, InventorySecurityControl, sort_by, order, InventorySecurityControl.product_name)
    total = q.count()
    if page_size == 0:
        controls = q.all()
    else:
        controls = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in controls})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "controls": [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "control_type": c.control_type, "product_name": c.product_name,
        "vendor": c.vendor, "version": c.version, "is_enabled": c.is_enabled,
        "is_up_to_date": c.is_up_to_date, "signature_date": c.signature_date,
        "details": c.details or {}, "source_plugin": c.source_plugin,
    } for c in controls]}


@router.get("/api/inventory/security-coverage")
def get_security_coverage(
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """
    Security control coverage matrix.
    Returns per-category coverage across assets and a per-asset control list.
    """
    from threat_intel.security_tool_catalog import SECURITY_TOOL_CATALOG
    from collections import defaultdict

    # Reverse map: control_type → canonical category name (from catalog)
    CT_TO_CAT = {}
    for _entry in SECURITY_TOOL_CATALOG:
        ct = _entry["control_type"]
        if ct not in CT_TO_CAT:
            CT_TO_CAT[ct] = _entry["category"]

    q = db.query(InventorySecurityControl).join(Scan, InventorySecurityControl.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventorySecurityControl.scan_id == scan_id)
    controls = q.all()

    aq = db.query(Asset).join(Scan, Asset.scan_id == Scan.id)
    aq = apply_scan_org_filter(aq, org_ids)
    if scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    all_assets = aq.all()
    total_assets = len(all_assets)

    asset_map = {
        a.id: {
            "asset_id": a.id,
            "asset_label": f"{a.ip or ''}" + (f" | {a.hostname}" if a.hostname else ""),
            "asset_ip": a.ip,
            "asset_env": a.environment_tag,
            "controls": [],
        }
        for a in all_assets
    }

    for c in controls:
        if c.asset_id not in asset_map:
            continue
        asset_map[c.asset_id]["controls"].append({
            "product_name": c.product_name,
            "vendor": c.vendor,
            "control_type": c.control_type,
            "category": (c.details or {}).get("category") or CT_TO_CAT.get(c.control_type, c.control_type),
            "is_enabled": c.is_enabled,
            "detection_method": (c.details or {}).get("detection_method", "plugin"),
            "source_plugin": c.source_plugin,
        })

    # Build unique category catalog (preserve insertion order by category first seen)
    CATALOG_CATEGORIES = {}
    for entry in SECURITY_TOOL_CATALOG:
        cat = entry["category"]
        if cat not in CATALOG_CATEGORIES:
            CATALOG_CATEGORIES[cat] = entry["control_type"]

    cat_to_assets = defaultdict(set)
    cat_to_products = defaultdict(set)
    for c in controls:
        cat = (c.details or {}).get("category") or CT_TO_CAT.get(c.control_type, c.control_type)
        cat_to_assets[cat].add(c.asset_id)
        if c.product_name:
            cat_to_products[cat].add(c.product_name)

    categories = []
    for cat, ct in CATALOG_CATEGORIES.items():
        covered = len(cat_to_assets.get(cat, set()))
        categories.append({
            "name": cat,
            "control_type": ct,
            "total_assets": total_assets,
            "covered_assets": covered,
            "coverage_pct": round(covered / total_assets * 100, 1) if total_assets else 0,
            "products": sorted(cat_to_products.get(cat, set())),
        })
    categories.sort(key=lambda x: x["coverage_pct"])

    if total_assets:
        per_asset_pct = [
            len({ctrl["category"] for ctrl in a["controls"]}) / len(CATALOG_CATEGORIES) * 100
            for a in asset_map.values()
        ]
        avg_coverage = round(sum(per_asset_pct) / len(per_asset_pct), 1)
    else:
        avg_coverage = 0.0

    missing_categories = [c["name"] for c in categories if c["covered_assets"] == 0]

    return {
        "categories": categories,
        "assets": sorted(asset_map.values(), key=lambda a: (a["asset_ip"] or "")),
        "summary": {
            "total_assets": total_assets,
            "avg_coverage_pct": avg_coverage,
            "total_categories": len(CATALOG_CATEGORIES),
            "categories_with_coverage": len([c for c in categories if c["covered_assets"] > 0]),
            "missing_categories": missing_categories,
        },
    }


@router.post("/api/scans/{scan_id}/detect-security-controls")
def rerun_security_control_detection(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """Re-run catalog-based security control detection for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.query(InventorySecurityControl).filter(
        InventorySecurityControl.scan_id == scan_id,
        InventorySecurityControl.source_plugin == "catalog",
    ).delete(synchronize_session=False)
    db.commit()
    from parsers.inventory_extractor import detect_security_controls_from_inventory
    count = detect_security_controls_from_inventory(db, scan_id)
    return {"scan_id": scan_id, "detected": count}


@router.get("/api/inventory/computers")
def list_inventory_computers(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    is_dc: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "computer_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryComputer).join(Scan, InventoryComputer.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryComputer.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryComputer.asset_id == asset_id)
    if is_dc is not None:
        q = q.filter(InventoryComputer.is_domain_controller == is_dc)
    if search:
        q = q.filter(
            InventoryComputer.computer_name.ilike(f"%{search}%") |
            InventoryComputer.dns_hostname.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryComputer, sort_by, order, InventoryComputer.computer_name)
    total = q.count()
    if page_size == 0:
        computers = q.all()
    else:
        computers = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {c.asset_id for c in computers})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "computers": [{
        "id": c.id, "scan_id": c.scan_id, "asset_id": c.asset_id,
        "asset_label": _asset_label(assets.get(c.asset_id)),
        "asset_ip": (assets.get(c.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(c.asset_id) or {}).get("environment_tag"),
        "computer_name": c.computer_name, "dns_hostname": c.dns_hostname,
        "os": c.os, "os_version": c.os_version, "sid": c.sid, "dn": c.dn,
        "is_domain_controller": c.is_domain_controller, "is_disabled": c.is_disabled,
        "uac": c.uac, "date_joined": c.date_joined, "source_plugin": c.source_plugin,
    } for c in computers]}


@router.get("/api/inventory/password-policies")
def list_inventory_password_policies(
    scan_id: Optional[int] = None,
    sort_by: str = "domain",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryPasswordPolicy).join(Scan, InventoryPasswordPolicy.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryPasswordPolicy.scan_id == scan_id)
    q = _apply_sort(q, InventoryPasswordPolicy, sort_by, order, InventoryPasswordPolicy.domain)
    total = q.count()
    if page_size == 0:
        policies = q.all()
    else:
        policies = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {p.asset_id for p in policies})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "policies": [{
        "id": p.id, "scan_id": p.scan_id, "asset_id": p.asset_id,
        "asset_label": _asset_label(assets.get(p.asset_id)),
        "asset_ip": (assets.get(p.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(p.asset_id) or {}).get("environment_tag"),
        "domain": p.domain, "min_length": p.min_length,
        "history_count": p.history_count, "max_age_days": p.max_age_days,
        "min_age_days": p.min_age_days, "complexity_enabled": p.complexity_enabled,
        "reversible_encryption": p.reversible_encryption,
        "lockout_threshold": p.lockout_threshold,
        "lockout_duration_mins": p.lockout_duration_mins,
        "lockout_window_mins": p.lockout_window_mins,
        "is_weak": p.is_weak, "source_plugin": p.source_plugin,
    } for p in policies]}


@router.get("/api/inventory/env-vars")
def list_inventory_env_vars(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    scope: Optional[str] = None,
    sensitive_only: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryEnvVar).join(Scan, InventoryEnvVar.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryEnvVar.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryEnvVar.asset_id == asset_id)
    if scope:
        q = q.filter(InventoryEnvVar.scope == scope)
    if sensitive_only:
        q = q.filter(InventoryEnvVar.is_sensitive == True)
    if search:
        q = q.filter(
            InventoryEnvVar.name.ilike(f"%{search}%") |
            InventoryEnvVar.value.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryEnvVar, sort_by, order, InventoryEnvVar.name)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "env_vars": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "name": r.name, "value": r.value, "scope": r.scope,
        "is_sensitive": r.is_sensitive, "source_plugin": r.source_plugin,
    } for r in rows]}


@router.get("/api/inventory/certificates")
def list_inventory_certificates(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    expired_only: Optional[bool] = None,
    expiring_days: Optional[int] = None,   # certs expiring within N days
    self_signed_only: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: str = "not_after",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryCertificate).join(Scan, InventoryCertificate.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryCertificate.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryCertificate.asset_id == asset_id)
    if expired_only:
        q = q.filter(InventoryCertificate.is_expired == True)
    if expiring_days is not None:
        q = q.filter(
            InventoryCertificate.is_expired == False,
            InventoryCertificate.days_until_expiry != None,
            InventoryCertificate.days_until_expiry <= expiring_days,
        )
    if self_signed_only:
        q = q.filter(InventoryCertificate.is_self_signed == True)
    if search:
        q = q.filter(
            InventoryCertificate.subject_cn.ilike(f"%{search}%") |
            InventoryCertificate.issuer_cn.ilike(f"%{search}%") |
            InventoryCertificate.subject_o.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryCertificate, sort_by, order, InventoryCertificate.not_after)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "certificates": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "subject_cn": r.subject_cn, "subject_o": r.subject_o,
        "subject_ou": r.subject_ou, "subject_c": r.subject_c,
        "subject_email": r.subject_email,
        "issuer_cn": r.issuer_cn, "issuer_o": r.issuer_o,
        "issuer_c": r.issuer_c,
        "serial_number": r.serial_number,
        "not_before": r.not_before, "not_after": r.not_after,
        "is_expired": r.is_expired, "days_until_expiry": r.days_until_expiry,
        "signature_algorithm": r.signature_algorithm,
        "key_algorithm": r.key_algorithm, "key_bits": r.key_bits,
        "subject_alt_names": r.subject_alt_names or [],
        "is_ca": r.is_ca, "is_self_signed": r.is_self_signed,
        "port": r.port, "protocol": r.protocol,
        "source_plugin": r.source_plugin,
    } for r in rows]}


@router.get("/api/inventory/databases")
def list_inventory_databases(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    db_type: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "db_type",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    from models.models import InventoryDatabaseInstance
    q = db.query(InventoryDatabaseInstance).join(Scan, InventoryDatabaseInstance.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryDatabaseInstance.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryDatabaseInstance.asset_id == asset_id)
    if db_type:
        q = q.filter(InventoryDatabaseInstance.db_type == db_type)
    if search:
        q = q.filter(
            InventoryDatabaseInstance.instance_name.ilike(f"%{search}%") |
            InventoryDatabaseInstance.version.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryDatabaseInstance, sort_by, order, InventoryDatabaseInstance.db_type)
    total = q.count()
    if page_size == 0:
        instances = q.all()
    else:
        instances = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {i.asset_id for i in instances})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "databases": [{
        "id": i.id, "scan_id": i.scan_id, "asset_id": i.asset_id,
        "asset_label": _asset_label(assets.get(i.asset_id)),
        "asset_ip": (assets.get(i.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(i.asset_id) or {}).get("environment_tag"),
        "db_type": i.db_type, "instance_name": i.instance_name,
        "version": i.version, "port": i.port,
        "databases": i.databases or [], "named_pipes": i.named_pipes or [],
        "is_running": i.is_running, "source_plugin": i.source_plugin,
    } for i in instances]}


@router.get("/api/inventory/domain-trusts")
def list_inventory_domain_trusts(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    trust_direction: Optional[str] = None,
    sort_by: str = "trusted_domain",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryDomainTrust).join(Scan, InventoryDomainTrust.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryDomainTrust.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryDomainTrust.asset_id == asset_id)
    if trust_direction:
        q = q.filter(InventoryDomainTrust.trust_direction == trust_direction)
    q = _apply_sort(q, InventoryDomainTrust, sort_by, order, InventoryDomainTrust.trusted_domain)
    total = q.count()
    if page_size == 0:
        trusts = q.all()
    else:
        trusts = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {t.asset_id for t in trusts})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "domain_trusts": [{
        "id": t.id, "scan_id": t.scan_id, "asset_id": t.asset_id,
        "asset_label": _asset_label(assets.get(t.asset_id)),
        "asset_ip": (assets.get(t.asset_id) or {}).get("ip"),
        "trusted_domain": t.trusted_domain, "flat_name": t.flat_name,
        "sid": t.sid, "dn": t.dn,
        "trust_direction": t.trust_direction, "trust_type": t.trust_type,
        "trust_attributes": t.trust_attributes,
        "is_transitive": t.is_transitive, "is_sid_filtering_enabled": t.is_sid_filtering_enabled,
        "source_domain": t.source_domain, "when_created": t.when_created,
        "source_plugin": t.source_plugin,
    } for t in trusts]}


@router.get("/api/inventory/ai-tools")
def list_inventory_ai_tools(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "tool_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryAITool).join(Scan, InventoryAITool.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryAITool.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryAITool.asset_id == asset_id)
    if category:
        q = q.filter(InventoryAITool.category == category)
    if search:
        q = q.filter(InventoryAITool.tool_name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventoryAITool, sort_by, order, InventoryAITool.tool_name)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "ai_tools": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "tool_name": r.tool_name, "category": r.category,
        "source_plugin": r.source_plugin,
    } for r in rows]}


@router.get("/api/inventory/credentials")
def list_inventory_credentials(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    credential_type: Optional[str] = None,
    protocol: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity",
    order: str = "desc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryCredential).join(Scan, InventoryCredential.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryCredential.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryCredential.asset_id == asset_id)
    if credential_type:
        q = q.filter(InventoryCredential.credential_type == credential_type)
    if protocol:
        q = q.filter(InventoryCredential.protocol == protocol)
    if severity:
        q = q.filter(InventoryCredential.severity == severity)
    if search:
        q = q.filter(
            InventoryCredential.plugin_name.ilike(f"%{search}%") |
            InventoryCredential.username.ilike(f"%{search}%") |
            InventoryCredential.protocol.ilike(f"%{search}%")
        )
    q = _apply_sort(q, InventoryCredential, sort_by, order, InventoryCredential.severity)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "credentials": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "credential_type": r.credential_type, "protocol": r.protocol,
        "username": r.username, "severity": r.severity, "port": r.port,
        "description": r.description, "plugin_name": r.plugin_name,
        "source_plugin": r.source_plugin, "remediation": r.remediation,
    } for r in rows]}


@router.get("/api/inventory/processes")
def list_inventory_processes(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    session_id: Optional[int] = None,
    sort_by: str = "process_name",
    order: str = "asc",
    page: int = 1,
    page_size: int = 100,
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    from app import _apply_sort
    q = db.query(InventoryProcess).join(Scan, InventoryProcess.scan_id == Scan.id)
    q = apply_scan_org_filter(q, org_ids)
    if scan_id:
        q = q.filter(InventoryProcess.scan_id == scan_id)
    if asset_id:
        q = q.filter(InventoryProcess.asset_id == asset_id)
    if session_id is not None:
        q = q.filter(InventoryProcess.session_id == session_id)
    if search:
        q = q.filter(InventoryProcess.process_name.ilike(f"%{search}%"))
    q = _apply_sort(q, InventoryProcess, sort_by, order, InventoryProcess.process_name)
    total = q.count()
    if page_size == 0:
        rows = q.all()
    else:
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
    assets = _asset_lookup(db, {r.asset_id for r in rows})
    return {"total": total, "page": 1 if page_size == 0 else page, "page_size": page_size, "processes": [{
        "id": r.id, "scan_id": r.scan_id, "asset_id": r.asset_id,
        "asset_label": _asset_label(assets.get(r.asset_id)),
        "asset_ip": (assets.get(r.asset_id) or {}).get("ip"),
        "asset_env": (assets.get(r.asset_id) or {}).get("environment_tag"),
        "process_name": r.process_name, "pid": r.pid, "ppid": r.ppid,
        "session_id": r.session_id, "parent_name": r.parent_name,
        "depth": r.depth, "source_plugin": r.source_plugin,
    } for r in rows]}

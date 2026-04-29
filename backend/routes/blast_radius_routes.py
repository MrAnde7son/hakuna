"""
Blast radius / attack path route handlers.
"""
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from core.database import get_db
from core.query_guards import set_statement_timeout, check_row_count
from core.auth import get_accessible_org_ids
from models.models import (
    Asset, Scan, Finding, InventoryComputer, InventoryUser, InventoryGroup,
    InventoryNetConn, InventoryLoggedOn, InventoryScheduledTask,
    InventoryPatch, InventoryShare, InventorySecurityControl,
    InventoryCredential, InventoryDatabaseInstance, InventoryCertificate,
    AssetRelationship, FirewallPolicy,
)
from parsers.inventory_extractor import _cn_from_dn
from services.blast_radius import (
    resolve_dc_asset_ids,
    AD_ACCESS_GROUPS, LOCAL_ACCESS_GROUPS, LINUX_ACCESS_GROUPS,
    LINUX_OS_HINTS, RISKY_PORTS, GROUP_ACCESS_LABELS,
)
from services.asset_edges_query import (
    REACHABILITY_EDGE_TYPES,
    internet_facing_assets,
    list_outbound_edges,
    reachable_targets,
)

router = APIRouter()


@router.get("/api/blast-radius/bulk")
def get_blast_radius_bulk(
    asset_ids: str = Query(None, description="Comma-separated asset IDs"),
    scan_id: int = Query(None, description="Deprecated — kept for backward compat"),
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute blast radius scores for assets in one pass (org-scoped)."""

    set_statement_timeout(db)

    # Load assets: prefer explicit asset_ids, fall back to scan_id for backward compat
    if asset_ids:
        id_list = [int(x) for x in asset_ids.split(",") if x.strip().isdigit()]
        asset_q = db.query(Asset).filter(Asset.id.in_(id_list))
        if org_ids is not None:
            asset_q = asset_q.outerjoin(Scan, Asset.scan_id == Scan.id).filter(
                or_(Scan.org_id.in_(org_ids), Asset.scan_id.is_(None))
            )
    elif scan_id:
        asset_q = db.query(Asset).filter(Asset.scan_id == scan_id)
    else:
        return {}

    check_row_count(db, asset_q)
    all_assets = asset_q.all()
    if not all_assets:
        return {}

    asset_map = {a.id: a for a in all_assets}
    all_asset_ids = list(asset_map.keys())
    ip_to_asset_id = {a.ip: a.id for a in all_assets if a.ip}

    # Pre-resolve org for edge queries (every asset in the result set
    # belongs to one or more orgs — pick the first scan's org).
    asset_org_map: dict[int, int] = {}
    for a in all_assets:
        if a.scan_id is None:
            continue
        s = db.query(Scan.org_id).filter(Scan.id == a.scan_id).first()
        if s:
            asset_org_map[a.id] = s[0]

    # Phase 2 read path: pull reachable targets from the unified edge
    # graph (asset_to_asset_port + asset_to_asset_auth + legacy types),
    # rather than re-querying InventoryNetConn here. The materializer
    # has already deduplicated and capped the netconn graph.
    reachable_via_edges: dict[int, set[int]] = {}
    if org_ids is not None:
        for oid in org_ids:
            scoped = [aid for aid in all_asset_ids if asset_org_map.get(aid) == oid]
            if not scoped:
                continue
            for src, targets in reachable_targets(
                db, org_id=oid, src_asset_ids=scoped,
            ).items():
                reachable_via_edges.setdefault(src, set()).update(targets)

    all_logons = db.query(InventoryLoggedOn).filter(
        InventoryLoggedOn.asset_id.in_(all_asset_ids),
    ).all()
    logons_by_asset = {}
    for lo in all_logons:
        logons_by_asset.setdefault(lo.asset_id, []).append(lo)

    all_priv_users = db.query(InventoryUser).filter(
        InventoryUser.asset_id.in_(all_asset_ids),
        or_(
            InventoryUser.is_domain_admin == True,
            InventoryUser.is_local_admin == True,
            InventoryUser.is_privileged == True,
        ),
    ).all()
    priv_users_by_name = {}
    for u in all_priv_users:
        if u.username:
            priv_users_by_name.setdefault(u.username, []).append(u)

    admin_users = db.query(InventoryUser).filter(
        InventoryUser.asset_id.in_(all_asset_ids),
        or_(
            InventoryUser.is_domain_admin == True,
            InventoryUser.is_local_admin == True,
        ),
    ).all()
    admins_by_asset = {}
    for u in admin_users:
        admins_by_asset.setdefault(u.asset_id, []).append(u)

    dc_asset_ids = resolve_dc_asset_ids(db, restrict_to_asset_ids=all_asset_ids)

    # Pre-fetch group data for group-membership access paths
    all_groups = db.query(InventoryGroup).filter(InventoryGroup.asset_id.in_(all_asset_ids)).all()
    groups_by_asset: dict[int, list] = {}
    for g in all_groups:
        groups_by_asset.setdefault(g.asset_id, []).append(g)

    # Pre-fetch all users indexed by username (lowercase) for member resolution
    all_users_scan = db.query(InventoryUser).filter(InventoryUser.asset_id.in_(all_asset_ids)).all()
    users_by_name = {}
    for u in all_users_scan:
        if u.username:
            users_by_name.setdefault(u.username.lower(), []).append(u)
    users_by_asset: dict[int, list] = {}
    for u in all_users_scan:
        users_by_asset.setdefault(u.asset_id, []).append(u)

    # Pre-fetch new data sources for enhanced scoring
    all_creds = db.query(InventoryCredential).filter(InventoryCredential.asset_id.in_(all_asset_ids)).all()
    creds_by_asset: dict[int, list] = {}
    for c in all_creds:
        creds_by_asset.setdefault(c.asset_id, []).append(c)

    all_exploitable = db.query(Finding).filter(
        Finding.asset_id.in_(all_asset_ids), Finding.severity >= 3, Finding.exploit_available == True,
    ).all()
    exploitable_by_asset: dict[int, list] = {}
    for f in all_exploitable:
        exploitable_by_asset.setdefault(f.asset_id, []).append(f)

    all_dbs = db.query(InventoryDatabaseInstance).filter(
        InventoryDatabaseInstance.asset_id.in_(all_asset_ids), InventoryDatabaseInstance.is_running == True,
    ).all()
    dbs_by_asset: dict[int, list] = {}
    for d in all_dbs:
        dbs_by_asset.setdefault(d.asset_id, []).append(d)

    all_patches = db.query(InventoryPatch).filter(InventoryPatch.asset_id.in_(all_asset_ids)).all()
    patches_by_asset: dict[int, list] = {}
    for p in all_patches:
        if (p.vuln_count or 0) >= 5:
            patches_by_asset.setdefault(p.asset_id, []).append(p)

    # Scheduled tasks running as privileged users
    all_schtasks = db.query(InventoryScheduledTask).filter(InventoryScheduledTask.asset_id.in_(all_asset_ids)).all()
    schtask_priv_assets: set = set()
    for t in all_schtasks:
        run_user = (t.run_as_user or "").strip().lower()
        if run_user and run_user in users_by_name:
            for mu in users_by_name[run_user]:
                if mu.is_domain_admin or mu.is_local_admin or mu.is_privileged:
                    schtask_priv_assets.add(t.asset_id)
                    break

    # AssetRelationship edges that don't fit the unified reachability
    # taxonomy but are still meaningful (knowledge-graph infra hops).
    # Cheaper to skip — the unified edge query above already covers
    # `resolves_to` / `alias_of`. Kept as an empty dict so the loop
    # below preserves shape.
    rels_by_asset: dict[int, list] = {}

    results = {}

    for asset in all_assets:
        asset_id = asset.id
        reachable = set()
        da_exposed = False
        la_exposed = False
        kerb_exposed = False
        group_access_exposed = False
        seen_users = set()

        # 1. Reachable assets via unified edge graph (asset_to_asset_port,
        # asset_to_asset_auth, legacy connects_to / member_of_domain /
        # trusts_domain / shares_credential_with / runs_as_principal,
        # and infra resolves_to / alias_of).
        for dst_id in reachable_via_edges.get(asset_id, ()):
            if dst_id != asset_id:
                reachable.add(dst_id)

        # 2. Privileged users logged on
        for logon in logons_by_asset.get(asset_id, []):
            if not logon.username:
                continue
            for u in priv_users_by_name.get(logon.username, []):
                if u.id in seen_users:
                    continue
                seen_users.add(u.id)
                if u.is_domain_admin:
                    da_exposed = True
                if u.is_local_admin:
                    la_exposed = True
                if u.spns:
                    kerb_exposed = True

        # 3. Admin accounts on this asset
        for u in admins_by_asset.get(asset_id, []):
            if u.id in seen_users:
                continue
            seen_users.add(u.id)
            if u.is_domain_admin:
                da_exposed = True
                # DA exposes other assets they're on
                for other in priv_users_by_name.get(u.username, []):
                    if other.asset_id != asset_id and other.is_domain_admin:
                        reachable.add(other.asset_id)
            if u.is_local_admin:
                la_exposed = True
            if u.spns:
                kerb_exposed = True

        # 4. AD group memberships → DC access
        cur_os_lower = (asset.os or "").lower()
        is_linux = any(h in cur_os_lower for h in LINUX_OS_HINTS)
        for u in users_by_asset.get(asset_id, []):
            for group_entry in (u.member_of or []):
                cn = _cn_from_dn(group_entry) if "=" in group_entry else group_entry.strip()
                if "\\" in cn:
                    cn = cn.split("\\", 1)[1]
                cn_lower = cn.lower().strip()
                if cn_lower in AD_ACCESS_GROUPS:
                    etype, _ = AD_ACCESS_GROUPS[cn_lower]
                    if etype == "domain_admin":
                        da_exposed = True
                    else:
                        group_access_exposed = True
                    # Access to all DC assets
                    for dc_id in dc_asset_ids:
                        if dc_id != asset_id:
                            reachable.add(dc_id)

        # 5. Local / Linux group membership
        local_groups_map = LINUX_ACCESS_GROUPS if is_linux else LOCAL_ACCESS_GROUPS
        for group in groups_by_asset.get(asset_id, []):
            group_lower = (group.group_name or "").lower().strip()
            if group_lower not in local_groups_map:
                continue
            etype, _ = local_groups_map[group_lower]
            for member_raw in (group.members or []):
                cn = _cn_from_dn(member_raw) if "=" in member_raw else member_raw.strip()
                if "\\" in cn:
                    cn = cn.split("\\", 1)[1]
                if not cn or cn.endswith("$"):
                    continue
                matched = users_by_name.get(cn.lower(), [])
                for mu in matched:
                    if mu.asset_id != asset_id:
                        pass  # handled on the other asset's pass
                    if mu.id not in seen_users:
                        seen_users.add(mu.id)
                        if etype == "local_admin":
                            la_exposed = True
                        else:
                            group_access_exposed = True

        dc_reachable = bool(reachable & dc_asset_ids)

        # Additional factors from new data sources
        has_weak_creds = len(creds_by_asset.get(asset_id, [])) > 0
        has_exploitable = len(exploitable_by_asset.get(asset_id, [])) > 0
        has_exposed_dbs = len(dbs_by_asset.get(asset_id, [])) > 0
        has_schtask_priv = asset_id in schtask_priv_assets
        has_missing_patches = len(patches_by_asset.get(asset_id, [])) > 0

        is_inet = asset.is_internet_facing or False
        reachable_count = len(reachable) + (1 if is_inet else 0)

        score = min(reachable_count * 1.5, 5.0)
        if dc_reachable:              score += 3.0
        if da_exposed:                score += 2.0
        elif la_exposed:              score += 1.0
        if kerb_exposed:              score += 1.0
        if group_access_exposed:      score += 0.5
        if has_weak_creds:            score += 1.5
        if has_exploitable:           score += 1.0
        if has_schtask_priv:          score += 0.5
        if has_missing_patches:       score += 0.5
        if has_exposed_dbs:           score += 0.5
        if is_inet:                   score += 1.5
        score = min(round(score, 1), 10.0)

        results[str(asset_id)] = {
            "asset_id": asset_id,
            "score": score,
            "reachable_assets": reachable_count,
            "da_exposed": da_exposed,
            "dc_reachable": dc_reachable,
            "group_access_exposed": group_access_exposed,
            "has_weak_creds": has_weak_creds,
            "has_exploitable": has_exploitable,
            "has_exposed_dbs": has_exposed_dbs,
        }

    return results


@router.get("/api/blast-radius")
def get_blast_radius(
    asset_id: int = Query(...),
    scan_id: int = Query(None, description="Deprecated — ignored"),
    finding_id: int = Query(None, description="Scope blast radius to a specific finding"),
    db: Session = Depends(get_db),
    org_ids: Optional[List[int]] = Depends(get_accessible_org_ids),
):
    """Compute blast radius for a specific asset using inventory + relationship data."""

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    # Determine org scope: use scan's org_id, or fall back to org_ids from auth
    asset_org_id = None
    if asset.scan_id:
        scan_row = db.query(Scan).filter(Scan.id == asset.scan_id).first()
        if scan_row:
            asset_org_id = scan_row.org_id
    if asset_org_id:
        all_assets = db.query(Asset).join(Scan, Asset.scan_id == Scan.id).filter(Scan.org_id == asset_org_id).all()
        # Also include scan-less assets linked via relationships
        rel_asset_ids = {r[0] for r in db.query(AssetRelationship.target_asset_id).filter(
            AssetRelationship.org_id == asset_org_id,
        ).all()} | {r[0] for r in db.query(AssetRelationship.source_asset_id).filter(
            AssetRelationship.org_id == asset_org_id,
        ).all()}
        if rel_asset_ids:
            extra = db.query(Asset).filter(Asset.id.in_(rel_asset_ids), Asset.scan_id.is_(None)).all()
            all_assets.extend(extra)
    elif org_ids:
        all_assets = db.query(Asset).outerjoin(Scan, Asset.scan_id == Scan.id).filter(
            or_(Scan.org_id.in_(org_ids), Asset.scan_id.is_(None))
        ).all()
    else:
        all_assets = [asset]
    asset_map = {a.id: a for a in all_assets}
    ip_to_asset_id = {a.ip: a.id for a in all_assets if a.ip}

    nodes: dict = {}
    edges: list = []
    seen_edge_ids: set = set()

    def _asset_dc(aid):
        return db.query(InventoryComputer).filter(
            InventoryComputer.asset_id == aid,
            InventoryComputer.is_domain_controller == True,
        ).first() is not None

    def _asset_av(aid):
        return db.query(InventorySecurityControl).filter(
            InventorySecurityControl.asset_id == aid,
            InventorySecurityControl.control_type == "av",
            InventorySecurityControl.is_enabled == True,
        ).first() is not None

    def _asset_share(aid):
        return db.query(InventoryShare).filter(
            InventoryShare.asset_id == aid,
            InventoryShare.is_writeable == True,
        ).first() is not None

    def _asset_node_data(a):
        return {
            "label": a.hostname or a.fqdn or a.netbios_name or a.ip or f"Asset {a.id}",
            "ip": a.ip, "hostname": a.hostname, "os": a.os,
            "is_internet_facing": a.is_internet_facing,
            "internet_facing_methods": a.internet_facing_methods or [],
            "risk_score": a.risk_score, "criticality": a.criticality,
            "critical_count": a.critical_count, "high_count": a.high_count,
            "medium_count": a.medium_count,
            "is_dc": _asset_dc(a.id),
            "has_av": _asset_av(a.id),
            "has_writeable_share": _asset_share(a.id),
        }

    def add_node(nid, ntype, data):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "data": data}

    def add_edge(eid, source, target, etype, label):
        if eid not in seen_edge_ids:
            seen_edge_ids.add(eid)
            edges.append({"id": eid, "source": source, "target": target,
                          "type": etype, "data": {"label": label}})

    def _user_nid(u):
        """Canonical node ID for a user — deduplicates same user across assets."""
        name = (u.username or "unknown").lower()
        dom = (u.domain or "local").lower()
        return f"user-{dom}-{name}"

    def _user_node_data(u):
        return {
            "label": u.username or "unknown",
            "username": u.username, "domain": u.domain,
            "user_type": u.user_type,
            "is_domain_admin": u.is_domain_admin,
            "is_local_admin": u.is_local_admin,
            "is_privileged": u.is_privileged,
            "kerberoastable": bool(u.spns),
            "spns": u.spns or [],
            "password_never_expires": u.password_never_expires,
            "member_of": u.member_of or [],
        }

    def _add_user_node(u):
        """Add user node with dedup — merges privilege flags from multiple records."""
        nid = _user_nid(u)
        if nid in nodes:
            d = nodes[nid]["data"]
            if u.is_domain_admin: d["is_domain_admin"] = True
            if u.is_local_admin:  d["is_local_admin"] = True
            if u.is_privileged:   d["is_privileged"] = True
            if u.spns:            d["kerberoastable"] = True
            if u.password_never_expires: d["password_never_expires"] = True
        else:
            add_node(nid, "user", _user_node_data(u))
        return nid

    # Pre-compute DC asset IDs for group membership paths
    dc_asset_ids = [a.id for a in all_assets if _asset_dc(a.id)]

    # Pre-index all org users by username (lowercase) for fast member resolution
    all_org_asset_ids = [a.id for a in all_assets]
    all_scan_users = db.query(InventoryUser).filter(InventoryUser.asset_id.in_(all_org_asset_ids)).all()
    users_by_name_idx = {}
    for u in all_scan_users:
        if u.username:
            users_by_name_idx.setdefault(u.username.lower(), []).append(u)

    start_nid = f"asset-{asset_id}"
    add_node(start_nid, "asset", {**_asset_node_data(asset), "_start": True})

    # Virtual "Internet" node for internet-facing assets
    port_str = None
    inet_label = "Externally reachable"
    if asset.is_internet_facing:
        easm = asset.easm_data or {}
        port_svc_map: dict[int, str] = {}

        for p in (easm.get("open_ports") or []):
            svc = (easm.get("services") or {}).get(str(p)) or {}
            port_svc_map.setdefault(int(p), svc.get("name", ""))

        finding_ports = db.query(Finding.port).filter(
            Finding.asset_id == asset_id, Finding.port.isnot(None),
        ).distinct().all()
        for (fp,) in finding_ports:
            try:
                port_svc_map.setdefault(int(fp), "")
            except (ValueError, TypeError):
                pass

        listen_ports = db.query(
            InventoryNetConn.local_port, InventoryNetConn.proto,
        ).filter(
            InventoryNetConn.asset_id == asset_id,
            InventoryNetConn.state.in_(["LISTEN", "LISTENING"]),
            InventoryNetConn.local_port.isnot(None),
        ).distinct().all()
        for lp, proto in listen_ports:
            port_svc_map.setdefault(int(lp), "")

        if port_svc_map:
            port_labels = []
            for p in sorted(port_svc_map):
                svc_name = port_svc_map[p]
                port_labels.append(f"{p}/{svc_name}" if svc_name else str(p))
            port_str = ", ".join(port_labels)
        inet_label = f"Exposed ports: {port_str}" if port_str else "Externally reachable"
        add_node("internet", "internet", {
            "label": "Internet",
            "ip": None, "hostname": None, "os": None,
        })
        add_edge("e-inet-access", "internet", start_nid, "internet_access",
                 inet_label)

    visited_assets = {asset_id}
    queue = [asset_id]

    for hop in range(2):
        next_queue = []
        for cur_id in queue:
            cur = asset_map.get(cur_id)
            if not cur:
                continue

            # 1. Reachable assets via the unified edge graph (Phase 2).
            # Pulls `asset_to_asset_port` (materialized from netconns)
            # plus legacy `connects_to`. Per-edge label encodes the
            # port so the UI keeps the ":<port>" affordance.
            cur_org = (
                db.query(Scan.org_id)
                .filter(Scan.id == cur.scan_id)
                .scalar()
                if cur.scan_id else None
            )
            if cur_org:
                edges_out = list_outbound_edges(
                    db, org_id=cur_org, src_asset_ids=[cur_id],
                    edge_types=["asset_to_asset_port", "connects_to"],
                ).get(cur_id, [])
                for rel in edges_out:
                    dst_id = rel.target_asset_id
                    if not dst_id or dst_id == cur_id:
                        continue
                    dst = asset_map.get(dst_id)
                    if not dst:
                        continue
                    props = rel.properties or {}
                    port = props.get("port") or props.get("remote_port") or "?"
                    add_node(f"asset-{dst_id}", "asset", _asset_node_data(dst))
                    add_edge(
                        f"e-net-{cur_id}-{dst_id}-{port}",
                        f"asset-{cur_id}", f"asset-{dst_id}",
                        "network_connection", f":{port}",
                    )
                    if dst_id not in visited_assets:
                        visited_assets.add(dst_id)
                        next_queue.append(dst_id)

            # 2. Privileged users currently logged on (credential exposure)
            for logon in db.query(InventoryLoggedOn).filter(
                InventoryLoggedOn.asset_id == cur_id,
            ).all():
                if not logon.username:
                    continue
                user = db.query(InventoryUser).filter(
                    InventoryUser.asset_id.in_(all_org_asset_ids),
                    InventoryUser.username == logon.username,
                    or_(
                        InventoryUser.is_domain_admin == True,
                        InventoryUser.is_local_admin == True,
                        InventoryUser.is_privileged == True,
                    ),
                ).first()
                if not user:
                    continue
                unid = _add_user_node(user)
                add_edge(f"e-logon-{cur_id}-{unid}",
                         f"asset-{cur_id}", unid, "credential_exposure", "Logged On")

            # 3. Admin accounts declared on this asset
            for user in db.query(InventoryUser).filter(
                InventoryUser.asset_id == cur_id,
                or_(
                    InventoryUser.is_domain_admin == True,
                    InventoryUser.is_local_admin == True,
                ),
            ).all():
                unid = _add_user_node(user)
                etype = "domain_admin" if user.is_domain_admin else "local_admin"
                elabel = "Domain Admin" if user.is_domain_admin else "Local Admin"
                add_edge(f"e-admin-{unid}-{cur_id}",
                         unid, f"asset-{cur_id}", etype, elabel)

                # Domain admins expose all other assets they control (1 hop)
                if user.is_domain_admin and hop == 0:
                    for other in db.query(InventoryUser).filter(
                        InventoryUser.asset_id.in_(all_org_asset_ids),
                        InventoryUser.username == user.username,
                        InventoryUser.asset_id != cur_id,
                        InventoryUser.is_domain_admin == True,
                    ).limit(5).all():
                        other_asset = asset_map.get(other.asset_id)
                        if not other_asset:
                            continue
                        add_node(f"asset-{other.asset_id}", "asset",
                                 _asset_node_data(other_asset))
                        add_edge(f"e-admin-{unid}-{other.asset_id}",
                                 unid, f"asset-{other.asset_id}",
                                 "domain_admin", "Domain Admin")
                        if other.asset_id not in visited_assets:
                            visited_assets.add(other.asset_id)
                            next_queue.append(other.asset_id)

            # 4. AD group memberships → DC access
            cur_os_lower = (cur.os or "").lower()
            is_linux = any(h in cur_os_lower for h in LINUX_OS_HINTS)
            for user in db.query(InventoryUser).filter(
                InventoryUser.asset_id == cur_id,
            ).all():
                for group_entry in (user.member_of or []):
                    cn = _cn_from_dn(group_entry) if "=" in group_entry else group_entry.strip()
                    if "\\" in cn:
                        cn = cn.split("\\", 1)[1]
                    cn_lower = cn.lower().strip()
                    if cn_lower not in AD_ACCESS_GROUPS:
                        continue
                    etype, elabel = AD_ACCESS_GROUPS[cn_lower]
                    unid = _add_user_node(user)
                    add_edge(f"e-account-{unid}-{cur_id}",
                             f"asset-{cur_id}", unid,
                             "credential_exposure", "Has Account")
                    # Create edges to all DC assets
                    for dc_id in dc_asset_ids:
                        dc_asset = asset_map.get(dc_id)
                        if not dc_asset or dc_id == cur_id:
                            continue
                        add_node(f"asset-{dc_id}", "asset", _asset_node_data(dc_asset))
                        add_edge(
                            f"e-grp-dc-{unid}-{dc_id}-{cn_lower.replace(' ', '_')}",
                            unid, f"asset-{dc_id}",
                            etype, f"{elabel} → DC",
                        )
                        if dc_id not in visited_assets:
                            visited_assets.add(dc_id)
                            next_queue.append(dc_id)

            # 5. Local / Linux group membership → access to this asset
            local_groups_map = LINUX_ACCESS_GROUPS if is_linux else LOCAL_ACCESS_GROUPS
            for group in db.query(InventoryGroup).filter(
                InventoryGroup.asset_id == cur_id,
            ).all():
                group_lower = (group.group_name or "").lower().strip()
                if group_lower not in local_groups_map:
                    continue
                etype, elabel = local_groups_map[group_lower]
                for member_raw in (group.members or []):
                    cn = _cn_from_dn(member_raw) if "=" in member_raw else member_raw.strip()
                    if "\\" in cn:
                        cn = cn.split("\\", 1)[1]
                    if not cn or cn.endswith("$"):
                        continue  # skip computer accounts
                    for mu in users_by_name_idx.get(cn.lower(), []):
                        munid = _add_user_node(mu)
                        add_edge(
                            f"e-grp-{munid}-{cur_id}-{etype}",
                            munid, f"asset-{cur_id}",
                            etype, elabel,
                        )

        queue = next_queue

    # ── 5b. Follow infrastructure relationships (DNS → cloud workload) ──
    # Phase 2: filter out the unified-edge families already rendered as
    # network_connection (step 1) or auth/coerce edges so they don't
    # surface twice in the graph view.
    _INFRA_EXCLUDED = {
        "asset_to_asset_port", "asset_to_asset_auth",
        "asset_to_asset_coerce", "user_to_asset",
        "internet_to_asset", "cve_on_asset",
        "connects_to", "shares_credential_with",
        "runs_as_principal", "trusts_domain", "member_of_domain",
    }
    infra_visited = set()
    try:
        for aid in list(visited_assets):
            for rel in db.query(AssetRelationship).filter(
                AssetRelationship.source_asset_id == aid,
                ~AssetRelationship.relationship_type.in_(_INFRA_EXCLUDED),
            ).all():
                tgt_id = rel.target_asset_id
                if tgt_id in visited_assets or tgt_id in infra_visited:
                    continue
                tgt = asset_map.get(tgt_id) or db.query(Asset).filter(Asset.id == tgt_id).first()
                if not tgt:
                    continue
                asset_map[tgt_id] = tgt
                if tgt.ip:
                    ip_to_asset_id.setdefault(tgt.ip, tgt_id)
                add_node(f"asset-{tgt_id}", "asset", _asset_node_data(tgt))
                label = rel.relationship_type.replace("_", " ").title()
                detail = rel.source_detail or {}
                if detail.get("connector"):
                    label += f" ({detail['connector']})"
                add_edge(
                    f"e-infra-{rel.id}",
                    f"asset-{aid}", f"asset-{tgt_id}",
                    rel.relationship_type, label,
                )
                infra_visited.add(tgt_id)
                visited_assets.add(tgt_id)
    except Exception:
        pass  # table may not exist yet before restart

    # ── 5c. Firewall policy reachability (lateral movement via NGFW rules) ──
    _FW_RISKY_PORTS = {22, 23, 445, 3389, 5985, 5986}
    firewall_lateral_paths = []
    try:
        import ipaddress as _ipamod
        fw_policies = (
            db.query(FirewallPolicy)
            .filter(
                FirewallPolicy.org_id.in_(org_ids),
                FirewallPolicy.enabled.is_(True),
                FirewallPolicy.action.in_(["allow", "accept", "permit"]),
            )
            .all()
        )
        def _fw_ip_in_cidr(ip, cidr):
            if cidr.strip().lower() == "any":
                return True
            try:
                return _ipamod.ip_address(ip) in _ipamod.ip_network(cidr, strict=False)
            except (ValueError, TypeError):
                return False

        if fw_policies and asset.ip:
            for policy in fw_policies:
                in_src = any(_fw_ip_in_cidr(asset.ip, c) for c in (policy.src_cidrs or []))
                if not in_src:
                    continue
                ports = set()
                for svc in (policy.services or []):
                    if isinstance(svc, dict) and isinstance(svc.get("port"), int):
                        ports.add(svc["port"])
                risky = ports & _FW_RISKY_PORTS
                for dst_cidr in (policy.dst_cidrs or []):
                    for other_a in all_assets:
                        if not other_a.ip or other_a.id == asset_id:
                            continue
                        if not _fw_ip_in_cidr(other_a.ip, dst_cidr):
                            continue
                        other_nid = f"asset-{other_a.id}"
                        add_node(other_nid, "asset", _asset_node_data(other_a))
                        port_label = ",".join(str(p) for p in sorted(risky)[:3]) if risky else "any"
                        add_edge(
                            f"e-fw-{policy.id}-{other_a.id}",
                            start_nid, other_nid,
                            "firewall_allow", f"FW {policy.vendor}: :{port_label}",
                        )
                        if other_a.id not in visited_assets:
                            visited_assets.add(other_a.id)
                        if risky:
                            firewall_lateral_paths.append({
                                "rule_id": policy.rule_id,
                                "vendor": policy.vendor,
                                "dst_ip": other_a.ip,
                                "ports": sorted(risky),
                            })
    except Exception:
        pass  # firewall_policies table may not exist yet

    # ── 6. Scheduled tasks running as privileged users (persistence paths) ──
    for nid, n in list(nodes.items()):
        if n["type"] != "asset":
            continue
        aid = int(nid.split("-")[1])
        for task in db.query(InventoryScheduledTask).filter(
            InventoryScheduledTask.asset_id == aid,
        ).all():
            run_user = (task.run_as_user or "").strip()
            if not run_user:
                continue
            for mu in users_by_name_idx.get(run_user.lower(), []):
                if mu.is_domain_admin or mu.is_local_admin or mu.is_privileged:
                    munid = _add_user_node(mu)
                    add_edge(
                        f"e-schtask-{task.id}-{munid}-{aid}",
                        munid, nid,
                        "scheduled_task", f"Task: {(task.task_uri or '?').rsplit(chr(92), 1)[-1][:20]}",
                    )
                    break

    # ── 7. Domain trusts (cross-domain attack paths from DC assets) ──
    for nid, n in list(nodes.items()):
        if n["type"] != "asset" or not n["data"].get("is_dc"):
            continue
        aid = int(nid.split("-")[1])
        from models.models import InventoryDomainTrust
        for trust in db.query(InventoryDomainTrust).filter(
            InventoryDomainTrust.asset_id == aid,
        ).all():
            trusted_name = (trust.trusted_domain or "").lower()
            flat = (trust.flat_name or "").lower()
            for other_a in all_assets:
                other_fqdn = (other_a.fqdn or "").lower()
                other_host = (other_a.hostname or "").lower()
                if not (trusted_name and (trusted_name in other_fqdn or flat == other_host)):
                    continue
                if other_a.id == aid:
                    continue
                other_nid = f"asset-{other_a.id}"
                add_node(other_nid, "asset", _asset_node_data(other_a))
                direction = trust.trust_direction or "bidirectional"
                add_edge(
                    f"e-trust-{trust.id}",
                    nid, other_nid,
                    "domain_trust", f"Trust ({direction[:5]})",
                )
                if other_a.id not in visited_assets:
                    visited_assets.add(other_a.id)

    # ── 8. Weak / exposed credentials on visited assets ──
    for nid, n in list(nodes.items()):
        if n["type"] != "asset":
            continue
        aid = int(nid.split("-")[1])
        for cred in db.query(InventoryCredential).filter(
            InventoryCredential.asset_id == aid,
        ).limit(5).all():
            proto = (cred.protocol or "unknown").upper()
            add_edge(
                f"e-cred-{cred.id}",
                nid, nid,
                "weak_credential", f"{cred.credential_type or 'Weak'} ({proto}:{cred.port or '?'})",
            )

    # ── 9. Exploitable findings / CVEs on ALL visited assets ──
    visited_asset_ids = [int(n["id"].split("-")[1]) for n in nodes.values() if n["type"] == "asset"]
    if finding_id:
        scoped_finding = db.query(Finding).filter(Finding.id == finding_id).first()
        exploit_findings = [scoped_finding] if scoped_finding else []
    else:
        exploit_findings = db.query(Finding).filter(
            Finding.asset_id.in_(visited_asset_ids),
            Finding.severity >= 3,
            Finding.exploit_available == True,
        ).limit(20).all()
        exploit_ids = {f.id for f in exploit_findings}

        internet_facing_ids = [
            aid for aid in visited_asset_ids
            if asset_map.get(aid) and asset_map[aid].is_internet_facing
        ]
        if internet_facing_ids and exploit_ids:
            inet_findings = db.query(Finding).filter(
                Finding.asset_id.in_(internet_facing_ids),
                Finding.severity >= 3,
                Finding.id.notin_(exploit_ids),
                or_(
                    Finding.cvss3_vector.like("%AV:N%"),
                    Finding.cvss2_vector.like("%AV:N%"),
                ),
            ).limit(10).all()
            exploit_findings.extend(inet_findings)
        elif internet_facing_ids:
            inet_findings = db.query(Finding).filter(
                Finding.asset_id.in_(internet_facing_ids),
                Finding.severity >= 3,
                or_(
                    Finding.cvss3_vector.like("%AV:N%"),
                    Finding.cvss2_vector.like("%AV:N%"),
                ),
            ).limit(10).all()
            exploit_findings.extend(inet_findings)

    for f in exploit_findings:
        cve_list = (f.cves or [])[:3]
        cve_str = ", ".join(cve_list) if cve_list else f.plugin_name or f"Plugin {f.plugin_id}"
        sev_label = "Critical" if f.severity >= 4 else "High"
        f_asset = asset_map.get(f.asset_id)
        is_inet = f_asset.is_internet_facing if f_asset else False
        vnid = f"vuln-{f.id}"
        add_node(vnid, "vuln", {
            "label": cve_str,
            "severity": sev_label.lower(),
            "severity_num": f.severity,
            "plugin_name": f.plugin_name,
            "plugin_id": f.plugin_id,
            "cves": f.cves or [],
            "is_kev": bool(f.is_kev),
            "cvss": f.cvss3_score or f.cvss2_score,
            "exploit_available": bool(f.exploit_available),
            "internet_reachable": is_inet,
            "finding_id": f.id,
        })
        edge_type = "internet_vulnerability" if is_inet and not f.exploit_available else "vulnerability"
        add_edge(
            f"e-vuln-{f.id}-{f.asset_id}",
            vnid, f"asset-{f.asset_id}",
            edge_type, cve_str,
        )

    # ── 10. Listening risky services on visited assets ──
    listening_services = {}
    for nid, n in list(nodes.items()):
        if n["type"] != "asset":
            continue
        aid = int(nid.split("-")[1])
        for conn in db.query(InventoryNetConn).filter(
            InventoryNetConn.asset_id == aid,
            InventoryNetConn.state.in_(["LISTEN", "LISTENING"]),
        ).all():
            port = conn.local_port
            if port and port in RISKY_PORTS:
                listening_services.setdefault(aid, []).append(
                    (port, RISKY_PORTS[port])
                )

    # ── 11. Missing critical patches on focal asset ──
    missing_patches = db.query(InventoryPatch).filter(
        InventoryPatch.asset_id == asset_id,
    ).all()
    critical_patches = [p for p in missing_patches if (p.vuln_count or 0) >= 5]

    # ── 12. Exposed database instances on visited assets ──
    db_instances = {}
    for nid, n in list(nodes.items()):
        if n["type"] != "asset":
            continue
        aid = int(nid.split("-")[1])
        for dbi in db.query(InventoryDatabaseInstance).filter(
            InventoryDatabaseInstance.asset_id == aid,
            InventoryDatabaseInstance.is_running == True,
        ).all():
            db_instances.setdefault(aid, []).append(dbi)

    # ── 13. Writeable shares on visited assets (explicit edges) ──
    for nid, n in list(nodes.items()):
        if n["type"] != "asset":
            continue
        aid = int(nid.split("-")[1])
        for share in db.query(InventoryShare).filter(
            InventoryShare.asset_id == aid,
            InventoryShare.is_writeable == True,
        ).limit(3).all():
            add_edge(
                f"e-share-{share.id}",
                nid, nid,
                "writeable_share", f"Share: {share.share_name or '?'}",
            )

    # ── 14. Expired / weak certificates on focal asset ──
    expired_certs = db.query(InventoryCertificate).filter(
        InventoryCertificate.asset_id == asset_id,
        InventoryCertificate.is_expired == True,
    ).all()

    # Compute blast radius score 0–10
    reachable_asset_ids = {
        int(n["id"].split("-")[1])
        for n in nodes.values()
        if n["type"] == "asset" and n["id"] != start_nid
    }
    internet_reachable = "internet" in nodes
    reachable_count = len(reachable_asset_ids) + (1 if internet_reachable else 0)
    user_nodes = [n for n in nodes.values() if n["type"] == "user"]
    da_exposed = any(u["data"].get("is_domain_admin") for u in user_nodes)
    la_exposed = any(u["data"].get("is_local_admin") for u in user_nodes)
    dc_reachable = any(
        n["data"].get("is_dc")
        for n in nodes.values()
        if n["type"] == "asset" and n["id"] != start_nid
    )
    kerb_exposed = any(u["data"].get("kerberoastable") for u in user_nodes)

    group_access_edges = [
        e for e in edges
        if e["type"] in ("rdp_access", "dcom_access", "power_user",
                         "winrm_access", "ssh_access", "sudo_access", "docker_access")
    ]
    group_access_exposed = len(group_access_edges) > 0

    has_weak_creds = any(e["type"] == "weak_credential" for e in edges)
    has_exploitable = len(exploit_findings) > 0
    has_trust_paths = any(e["type"] == "domain_trust" for e in edges)
    has_schtask_priv = any(e["type"] == "scheduled_task" for e in edges)
    has_missing_patches = len(critical_patches) > 0
    has_exposed_dbs = sum(len(v) for v in db_instances.values()) > 0
    has_expired_certs = len(expired_certs) > 0
    is_internet_facing = asset.is_internet_facing or False
    has_cloud_workload = len(infra_visited) > 0
    inet_vuln_count = sum(1 for e in edges if e["type"] == "internet_vulnerability")

    score = min(reachable_count * 1.5, 5.0)
    if dc_reachable:              score += 3.0
    if da_exposed:                score += 2.0
    elif la_exposed:              score += 1.0
    if kerb_exposed:              score += 1.0
    if group_access_exposed:      score += 0.5
    if has_weak_creds:            score += 1.5
    if has_exploitable:           score += 1.0
    if has_trust_paths:           score += 0.5
    if has_schtask_priv:          score += 0.5
    if has_missing_patches:       score += 0.5
    if has_exposed_dbs:           score += 0.5
    if has_expired_certs:         score += 0.3
    if is_internet_facing:        score += 1.5
    if is_internet_facing and inet_vuln_count:
        score += min(inet_vuln_count * 0.5, 2.0)
    if has_cloud_workload:        score += 0.5
    has_fw_lateral = len(firewall_lateral_paths) > 0
    if has_fw_lateral:            score += min(len(firewall_lateral_paths) * 0.5, 2.0)
    score = min(round(score, 1), 10.0)

    vectors = []
    for u in user_nodes:
        d = u["data"]
        if d.get("is_domain_admin"):
            vectors.append({"type": "domain_admin",
                            "label": f"Domain Admin credential on host: {d['username']}",
                            "severity": "critical"})
        elif d.get("kerberoastable"):
            vectors.append({"type": "kerberoastable",
                            "label": f"Kerberoastable account: {d['username']}",
                            "severity": "high"})
        elif d.get("is_local_admin"):
            vectors.append({"type": "local_admin",
                            "label": f"Local Admin account: {d['username']}",
                            "severity": "high"})
    for e in edges:
        if e["type"] == "credential_exposure":
            un = nodes.get(e["target"])
            if un:
                vectors.append({
                    "type": "credential_exposure",
                    "label": f"Credential exposure: {un['data'].get('username','?')} logged on",
                    "severity": "high" if un["data"].get("is_domain_admin") else "medium",
                })
        elif e["type"] == "network_connection" and e["source"] == start_nid:
            tid = int(e["target"].split("-")[1])
            ta = asset_map.get(tid)
            vectors.append({
                "type": "network_connection",
                "label": f"Established → {ta.ip or ta.hostname if ta else e['target']} {e['data']['label']}",
                "severity": "low",
            })
        elif e["type"] in GROUP_ACCESS_LABELS:
            un = nodes.get(e["source"])
            ta = nodes.get(e["target"])
            if un and ta:
                alabel, aseverity = GROUP_ACCESS_LABELS[e["type"]]
                vectors.append({
                    "type": e["type"],
                    "label": f"{alabel}: {un['data'].get('username', '?')} → {ta['data'].get('label', '?')}",
                    "severity": aseverity,
                })

    # New vector categories
    for f in exploit_findings:
        cve_str = ", ".join((f.cves or [])[:3]) or f.plugin_name or f"Plugin {f.plugin_id}"
        vectors.append({
            "type": "vuln_exploit",
            "label": f"Exploitable: {cve_str}" + (" [KEV]" if f.is_kev else ""),
            "severity": "critical" if f.severity >= 4 else "high",
        })
    for e in edges:
        if e["type"] == "weak_credential":
            vectors.append({
                "type": "weak_credential",
                "label": f"Weak credential: {e['data']['label']}",
                "severity": "critical",
            })
        elif e["type"] == "scheduled_task":
            un = nodes.get(e["source"])
            vectors.append({
                "type": "scheduled_task",
                "label": f"Privileged task: {un['data'].get('username', '?')} — {e['data']['label']}",
                "severity": "high",
            })
        elif e["type"] == "domain_trust":
            ta = nodes.get(e["target"])
            vectors.append({
                "type": "domain_trust",
                "label": f"Domain trust → {ta['data'].get('label', '?')}",
                "severity": "medium",
            })
        elif e["type"] == "writeable_share":
            vectors.append({
                "type": "writeable_share",
                "label": f"Writeable share: {e['data']['label']}",
                "severity": "medium",
            })
    for aid, svcs in listening_services.items():
        a = asset_map.get(aid)
        lbl = a.ip or a.hostname if a else str(aid)
        svc_names = ", ".join(s[1] for s in svcs[:4])
        vectors.append({
            "type": "service_exposure",
            "label": f"Risky services on {lbl}: {svc_names}",
            "severity": "medium",
        })
    for aid, dbis in db_instances.items():
        a = asset_map.get(aid)
        lbl = a.ip or a.hostname if a else str(aid)
        db_names = ", ".join(f"{d.db_type}:{d.port}" for d in dbis[:3])
        vectors.append({
            "type": "db_exposure",
            "label": f"Database on {lbl}: {db_names}",
            "severity": "high",
        })
    if critical_patches:
        total_cves = sum(p.vuln_count or 0 for p in critical_patches)
        vectors.append({
            "type": "missing_patch",
            "label": f"Missing {len(critical_patches)} critical patches ({total_cves} CVEs)",
            "severity": "high",
        })
    if expired_certs:
        vectors.append({
            "type": "expired_cert",
            "label": f"{len(expired_certs)} expired certificate(s)",
            "severity": "medium",
        })
    if is_internet_facing:
        vectors.insert(0, {
            "type": "internet_facing",
            "label": f"Internet-facing — {inet_label.lower()}" if port_str else "Internet-facing asset — externally reachable",
            "severity": "critical",
        })

    # ── Internet-exploitable attack vectors ──
    for f in exploit_findings:
        f_asset = asset_map.get(f.asset_id)
        if not f_asset or not f_asset.is_internet_facing:
            continue
        cve_list = (f.cves or [])[:2]
        cve_str = ", ".join(cve_list) if cve_list else f.plugin_name or f"Plugin {f.plugin_id}"
        kev_tag = " [KEV]" if f.is_kev else ""
        vectors.append({
            "type": "internet_exploitable",
            "label": f"Internet-reachable: {cve_str}{kev_tag} on {f_asset.hostname or f_asset.ip}",
            "severity": "critical" if f.severity >= 4 or f.is_kev else "high",
        })

    # ── Cloud workload exposure vectors ──
    for cloud_id in infra_visited:
        cloud = asset_map.get(cloud_id)
        if not cloud:
            continue
        identity = cloud.asset_identity or {}
        canonical = identity.get("instance_id", cloud.hostname or "")
        cloud_vulns = [f for f in exploit_findings if f.asset_id == cloud_id]
        if cloud_vulns:
            vectors.append({
                "type": "cloud_workload_compromise",
                "label": f"Cloud workload compromised: {canonical} — {len(cloud_vulns)} exploitable finding(s)",
                "severity": "critical",
            })
        else:
            vectors.append({
                "type": "cloud_workload_exposure",
                "label": f"Resolves to cloud workload: {canonical}",
                "severity": "medium",
            })

    # ── Firewall lateral movement vectors ──
    for fwp in firewall_lateral_paths[:10]:
        port_str_fw = ", ".join(str(p) for p in fwp["ports"][:3])
        vectors.append({
            "type": "firewall_lateral_movement",
            "label": f"FW allow ({fwp['vendor']}): rule {fwp['rule_id']} → {fwp['dst_ip']} on port {port_str_fw}",
            "severity": "high",
        })

    return {
        "asset_id": asset_id,
        "finding_id": finding_id,
        "score": score,
        "reachable_assets": reachable_count,
        "privileged_users": len(user_nodes),
        "da_exposed": da_exposed,
        "dc_reachable": dc_reachable,
        "kerberoastable_exposed": kerb_exposed,
        "group_access_exposed": group_access_exposed,
        "has_weak_creds": has_weak_creds,
        "has_exploitable": has_exploitable,
        "has_exposed_dbs": has_exposed_dbs,
        "has_cloud_workload": has_cloud_workload,
        "has_fw_lateral": has_fw_lateral,
        "internet_vuln_count": inet_vuln_count,
        "firewall_lateral_paths": firewall_lateral_paths[:10],
        "vectors": vectors[:30],
        "nodes": list(nodes.values()),
        "edges": edges,
    }

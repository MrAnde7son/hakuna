"""
Export endpoints — CSV & JSON download for assets, findings, and inventory tables.
"""
import csv
import io
import json
from typing import Optional, List, Dict
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from core.database import get_db
from models.models import (
    Asset, Finding, Scan,
    InventoryUser, InventoryGroup, InventoryService,
    InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
    InventoryShare, InventorySoftware, InventorySecurityControl,
    InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
    InventoryAITool, InventoryProcess,
)

router = APIRouter(prefix="/api/export", tags=["export"])

SEVERITY_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


# ── helpers ──────────────────────────────────────────────

def _csv_response(rows: List[Dict], filename: str) -> StreamingResponse:
    """Build a StreamingResponse from a list of dicts → CSV."""
    if not rows:
        buf = io.StringIO("No data\n")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    fieldnames = list(rows[0].keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        # Flatten lists/dicts to strings for CSV
        flat = {}
        for k, v in row.items():
            if isinstance(v, (list, dict)):
                flat[k] = json.dumps(v)
            elif isinstance(v, bool):
                flat[k] = str(v)
            elif v is None:
                flat[k] = ""
            else:
                flat[k] = v
        writer.writerow(flat)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json_response(rows: List[Dict], filename: str) -> StreamingResponse:
    data = json.dumps(rows, indent=2, default=str)
    return StreamingResponse(
        iter([data]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _format_response(rows: List[Dict], base_name: str, fmt: str) -> StreamingResponse:
    if fmt == "json":
        return _json_response(rows, f"{base_name}.json")
    return _csv_response(rows, f"{base_name}.csv")


def _asset_lookup(db: Session, asset_ids: set) -> dict:
    if not asset_ids:
        return {}
    assets = db.query(Asset.id, Asset.hostname, Asset.ip, Asset.environment_tag).filter(Asset.id.in_(asset_ids)).all()
    return {a.id: {"hostname": a.hostname, "ip": a.ip, "environment_tag": a.environment_tag} for a in assets}


def _ts(prefix: str) -> str:
    return f"{prefix}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"


# ── Assets ───────────────────────────────────────────────

@router.get("/assets")
def export_assets(
    scan_id: Optional[int] = None,
    environment: Optional[str] = None,
    search: Optional[str] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if scan_id:
        q = q.filter(Asset.scan_id == scan_id)
    if environment:
        q = q.filter(Asset.environment_tag == environment)
    if search:
        p = f"%{search}%"
        q = q.filter(or_(Asset.hostname.ilike(p), Asset.ip.ilike(p), Asset.fqdn.ilike(p), Asset.os.ilike(p)))
    q = q.order_by(desc(Asset.risk_score))
    assets = q.all()
    rows = [
        {
            "IP": a.ip,
            "Hostname": a.hostname,
            "FQDN": a.fqdn,
            "OS": a.os,
            "NetBIOS": a.netbios_name,
            "MAC": a.mac_address,
            "Environment": a.environment_tag,
            "Criticality": a.criticality,
            "Risk Score": round(a.risk_score or 0, 2),
            "Critical": a.critical_count,
            "High": a.high_count,
            "Medium": a.medium_count,
            "Low": a.low_count,
            "Info": a.info_count,
            "Internet Facing": a.is_internet_facing or False,
            "Primary User": a.inferred_primary_user,
            "Team": a.inferred_team,
        }
        for a in assets
    ]
    return _format_response(rows, _ts("assets"), fmt)


# ── Findings ─────────────────────────────────────────────

@router.get("/findings")
def export_findings(
    request: Request,
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    severity: Optional[int] = None,
    plugin_family: Optional[str] = None,
    has_exploit: Optional[bool] = None,
    is_kev: Optional[bool] = None,
    effort_level: Optional[str] = None,
    search: Optional[str] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id)
    if severity is not None:
        q = q.filter(Finding.severity == severity)
    if plugin_family:
        q = q.filter(Finding.plugin_family == plugin_family)
    if has_exploit is not None:
        q = q.filter(Finding.exploit_available == has_exploit)
    if is_kev is not None:
        q = q.filter(Finding.is_kev == is_kev)
    if effort_level:
        q = q.filter(Finding.effort_level == effort_level)
    if search:
        q = q.filter(
            Finding.plugin_name.ilike(f"%{search}%") |
            Finding.synopsis.ilike(f"%{search}%") |
            Finding.plugin_id.ilike(f"%{search}%")
        )
    ws = request.query_params.get("workflow_status")
    if ws:
        if ws == "excepted":
            q = q.filter(Finding.workflow_status.in_(["accepted_risk", "false_positive", "compensating_control"]))
        else:
            q = q.filter(Finding.workflow_status == ws)
    q = q.order_by(desc(Finding.priority_score))
    findings = q.all()

    # Batch-fetch asset info
    asset_ids = {f.asset_id for f in findings}
    amap = _asset_lookup(db, asset_ids)

    rows = [
        {
            "Plugin ID": f.plugin_id,
            "Plugin Name": f.plugin_name,
            "Plugin Family": f.plugin_family,
            "Severity": SEVERITY_MAP.get(f.severity, str(f.severity)),
            "CVSS v3": f.cvss3_score,
            "VPR": f.vpr_score,
            "EPSS": f.epss_score,
            "Priority Score": round(f.priority_score or 0, 2),
            "CVEs": ", ".join(f.cves or []),
            "Asset IP": (amap.get(f.asset_id) or {}).get("ip"),
            "Asset Hostname": (amap.get(f.asset_id) or {}).get("hostname"),
            "Port": f.port,
            "Protocol": f.protocol,
            "Exploit Available": f.exploit_available,
            "KEV": f.is_kev or False,
            "Ransomware Linked": f.ransomware_linked or False,
            "Effort": f.effort_level,
            "Owner Suggestion": f.owner_suggestion,
            "Workflow Status": f.workflow_status or "open",
            "SLA Status": f.sla_status or "n/a",
            "Synopsis": f.synopsis,
            "Solution": f.solution,
        }
        for f in findings
    ]
    return _format_response(rows, _ts("findings"), fmt)


# ── Inventory ────────────────────────────────────────────
# Generic helper for simple inventory tables

def _inv_export(
    db: Session,
    model,
    scan_id: Optional[int],
    asset_id: Optional[int],
    row_fn,
    name: str,
    fmt: str,
):
    q = db.query(model)
    if scan_id:
        q = q.filter(model.scan_id == scan_id)
    if asset_id:
        q = q.filter(model.asset_id == asset_id)
    items = q.all()
    amap = _asset_lookup(db, {i.asset_id for i in items})
    rows = [row_fn(i, amap) for i in items]
    return _format_response(rows, _ts(name), fmt)


def _al(info):
    """Asset label from lookup info."""
    if not info:
        return ""
    return info.get("hostname") or info.get("ip") or ""


@router.get("/inventory/users")
def export_inv_users(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(u, amap):
        info = amap.get(u.asset_id)
        return {
            "Username": u.username,
            "Domain": u.domain,
            "User Type": u.user_type,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
            "SID": u.sid,
            "Local Admin": u.is_local_admin,
            "Domain Admin": u.is_domain_admin,
            "Privileged": u.is_privileged,
            "Disabled": u.is_disabled,
            "Password Never Expires": u.password_never_expires,
            "SPNs": ", ".join(u.spns or []),
            "Member Of": ", ".join(u.member_of or []),
        }
    return _inv_export(db, InventoryUser, scan_id, asset_id, row, "inventory_users", fmt)


@router.get("/inventory/groups")
def export_inv_groups(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(g, amap):
        info = amap.get(g.asset_id)
        return {
            "Group Name": g.group_name,
            "Domain": g.domain,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
            "SID": g.sid,
            "Privileged": g.is_privileged,
            "Members": ", ".join(g.members or []),
            "Description": g.description,
        }
    return _inv_export(db, InventoryGroup, scan_id, asset_id, row, "inventory_groups", fmt)


@router.get("/inventory/services")
def export_inv_services(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(s, amap):
        info = amap.get(s.asset_id)
        return {
            "Service Name": s.service_name,
            "Display Name": s.display_name,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
            "Running": s.is_running,
        }
    return _inv_export(db, InventoryService, scan_id, asset_id, row, "inventory_services", fmt)


@router.get("/inventory/netconns")
def export_inv_netconns(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(n, amap):
        info = amap.get(n.asset_id)
        return {
            "Protocol": n.proto,
            "State": n.state,
            "Local Address": n.local_addr,
            "Local Port": n.local_port,
            "Remote Address": n.remote_addr,
            "Remote Port": n.remote_port,
            "PID": n.pid,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryNetConn, scan_id, asset_id, row, "inventory_netconns", fmt)


@router.get("/inventory/scheduled-tasks")
def export_inv_scheduled_tasks(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(t, amap):
        info = amap.get(t.asset_id)
        return {
            "Task URI": t.task_uri,
            "Author": t.author,
            "Command": t.command,
            "Arguments": t.arguments,
            "Run As": t.run_as_sid,
            "Trigger": t.trigger_type,
            "Enabled": getattr(t, "is_enabled", None),
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryScheduledTask, scan_id, asset_id, row, "inventory_scheduled_tasks", fmt)


@router.get("/inventory/patches")
def export_inv_patches(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(p, amap):
        info = amap.get(p.asset_id)
        return {
            "KB ID": p.kb_id,
            "Vuln Count": p.vuln_count,
            "Description": p.description,
            "CVEs": ", ".join(p.cves or []),
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryPatch, scan_id, asset_id, row, "inventory_patches", fmt)


@router.get("/inventory/logged-on")
def export_inv_logged_on(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(l, amap):
        info = amap.get(l.asset_id)
        return {
            "Username": l.username,
            "Domain": l.domain,
            "SID": l.sid,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryLoggedOn, scan_id, asset_id, row, "inventory_logged_on", fmt)


@router.get("/inventory/shares")
def export_inv_shares(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(s, amap):
        info = amap.get(s.asset_id)
        return {
            "Share Name": s.share_name,
            "Path": s.path,
            "Type": s.share_type,
            "Comment": s.comment,
            "Writeable": s.is_writeable,
            "Default Share": s.is_default_share,
            "ACL": json.dumps(s.acl or []),
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryShare, scan_id, asset_id, row, "inventory_shares", fmt)


@router.get("/inventory/software")
def export_inv_software(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(s, amap):
        info = amap.get(s.asset_id)
        return {
            "Name": s.name,
            "Version": s.version,
            "Vendor": s.vendor,
            "Install Date": s.installed_on,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventorySoftware, scan_id, asset_id, row, "inventory_software", fmt)


@router.get("/inventory/security-controls")
def export_inv_security_controls(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(c, amap):
        info = amap.get(c.asset_id)
        return {
            "Product": c.product_name,
            "Type": c.control_type,
            "Enabled": c.is_enabled,
            "Up to Date": c.is_up_to_date,
            "Version": c.version,
            "Signature Date": c.signature_date,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventorySecurityControl, scan_id, asset_id, row, "inventory_security_controls", fmt)


@router.get("/inventory/computers")
def export_inv_computers(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(c, amap):
        info = amap.get(c.asset_id)
        return {
            "Computer Name": c.computer_name,
            "Domain": c.domain,
            "DN": c.dn,
            "OS": c.os,
            "Domain Controller": c.is_domain_controller,
            "Disabled": c.is_disabled,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryComputer, scan_id, asset_id, row, "inventory_computers", fmt)


@router.get("/inventory/password-policies")
def export_inv_password_policies(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(p, amap):
        info = amap.get(p.asset_id)
        return {
            "Policy Name": p.policy_name,
            "Min Length": p.min_length,
            "Max Age (days)": p.max_age_days,
            "Min Age (days)": p.min_age_days,
            "History Count": p.history_count,
            "Lockout Threshold": p.lockout_threshold,
            "Complexity Enabled": p.complexity_enabled,
            "Is Weak": p.is_weak,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryPasswordPolicy, scan_id, asset_id, row, "inventory_password_policies", fmt)


@router.get("/inventory/certificates")
def export_inv_certificates(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(c, amap):
        info = amap.get(c.asset_id)
        return {
            "Subject CN": c.subject_cn,
            "Issuer CN": c.issuer_cn,
            "Serial": c.serial_number,
            "Not Before": c.not_before,
            "Not After": c.not_after,
            "Key Algorithm": c.key_algorithm,
            "Key Bits": c.key_bits,
            "Signature Algorithm": c.signature_algorithm,
            "Expired": c.is_expired,
            "CA": c.is_ca,
            "Self-Signed": c.is_self_signed,
            "SANs": ", ".join(c.subject_alt_names or []),
            "Port": c.port,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryCertificate, scan_id, asset_id, row, "inventory_certificates", fmt)


@router.get("/inventory/env-vars")
def export_inv_env_vars(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(e, amap):
        info = amap.get(e.asset_id)
        return {
            "Name": e.name,
            "Value": e.value,
            "Sensitive": e.is_sensitive,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryEnvVar, scan_id, asset_id, row, "inventory_env_vars", fmt)


@router.get("/inventory/ai-tools")
def export_inv_ai_tools(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(a, amap):
        info = amap.get(a.asset_id)
        return {
            "Tool Name": a.tool_name,
            "Category": a.category,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryAITool, scan_id, asset_id, row, "inventory_ai_tools", fmt)


@router.get("/inventory/processes")
def export_inv_processes(
    scan_id: Optional[int] = None,
    asset_id: Optional[int] = None,
    fmt: str = Query("csv", regex="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    def row(p, amap):
        info = amap.get(p.asset_id)
        return {
            "PID": p.pid,
            "Name": p.process_name,
            "Parent": p.parent_name,
            "Asset": _al(info),
            "Asset IP": (info or {}).get("ip"),
        }
    return _inv_export(db, InventoryProcess, scan_id, asset_id, row, "inventory_processes", fmt)

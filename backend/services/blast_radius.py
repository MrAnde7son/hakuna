"""
Blast radius / attack path analysis service.

Contains access-group constants, DC resolution logic, and scoring helpers
used by the blast radius route handlers.
"""
from typing import Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from models.models import (
    Asset, Scan, InventoryComputer, InventoryUser, InventoryGroup,
    InventoryNetConn, InventoryLoggedOn, InventoryScheduledTask,
    InventoryPatch, InventoryShare, InventorySecurityControl,
    InventoryCredential, InventoryDatabaseInstance, InventoryCertificate,
    Finding, AssetRelationship, FirewallPolicy,
)
from parsers.inventory_extractor import _cn_from_dn
import services.dedup as dedup_engine


# ── Mapping from asset dedup key fields → (InventoryComputer field, Asset field(s)) ──
_COMPUTER_TO_ASSET_FIELD_MAP = {
    "fqdn":        ("dns_hostname", ["fqdn"]),
    "hostname":    ("computer_name", ["hostname"]),
    "netbios_name": ("computer_name", ["netbios_name"]),
}


def resolve_dc_asset_ids(db: Session, scan_id=None, restrict_to_asset_ids=None) -> set:
    """Return IDs of Asset records that ARE Domain Controllers.

    InventoryComputer.asset_id is the SOURCE asset that ran the AD enumeration plugin,
    not the DC itself.  We resolve the actual DC asset by matching computer name/fqdn
    against Asset fields using the same key fields as the asset dedup config.
    """
    dedup_cfg = dedup_engine.load_config()
    key_fields = dedup_cfg.get("assets", {}).get("key_fields", ["ip", "fqdn"])
    match_pairs = [
        _COMPUTER_TO_ASSET_FIELD_MAP[f]
        for f in key_fields
        if f in _COMPUTER_TO_ASSET_FIELD_MAP
    ]
    if not any(af[0] == "computer_name" for af in match_pairs):
        match_pairs.append(("computer_name", ["hostname", "netbios_name"]))

    q = db.query(
        InventoryComputer.asset_id,
        InventoryComputer.computer_name,
        InventoryComputer.dns_hostname,
    ).filter(InventoryComputer.is_domain_controller == True)
    if scan_id:
        q = q.filter(InventoryComputer.scan_id == scan_id)
    elif restrict_to_asset_ids:
        q = q.filter(InventoryComputer.asset_id.in_(restrict_to_asset_ids))
    dc_computers = q.all()
    if not dc_computers:
        return set()

    comp_field_map = {"dns_hostname": lambda row: row[2], "computer_name": lambda row: row[1]}
    all_conditions = []
    for dc_row in dc_computers:
        for comp_field, asset_fields in match_pairs:
            val = comp_field_map.get(comp_field, lambda r: None)(dc_row)
            if not val:
                continue
            vl = val.lower()
            for af in asset_fields:
                col = getattr(Asset, af, None)
                if col is not None:
                    all_conditions.append(func.lower(col) == vl)

    result = set()
    if not all_conditions:
        return result
    aq = db.query(Asset.id).filter(or_(*all_conditions))
    if restrict_to_asset_ids:
        aq = aq.filter(Asset.id.in_(restrict_to_asset_ids))
    elif scan_id:
        aq = aq.filter(Asset.scan_id == scan_id)
    for row in aq.all():
        result.add(row[0])
    return result


# ── AD domain-level groups → grants access to Domain Controllers ──
AD_ACCESS_GROUPS = {
    "remote desktop users":       ("rdp_access",   "RDP Access"),
    "administrators":             ("local_admin",   "Admin (AD Group)"),
    "distributed com users":      ("dcom_access",   "DCOM Access"),
    "dcom users":                 ("dcom_access",   "DCOM Access"),
    "power users":                ("power_user",    "Power User"),
    "remote management users":    ("winrm_access",  "WinRM Access"),
    "domain admins":              ("domain_admin",  "Domain Admin"),
    "enterprise admins":          ("domain_admin",  "Enterprise Admin"),
}

# Local Windows groups → grants access to that specific machine
LOCAL_ACCESS_GROUPS = {
    "administrators":             ("local_admin",   "Local Admin"),
    "remote desktop users":       ("rdp_access",    "RDP Access"),
    "distributed com users":      ("dcom_access",   "DCOM Access"),
    "dcom users":                 ("dcom_access",   "DCOM Access"),
    "power users":                ("power_user",    "Power User"),
    "remote management users":    ("winrm_access",  "WinRM Access"),
}

# Linux/Unix groups → grants access to that specific machine
LINUX_ACCESS_GROUPS = {
    "sudo":       ("sudo_access",    "Sudo Access"),
    "wheel":      ("sudo_access",    "Sudo Access"),
    "docker":     ("docker_access",  "Docker Access"),
    "sshusers":   ("ssh_access",     "SSH Access"),
    "ssh":        ("ssh_access",     "SSH Access"),
    "adm":        ("admin_read",     "Admin Read"),
}

LINUX_OS_HINTS = ("linux", "unix", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "bsd")

RISKY_PORTS = {
    22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-S",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elastic",
    27017: "MongoDB",
}

GROUP_ACCESS_LABELS = {
    "rdp_access":    ("RDP Access",         "high"),
    "dcom_access":   ("DCOM Access",         "medium"),
    "power_user":    ("Power User Access",   "medium"),
    "winrm_access":  ("WinRM Access",        "high"),
    "ssh_access":    ("SSH Access",          "high"),
    "sudo_access":   ("Sudo Access",         "high"),
    "docker_access": ("Docker Escape Risk",  "high"),
    "admin_read":    ("Admin Read Access",   "medium"),
}

"""Map WMI query results from the relay agent into Inventory* ORM rows.

The relay agent returns one list of dicts per profile (keys match the WMI
property names from agent/wmi_catalog.py). This module is pure mapping — no
network, no broker. It only writes via `db.add_all`; the caller owns the
transaction.

Why keep this separate from services.wmi_scanner: the orchestration code
deals with sessions, credentials, and broker I/O; the mapping logic is easy
to unit-test in isolation and doesn't need any of that.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from models.models import (
    InventoryGroup,
    InventoryPatch,
    InventoryService,
    InventoryShare,
    InventorySoftware,
    InventoryUser,
    Scan,
)

logger = logging.getLogger(__name__)


# Any row written by this module is tagged with this prefix in source_plugin
# so it's trivially distinguishable from scanner-ingested rows (which use
# real Nessus plugin IDs like "20811") in downstream queries.
SOURCE_PREFIX = "hakuna_wmi_"


def build_rows(scan: Scan, asset_id: int, result: dict) -> dict[str, list]:
    """Pure mapping — raw WMI result dict → Inventory* ORM instances by bucket.

    No session, no I/O. Easy to unit-test and reused by the Collector interface
    in services.collectors.wmi_collector.
    """
    buckets: dict[str, list] = {}

    software_rows = _collect_software_rows(scan, asset_id, result)
    if software_rows:
        buckets["software"] = software_rows

    service_rows = _map_services(scan, asset_id, result.get("services") or [])
    if service_rows:
        buckets["services"] = service_rows

    patch_rows = _map_patches(scan, asset_id, result.get("patches") or [])
    if patch_rows:
        buckets["patches"] = patch_rows

    share_rows = _map_shares(scan, asset_id, result.get("shares") or [])
    if share_rows:
        buckets["shares"] = share_rows

    user_rows, group_rows = _map_users_and_groups(
        scan, asset_id,
        result.get("local_users") or [],
        result.get("local_groups") or [],
        result.get("group_membership") or [],
    )
    if user_rows:
        buckets["users"] = user_rows
    if group_rows:
        buckets["groups"] = group_rows

    errors = result.get("_errors") or {}
    if errors:
        logger.warning("WMI result had per-profile errors for asset=%s: %s", asset_id, errors)

    return buckets


def ingest_result(db, scan: Scan, asset_id: int, result: dict) -> dict[str, int]:
    """Write all profiles from one host's WMI result into Inventory* tables.

    Returns per-profile row counts: {"software": 128, "services": 42, ...}.
    Does NOT commit — the caller batches commits across hosts.
    """
    buckets = build_rows(scan, asset_id, result)
    counts: dict[str, int] = {}
    for bucket, rows in buckets.items():
        if rows:
            db.add_all(rows)
            counts[bucket] = len(rows)
    return counts


# ── Software (Win32_Product + StdRegProv Uninstall walk) ─────────────────


def _collect_software_rows(scan: Scan, asset_id: int, result: dict) -> list[InventorySoftware]:
    """Combine Uninstall walk (primary) + Win32_Product (secondary) with dedup.

    Dedup key is (lower(name), lower(version)). Uninstall wins on conflict
    because Win32_Product only sees MSI-installed apps, so it's a subset.
    """
    uninstall = result.get("software_uninstall") or []
    product = result.get("software_product") or []

    seen: set[tuple[str, str]] = set()
    rows: list[InventorySoftware] = []

    for raw in uninstall:
        # wmi_query._walk_uninstall already shapes these with {name, version, vendor, installed_on}
        key = (_norm(raw.get("name")), _norm(raw.get("version")))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        rows.append(InventorySoftware(
            scan_id=scan.id,
            asset_id=asset_id,
            name=raw.get("name"),
            version=raw.get("version"),
            vendor=raw.get("vendor"),
            installed_on=raw.get("installed_on"),
            source_plugin=f"{SOURCE_PREFIX}uninstall",
        ))

    for raw in product:
        name = raw.get("Name")
        key = (_norm(name), _norm(raw.get("Version")))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        rows.append(InventorySoftware(
            scan_id=scan.id,
            asset_id=asset_id,
            name=name,
            version=raw.get("Version"),
            vendor=raw.get("Vendor"),
            installed_on=raw.get("InstallDate"),
            source_plugin=f"{SOURCE_PREFIX}win32_product",
        ))

    return rows


# ── Services (Win32_Service) ─────────────────────────────────────────────


def _map_services(scan: Scan, asset_id: int, rows: list[dict]) -> list[InventoryService]:
    out: list[InventoryService] = []
    seen: set[str] = set()
    for r in rows:
        name = r.get("Name")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(InventoryService(
            scan_id=scan.id,
            asset_id=asset_id,
            service_name=name,
            display_name=r.get("DisplayName"),
            is_running=(r.get("State") == "Running"),
            startup_type=r.get("StartMode"),
            run_as_user=r.get("StartName"),
            source_plugin=f"{SOURCE_PREFIX}services",
        ))
    return out


# ── Patches (Win32_QuickFixEngineering) ──────────────────────────────────


_KB_RE = re.compile(r"KB\d+", re.IGNORECASE)


def _map_patches(scan: Scan, asset_id: int, rows: list[dict]) -> list[InventoryPatch]:
    out: list[InventoryPatch] = []
    seen: set[str] = set()
    for r in rows:
        kb = r.get("HotFixID") or ""
        # Normalize to uppercase "KB\d+" — QFE sometimes returns "kb5034441" or similar.
        m = _KB_RE.search(kb)
        if not m:
            continue
        kb_norm = m.group(0).upper()
        if kb_norm in seen:
            continue
        seen.add(kb_norm)
        out.append(InventoryPatch(
            scan_id=scan.id,
            asset_id=asset_id,
            kb_id=kb_norm,
            description=r.get("Description") or "",
            cves=[],               # QFE doesn't expose CVEs — enriched later by sbom_pipeline
            vuln_count=0,
            source_plugin=f"{SOURCE_PREFIX}patches",
        ))
    return out


# ── Shares (Win32_Share) ─────────────────────────────────────────────────


# Win32_Share.Type encoding — low bits: 0=Disk, 1=Print, 2=Device, 3=IPC.
# High bit 0x80000000 marks special/hidden shares (ADMIN$, C$, IPC$).
_SHARE_TYPE_MAP = {0: "Disk", 1: "Print", 2: "Device", 3: "IPC"}


def _map_shares(scan: Scan, asset_id: int, rows: list[dict]) -> list[InventoryShare]:
    out: list[InventoryShare] = []
    seen: set[str] = set()
    for r in rows:
        name = r.get("Name")
        if not name or name in seen:
            continue
        seen.add(name)
        raw_type = r.get("Type")
        low = (raw_type & 0xFF) if isinstance(raw_type, int) else None
        share_type = _SHARE_TYPE_MAP.get(low, "Unknown") if low is not None else None
        is_default = name.endswith("$") or name in {"ADMIN$", "IPC$"}
        out.append(InventoryShare(
            scan_id=scan.id,
            asset_id=asset_id,
            share_name=name,
            share_type=share_type,
            path=r.get("Path"),
            comment=r.get("Description"),
            is_default_share=is_default,
            source_plugin=f"{SOURCE_PREFIX}shares",
        ))
    return out


# ── Users + Groups + Membership ──────────────────────────────────────────


# Win32_GroupUser refs come back as e.g.:
#   \\HOST\root\cimv2:Win32_Group.Domain="WINHOST",Name="Administrators"
_REF_RE = re.compile(
    r':Win32_(?P<kind>Group|UserAccount|Account)\.Domain="(?P<domain>[^"]*)",Name="(?P<name>[^"]*)"',
    re.IGNORECASE,
)


def _parse_ref(ref: str) -> tuple[str, str, str] | None:
    """Parse a Win32_GroupUser ref string into (kind, domain, name).

    Returns None when the ref doesn't match — we skip those silently
    rather than failing the whole membership map.
    """
    if not ref or not isinstance(ref, str):
        return None
    m = _REF_RE.search(ref)
    if not m:
        return None
    return (m.group("kind").lower(), m.group("domain"), m.group("name"))


def _map_users_and_groups(
    scan: Scan,
    asset_id: int,
    users: list[dict],
    groups: list[dict],
    memberships: list[dict],
) -> tuple[list[InventoryUser], list[InventoryGroup]]:
    """Map local users + groups + membership edges.

    Side effect captured in return: InventoryUser.is_local_admin is True
    for users that appear in the local "Administrators" group via memberships.
    """
    # Index memberships by group name (case-insensitive).
    by_group: dict[str, list[tuple[str, str]]] = {}
    for m in memberships:
        gref = _parse_ref(m.get("GroupComponent") or "")
        uref = _parse_ref(m.get("PartComponent") or "")
        if not gref or not uref:
            continue
        _, gdomain, gname = gref
        ukind, udomain, uname = uref
        if ukind == "group":
            # Skip nested groups for v1 — local-admin-by-membership is what we need.
            continue
        by_group.setdefault(gname.lower(), []).append((udomain, uname))

    admins = {(d.lower(), n.lower()) for (d, n) in by_group.get("administrators", [])}

    user_rows: list[InventoryUser] = []
    user_seen: set[tuple[str, str]] = set()
    for u in users:
        name = u.get("Name")
        if not name:
            continue
        sid = u.get("SID") or ""
        # Use SID as the dedup key when available, otherwise (domain, name).
        key = ("sid", sid) if sid else ("name", name.lower())
        if key in user_seen:
            continue
        user_seen.add(key)
        user_rows.append(InventoryUser(
            scan_id=scan.id,
            asset_id=asset_id,
            username=name,
            domain=None,                         # local account — domain is the hostname, filled upstream if needed
            sid=sid or None,
            rid=_rid_from_sid(sid),
            user_type="local_user",
            is_disabled=bool(u.get("Disabled")),
            is_locked=bool(u.get("Lockout")),
            password_never_expires=(u.get("PasswordExpires") is False),
            is_local_admin=(("", name.lower()) in admins),
            source_plugin=f"{SOURCE_PREFIX}local_users",
        ))

    group_rows: list[InventoryGroup] = []
    for g in groups:
        gname = g.get("Name")
        if not gname:
            continue
        # Flatten membership list to a simple ["Domain\Name", ...] for the JSON column.
        raw_members = by_group.get(gname.lower(), [])
        members_flat = [f"{d}\\{n}" if d else n for (d, n) in raw_members]
        group_rows.append(InventoryGroup(
            scan_id=scan.id,
            asset_id=asset_id,
            group_name=gname,
            sid=g.get("SID"),
            description=g.get("Description"),
            members=members_flat,
            is_privileged=(gname.lower() in {"administrators", "domain admins", "enterprise admins"}),
            source_plugin=f"{SOURCE_PREFIX}local_groups",
        ))

    return user_rows, group_rows


def _rid_from_sid(sid: str | None) -> int | None:
    """Extract the RID (last segment) from a SID string like S-1-5-21-...-500."""
    if not sid or not isinstance(sid, str):
        return None
    parts = sid.rsplit("-", 1)
    if len(parts) != 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _norm(s: Any) -> str:
    return (str(s) if s is not None else "").strip().lower()

"""Unit tests for services.wmi_result_mapper.

All tests use the in-memory SQLite engine from conftest.py — no mocks of
the ORM. Focuses on field mapping, dedup, and the cross-profile admin-flag
enrichment between users and group memberships.
"""

from __future__ import annotations

import pytest

from models.models import (
    Asset,
    InventoryGroup,
    InventoryPatch,
    InventoryService,
    InventoryShare,
    InventorySoftware,
    InventoryUser,
    Scan,
)
from services.wmi_result_mapper import (
    SOURCE_PREFIX,
    _map_patches,
    _parse_ref,
    _rid_from_sid,
    ingest_result,
)


# ── Shared fixtures ───────────────────────────────────────────────────


@pytest.fixture
def scan_and_asset(db_session):
    """A minimal Scan + Asset pair so Inventory* FKs resolve."""
    scan = Scan(filename="wmi://test", scan_type="wmi_inventory", source_type="wmi_inventory")
    db_session.add(scan)
    db_session.flush()
    asset = Asset(scan_id=scan.id, hostname="WINHOST", ip="10.0.0.5")
    db_session.add(asset)
    db_session.flush()
    return scan, asset


# ── Software dedup (Uninstall + Win32_Product) ────────────────────────


def test_uninstall_walk_writes_inventory_software(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "software_uninstall": [
            {"name": "Chrome", "version": "124.0", "vendor": "Google", "installed_on": "20240401", "_reg_path": "HKLM\\...\\Chrome"},
            {"name": "7-Zip", "version": "23.01", "vendor": "Igor Pavlov", "installed_on": "20230901", "_reg_path": "HKLM\\...\\7-Zip"},
        ],
    }
    counts = ingest_result(db_session, scan, asset.id, result)
    db_session.flush()

    assert counts["software"] == 2
    rows = db_session.query(InventorySoftware).filter_by(scan_id=scan.id).all()
    chrome = next(r for r in rows if r.name == "Chrome")
    assert chrome.version == "124.0"
    assert chrome.vendor == "Google"
    assert chrome.installed_on == "20240401"
    assert chrome.source_plugin == f"{SOURCE_PREFIX}uninstall"


def test_software_dedup_prefers_uninstall_over_win32_product(db_session, scan_and_asset):
    """Both sources surface Chrome 124.0 — only one row should exist and
    source_plugin should be the Uninstall tag (primary source)."""
    scan, asset = scan_and_asset
    result = {
        "software_uninstall": [
            {"name": "Chrome", "version": "124.0", "vendor": "Google", "installed_on": "20240401"},
        ],
        "software_product": [
            {"Name": "Chrome", "Version": "124.0", "Vendor": "Google Inc.", "InstallDate": "20240401"},
            {"Name": "SQL Server", "Version": "16.0", "Vendor": "Microsoft", "InstallDate": "20230101"},
        ],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()

    rows = db_session.query(InventorySoftware).filter_by(scan_id=scan.id).all()
    assert len(rows) == 2
    chrome = next(r for r in rows if r.name == "Chrome")
    assert chrome.source_plugin == f"{SOURCE_PREFIX}uninstall"
    sql = next(r for r in rows if r.name == "SQL Server")
    assert sql.source_plugin == f"{SOURCE_PREFIX}win32_product"


def test_software_dedup_is_case_insensitive(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "software_uninstall": [{"name": "Chrome", "version": "124.0"}],
        "software_product": [{"Name": "CHROME", "Version": "124.0"}],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    assert db_session.query(InventorySoftware).count() == 1


def test_software_skips_rows_without_name(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "software_uninstall": [
            {"name": None, "version": "1.0"},
            {"name": "", "version": "2.0"},
            {"name": "Real App", "version": "3.0"},
        ],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    rows = db_session.query(InventorySoftware).all()
    assert len(rows) == 1
    assert rows[0].name == "Real App"


# ── Services ──────────────────────────────────────────────────────────


def test_services_map_running_state_to_bool(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "services": [
            {"Name": "DNS", "DisplayName": "DNS Server", "State": "Running",
             "StartMode": "Auto", "StartName": "LocalSystem"},
            {"Name": "Spooler", "DisplayName": "Print Spooler", "State": "Stopped",
             "StartMode": "Manual", "StartName": "NT AUTHORITY\\NetworkService"},
        ],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()

    rows = db_session.query(InventoryService).filter_by(scan_id=scan.id).all()
    by_name = {r.service_name: r for r in rows}
    assert by_name["DNS"].is_running is True
    assert by_name["DNS"].startup_type == "Auto"
    assert by_name["DNS"].run_as_user == "LocalSystem"
    assert by_name["Spooler"].is_running is False


def test_services_dedupe_by_name(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {"services": [
        {"Name": "DNS", "State": "Running"},
        {"Name": "DNS", "State": "Running"},  # duplicate
    ]}
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    assert db_session.query(InventoryService).count() == 1


# ── Patches (Win32_QuickFixEngineering) ───────────────────────────────


def test_patches_normalize_kb_id_case(scan_and_asset):
    scan, asset = scan_and_asset
    rows = _map_patches(scan, asset.id, [
        {"HotFixID": "kb5034441", "Description": "Security Update"},
        {"HotFixID": "KB5034441", "Description": "Duplicate"},        # dedup
        {"HotFixID": "Update for Windows (KB5046615)", "Description": "Cumulative Update"},
        {"HotFixID": "NotAKB", "Description": "garbage"},               # dropped
    ])
    kbs = [r.kb_id for r in rows]
    assert kbs == ["KB5034441", "KB5046615"]


def test_patches_write_to_db(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {"patches": [{"HotFixID": "KB5034441", "Description": "Security Update"}]}
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    patch = db_session.query(InventoryPatch).first()
    assert patch.kb_id == "KB5034441"
    assert patch.description == "Security Update"
    assert patch.cves == []


# ── Shares ────────────────────────────────────────────────────────────


def test_shares_decode_type_and_default_flag(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    # Type values per Win32_Share: 0=Disk, 1=Print, 3=IPC; 0x80000000 | 0 = hidden disk
    result = {"shares": [
        {"Name": "Public", "Path": "C:\\Public", "Description": "", "Type": 0},
        {"Name": "ADMIN$", "Path": "C:\\Windows", "Description": "Remote Admin", "Type": 0x80000000},
        {"Name": "IPC$", "Path": "", "Description": "Remote IPC", "Type": 0x80000003},
        {"Name": "HPLaserJet", "Path": "", "Description": "Printer", "Type": 1},
    ]}
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    rows = {r.share_name: r for r in db_session.query(InventoryShare).all()}
    assert rows["Public"].share_type == "Disk"
    assert rows["Public"].is_default_share is False
    assert rows["ADMIN$"].share_type == "Disk"
    assert rows["ADMIN$"].is_default_share is True
    assert rows["IPC$"].share_type == "IPC"
    assert rows["IPC$"].is_default_share is True
    assert rows["HPLaserJet"].share_type == "Print"


# ── Users + Groups + Admin flag enrichment ────────────────────────────


def test_parse_ref_extracts_domain_and_name():
    ref = r'\\\\WINHOST\\root\\cimv2:Win32_Group.Domain="WINHOST",Name="Administrators"'
    assert _parse_ref(ref) == ("group", "WINHOST", "Administrators")

    ref_user = r':Win32_UserAccount.Domain="WINHOST",Name="Alice"'
    assert _parse_ref(ref_user) == ("useraccount", "WINHOST", "Alice")


def test_parse_ref_returns_none_on_malformed():
    assert _parse_ref("") is None
    assert _parse_ref("garbage") is None
    assert _parse_ref(None) is None


def test_rid_extraction():
    assert _rid_from_sid("S-1-5-21-1-2-3-500") == 500
    assert _rid_from_sid("S-1-5-18") == 18
    assert _rid_from_sid("not-a-sid") is None
    assert _rid_from_sid(None) is None


def test_local_admin_flag_set_from_group_membership(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "local_users": [
            {"Name": "Alice", "SID": "S-1-5-21-1-1-1-500", "Disabled": False,
             "Lockout": False, "PasswordExpires": True},
            {"Name": "Bob", "SID": "S-1-5-21-1-1-1-501", "Disabled": False,
             "Lockout": False, "PasswordExpires": True},
        ],
        "local_groups": [
            {"Name": "Administrators", "SID": "S-1-5-32-544", "Description": "Admins"},
            {"Name": "Users", "SID": "S-1-5-32-545", "Description": "Regular users"},
        ],
        "group_membership": [
            # Alice → Administrators; Bob → Users
            {
                "GroupComponent": r':Win32_Group.Domain="WINHOST",Name="Administrators"',
                "PartComponent":  r':Win32_UserAccount.Domain="",Name="Alice"',
            },
            {
                "GroupComponent": r':Win32_Group.Domain="WINHOST",Name="Users"',
                "PartComponent":  r':Win32_UserAccount.Domain="",Name="Bob"',
            },
        ],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()

    users = {u.username: u for u in db_session.query(InventoryUser).all()}
    assert users["Alice"].is_local_admin is True
    assert users["Bob"].is_local_admin is False
    assert users["Alice"].user_type == "local_user"
    assert users["Alice"].rid == 500
    assert users["Alice"].sid == "S-1-5-21-1-1-1-500"

    groups = {g.group_name: g for g in db_session.query(InventoryGroup).all()}
    assert groups["Administrators"].is_privileged is True
    assert groups["Users"].is_privileged is False
    # members JSON should reflect the parsed membership for Administrators
    assert any("Alice" in m for m in (groups["Administrators"].members or []))


def test_password_never_expires_flag(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "local_users": [
            {"Name": "NoExpire", "SID": "S-1-5-21-1-1-1-1001",
             "Disabled": False, "Lockout": False, "PasswordExpires": False},
            {"Name": "Normal", "SID": "S-1-5-21-1-1-1-1002",
             "Disabled": False, "Lockout": False, "PasswordExpires": True},
        ],
    }
    ingest_result(db_session, scan, asset.id, result)
    db_session.flush()

    users = {u.username: u for u in db_session.query(InventoryUser).all()}
    assert users["NoExpire"].password_never_expires is True
    assert users["Normal"].password_never_expires is False


# ── Errors field is logged but doesn't fail ingest ────────────────────


def test_errors_field_does_not_block_ingest(db_session, scan_and_asset):
    scan, asset = scan_and_asset
    result = {
        "services": [{"Name": "DNS", "State": "Running"}],
        "_errors": {"shares": "Access denied"},
    }
    counts = ingest_result(db_session, scan, asset.id, result)
    db_session.flush()
    assert counts.get("services") == 1
    # No share rows written because shares profile errored
    assert db_session.query(InventoryShare).count() == 0

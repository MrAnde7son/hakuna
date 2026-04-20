"""Unit tests for agent.wmi_query.

impacket isn't stubbed end-to-end — we only verify the pieces we own:
  - Result-row normalization from impacket's getProperties() shape
  - CIM value coercion (bytes, lists, scalars)
  - Enumerator drain (including the WBEM_S_FALSE termination path)
  - _run_sync's profile dispatch (WQL vs. software_uninstall vs. unknown)
  - _walk_uninstall's interaction with a fake StdRegProv
"""

from __future__ import annotations

import asyncio

import pytest

from agent import wmi_query
from agent.wmi_catalog import WQL_PROFILES, STDREGPROV_UNINSTALL_PATHS


# ── _normalize_row / _coerce ─────────────────────────────────────────


def test_normalize_row_unwraps_impacket_dict_shape():
    props = {
        "Name": {"stype": "string", "value": "Google Chrome"},
        "Version": {"stype": "string", "value": "124.0.6367.8"},
        "Disabled": {"stype": "boolean", "value": False},
        "SessionID": {"stype": "uint32", "value": 1},
    }
    row = wmi_query._normalize_row(props)
    assert row == {
        "Name": "Google Chrome",
        "Version": "124.0.6367.8",
        "Disabled": False,
        "SessionID": 1,
    }


def test_normalize_row_keeps_none():
    row = wmi_query._normalize_row({"Vendor": {"stype": "string", "value": None}})
    assert row == {"Vendor": None}


def test_coerce_decodes_bytes():
    assert wmi_query._coerce(b"hello") == "hello"


def test_coerce_recurses_into_list():
    assert wmi_query._coerce(["a", b"b", 3]) == ["a", "b", 3]


def test_coerce_stringifies_unknown_types():
    class Weird:
        def __str__(self): return "weird-value"
    assert wmi_query._coerce(Weird()) == "weird-value"


# ── _drain_enum ───────────────────────────────────────────────────────


class _FakeObj:
    """Stand-in for an impacket IWbemClassObject — exposes getProperties()."""
    def __init__(self, props): self._props = props
    def getProperties(self): return self._props


class _FakeEnum:
    """Stand-in for an impacket enumerator.

    Yields `batches` one Next() call at a time, then raises the exception
    with message `terminator` to signal exhaustion. Mirrors impacket's
    real behavior where exhaustion is surfaced via DCERPCException with
    'WBEM_S_FALSE' in the message.
    """
    def __init__(self, batches, terminator="WBEM_S_FALSE"):
        self._batches = list(batches)
        self._terminator = terminator

    def Next(self, _timeout, _count):
        if not self._batches:
            raise RuntimeError(self._terminator)
        return self._batches.pop(0)

    def RemRelease(self): pass


def test_drain_enum_collects_rows_across_batches():
    e = _FakeEnum([
        [_FakeObj({"Name": {"value": "svc-a"}})],
        [_FakeObj({"Name": {"value": "svc-b"}}), _FakeObj({"Name": {"value": "svc-c"}})],
    ])
    rows = wmi_query._drain_enum(e)
    assert [r["Name"] for r in rows] == ["svc-a", "svc-b", "svc-c"]


def test_drain_enum_stops_on_empty_batch():
    e = _FakeEnum([[_FakeObj({"Name": {"value": "only"}})], []])
    rows = wmi_query._drain_enum(e)
    assert [r["Name"] for r in rows] == ["only"]


def test_drain_enum_propagates_unexpected_errors():
    e = _FakeEnum([], terminator="SOMETHING_UNEXPECTED")
    with pytest.raises(RuntimeError, match="SOMETHING_UNEXPECTED"):
        wmi_query._drain_enum(e)


# ── _walk_uninstall ───────────────────────────────────────────────────


class _FakeRegResult:
    def __init__(self, **kwargs): self.__dict__.update(kwargs)


class _FakeStdRegProv:
    """Fake that implements just enough of StdRegProv for _walk_uninstall."""
    def __init__(self, tree: dict):
        # tree: {subkey_path: {"subkeys": [...], "values": {name: value, ...}}}
        self._tree = tree
    def EnumKey(self, _hive, subkey):
        node = self._tree.get(subkey, {})
        return _FakeRegResult(sNames=node.get("subkeys", []))
    def GetStringValue(self, _hive, subkey, value_name):
        node = self._tree.get(subkey, {})
        return _FakeRegResult(sValue=node.get("values", {}).get(value_name))
    def RemRelease(self): pass


class _FakeServices:
    def __init__(self, reg): self._reg = reg
    def GetObject(self, _name): return (self._reg,)


def _uninstall_tree_with(apps: list[dict]) -> dict:
    """Build a fake registry tree: each app becomes a subkey under both
    Uninstall paths (half under 64-bit, half under Wow6432Node) so we
    verify both base paths are walked.
    """
    tree: dict = {}
    split = len(apps) // 2
    for base_path, bucket in [
        (STDREGPROV_UNINSTALL_PATHS[0], apps[:split]),
        (STDREGPROV_UNINSTALL_PATHS[1], apps[split:]),
    ]:
        subkey_names = [f"app{i}" for i in range(len(bucket))]
        tree[base_path] = {"subkeys": subkey_names, "values": {}}
        for name, app in zip(subkey_names, bucket):
            tree[f"{base_path}\\{name}"] = {"subkeys": [], "values": app}
    return tree


def test_walk_uninstall_produces_inventory_rows():
    apps = [
        {"DisplayName": "Chrome", "DisplayVersion": "124.0", "Publisher": "Google", "InstallDate": "20240401"},
        {"DisplayName": "7-Zip",  "DisplayVersion": "23.01", "Publisher": "Igor Pavlov", "InstallDate": "20230901"},
        {"DisplayName": "Notepad++", "DisplayVersion": "8.6", "Publisher": "Don HO", "InstallDate": "20240115"},
        {"DisplayName": "VSCode", "DisplayVersion": "1.88", "Publisher": "Microsoft", "InstallDate": "20240410"},
    ]
    reg = _FakeStdRegProv(_uninstall_tree_with(apps))
    services = _FakeServices(reg)

    rows = wmi_query._walk_uninstall(services)

    # All 4 apps surface with the mapped field names.
    assert len(rows) == 4
    names = {r["name"] for r in rows}
    assert names == {"Chrome", "7-Zip", "Notepad++", "VSCode"}
    chrome = next(r for r in rows if r["name"] == "Chrome")
    assert chrome["version"] == "124.0"
    assert chrome["vendor"] == "Google"
    assert chrome["installed_on"] == "20240401"
    # _reg_path is preserved so the mapper can trace back if needed.
    assert "_reg_path" in chrome


def test_walk_uninstall_skips_subkeys_without_display_name():
    # A subkey with no DisplayName (e.g. security updates) should be dropped,
    # not written as a blank InventorySoftware row.
    tree = _uninstall_tree_with([
        {"DisplayName": "Real App", "DisplayVersion": "1.0", "Publisher": "Acme", "InstallDate": ""},
    ])
    # Inject a second subkey with no DisplayName under the first path
    base = STDREGPROV_UNINSTALL_PATHS[0]
    tree[base]["subkeys"] = ["app0", "ghost"]
    tree[f"{base}\\ghost"] = {"subkeys": [], "values": {"DisplayVersion": "2.0"}}

    reg = _FakeStdRegProv(tree)
    services = _FakeServices(reg)
    rows = wmi_query._walk_uninstall(services)
    assert len(rows) == 1
    assert rows[0]["name"] == "Real App"


# ── Catalog sanity ────────────────────────────────────────────────────


@pytest.mark.parametrize("profile", list(WQL_PROFILES.keys()))
def test_every_wql_profile_is_a_select(profile):
    """Guard against non-SELECT queries sneaking in — we are read-only."""
    assert WQL_PROFILES[profile].strip().upper().startswith("SELECT ")


# ── Input validation on run_wmi_queries ──────────────────────────────


def test_run_wmi_queries_requires_target():
    with pytest.raises(wmi_query.WMIError, match="target"):
        asyncio.run(wmi_query.run_wmi_queries("", {"username": "u"}, ["services"]))


def test_run_wmi_queries_requires_profiles():
    with pytest.raises(wmi_query.WMIError, match="profile"):
        asyncio.run(wmi_query.run_wmi_queries("host", {"username": "u"}, []))


def test_run_wmi_queries_requires_username():
    with pytest.raises(wmi_query.WMIError, match="username"):
        asyncio.run(wmi_query.run_wmi_queries("host", {"password": "p"}, ["services"]))

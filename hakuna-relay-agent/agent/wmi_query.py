"""impacket WMI query executor for the Hakuna relay agent.

Runs read-only WQL queries (and a StdRegProv Uninstall walk) against a remote
Windows host over DCERPC. Used by agent.executor when a `method=wmi_query`
task arrives from the backend.

Design notes
------------
- One DCOM connection per target host, reused across all profiles. Connection
  setup is the expensive part (NTLM handshake over SMB → DCOM activation); the
  actual queries are cheap.
- All impacket work happens inside `asyncio.to_thread` because impacket is
  synchronous. This keeps the agent's WebSocket loop responsive so the broker
  can time out cleanly if a query hangs.
- We never log credentials; only target + profile names and row counts.
- The StdRegProv walk is the *primary* software source. Win32_Product only
  sees MSI-installed apps and triggers an MSI reconfiguration event on the
  target, so it's kept as a secondary when the backend explicitly asks for it.

Result shape returned to the backend:
    {
      "<profile_name>": [ {col: value, ...}, ... ],
      ...
      "_errors": { "<profile_name>": "error message", ... }   # optional
    }
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .method_registry import register_method
from .wmi_catalog import (
    STDREGPROV_UNINSTALL_PATHS,
    UNINSTALL_VALUES,
    WQL_PROFILES,
)

logger = logging.getLogger(__name__)


# Lazy imports — impacket brings in pyOpenSSL/pycryptodome which we don't want
# loaded on relay agents that never run WMI tasks.
def _impacket():
    from impacket.dcerpc.v5.dcom import wmi  # noqa: F401 — imported for side effects
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dtypes import NULL

    return DCOMConnection, NULL


# HKEY_LOCAL_MACHINE — constant used by StdRegProv methods.
HKEY_LOCAL_MACHINE = 0x80000002


class WMIError(Exception):
    """Any WMI connection / query failure surfaced back to the backend."""


@register_method("wmi_query")
async def wmi_query_handler(ws, task, transport_config, credentials, params) -> dict:
    """Task method handler — adapts the executor's uniform signature to run_wmi_queries."""
    target = (transport_config or {}).get("target")
    profiles = (params or {}).get("profiles") or []
    registry_reads = (params or {}).get("registry_reads") or []
    timeout_s = int((params or {}).get("timeout_s") or 120)
    return await run_wmi_queries(
        target, credentials or {}, profiles, timeout_s, registry_reads,
    )


async def run_wmi_queries(
    target: str,
    credentials: dict,
    profiles: list[str],
    timeout_s: int = 120,
    registry_reads: list[dict] | None = None,
) -> dict[str, Any]:
    """Execute the requested profiles against a single Windows target.

    The whole impacket interaction is wrapped in a single `to_thread` + timeout
    so one slow host can't stall the agent's event loop.

    `registry_reads` is an optional list of ad-hoc StdRegProv ops used by the
    WMI audit agent. Each entry is `{op, hive, key, value_name?}` where op is
    `get_value` | `enum_keys` | `enum_values`. Results come back under the
    `registry_read` key as a list aligned with the input order.
    """
    if not target:
        raise WMIError("target is required")
    if not profiles and not registry_reads:
        raise WMIError("at least one profile or registry_read is required")
    if not credentials or not credentials.get("username"):
        raise WMIError("credentials with 'username' are required")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, credentials, profiles, registry_reads or []),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise WMIError(f"WMI query timed out after {timeout_s}s for target {target}")


def _run_sync(target: str, credentials: dict, profiles: list[str], registry_reads: list[dict]) -> dict:
    """Synchronous impacket driver — runs inside a thread."""
    DCOMConnection, NULL = _impacket()

    username = credentials.get("username", "")
    password = credentials.get("password", "")
    domain = credentials.get("domain", "") or ""
    # NTLM hash auth (pass-the-hash) — rarely used but trivial to support
    lmhash = credentials.get("lmhash", "") or ""
    nthash = credentials.get("nthash", "") or ""

    dcom = DCOMConnection(
        target, username, password, domain, lmhash, nthash, oxidResolver=True,
    )
    try:
        # Namespace cache — key = namespace (e.g., "root\\cimv2"), val = services.
        # Most audits hit multiple profiles in the same namespace; keeping one
        # services handle per namespace avoids repeated NTLMLogin round-trips.
        ns_cache: dict[str, Any] = {}
        try:
            out = _collect_profiles(dcom, profiles, ns_cache) if profiles else {}
            if registry_reads:
                # Registry reads always go through root\cimv2 (StdRegProv lives there).
                cimv2 = _get_namespace(dcom, "root\\cimv2", ns_cache)
                out["registry_read"] = _run_registry_reads(cimv2, registry_reads)
            return out
        finally:
            for services in ns_cache.values():
                try:
                    services.RemRelease()
                except Exception:
                    pass
    finally:
        try:
            dcom.disconnect()
        except Exception:
            logger.debug("dcom.disconnect raised; ignoring", exc_info=True)


def _get_namespace(dcom, namespace: str, cache: dict):
    """Return a cached IWbemServices for `namespace`, opening it if needed.

    Impacket wants forward-slash paths (`//./root/cimv2`) in NTLMLogin even
    though WMI docs use backslashes. We accept either form from the catalog.
    """
    key = namespace.replace("/", "\\").lower()
    if key in cache:
        return cache[key]
    from impacket.dcerpc.v5.dcom import wmi
    ns_path = "//./" + namespace.replace("\\", "/")
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    try:
        services = iWbemLevel1Login.NTLMLogin(ns_path, None, None)
    finally:
        iWbemLevel1Login.RemRelease()
    cache[key] = services
    return services


def _collect_profiles(dcom, profiles: list[str], ns_cache: dict) -> dict:
    """Dispatch each requested profile and collect results + per-profile errors.

    Profile values in `WQL_PROFILES` may be a string (root\\cimv2 query) or a
    `(namespace, query)` tuple. Cross-namespace profiles get a fresh
    IWbemServices via `_get_namespace`, cached for the duration of the task.
    """
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for profile in profiles:
        try:
            if profile == "software_uninstall":
                cimv2 = _get_namespace(dcom, "root\\cimv2", ns_cache)
                rows = _walk_uninstall(cimv2)
            elif profile in WQL_PROFILES:
                spec = WQL_PROFILES[profile]
                if isinstance(spec, tuple):
                    namespace, query = spec
                else:
                    namespace, query = "root\\cimv2", spec
                services = _get_namespace(dcom, namespace, ns_cache)
                rows = _run_wql(services, query)
            else:
                errors[profile] = f"unknown profile: {profile}"
                continue
            out[profile] = rows
            logger.info("wmi profile=%s rows=%d", profile, len(rows))
        except Exception as e:
            # Per-profile isolation: one broken query (missing provider on
            # pre-Win8 hosts, namespace denied by ACL, etc.) doesn't kill the
            # whole scan.
            errors[profile] = f"{type(e).__name__}: {e}"
            logger.warning("wmi profile=%s failed: %s", profile, e)

    if errors:
        out["_errors"] = errors
    return out


# ── WQL path ────────────────────────────────────────────────────────────


def _run_wql(services, query: str) -> list[dict]:
    """Execute a WQL query and materialize all rows as plain dicts.

    We pull the full result set into memory because downstream mapping runs
    on the backend, not here — and WMI result sets for inventory queries are
    small (services cap around ~300, installed software rarely >500).
    """
    enum = services.ExecQuery(query)
    try:
        return _drain_enum(enum)
    finally:
        enum.RemRelease()


def _drain_enum(enum) -> list[dict]:
    rows: list[dict] = []
    while True:
        try:
            wmi_objects = enum.Next(0xFFFFFFFF, 1)
        except Exception as e:
            # Normal termination path: impacket raises DCERPCException with
            # WBEM_S_FALSE (1) when the enumerator is exhausted. We detect
            # that by string since the exception type varies across versions.
            if "WBEM_S_FALSE" in str(e) or "S_FALSE" in str(e):
                break
            raise
        if not wmi_objects:
            break
        for obj in wmi_objects:
            rows.append(_normalize_row(obj.getProperties()))
    return rows


def _normalize_row(props: dict) -> dict:
    """Flatten impacket's getProperties() output to {field: primitive}.

    impacket returns `{"FieldName": {"stype": "string", "value": "..."}, ...}`;
    we only need the value. `None` stays as None.
    """
    flat: dict[str, Any] = {}
    for name, meta in props.items():
        if isinstance(meta, dict) and "value" in meta:
            flat[name] = _coerce(meta.get("value"))
        else:
            flat[name] = _coerce(meta)
    return flat


def _coerce(value: Any) -> Any:
    """Coerce impacket's CIM wrappers into JSON-safe primitives."""
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return repr(value)
    if isinstance(value, (list, tuple)):
        return [_coerce(v) for v in value]
    # impacket occasionally returns ctypes-like objects with str() defined
    return str(value)


# ── StdRegProv (ad-hoc registry reads for the WMI audit agent) ──────────

# HKEY name → constant. StdRegProv accepts the numeric hive, so we translate
# human names the agent tool passes in. We only allow read-oriented hives —
# HKCU on a remote host is nonsensical without the target user's context,
# so we don't expose it.
_HIVES: dict[str, int] = {
    "HKLM": 0x80000002,
    "HKEY_LOCAL_MACHINE": 0x80000002,
    "HKCR": 0x80000000,
    "HKEY_CLASSES_ROOT": 0x80000000,
    "HKU": 0x80000003,
    "HKEY_USERS": 0x80000003,
}

# Reverse map for numeric value types from StdRegProv.EnumValues.
_REG_TYPES: dict[int, str] = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def _resolve_hive(name: str) -> int:
    """Translate an HKLM/HKCR/HKU name to its StdRegProv numeric constant."""
    key = (name or "").strip().upper()
    if key not in _HIVES:
        raise ValueError(f"unknown hive: {name!r}")
    return _HIVES[key]


def _run_registry_reads(services, reads: list[dict]) -> list[dict]:
    """Run a list of registry read ops and return results in input order.

    Each op is `{op, hive, key, value_name?, type?}`. Supported ops:
      - `get_value`   — read one value (type auto-detected via EnumValues)
      - `enum_keys`   — list immediate subkey names
      - `enum_values` — list value names + types for the key (values not read)

    Errors are captured per-op (not raised) so one bad key doesn't wipe out
    the whole batch.
    """
    reg = services.GetObject("StdRegProv")[0]
    try:
        out: list[dict] = []
        for req in reads:
            op = (req.get("op") or "get_value").strip()
            try:
                hive = _resolve_hive(req.get("hive") or "HKLM")
            except ValueError as e:
                out.append({**req, "error": str(e)})
                continue
            key = (req.get("key") or "").strip()
            if not key:
                out.append({**req, "error": "key is required"})
                continue
            try:
                if op == "get_value":
                    out.append(_reg_get_value(reg, hive, key, req.get("value_name") or ""))
                elif op == "enum_keys":
                    names = _enum_subkeys(reg, hive, key)
                    out.append({"op": op, "hive": req.get("hive"), "key": key, "subkeys": names})
                elif op == "enum_values":
                    vals = _enum_values(reg, hive, key)
                    out.append({"op": op, "hive": req.get("hive"), "key": key, "values": vals})
                else:
                    out.append({**req, "error": f"unknown op: {op}"})
            except Exception as e:
                out.append({**req, "error": f"{type(e).__name__}: {e}"})
        return out
    finally:
        reg.RemRelease()


def _reg_get_value(reg, hive: int, key: str, value_name: str) -> dict:
    """Read one registry value, auto-picking the right StdRegProv accessor.

    We don't ask the caller for the value type because the agent usually
    doesn't know it up front. Strategy: look up the type via EnumValues, then
    dispatch to the typed Get*Value call. Unknown types fall back to binary.
    """
    types = {v["name"]: v["type_id"] for v in _enum_values(reg, hive, key)}
    if value_name not in types:
        return {
            "op": "get_value", "hive": _hive_name(hive), "key": key,
            "value_name": value_name, "found": False,
        }
    type_id = types[value_name]
    base = {"op": "get_value", "hive": _hive_name(hive), "key": key,
            "value_name": value_name, "found": True,
            "type": _REG_TYPES.get(type_id, f"type_{type_id}")}
    if type_id in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        res = reg.GetStringValue(hive, key, value_name) if type_id == 1 else reg.GetExpandedStringValue(hive, key, value_name)
        base["data"] = getattr(res, "sValue", None) or (res["sValue"] if "sValue" in res else None)
    elif type_id == 4:  # REG_DWORD
        res = reg.GetDWORDValue(hive, key, value_name)
        base["data"] = getattr(res, "uValue", None) if hasattr(res, "uValue") else res.get("uValue")
    elif type_id == 7:  # REG_MULTI_SZ
        res = reg.GetMultiStringValue(hive, key, value_name)
        base["data"] = list(getattr(res, "sValue", None) or res.get("sValue") or [])
    elif type_id == 11:  # REG_QWORD
        res = reg.GetQWORDValue(hive, key, value_name)
        base["data"] = getattr(res, "uValue", None) if hasattr(res, "uValue") else res.get("uValue")
    elif type_id == 3:  # REG_BINARY
        res = reg.GetBinaryValue(hive, key, value_name)
        raw = getattr(res, "uValue", None) if hasattr(res, "uValue") else res.get("uValue")
        # Hex-encode so the JSON round-trip is safe.
        base["data"] = bytes(raw or b"").hex()
    else:
        base["data"] = None
    return base


def _enum_values(reg, hive: int, subkey: str) -> list[dict]:
    """Return [{name, type_id}, ...] for all values under a key."""
    res = reg.EnumValues(hive, subkey)
    names = getattr(res, "sNames", None)
    types = getattr(res, "Types", None)
    if names is None:
        names = res.get("sNames") if hasattr(res, "get") else []
    if types is None:
        types = res.get("Types") if hasattr(res, "get") else []
    return [{"name": n, "type_id": int(t), "type": _REG_TYPES.get(int(t), f"type_{t}")}
            for n, t in zip(names or [], types or [])]


def _hive_name(hive: int) -> str:
    for name, val in _HIVES.items():
        if val == hive and name.startswith("HK") and len(name) <= 4:
            return name
    return hex(hive)


# ── StdRegProv (Uninstall registry walk) ────────────────────────────────


def _walk_uninstall(services) -> list[dict]:
    """Enumerate Uninstall subkeys under both 64-bit and 32-bit HKLM paths
    and pull the four display fields from each.

    Returns a list of dicts compatible with InventorySoftware upsert:
      {"name": ..., "version": ..., "vendor": ..., "installed_on": ...,
       "_reg_path": "<HKLM subkey>"}
    """
    reg = services.GetObject("StdRegProv")[0]
    try:
        rows: list[dict] = []
        for base_path in STDREGPROV_UNINSTALL_PATHS:
            try:
                subkeys = _enum_subkeys(reg, HKEY_LOCAL_MACHINE, base_path)
            except Exception as e:
                logger.debug("EnumKey failed for %s: %s", base_path, e)
                continue
            for sub in subkeys:
                key = f"{base_path}\\{sub}"
                entry = {"_reg_path": key}
                got_any = False
                for vname in UNINSTALL_VALUES:
                    try:
                        val = _get_string_value(reg, HKEY_LOCAL_MACHINE, key, vname)
                    except Exception:
                        val = None
                    if val:
                        got_any = True
                    entry[vname] = val
                if got_any and entry.get("DisplayName"):
                    rows.append({
                        "name": entry.get("DisplayName"),
                        "version": entry.get("DisplayVersion"),
                        "vendor": entry.get("Publisher"),
                        "installed_on": entry.get("InstallDate"),
                        "_reg_path": key,
                    })
        return rows
    finally:
        reg.RemRelease()


def _enum_subkeys(reg, hive: int, subkey: str) -> list[str]:
    """Return the list of immediate subkeys under `hive\\subkey`.

    StdRegProv.EnumKey returns a single outParam with sNames as a string array.
    """
    result = reg.EnumKey(hive, subkey)
    names = getattr(result, "sNames", None)
    if names is None:
        # impacket may return a dict or a ctypes struct; handle both
        try:
            names = result["sNames"]
        except Exception:
            return []
    return [n for n in (names or []) if n]


def _get_string_value(reg, hive: int, subkey: str, value_name: str) -> str | None:
    """Read a REG_SZ value; returns None when the value is missing."""
    result = reg.GetStringValue(hive, subkey, value_name)
    val = getattr(result, "sValue", None)
    if val is None:
        try:
            val = result["sValue"]
        except Exception:
            return None
    return val or None

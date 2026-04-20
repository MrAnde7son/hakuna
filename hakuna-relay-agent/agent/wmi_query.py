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


async def run_wmi_queries(
    target: str,
    credentials: dict,
    profiles: list[str],
    timeout_s: int = 120,
) -> dict[str, Any]:
    """Execute the requested profiles against a single Windows target.

    The whole impacket interaction is wrapped in a single `to_thread` + timeout
    so one slow host can't stall the agent's event loop.
    """
    if not target:
        raise WMIError("target is required")
    if not profiles:
        raise WMIError("at least one profile is required")
    if not credentials or not credentials.get("username"):
        raise WMIError("credentials with 'username' are required")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, credentials, profiles),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise WMIError(f"WMI query timed out after {timeout_s}s for target {target}")


def _run_sync(target: str, credentials: dict, profiles: list[str]) -> dict:
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
        services = _open_cimv2(dcom)
        try:
            return _collect_profiles(services, dcom, profiles)
        finally:
            services.RemRelease()
    finally:
        try:
            dcom.disconnect()
        except Exception:
            logger.debug("dcom.disconnect raised; ignoring", exc_info=True)


def _open_cimv2(dcom):
    """Bind to root\\cimv2 and return an IWbemServices proxy."""
    from impacket.dcerpc.v5.dcom import wmi

    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    services = iWbemLevel1Login.NTLMLogin("//./root/cimv2", None, None)
    iWbemLevel1Login.RemRelease()
    return services


def _collect_profiles(services, dcom, profiles: list[str]) -> dict:
    """Dispatch each requested profile and collect results + per-profile errors."""
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for profile in profiles:
        try:
            if profile == "software_uninstall":
                rows = _walk_uninstall(services)
            elif profile in WQL_PROFILES:
                rows = _run_wql(services, WQL_PROFILES[profile])
            else:
                errors[profile] = f"unknown profile: {profile}"
                continue
            out[profile] = rows
            logger.info("wmi profile=%s rows=%d", profile, len(rows))
        except Exception as e:
            # Per-profile isolation: one broken query doesn't kill the whole scan.
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

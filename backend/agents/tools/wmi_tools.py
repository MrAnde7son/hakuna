"""WMI tool palette for the WMI Audit ReAct agent.

Two generic primitives:

  - ``wmi_query`` — runs arbitrary WQL against any WMI namespace
    (``root\\cimv2`` by default; pass ``namespace`` for cross-namespace
    classes like Defender, Firewall, BitLocker, TPM, Hyper-V). WQL is
    SELECT-only by construction; the relay refuses anything else, so
    method invocation (``Win32_Process.Create`` etc.) is not reachable
    through this surface.
  - ``wmi_registry_read`` — StdRegProv get_value / enum_keys / enum_values
    over DCOM, for keys WMI classes don't expose (SMBv1 state, LanMan
    compat, audit policy, AlwaysInstallElevated, etc.).

Mission-specific recipes (local users, groups, services, software, patches,
Defender state, BitLocker volumes, …) live in the prompts as WQL snippets.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset
from agents.agent_tools import agent_tool, NeedsApproval
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_PER_QUERY_TIMEOUT_S = 60


# ── Relay dispatch helper ────────────────────────────────────────────


def _run_async(coro):
    # See agents/tools/ssh_tools.py for the cross-loop-future rationale.
    from core.event_loop import get_main_loop, is_on_main_loop
    main_loop = get_main_loop()
    if main_loop is not None and main_loop.is_running() and not is_on_main_loop():
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        return fut.result(timeout=_PER_QUERY_TIMEOUT_S + 15)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PER_QUERY_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch(
    db,
    org_id: int,
    asset_id: int,
    params_payload: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    target, target_port = resolve_asset_target(asset)
    if not target:
        raise ValueError(f"asset {asset_id} has no hostname or ip")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")
    if not credential_id:
        raise ValueError("credential_id missing from audit context")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    raw_creds = await load_credentials(db, credential_id, org_id)
    if not raw_creds or not raw_creds.get("username"):
        raise ValueError(f"credential {credential_id} missing or has no username")

    config: dict[str, Any] = {"target": target}
    if target_port:
        config["port"] = target_port

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="wmi_query",
        config=config,
        credentials={
            "username": raw_creds.get("username", ""),
            "password": raw_creds.get("password", ""),
            "domain": raw_creds.get("domain", "") or "",
        },
        params={**params_payload, "timeout_s": _PER_QUERY_TIMEOUT_S},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _trim(rows: list, limit: int = 40) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Generic WQL ─────────────────────────────────────────────────────


@agent_tool(
    "wmi_query",
    "Run an arbitrary WQL query against the target. WQL is SELECT-only by "
    "construction — the relay rejects anything else, so this surface cannot "
    "invoke methods or write properties. Default namespace is "
    "`root\\cimv2`; pass `namespace` for cross-namespace classes:\n"
    "  • Defender: `root\\Microsoft\\Windows\\Defender` (MSFT_MpComputerStatus)\n"
    "  • Firewall: `root\\StandardCimv2` (MSFT_NetFirewallProfile, MSFT_NetFirewallRule)\n"
    "  • BitLocker: `root\\cimv2\\Security\\MicrosoftVolumeEncryption` (Win32_EncryptableVolume)\n"
    "  • TPM: `root\\cimv2\\Security\\MicrosoftTpm` (Win32_Tpm)\n"
    "  • Hyper-V: `root\\virtualization\\v2`\n"
    "Common recipes (root\\cimv2 unless noted):\n"
    "  • Local users: `SELECT Name,SID,Disabled,Lockout,PasswordExpires,"
    "PasswordRequired,Description,FullName FROM Win32_UserAccount WHERE "
    "LocalAccount=TRUE`\n"
    "  • Local groups: `SELECT Name,SID,Description FROM Win32_Group WHERE "
    "LocalAccount=TRUE`\n"
    "  • Group membership: `SELECT GroupComponent,PartComponent FROM "
    "Win32_GroupUser` (filter client-side by group name in GroupComponent)\n"
    "  • Services: `SELECT Name,DisplayName,State,StartMode,StartName,"
    "PathName FROM Win32_Service`\n"
    "  • Computer system: `SELECT Name,Domain,PartOfDomain,DomainRole,"
    "Manufacturer,Model,TotalPhysicalMemory FROM Win32_ComputerSystem`\n"
    "  • OS / patch level: `SELECT Caption,Version,BuildNumber,InstallDate,"
    "OSArchitecture FROM Win32_OperatingSystem`\n"
    "  • Hotfixes: `SELECT HotFixID,Description,InstalledBy,InstalledOn "
    "FROM Win32_QuickFixEngineering`\n"
    "  • Drivers: `SELECT Name,DisplayName,State,StartMode,PathName FROM "
    "Win32_SystemDriver`\n"
    "  • Shares: `SELECT Name,Path,Description,Type,AllowMaximum FROM "
    "Win32_Share`\n"
    "  • Startup: `SELECT Caption,Command,Location,User,UserSID FROM "
    "Win32_StartupCommand`\n"
    "  • Scheduled jobs (legacy at): `SELECT Caption,Command,Owner,Status,"
    "JobId FROM Win32_ScheduledJob`\n"
    "  • Defender: `SELECT * FROM MSFT_MpComputerStatus` "
    "(namespace `root\\Microsoft\\Windows\\Defender`)\n"
    "  • Firewall: `SELECT Name,Enabled,DefaultInboundAction,"
    "DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName,"
    "AllowInboundRules FROM MSFT_NetFirewallProfile` "
    "(namespace `root\\StandardCimv2`)\n"
    "  • BitLocker: `SELECT DeviceID,DriveLetter,ProtectionStatus,"
    "EncryptionMethod,VolumeType,LockStatus FROM Win32_EncryptableVolume` "
    "(namespace `root\\cimv2\\Security\\MicrosoftVolumeEncryption`)\n"
    "  • TPM: `SELECT * FROM Win32_Tpm` "
    "(namespace `root\\cimv2\\Security\\MicrosoftTpm`)\n"
    "  • Password policy: `SELECT MinimumPasswordLength,PasswordHistorySize,"
    "MaximumPasswordAge,MinimumPasswordAge,LockoutThreshold,LockoutDuration,"
    "LockoutObservationWindow FROM Win32_NetworkLoginProfile`\n"
    "Up to 5 queries per call.",
    {
        "asset_id": {"type": "integer"},
        "query": {
            "type": "string",
            "description": "Single WQL query (alternative to `queries`)",
        },
        "namespace": {
            "type": "string",
            "description": "Default namespace for `query` (default `root\\cimv2`)",
        },
        "queries": {
            "type": "array",
            "description": "Up to 5 queries; each `{namespace?, query}`",
            "items": {
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "query": {"type": "string"},
                },
                "required": ["query"],
            },
            "maxItems": 5,
        },
    },
)
def wmi_query_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")

    queries: list[dict[str, Any]] = list(params.get("queries") or [])
    if params.get("query"):
        queries.append({
            "namespace": params.get("namespace") or "root\\cimv2",
            "query": params["query"],
        })
    if not queries:
        return {"error": "must pass `query` or non-empty `queries`"}
    if len(queries) > 5:
        queries = queries[:5]

    _, result = _run_async(_dispatch(
        db, org_id, asset_id,
        {"wql": queries}, relay, cred,
    ))
    items = result.get("wql") or []
    out: list[dict[str, Any]] = []
    for entry in items:
        if entry.get("error"):
            out.append({
                "namespace": entry.get("namespace"),
                "query": entry.get("query"),
                "error": entry.get("error"),
            })
            continue
        rows = entry.get("rows") or []
        out.append({
            "namespace": entry.get("namespace"),
            "query": entry.get("query"),
            "row_count": len(rows),
            "rows": _trim(rows, 30),
        })
    return {"total_queries": len(out), "results": out}


# ── Method invocation (write/exec, gated by approval) ──────────────


@agent_tool(
    "wmi_invoke_method",
    "Invoke a WMI class method via DCOM ExecMethod. ALWAYS PAUSES for user "
    "approval — these are write/exec operations (process creation, service "
    "control, registry writes, firewall rule changes). The user signs off on "
    "every call before the relay touches the host. Common methods:\n"
    "  • `Win32_Process.Create(command_line, working_dir?, startup_info?)` — "
    "spawns a process. Returns ReturnValue=0 on success and ProcessId in "
    "out_params.\n"
    "  • `Win32_Service.StartService()` / `StopService()` / `ChangeStartMode("
    "start_mode)` / `Delete()` — service control. Set `target_path` to the "
    "instance, e.g. `Win32_Service.Name=\"Spooler\"`.\n"
    "  • `StdRegProv.SetStringValue(hive, key, value_name, value)` — registry "
    "write. Hive constants: HKLM=2147483650, HKU=2147483651, HKCR=2147483648.\n"
    "  • `StdRegProv.SetDWORDValue(hive, key, value_name, value)` — DWORD "
    "write.\n"
    "  • `StdRegProv.DeleteValue(hive, key, value_name)` / `DeleteKey(hive, "
    "key)`.\n"
    "  • `MSFT_NetFirewallRule.Delete()` (namespace `root\\StandardCimv2`) — "
    "remove a firewall rule (set `target_path` to the instance).\n"
    "Pass `arguments` as a list of positional values matching the method "
    "signature.",
    {
        "asset_id": {"type": "integer"},
        "class": {
            "type": "string",
            "description": "WMI class (e.g. 'Win32_Process', 'Win32_Service', 'StdRegProv')",
        },
        "method": {
            "type": "string",
            "description": "Method name (e.g. 'Create', 'StartService', 'SetStringValue')",
        },
        "arguments": {
            "type": "array",
            "description": "Positional args matching the method signature (omit for no-arg methods)",
        },
        "namespace": {
            "type": "string",
            "description": "WMI namespace (default 'root\\cimv2')",
        },
        "target_path": {
            "type": "string",
            "description": (
                "Instance reference for instance methods (e.g. "
                "'Win32_Service.Name=\"Spooler\"'). Omit for static methods "
                "like Win32_Process.Create."
            ),
        },
    },
)
def wmi_invoke_method_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    class_name = (params.get("class") or "").strip()
    method = (params.get("method") or "").strip()
    arguments = params.get("arguments") or []
    namespace = (params.get("namespace") or "root\\cimv2").strip()
    target_path = (params.get("target_path") or "").strip()

    if not class_name or not method:
        return {"error": "class and method are required"}

    if not params.get("_approved"):
        target = target_path or class_name
        raise NeedsApproval(
            reason=(
                f"WMI method invocation requires approval: "
                f"{target}.{method}({', '.join(repr(a) for a in arguments)}) "
                f"in {namespace}"
            ),
            category="wmi_invoke_method",
            details={
                "namespace": namespace,
                "class": class_name,
                "method": method,
                "target_path": target_path or None,
                "arguments": arguments,
            },
        )

    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    invocation = {
        "namespace": namespace,
        "class": class_name,
        "method": method,
        "arguments": arguments,
    }
    if target_path:
        invocation["target_path"] = target_path
    _, result = _run_async(_dispatch(
        db, org_id, asset_id,
        {"invoke": [invocation]}, relay, cred,
    ))
    items = result.get("invoke") or []
    if not items:
        return {"error": "no result returned from relay"}
    entry = items[0]
    if entry.get("error"):
        return {
            "namespace": entry.get("namespace"),
            "class": entry.get("class"),
            "method": entry.get("method"),
            "error": entry["error"],
        }
    return {
        "namespace": entry.get("namespace"),
        "class": entry.get("class"),
        "method": entry.get("method"),
        "target_path": entry.get("target_path"),
        "return_value": entry.get("return_value"),
        "out_params": entry.get("out_params") or {},
    }


# ── Registry primitive ──────────────────────────────────────────────


@agent_tool(
    "wmi_registry_read",
    "Read arbitrary registry keys/values on the target via StdRegProv over DCOM. "
    "Use for things WMI classes don't expose: SMBv1 state, LanMan compatibility "
    "level, audit policy, AlwaysInstallElevated, autologon credentials, stored "
    "app settings, etc. Three ops: `get_value` (read one value — type auto-"
    "detected), `enum_keys` (list subkey names), `enum_values` (list value "
    "names + types). Pass up to 20 reads in one call; each runs independently "
    "so permission errors on one key don't fail the rest. Hives: HKLM "
    "(default), HKU, HKCR. HKCU is NOT supported over the network — use "
    "HKU\\<SID> instead. Example: "
    "[{\"op\":\"get_value\",\"key\":\"SYSTEM\\\\CurrentControlSet\\\\"
    "Services\\\\LanmanServer\\\\Parameters\",\"value_name\":\"SMB1\"}].",
    {
        "asset_id": {"type": "integer"},
        "reads": {
            "type": "array",
            "description": (
                "Up to 20 read operations. Each: "
                "{op: 'get_value'|'enum_keys'|'enum_values', "
                "hive?: 'HKLM'|'HKU'|'HKCR' (default HKLM), "
                "key: 'Subkey\\\\Path', "
                "value_name?: required for get_value}"
            ),
            "items": {
                "type": "object",
                "properties": {
                    "op": {"type": "string", "enum": ["get_value", "enum_keys", "enum_values"]},
                    "hive": {"type": "string"},
                    "key": {"type": "string"},
                    "value_name": {"type": "string"},
                },
                "required": ["op", "key"],
            },
            "maxItems": 20,
        },
    },
)
def wmi_registry_read_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    reads = params.get("reads") or []
    if not isinstance(reads, list) or not reads:
        return {"error": "reads must be a non-empty list of read ops"}
    if len(reads) > 20:
        reads = reads[:20]
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch(
        db, org_id, asset_id,
        {"registry_reads": reads}, relay, cred,
    ))
    results = result.get("registry_read") or []

    slimmed: list[dict] = []
    for r in results:
        if r.get("type") == "REG_BINARY" and isinstance(r.get("data"), str) and len(r["data"]) > 256:
            r = {**r, "data": r["data"][:256], "_truncated": True}
        if r.get("type") == "REG_MULTI_SZ" and isinstance(r.get("data"), list) and len(r["data"]) > 20:
            r = {**r, "data": r["data"][:20] + ["..."], "_truncated": True}
        if r.get("op") == "enum_keys" and isinstance(r.get("subkeys"), list) and len(r["subkeys"]) > 100:
            r = {**r, "subkeys": r["subkeys"][:100] + ["..."], "_truncated": True}
        if r.get("op") == "enum_values" and isinstance(r.get("values"), list) and len(r["values"]) > 50:
            r = {**r, "values": r["values"][:50] + [{"name": "...", "type": "..."}], "_truncated": True}
        slimmed.append(r)
    return {"total": len(slimmed), "results": slimmed}


# ── ProtocolAudit registration ────────────────────────────────────────

_SHARED_TOOL_NAMES = [
    "wmi_query",
    "wmi_registry_read",
    # Write/exec primitive — every call routes through user approval.
    "wmi_invoke_method",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="wmi",
    label="WMI Audit",
    description=(
        "Credentialed Windows host audit over DCOM/WMI. A ReAct agent issues "
        "arbitrary WQL queries (and StdRegProv registry reads where WMI "
        "classes don't reach) to hunt for identity, privesc, software, and "
        "hygiene exposures."
    ),
    supported_os=["windows"],
    auth_modes=["basic"],
    relay_method="wmi_query",
    credential_connector_ids=["windows_host", "windows-host"],
    tool_names=_SHARED_TOOL_NAMES,
    required_ports=(135, 445),
    missions=[
        MissionTemplate(
            key="exposure_audit",
            label="Exposure Audit",
            description=(
                "End-to-end Windows exposure hunt: identity (local admins, "
                "stale accounts, password policy), privesc (unquoted service "
                "paths, AlwaysInstallElevated, dangerous startup commands), "
                "network hygiene (SMBv1, LLMNR, firewall, RDP NLA), CVE hunt "
                "via the correlator + config triage."
            ),
            prompt_key="wmi_audit_exposure_audit",
            suggested_budget=50,
            cost_hint="high",
        ),
    ],
))

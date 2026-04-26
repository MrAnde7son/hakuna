"""SMB tool palette for the SMB Audit ReAct agent.

Each tool dispatches a `method=smb_query` task to the relay. The relay handler
(hakuna-relay-agent/agent/smb_query.py) opens one impacket SMBConnection per
target and routes the task's `op` to the matching impacket operation:

  - `op="server_info"`   — negotiation info (dialect, signing state, OS)
  - `op="list_shares"`   — NetShareEnumAll + current caller's access probe
  - `op="list_contents"` — SMB2 find on one share's top-level path
  - `op="read_file"`     — read a bounded-size file (for known-public banners)
  - `op="null_bind"`     — anonymous auth attempt — null session viability
  - `op="check_pipe"`    — open-then-close \\PIPE\<name> to test reachability
  - `op="samr_enum_anon"` — SAMR user enum via null session (if available)

All tool results summarize rather than dump — raw output stays on the relay.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_SMB_TIMEOUT_S = 45


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_SMB_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_smb(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
    anonymous: bool = False,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    target, target_port = resolve_asset_target(asset)
    if not target:
        raise ValueError(f"asset {asset_id} has no hostname or ip")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    if anonymous:
        # Null session — explicit empty credentials; don't decrypt anything.
        smb_creds = {"username": "", "password": "", "domain": ""}
    else:
        if not credential_id:
            # Dispatched without a credential (e.g. SMB anonymous mission).
            # Surface a clean message so the LLM falls back to the *_anonymous
            # tool variants instead of seeing a raw traceback.
            raise ValueError(
                "no credential was provided for this audit — use the "
                "smb_*_anonymous tool variants, or rerun with a credential"
            )
        raw_creds = await load_credentials(db, credential_id, org_id)
        if not raw_creds:
            raise ValueError(f"credential {credential_id} not found")
        smb_creds = {
            "username": raw_creds.get("username", ""),
            "password": raw_creds.get("password", ""),
            "domain": raw_creds.get("domain", "") or "",
        }
        # Optional pass-the-hash passthrough.
        if raw_creds.get("lmhash") or raw_creds.get("nthash"):
            smb_creds["lmhash"] = raw_creds.get("lmhash", "")
            smb_creds["nthash"] = raw_creds.get("nthash", "")

    config: dict[str, Any] = {"target": target}
    if target_port:
        config["port"] = target_port

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="smb_query",
        config=config,
        credentials=smb_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _SMB_TIMEOUT_S,
                "anonymous": bool(anonymous)},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _trim(rows: list, limit: int = 30) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Orientation ───────────────────────────────────────────────────────


@agent_tool(
    "smb_get_server_info",
    "Return the target's SMB negotiation info: dialect, signing state, OS, "
    "server name, domain membership. Call once at the start of every audit.",
    {"asset_id": {"type": "integer"}},
)
def smb_get_server_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "server_info", {}, relay, cred))
    return result


@agent_tool(
    "smb_check_signing",
    "Return SMB signing state: 'required' (enforced) | 'enabled' (advertised but "
    "not enforced) | 'disabled'. `disabled` on any domain-joined host is high-severity "
    "(enables NTLM relay).",
    {"asset_id": {"type": "integer"}},
)
def smb_check_signing_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "server_info", {}, relay, cred))
    return {
        "signing": result.get("signing"),
        "dialect": result.get("dialect"),
        "dns_host_name": result.get("dns_host_name"),
    }


# ── Shares ────────────────────────────────────────────────────────────


@agent_tool(
    "smb_list_shares",
    "Enumerate SMB shares on the target with current caller's access probe "
    "(Read / Write / Denied). Flag writable non-admin shares + world-readable "
    "sensitive-looking shares.",
    {"asset_id": {"type": "integer"}},
)
def smb_list_shares_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "list_shares", {}, relay, cred))
    shares = result.get("shares") or []
    return {
        "total": len(shares),
        "shares": _trim(shares, 40),
    }


@agent_tool(
    "smb_list_share_contents",
    "List the top-level contents of one share (NOT recursive). Use to check "
    "for scripts/configs/unattend.xml/autologon.reg at share root. Returns up "
    "to 100 entries.",
    {
        "asset_id": {"type": "integer"},
        "share": {"type": "string", "description": "Share name (e.g. 'IT', 'Scripts')"},
        "path": {"type": "string", "description": "Path within the share; defaults to root"},
    },
)
def smb_list_share_contents_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    share = (params.get("share") or "").strip()
    path = (params.get("path") or "").strip() or "*"
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "list_contents",
                                          {"share": share, "path": path}, relay, cred))
    entries = result.get("entries") or []
    return {
        "share": share,
        "path": path,
        "total": len(entries),
        "entries": _trim(entries, 50),
        "interesting": [
            e for e in entries
            if any(str(e.get("name", "")).lower().endswith(suf) for suf in (
                ".ps1", ".bat", ".vbs", ".config", ".xml", ".ini",
                ".reg", ".bak", ".sql", ".kdbx", ".pem", ".key",
            )) or str(e.get("name", "")).lower() in ("unattend.xml", "sysprep.xml", "autologon.reg")
        ],
    }


# ── Auth posture ──────────────────────────────────────────────────────


@agent_tool(
    "smb_check_null_session",
    "Try an anonymous (null) SMB bind to IPC$. Returns whether null session "
    "is accepted. If yes, the host exposes significant information without auth.",
    {"asset_id": {"type": "integer"}},
)
def smb_check_null_session_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "null_bind", {},
                                          relay, cred, anonymous=True))
    return result


@agent_tool(
    "smb_list_shares_anonymous",
    "Enumerate shares via null session. Only call after smb_check_null_session "
    "confirms null bind works. Every share name returned here is "
    "anonymously visible.",
    {"asset_id": {"type": "integer"}},
)
def smb_list_shares_anonymous_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "list_shares", {},
                                          relay, cred, anonymous=True))
    return {"anonymous_shares": result.get("shares") or [], "error": result.get("error")}


@agent_tool(
    "smb_samr_enum_users_anonymous",
    "Try SAMR user enumeration via null session. If successful, returns the "
    "domain's users without authentication — classic legacy-Windows exposure.",
    {"asset_id": {"type": "integer"}},
)
def smb_samr_enum_users_anonymous_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "samr_enum_anon", {},
                                          relay, cred, anonymous=True))
    users = result.get("users") or []
    return {
        "anonymous_access": result.get("anonymous_access", False),
        "total_users": len(users),
        "users": _trim(users, 30),
        "error": result.get("error"),
    }


@agent_tool(
    "smb_check_guest_access",
    "Check whether the Guest account is usable for SMB logins (some hosts map "
    "invalid credentials to Guest instead of rejecting — a legacy misconfiguration).",
    {"asset_id": {"type": "integer"}},
)
def smb_check_guest_access_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    # Relay tries a bind with user="guest" password="" and reports whether it's granted.
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "guest_bind", {},
                                          relay, cred, anonymous=True))
    return result


# ── Coercion primitives (reachability only) ──────────────────────────


@agent_tool(
    "smb_check_named_pipe",
    "Check whether a specific SMB named pipe is reachable (open-then-close only). "
    "Classic coercion vectors: 'spoolss' (PrinterBug), 'efsrpc' / 'lsarpc' "
    "(PetitPotam), 'netdfs' (DFSCoerce), 'DAV RPC Service' (WebClient/WebDAV). "
    "Reachability ≠ exploitation, but it's the prerequisite.",
    {
        "asset_id": {"type": "integer"},
        "pipe_name": {"type": "string", "description": "Pipe name without \\PIPE\\ prefix"},
    },
)
def smb_check_named_pipe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    pipe_name = (params.get("pipe_name") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(db, org_id, asset_id, "check_pipe",
                                          {"pipe_name": pipe_name}, relay, cred))
    return result


# ── Password policy ──────────────────────────────────────────────────


@agent_tool(
    "smb_samr_password_policy",
    "Read the domain/local password and lockout policy via SAMR over "
    "\\PIPE\\samr using the authenticated SMB session. On a DC this returns "
    "the AD domain policy (may be overridden by Fine-Grained Password "
    "Policies, which this tool doesn't read); on a member host it returns "
    "the local SAM policy. Flag: min_length < 12, no complexity, "
    "lockout_threshold = 0 (no lockout), password_history < 5. Different "
    "from wmi_get_password_policy — SAMR is authoritative on DCs while "
    "Win32_NetworkLoginProfile reflects the login's *effective* view.",
    {"asset_id": {"type": "integer"}},
)
def smb_samr_password_policy_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(
        db, org_id, asset_id, "samr_password_policy", {}, relay, cred,
    ))
    if result.get("_errors"):
        return {"error": (result.get("_errors") or {}).get("samr_password_policy")}
    domains = result.get("domains") or []
    # Convert seconds → days for age fields so the agent's reasoning is cleaner.
    for d in domains:
        for key in ("max_password_age_seconds", "min_password_age_seconds"):
            v = d.get(key)
            if isinstance(v, int):
                d[key.replace("_seconds", "_days")] = v // 86400
    return {"total_domains": len(domains), "domains": domains}


# ── Registry ──────────────────────────────────────────────────────────


@agent_tool(
    "smb_registry_read",
    "Read arbitrary registry keys/values on the target via MS-RRP over "
    "\\PIPE\\winreg. Use this when WMI is blocked or unavailable — MS-RRP "
    "rides the same SMB session that's already authenticated. "
    "Supports three ops: `get_value` (read one value — type auto-detected), "
    "`enum_keys` (list subkeys), `enum_values` (list value names + types). "
    "Pass up to 20 reads in one call; each runs independently. "
    "Hives: HKLM (default), HKU, HKCR. "
    "Requires the RemoteRegistry service to be running on the target; if it's "
    "Disabled, `remote_registry_available=false` comes back and the agent "
    "should treat 'credentialed registry audit unavailable' as its own finding. "
    "Common checks: SMB signing enforcement (HKLM\\\\SYSTEM\\\\CurrentControlSet"
    "\\\\Services\\\\LanmanServer\\\\Parameters\\\\RequireSecuritySignature), "
    "LLMNR (HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\"
    "DNSClient\\\\EnableMulticast), autologon credentials "
    "(HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\"
    "Winlogon), audit policy, AlwaysInstallElevated.",
    {
        "asset_id": {"type": "integer"},
        "reads": {
            "type": "array",
            "description": (
                "Up to 20 read operations. Each: "
                "{op: 'get_value'|'enum_keys'|'enum_values', "
                "hive?: 'HKLM'|'HKU'|'HKCR' (default HKLM), "
                "key: 'Subkey\\\\Path', value_name?: required for get_value}"
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
def smb_registry_read_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    reads = params.get("reads") or []
    if not isinstance(reads, list) or not reads:
        return {"error": "reads must be a non-empty list of read ops"}
    if len(reads) > 20:
        reads = reads[:20]
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_smb(
        db, org_id, asset_id, "reg_read", {"reads": reads}, relay, cred,
    ))

    if result.get("remote_registry_available") is False:
        return {
            "remote_registry_available": False,
            "error": (result.get("_errors") or {}).get("reg_read")
                     or "RemoteRegistry unavailable — service may be Disabled",
        }

    slimmed: list[dict] = []
    for r in (result.get("results") or []):
        # Same trimming as the WMI variant — keep payloads LLM-friendly.
        if r.get("type") == "REG_BINARY" and isinstance(r.get("data"), str) and len(r["data"]) > 256:
            r = {**r, "data": r["data"][:256], "_truncated": True}
        if r.get("type") == "REG_MULTI_SZ" and isinstance(r.get("data"), list) and len(r["data"]) > 20:
            r = {**r, "data": r["data"][:20] + ["..."], "_truncated": True}
        if r.get("op") == "enum_keys" and isinstance(r.get("subkeys"), list) and len(r["subkeys"]) > 100:
            r = {**r, "subkeys": r["subkeys"][:100] + ["..."], "_truncated": True}
        if r.get("op") == "enum_values" and isinstance(r.get("values"), list) and len(r["values"]) > 50:
            r = {**r, "values": r["values"][:50] + [{"name": "...", "type": "..."}], "_truncated": True}
        slimmed.append(r)
    return {
        "remote_registry_available": True,
        "total": len(slimmed),
        "results": slimmed,
    }


_SMB_TOOL_NAMES = [
    # Orientation
    "smb_get_server_info", "smb_check_signing",
    # Shares
    "smb_list_shares", "smb_list_share_contents",
    # Auth posture
    "smb_check_null_session", "smb_list_shares_anonymous",
    "smb_samr_enum_users_anonymous", "smb_check_guest_access",
    "smb_samr_password_policy",
    # Coercion
    "smb_check_named_pipe",
    # Generic registry primitive — covers checks WMI classes don't expose
    # and works when RemoteRegistry is reachable but WMI/DCOM is blocked.
    "smb_registry_read",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="smb",
    label="SMB Audit",
    description=(
        "Credentialed SMB audit for share exposure, authentication posture, "
        "and coercion primitive reachability. Can operate with null credentials "
        "for legacy hosts that allow anonymous binds."
    ),
    supported_os=["windows"],
    auth_modes=["basic", "anonymous"],
    relay_method="smb_query",
    credential_connector_ids=["windows_host", "windows-host"],
    tool_names=_SMB_TOOL_NAMES,
    required_ports=(445, 139),
    safety_class="anon_standard",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("cis_benchmarks", "nist_csf_pr_ac"),
    missions=[
        MissionTemplate(
            key="share_audit",
            label="Share Audit",
            description="Writable shares, world-readable sensitive shares, interesting content at share roots.",
            prompt_key="smb_audit_share_audit",
            suggested_budget=15,
            cost_hint="low",
        ),
        MissionTemplate(
            key="signing_coercion",
            label="Signing & Coercion",
            description="SMB signing enforcement + PrinterBug/PetitPotam/DFSCoerce pipe reachability.",
            prompt_key="smb_audit_signing_coercion",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="null_session",
            label="Null Session",
            description="Anonymous SMB exposure — null-visible shares + SAMR user enum + guest account.",
            prompt_key="smb_audit_null_session",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about SMB-surface exposures.",
            prompt_key="smb_audit_explore",
            suggested_budget=20,
            cost_hint="medium",
        ),
    ],
))

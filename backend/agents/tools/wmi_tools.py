"""WMI tool palette for the WMI Audit ReAct agent.

Each tool is a thin wrapper that:
  1. Resolves the relay agent + credential for the target asset
  2. Fires a `method=wmi_query` task through the relay broker for a single profile
  3. Returns a **summary** to the LLM (counts + sampled rows + flagged anomalies)
     rather than raw row dumps — dumping 500 software rows costs 30k tokens;
     a summary + follow-up `wmi_get_user(name)` costs ~1k.

The tools intentionally have small, focused signatures. The agent chains them:
    wmi_list_local_users(asset_id) → notices 3 non-standard admins
      → wmi_get_user(asset_id, "svc-app1")        → sees pw_never_expires
      → wmi_list_group_members(asset_id, "Administrators")  → confirms membership
      → emit_finding(protocol="wmi", finding_type="privileged_service_account", ...)

At registration time this module also calls `register_audit(...)` to put the
WMI audit into the shared `AUDITS` dict — that's how the kickoff route
discovers what missions + tool palette + relay method this protocol uses.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any

from models.models import Asset, IntegrationCredential
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


# Task envelope timeout per profile. Keep short — one profile is cheap;
# a stuck DCOM call here means the whole agent step is stuck.
_PER_PROFILE_TIMEOUT_S = 60


# ── Relay dispatch helper ────────────────────────────────────────────


def _run_async(coro):
    """Bridge sync tool → async broker call.

    Mirrors the _run_async helper in agent_tools.py (trigger_easm_scan etc.)
    so the tool works whether the engine is running under asyncio or threads.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PER_PROFILE_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_profile(
    db,
    org_id: int,
    asset_id: int,
    profile: str,
    relay_agent_id: str | None = None,
    credential_id: str | None = None,
) -> tuple[Asset, dict]:
    """Resolve target + credential, send one profile to the relay.

    Raises on connection / credential / asset errors. Returns (asset, raw_rows).
    `relay_agent_id` and `credential_id` come from the `AgentRun.raw_metadata`
    injected by the audit runner — tools don't ask the LLM for them.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")

    target = asset.fqdn or asset.hostname or asset.ip
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

    wmi_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", ""),
        "domain": raw_creds.get("domain", "") or "",
    }

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="wmi_query",
        config={"target": target},
        credentials=wmi_creds,
        params={"profiles": [profile], "timeout_s": _PER_PROFILE_TIMEOUT_S},
    )
    rows = (result or {}).get(profile) or []
    return asset, rows


def _ctx(params: dict) -> tuple[str | None, str | None]:
    """Extract (relay_agent_id, credential_id) from the tool params.

    The audit runner stamps these into each tool call via the _agent_run_id
    injection hook; for bring-up we also accept them as explicit params.
    """
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


def _trim(rows: list, limit: int = 20) -> list:
    """Trim row lists for LLM consumption — keep first N + a '...' marker."""
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


# ── Enumeration tools ────────────────────────────────────────────────


@agent_tool(
    "wmi_list_local_users",
    "List local user accounts on a Windows host via WMI. Returns a summary: "
    "total count, disabled/locked counts, accounts with pw_never_expires, and "
    "up to 20 account names. Use this to spot suspicious local admins, stale "
    "accounts, or service accounts with weak password settings. "
    "FOLLOW UP with wmi_get_user(username) for any name that looks interesting.",
    {
        "asset_id": {"type": "integer", "description": "Target asset"},
    },
)
def wmi_list_local_users_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "local_users", relay, cred))

    summary = {
        "total": len(rows),
        "disabled": sum(1 for r in rows if r.get("Disabled")),
        "locked": sum(1 for r in rows if r.get("Lockout")),
        "password_never_expires": sum(1 for r in rows if r.get("PasswordExpires") is False),
        "password_not_required": sum(1 for r in rows if r.get("PasswordRequired") is False),
        "accounts": [
            {
                "name": r.get("Name"),
                "sid": r.get("SID"),
                "rid": (r.get("SID") or "").rsplit("-", 1)[-1] if r.get("SID") else None,
                "disabled": bool(r.get("Disabled")),
                "pw_never_expires": r.get("PasswordExpires") is False,
                "pw_not_required": r.get("PasswordRequired") is False,
            }
            for r in _trim(rows)
        ],
    }
    return summary


@agent_tool(
    "wmi_get_user",
    "Fetch full detail for one local user account. Use after wmi_list_local_users "
    "to drill into a specific account. Returns SID/RID, state flags, description, "
    "full name.",
    {
        "asset_id": {"type": "integer"},
        "username": {"type": "string", "description": "Exact local account name"},
    },
)
def wmi_get_user_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    username = (params.get("username") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "local_users", relay, cred))
    for r in rows:
        if (r.get("Name") or "").lower() == username.lower():
            return {
                "name": r.get("Name"),
                "sid": r.get("SID"),
                "rid": (r.get("SID") or "").rsplit("-", 1)[-1] if r.get("SID") else None,
                "full_name": r.get("FullName"),
                "description": r.get("Description"),
                "disabled": bool(r.get("Disabled")),
                "locked": bool(r.get("Lockout")),
                "password_expires": r.get("PasswordExpires"),
                "password_required": r.get("PasswordRequired"),
            }
    return {"error": f"user {username!r} not found on asset {asset_id}"}


@agent_tool(
    "wmi_list_local_groups",
    "List local groups on a Windows host. Returns up to 20 group names and "
    "flags any with classically-privileged names (Administrators, Remote Desktop "
    "Users, Backup Operators). Chain with wmi_list_group_members for any "
    "privileged group to see who's in it.",
    {
        "asset_id": {"type": "integer"},
    },
)
def wmi_list_local_groups_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "local_groups", relay, cred))
    privileged = {"administrators", "remote desktop users", "backup operators",
                  "remote management users", "hyper-v administrators"}
    return {
        "total": len(rows),
        "privileged_present": [
            r.get("Name") for r in rows
            if (r.get("Name") or "").lower() in privileged
        ],
        "groups": [
            {"name": r.get("Name"), "sid": r.get("SID"), "description": r.get("Description")}
            for r in _trim(rows)
        ],
    }


@agent_tool(
    "wmi_list_group_members",
    "List the members of one local group. Critical for Identity Audit — "
    "checking Administrators membership, finding unexpected accounts, spotting "
    "nested group structures.",
    {
        "asset_id":   {"type": "integer"},
        "group_name": {"type": "string", "description": "Exact group name (e.g. 'Administrators')"},
    },
)
def wmi_list_group_members_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    group_name = (params.get("group_name") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "group_membership", relay, cred))

    members: list[dict] = []
    for r in rows:
        # Parse the association class refs — GroupComponent and PartComponent
        # come back as strings like 'Win32_Group.Domain="HOST",Name="Administrators"'.
        gc = r.get("GroupComponent") or ""
        pc = r.get("PartComponent") or ""
        if f'Name="{group_name}"' not in gc and group_name.lower() not in gc.lower():
            continue
        members.append({
            "member_ref": pc,
            "domain": _parse_ref_field(pc, "Domain"),
            "name": _parse_ref_field(pc, "Name"),
            "kind": _parse_ref_kind(pc),
        })
    return {
        "group": group_name,
        "total_members": len(members),
        "members": _trim(members),
    }


@agent_tool(
    "wmi_list_services",
    "List Windows services on the host, optionally filtered. Returns name, "
    "state, startup type, run-as account, and PATH for each. Use for "
    "Privilege Escalation Audit — look for services running as LocalSystem "
    "whose binary PATH you might be able to hijack, or services with domain "
    "account run-as (kerberoastable via SPN).",
    {
        "asset_id":    {"type": "integer"},
        "run_as_filter": {"type": "string", "description": "Optional substring to filter StartName (e.g. 'DOMAIN\\\\' for domain accounts)"},
        "state_filter": {"type": "string", "description": "Optional: 'Running' | 'Stopped'"},
    },
)
def wmi_list_services_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    run_as_filter = (params.get("run_as_filter") or "").lower()
    state_filter = (params.get("state_filter") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "services_with_paths", relay, cred))

    def _match(r: dict) -> bool:
        if run_as_filter and run_as_filter not in (r.get("StartName") or "").lower():
            return False
        if state_filter and (r.get("State") or "") != state_filter:
            return False
        return True

    filtered = [r for r in rows if _match(r)]
    return {
        "total": len(filtered),
        "services": [
            {
                "name": r.get("Name"),
                "display_name": r.get("DisplayName"),
                "state": r.get("State"),
                "start_mode": r.get("StartMode"),
                "run_as": r.get("StartName"),
                "path": r.get("PathName"),
            }
            for r in _trim(filtered, 30)
        ],
    }


@agent_tool(
    "wmi_find_unquoted_service_paths",
    "Find Windows services whose binary PathName contains spaces but isn't "
    "quoted — classic privesc primitive (Trusted Service Path). Returns only "
    "the subset of services matching this pattern, with enough context for "
    "the agent to judge whether it's exploitable (writable parent dir).",
    {
        "asset_id": {"type": "integer"},
    },
)
def wmi_find_unquoted_service_paths_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "services_with_paths", relay, cred))

    vulnerable: list[dict] = []
    for r in rows:
        path = (r.get("PathName") or "").strip()
        if not path:
            continue
        # If it starts with a quote, it's already quoted — skip.
        if path.startswith('"'):
            continue
        # Split off arguments — classic check considers only the exe part.
        binary_part = path.split(" -")[0].split(" /")[0]
        if " " in binary_part and not binary_part.lower().endswith(".dll"):
            vulnerable.append({
                "name": r.get("Name"),
                "display_name": r.get("DisplayName"),
                "start_mode": r.get("StartMode"),
                "run_as": r.get("StartName"),
                "path": path,
            })
    return {
        "total_services": len(rows),
        "unquoted_path_services": vulnerable,
        "notes": (
            "Each listed service has an unquoted PathName containing spaces. "
            "This is privesc-exploitable only if a parent directory is writable "
            "by a non-admin user — confirm before emitting a critical finding."
        ),
    }


@agent_tool(
    "wmi_get_password_policy",
    "Read the effective password / lockout policy from Win32_NetworkLoginProfile. "
    "Returns min length, history size, max/min age, lockout threshold, lockout "
    "duration. Use for Identity Audit — flag weak policies (min length < 14, "
    "no lockout, short history).",
    {
        "asset_id": {"type": "integer"},
    },
)
def wmi_get_password_policy_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "password_policy", relay, cred))
    # Per-user rows; the domain/local baseline is represented by the first entry
    # where the relevant fields are populated. We surface the most common values.
    if not rows:
        return {"error": "no password policy data returned (Win32_NetworkLoginProfile unavailable)"}
    sample = rows[0]
    return {
        "min_password_length": sample.get("MinimumPasswordLength"),
        "password_history_size": sample.get("PasswordHistorySize"),
        "max_password_age_s": sample.get("MaximumPasswordAge"),
        "min_password_age_s": sample.get("MinimumPasswordAge"),
        "lockout_threshold": sample.get("LockoutThreshold"),
        "lockout_duration_s": sample.get("LockoutDuration"),
        "lockout_observation_window_s": sample.get("LockoutObservationWindow"),
        "row_count": len(rows),
    }


@agent_tool(
    "wmi_get_computer_system",
    "Fetch Win32_ComputerSystem — domain membership, role (DC / server / "
    "workstation), manufacturer, total memory. Use at the start of an audit "
    "to orient: is this a domain controller? a workstation? a server? The "
    "mission focus depends on the answer.",
    {
        "asset_id": {"type": "integer"},
    },
)
def wmi_get_computer_system_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "computer_system", relay, cred))
    if not rows:
        return {"error": "Win32_ComputerSystem unavailable"}
    r = rows[0]
    # DomainRole: 0=standalone workstation, 1=member workstation,
    # 2=standalone server, 3=member server, 4=backup DC, 5=primary DC.
    role_map = {0: "standalone_workstation", 1: "member_workstation",
                2: "standalone_server", 3: "member_server",
                4: "backup_domain_controller", 5: "primary_domain_controller"}
    role_code = r.get("DomainRole")
    return {
        "hostname": r.get("Name"),
        "domain": r.get("Domain"),
        "part_of_domain": bool(r.get("PartOfDomain")),
        "role": role_map.get(role_code, f"unknown({role_code})"),
        "is_domain_controller": role_code in (4, 5),
        "manufacturer": r.get("Manufacturer"),
        "model": r.get("Model"),
        "total_memory_bytes": r.get("TotalPhysicalMemory"),
    }


@agent_tool(
    "wmi_list_software",
    "List installed software (registry Uninstall walk — primary source). "
    "Returns a summary with count + top N by install date + vendor histogram. "
    "Use for Software/CVE audit — chain with query_threat_cves from the "
    "generic tool palette to correlate against known CVEs.",
    {
        "asset_id": {"type": "integer"},
        "name_filter": {"type": "string", "description": "Optional substring filter on software name"},
    },
)
def wmi_list_software_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    name_filter = (params.get("name_filter") or "").lower()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "software_uninstall", relay, cred))

    filtered = [r for r in rows if not name_filter or name_filter in (r.get("name") or "").lower()]
    vendors: dict[str, int] = {}
    for r in filtered:
        v = (r.get("vendor") or "").strip() or "<unknown>"
        vendors[v] = vendors.get(v, 0) + 1

    return {
        "total": len(filtered),
        "top_vendors": sorted(vendors.items(), key=lambda x: -x[1])[:10],
        "software": [
            {
                "name": r.get("name"),
                "version": r.get("version"),
                "vendor": r.get("vendor"),
                "installed_on": r.get("installed_on"),
            }
            for r in _trim(filtered, 30)
        ],
    }


@agent_tool(
    "wmi_list_patches",
    "List applied Windows hotfixes (KB IDs). Returns the patch set + the most "
    "recent InstalledOn date. Use to flag hosts with stale patch cadence "
    "(no KBs installed in the last 90d) or to check for specific CVE patches.",
    {
        "asset_id": {"type": "integer"},
    },
)
def wmi_list_patches_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "installed_hotfix_detail", relay, cred))
    return {
        "total": len(rows),
        "patches": [
            {
                "kb": r.get("HotFixID"),
                "description": r.get("Description"),
                "installed_by": r.get("InstalledBy"),
                "installed_on": r.get("InstalledOn"),
            }
            for r in _trim(rows, 50)
        ],
    }


# ── Parsing helpers ───────────────────────────────────────────────────


def _parse_ref_field(ref: str, field: str) -> str | None:
    """Extract `field="value"` from a Win32 association ref string."""
    if not ref:
        return None
    marker = f'{field}="'
    idx = ref.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker)
    end = ref.find('"', start)
    if end == -1:
        return None
    return ref[start:end]


def _parse_ref_kind(ref: str) -> str | None:
    """Extract the class name from a ref — 'Win32_Group' or 'Win32_UserAccount'."""
    if not ref:
        return None
    # Ref shape: '\\HOST\root\cimv2:Win32_Group.Domain="X",Name="Y"'
    if ":Win32_" not in ref:
        return None
    start = ref.find(":Win32_") + 1
    end = ref.find(".", start)
    return ref[start:end] if end > start else None


# ── ProtocolAudit registration ────────────────────────────────────────

# The missions share one tool palette. Prompt differences (in agent_prompts.py)
# steer the agent toward different hypotheses, but every mission can call
# every tool — the LLM picks.
_SHARED_TOOL_NAMES = [
    # Enumeration
    "wmi_list_local_users", "wmi_get_user",
    "wmi_list_local_groups", "wmi_list_group_members",
    "wmi_list_services", "wmi_find_unquoted_service_paths",
    "wmi_get_password_policy", "wmi_get_computer_system",
    "wmi_list_software", "wmi_list_patches",
    # Shared
    "emit_finding",
    # Generic context tools already registered in agent_tools.py
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="wmi",
    label="WMI Audit",
    description=(
        "Credentialed Windows host audit over DCOM/WMI. A ReAct agent probes "
        "local users, groups, services, software, patches, and password policy "
        "to hunt for identity, privesc, software, and hygiene exposures."
    ),
    supported_os=["windows"],
    auth_modes=["basic"],
    relay_method="wmi_query",
    credential_connector_ids=["windows_host", "windows-host"],
    tool_names=_SHARED_TOOL_NAMES,
    missions=[
        MissionTemplate(
            key="identity",
            label="Identity Audit",
            description="Hunt kerberoastable accounts, weak password policies, local admin bloat, stale accounts.",
            prompt_key="wmi_audit_identity",
            suggested_budget=20,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="privesc",
            label="Privilege Escalation Hunt",
            description="Weak service SDDL, unquoted service paths, writable binaries in %PATH%, AlwaysInstallElevated.",
            prompt_key="wmi_audit_privesc",
            suggested_budget=20,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="software_cve",
            label="Software & CVEs",
            description="Enumerate installed software + patches and correlate against threat intelligence for known CVEs.",
            prompt_key="wmi_audit_software_cve",
            suggested_budget=15,
            cost_hint="low",
        ),
        MissionTemplate(
            key="network_hygiene",
            label="Network Hygiene",
            description="SMBv1, LLMNR/NBT-NS, firewall state, RDP NLA, outdated OS build.",
            prompt_key="wmi_audit_network_hygiene",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about what's interesting on this host and emits any exposures it can justify.",
            prompt_key="wmi_audit_explore",
            suggested_budget=30,
            cost_hint="high",
        ),
    ],
))

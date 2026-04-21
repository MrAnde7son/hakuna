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


async def _dispatch_registry_reads(
    db,
    org_id: int,
    asset_id: int,
    reads: list[dict],
    relay_agent_id: str | None = None,
    credential_id: str | None = None,
) -> tuple[Asset, list[dict]]:
    """Like _dispatch_profile but for StdRegProv ad-hoc registry ops.

    The relay runs each op independently and returns the results in input
    order; one bad key (permission denied, missing subkey) doesn't wipe out
    the batch. This is why we send multiple reads in one round-trip instead
    of one per tool call — far cheaper over the wire.
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

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="wmi_query",
        config={"target": target},
        credentials={
            "username": raw_creds.get("username", ""),
            "password": raw_creds.get("password", ""),
            "domain": raw_creds.get("domain", "") or "",
        },
        params={"registry_reads": reads, "timeout_s": _PER_PROFILE_TIMEOUT_S},
    )
    return asset, (result or {}).get("registry_read") or []


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


# ── Security provider queries (cross-namespace) ─────────────────────


@agent_tool(
    "wmi_defender_status",
    "Query Windows Defender state via MSFT_MpComputerStatus "
    "(root\\Microsoft\\Windows\\Defender namespace). Returns realtime protection "
    "on/off, signature age, last scan age, tamper-protection state. Call this "
    "on any Windows host to detect disabled/stale AV — a gate check for many "
    "privilege escalation findings (an attacker can't dump LSASS if Defender "
    "is healthy). Returns an error gracefully if Defender isn't installed "
    "(3rd-party AV machines, stripped servers).",
    {"asset_id": {"type": "integer"}},
)
def wmi_defender_status_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "defender_status", relay, cred))
    if not rows:
        return {"installed": False, "note": "Defender not present or provider unreachable"}
    r = rows[0]  # singleton class
    return {
        "installed": True,
        "antivirus_enabled": r.get("AntivirusEnabled"),
        "antispyware_enabled": r.get("AntispywareEnabled"),
        "realtime_protection": r.get("RealTimeProtectionEnabled"),
        "behavior_monitor": r.get("BehaviorMonitorEnabled"),
        "on_access_protection": r.get("OnAccessProtectionEnabled"),
        "network_inspection": r.get("NISEnabled"),
        "tamper_protected": r.get("IsTamperProtected"),
        "tamper_protection_source": r.get("TamperProtectionSource"),
        "engine_version": r.get("AMEngineVersion"),
        "signature_last_updated": r.get("AntivirusSignatureLastUpdated"),
        "quick_scan_age_days": r.get("QuickScanAge"),
        "full_scan_age_days": r.get("FullScanAge"),
    }


@agent_tool(
    "wmi_firewall_profile",
    "Read Windows Firewall profile state via MSFT_NetFirewallProfile "
    "(root\\StandardCimv2 namespace). Returns one row per profile (Domain, "
    "Private, Public) with enabled state, default inbound/outbound action, "
    "logging config. A profile with Enabled=false is a finding on any host; "
    "DefaultInboundAction=Allow (value 4) is high-severity.",
    {"asset_id": {"type": "integer"}},
)
def wmi_firewall_profile_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "firewall_profile", relay, cred))
    action_map = {2: "Block", 4: "Allow", 0: "NotConfigured"}
    profiles = [
        {
            "name": r.get("Name"),
            "enabled": r.get("Enabled"),
            "default_inbound": action_map.get(int(r.get("DefaultInboundAction") or 0), r.get("DefaultInboundAction")),
            "default_outbound": action_map.get(int(r.get("DefaultOutboundAction") or 0), r.get("DefaultOutboundAction")),
            "log_allowed": r.get("LogAllowed"),
            "log_blocked": r.get("LogBlocked"),
            "log_file": r.get("LogFileName"),
            "allow_inbound_rules": r.get("AllowInboundRules"),
        }
        for r in rows
    ]
    return {
        "total": len(profiles),
        "profiles": profiles,
        "any_disabled": any(p.get("enabled") is False for p in profiles),
        "any_allow_inbound_default": any(p.get("default_inbound") == "Allow" for p in profiles),
    }


@agent_tool(
    "wmi_bitlocker_status",
    "Enumerate BitLocker-encryptable volumes via Win32_EncryptableVolume "
    "(root\\cimv2\\Security\\MicrosoftVolumeEncryption namespace). Returns "
    "protection status, encryption method, and conversion state per volume. "
    "ProtectionStatus=0 on C: is the canonical 'disk not encrypted' finding.",
    {"asset_id": {"type": "integer"}},
)
def wmi_bitlocker_status_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "bitlocker_volumes", relay, cred))
    # Protection: 0 unprotected, 1 protected, 2 unknown.
    prot_map = {0: "unprotected", 1: "protected", 2: "unknown"}
    method_map = {0: "none", 1: "AES128_diffuser", 2: "AES256_diffuser",
                  3: "AES128", 4: "AES256", 6: "XTS_AES128", 7: "XTS_AES256"}
    volumes = []
    for r in rows:
        prot = r.get("ProtectionStatus")
        method = r.get("EncryptionMethod")
        volumes.append({
            "drive": r.get("DriveLetter") or r.get("DeviceID"),
            "protection": prot_map.get(int(prot) if prot is not None else -1, prot),
            "encryption_method": method_map.get(int(method) if method is not None else -1, method),
            "volume_type": r.get("VolumeType"),
            "lock_status": r.get("LockStatus"),
        })
    return {
        "total_volumes": len(volumes),
        "volumes": volumes,
        "unprotected_volumes": [v["drive"] for v in volumes if v["protection"] == "unprotected"],
    }


@agent_tool(
    "wmi_tpm_status",
    "Query TPM chip presence and state via Win32_Tpm "
    "(root\\cimv2\\Security\\MicrosoftTpm namespace). Returns whether TPM is "
    "activated/enabled/owned + spec version. Workstations without an "
    "activated TPM can't run Credential Guard or modern BitLocker configs — "
    "often a finding on refurbished/imaged hosts.",
    {"asset_id": {"type": "integer"}},
)
def wmi_tpm_status_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "tpm_info", relay, cred))
    if not rows:
        return {"present": False, "note": "no TPM device or provider not installed"}
    r = rows[0]
    return {
        "present": True,
        "activated": r.get("IsActivated_InitialValue"),
        "enabled": r.get("IsEnabled_InitialValue"),
        "owned": r.get("IsOwned_InitialValue"),
        "manufacturer_id": r.get("ManufacturerId"),
        "manufacturer_version": r.get("ManufacturerVersion"),
        "spec_version": r.get("SpecVersion"),
    }


# ── Additional root\cimv2 inventory wrappers ────────────────────────


@agent_tool(
    "wmi_list_drivers",
    "Enumerate kernel-mode system drivers via Win32_SystemDriver. Returns "
    "name, state, start mode, and binary path. Drivers with StartMode in "
    "{Boot, System} loaded from non-standard paths (not under \\Windows\\) "
    "are a rootkit / legacy-driver indicator; chain with smb_registry_read "
    "or wmi_registry_read on HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name> "
    "for the full config.",
    {"asset_id": {"type": "integer"}},
)
def wmi_list_drivers_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "system_drivers", relay, cred))
    drivers = []
    suspicious: list[dict] = []
    for r in rows:
        path = (r.get("PathName") or "").strip('"')
        start_mode = r.get("StartMode")
        entry = {
            "name": r.get("Name"),
            "display_name": r.get("DisplayName"),
            "state": r.get("State"),
            "start_mode": start_mode,
            "path": path,
        }
        drivers.append(entry)
        # Boot/System drivers not in \Windows\ is a classic persistence signal.
        low = path.lower()
        if start_mode in ("Boot", "System") and low and not (
            low.startswith(r"\systemroot\\") or low.startswith(r"\??\c:\windows")
            or "\\windows\\system32\\" in low or "\\windows\\systemroot\\" in low
        ):
            suspicious.append(entry)
    return {
        "total": len(drivers),
        "drivers": _trim(drivers, 40),
        "suspicious_boot_drivers": suspicious,
    }


@agent_tool(
    "wmi_list_shares",
    "List SMB shares advertised by the target via Win32_Share. Use alongside "
    "smb_list_shares (which probes access from the caller's credentials); "
    "this view returns the server-side share config (name, path, type, max "
    "connections).",
    {"asset_id": {"type": "integer"}},
)
def wmi_list_shares_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "shares_detailed", relay, cred))
    shares = [
        {
            "name": r.get("Name"),
            "path": r.get("Path"),
            "description": r.get("Description"),
            "type": r.get("Type"),
            "max_connections": r.get("AllowMaximum"),
        }
        for r in rows
    ]
    return {"total": len(shares), "shares": _trim(shares, 30)}


@agent_tool(
    "wmi_list_startup_commands",
    "Enumerate startup items (Run keys, Startup folder entries) via "
    "Win32_StartupCommand. Each entry is a persistence mechanism — an "
    "attacker-controlled binary here survives reboots. Flag commands "
    "outside Program Files / \\Windows\\ or referencing user-writable paths.",
    {"asset_id": {"type": "integer"}},
)
def wmi_list_startup_commands_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "startup_commands", relay, cred))
    items = [
        {
            "name": r.get("Caption"),
            "command": r.get("Command"),
            "location": r.get("Location"),
            "user": r.get("User"),
            "user_sid": r.get("UserSID"),
        }
        for r in rows
    ]
    return {"total": len(items), "items": _trim(items, 30)}


@agent_tool(
    "wmi_list_scheduled_tasks_legacy",
    "Enumerate classic at.exe scheduled jobs via Win32_ScheduledJob. This is "
    "the LEGACY scheduler — modern scheduled tasks (Task Scheduler 2.0, the "
    "ones visible in taskschd.msc) live under \\Windows\\System32\\Tasks\\ as "
    "XML files; use smb_list_share_contents on ADMIN$ for those. Legacy "
    "at-jobs are rare on modern Windows — any hit is worth investigating.",
    {"asset_id": {"type": "integer"}},
)
def wmi_list_scheduled_tasks_legacy_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, rows = _run_async(_dispatch_profile(db, org_id, asset_id, "scheduled_tasks", relay, cred))
    jobs = [
        {
            "name": r.get("Caption"),
            "command": r.get("Command"),
            "owner": r.get("Owner"),
            "status": r.get("Status"),
            "job_id": r.get("JobId"),
        }
        for r in rows
    ]
    return {"total": len(jobs), "jobs": _trim(jobs, 30)}


# ── Registry read ─────────────────────────────────────────────────────


@agent_tool(
    "wmi_registry_read",
    "Read arbitrary registry keys/values on the target via StdRegProv over DCOM. "
    "This is the universal primitive for Windows config audits — use it for "
    "things WMI classes don't expose: SMBv1 state, LanMan compatibility level, "
    "audit policy, AlwaysInstallElevated, autologon credentials, stored app "
    "settings, etc. Supports three ops: "
    "`get_value` (read one value — auto-detects type), "
    "`enum_keys` (list subkey names under a key), "
    "`enum_values` (list value names + types under a key). "
    "Pass up to 20 reads in one call; each runs independently so permission "
    "errors on one key don't fail the rest. "
    "Hives: HKLM (default), HKU, HKCR. HKCU is NOT supported over the network — "
    "use HKU\\<SID> instead if you need a specific user's hive. "
    "Example: [{\"op\":\"get_value\",\"key\":\"SYSTEM\\\\CurrentControlSet\\\\"
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
    # Guard against runaway agents asking for hundreds of keys at once.
    if len(reads) > 20:
        reads = reads[:20]
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, results = _run_async(_dispatch_registry_reads(db, org_id, asset_id, reads, relay, cred))

    # Slim the payload per-result for LLM consumption: truncate long binary
    # blobs and multi_sz arrays so the agent doesn't burn tokens on a 4KB
    # REG_BINARY value it probably didn't need.
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
    # Security-provider queries (cross-namespace: Defender, firewall, BitLocker, TPM)
    "wmi_defender_status", "wmi_firewall_profile",
    "wmi_bitlocker_status", "wmi_tpm_status",
    # Inventory + persistence surfaces
    "wmi_list_drivers", "wmi_list_shares",
    "wmi_list_startup_commands", "wmi_list_scheduled_tasks_legacy",
    # Generic registry primitive — covers checks no WMI class exposes.
    "wmi_registry_read",
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

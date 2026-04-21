"""SSH tool palette for the Linux Audit ReAct agent.

Each tool dispatches a `method=ssh_query` task to the relay. The relay handler
(hakuna-relay-agent/agent/ssh_query.py) opens one paramiko SSHClient per
target and routes the task's `op` to a HARDCODED command or ALLOWLISTED file
read. There is no `run_command` escape hatch — the safety boundary is the
fact that the agent can't submit arbitrary shell input.

  - `op="sys_info"`           — uname + /etc/os-release + uptime
  - `op="read_file"`          — one allowlisted path (see _FILE_ALLOWLIST on relay)
  - `op="users"`              — /etc/passwd + /etc/group + /etc/shadow status
  - `op="sshd_config"`        — parsed sshd_config directives
  - `op="sudoers_effective"`  — sudo -ln + sudoers files
  - `op="find_suid"`          — SUID/SGID binaries (find -perm)
  - `op="listening_ports"`    — ss -tlnp
  - `op="installed_packages"` — dpkg/rpm/apk
  - `op="cron_scan"`          — crontab files
  - `op="process_list"`       — ps
  - `op="authorized_keys"`    — root + home authorized_keys metadata
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_SSH_TIMEOUT_S = 60


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_SSH_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_ssh(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
) -> tuple[Asset, dict]:
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

    ssh_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", "") or "",
        "private_key": raw_creds.get("private_key", "") or "",
        "private_key_passphrase": raw_creds.get("private_key_passphrase", "") or "",
        "port": raw_creds.get("port") or 22,
    }

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ssh_query",
        config={"target": target},
        credentials=ssh_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _SSH_TIMEOUT_S},
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


# ── Orientation ───────────────────────────────────────────────────────


@agent_tool(
    "ssh_get_system_info",
    "Return kernel (uname -a), OS release (/etc/os-release parsed: ID, NAME, "
    "VERSION_ID, PRETTY_NAME), and uptime. Call once at the start of every "
    "audit — the distro and version determine what findings matter.",
    {"asset_id": {"type": "integer"}},
)
def ssh_get_system_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "sys_info", {}, relay, cred))
    return result


@agent_tool(
    "ssh_read_file",
    "Read one file from the target's allowlist (/etc/os-release, sshd_config, "
    "/etc/passwd, /etc/group, /etc/shadow, sudoers, crontabs, /etc/hosts, "
    "/etc/resolv.conf, /etc/login.defs, pam.d/*, authorized_keys). Paths "
    "outside the allowlist are rejected by the relay. 256 KB cap.",
    {
        "asset_id": {"type": "integer"},
        "path": {"type": "string", "description": "Absolute path; must match allowlist"},
    },
)
def ssh_read_file_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    path = (params.get("path") or "").strip()
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "read_file",
                                          {"path": path}, relay, cred))
    return result


# ── Identity ──────────────────────────────────────────────────────────


@agent_tool(
    "ssh_list_users",
    "Parse /etc/passwd + /etc/group + /etc/shadow. Returns login-capable user "
    "count, every UID=0 account (should only be root — anything else is critical), "
    "and shadow entry STATUS only (empty / locked / disabled / hashed_<algo>). "
    "Password hashes themselves are never returned.",
    {"asset_id": {"type": "integer"}},
)
def ssh_list_users_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "users", {}, relay, cred))
    users = result.get("users") or []
    return {
        "user_count": result.get("user_count", len(users)),
        "login_capable_count": result.get("login_capable_count"),
        "uid0_accounts": result.get("uid0_accounts") or [],
        "shadow_readable": result.get("shadow_readable", False),
        "shadow_statuses": _trim(result.get("shadow_statuses") or [], 80),
        "users": _trim(users, 80),
        "errors": result.get("_errors") or {},
    }


@agent_tool(
    "ssh_get_sudoers",
    "Run `sudo -ln` for the current user and read /etc/sudoers + /etc/sudoers.d/*. "
    "Flag: NOPASSWD rules, rules granting ALL without command restriction, "
    "user:ALL=(ALL) with no password, and shell escapes (vi, less, awk, env) "
    "in permitted commands.",
    {"asset_id": {"type": "integer"}},
)
def ssh_get_sudoers_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "sudoers_effective", {}, relay, cred))
    return result


@agent_tool(
    "ssh_scan_authorized_keys",
    "Walk /root/.ssh/authorized_keys and every /home/*/.ssh/authorized_keys. "
    "Returns per-key metadata: file, line number, key type, SHA256 fingerprint, "
    "whether options (command=, from=, restrict) are present. Flag: keys "
    "with no restrictions on root; ecdsa/ssh-dss weak keys; keys with no comment.",
    {"asset_id": {"type": "integer"}},
)
def ssh_scan_authorized_keys_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "authorized_keys", {}, relay, cred))
    keys = result.get("keys") or []
    return {
        "files": result.get("files") or [],
        "total_keys": len(keys),
        "keys": _trim(keys, 60),
        "weak_key_types": [k for k in keys if k.get("key_type") in ("ssh-dss", "ssh-rsa")],
    }


# ── Hardening ─────────────────────────────────────────────────────────


@agent_tool(
    "ssh_get_sshd_config",
    "Return the parsed sshd_config directives relevant for audit: "
    "PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, "
    "ChallengeResponseAuthentication, MaxAuthTries, Ciphers, MACs, "
    "KexAlgorithms, X11Forwarding, UsePAM, ClientAliveInterval, and more. "
    "Flag: PermitRootLogin yes, PasswordAuthentication yes with no MFA, "
    "PermitEmptyPasswords yes, weak ciphers (arcfour, 3des-cbc, etc.).",
    {"asset_id": {"type": "integer"}},
)
def ssh_get_sshd_config_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "sshd_config", {}, relay, cred))
    return result


@agent_tool(
    "ssh_find_suid_binaries",
    "Find all SUID/SGID files on the root filesystem. Returns path, octal "
    "mode, owner, group. Flag: SUID on non-standard paths (/home, /tmp, /opt), "
    "SUID on known-exploitable binaries (nmap, vim, find, awk — GTFOBins), "
    "or SGID on anything in a user-writable directory.",
    {"asset_id": {"type": "integer"}},
)
def ssh_find_suid_binaries_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "find_suid", {}, relay, cred))
    binaries = result.get("binaries") or []
    return {"total": len(binaries), "binaries": _trim(binaries, 80)}


@agent_tool(
    "ssh_list_listening_ports",
    "Run `ss -tlnp` (netstat fallback) and return every listening TCP socket "
    "with its process. Flag: unexpected services on public interfaces, "
    "sensitive services (mysql, postgres, redis, memcached, docker API) on "
    "0.0.0.0, or processes running as root that shouldn't.",
    {"asset_id": {"type": "integer"}},
)
def ssh_list_listening_ports_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "listening_ports", {}, relay, cred))
    listeners = result.get("listeners") or []
    return {"total": len(listeners), "listeners": _trim(listeners, 80)}


@agent_tool(
    "ssh_list_installed_packages",
    "Detect the package manager (dpkg/rpm/apk) and list installed packages "
    "with versions. Useful for CVE correlation against the Software inventory. "
    "Capped at 5000 rows on the relay.",
    {"asset_id": {"type": "integer"}},
)
def ssh_list_installed_packages_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "installed_packages", {}, relay, cred))
    packages = result.get("packages") or []
    return {
        "package_manager": result.get("package_manager"),
        "total": len(packages),
        "packages": _trim(packages, 100),
    }


@agent_tool(
    "ssh_scan_cron_jobs",
    "Read /etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly}/*, and every "
    "user crontab in /var/spool/cron[/crontabs]/. Returns file contents + mode. "
    "Flag: world-writable crontab files, crontabs running as root invoking "
    "scripts in world-writable directories, or scripts with missing shebangs.",
    {"asset_id": {"type": "integer"}},
)
def ssh_scan_cron_jobs_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "cron_scan", {}, relay, cred))
    crontabs = result.get("crontabs") or []
    return {"total": len(crontabs), "crontabs": _trim(crontabs, 40)}


@agent_tool(
    "ssh_list_processes",
    "Run `ps -eo pid,user,comm,cmd` and return up to 400 processes. Useful "
    "after listening-port analysis to understand what's running.",
    {"asset_id": {"type": "integer"}},
)
def ssh_list_processes_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "process_list", {}, relay, cred))
    processes = result.get("processes") or []
    return {"total": len(processes), "processes": _trim(processes, 80)}


# ── Registry ──────────────────────────────────────────────────────────


_SSH_TOOL_NAMES = [
    # Orientation
    "ssh_get_system_info", "ssh_read_file",
    # Identity
    "ssh_list_users", "ssh_get_sudoers", "ssh_scan_authorized_keys",
    # Hardening
    "ssh_get_sshd_config", "ssh_find_suid_binaries",
    "ssh_list_listening_ports", "ssh_list_installed_packages",
    "ssh_scan_cron_jobs", "ssh_list_processes",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ssh",
    label="Linux Audit (SSH)",
    description=(
        "Credentialed Linux/Unix audit over SSH. A ReAct agent reads a curated "
        "allowlist of system files and runs read-only inspection commands to "
        "surface hardening (sshd_config, SUID, listening services), identity "
        "(users, sudoers, SSH keys), and software-inventory findings. There "
        "is no arbitrary command execution — every op is a hardcoded command "
        "or an allowlisted file read."
    ),
    supported_os=["linux", "unix", "macos"],
    auth_modes=["password", "key"],
    relay_method="ssh_query",
    credential_connector_ids=["linux_host", "linux-host"],
    tool_names=_SSH_TOOL_NAMES,
    missions=[
        MissionTemplate(
            key="hardening_posture",
            label="Hardening Posture",
            description="sshd_config weaknesses, SUID/SGID anomalies, listening services, kernel/OS patch level.",
            prompt_key="ssh_audit_hardening_posture",
            suggested_budget=20,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="identity_audit",
            label="Identity Audit",
            description="UID=0 accounts, shadow anomalies (locked/empty/weak algo), sudoers NOPASSWD, authorized_keys risk.",
            prompt_key="ssh_audit_identity_audit",
            suggested_budget=20,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="software_inventory",
            label="Software Inventory",
            description="Full package inventory from dpkg/rpm/apk for downstream CVE correlation.",
            prompt_key="ssh_audit_software_inventory",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about Linux exposures within the read-only boundary.",
            prompt_key="ssh_audit_explore",
            suggested_budget=25,
            cost_hint="high",
        ),
    ],
))

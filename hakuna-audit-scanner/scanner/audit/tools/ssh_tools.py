"""SSH tool palette for the Linux Audit ReAct agent.

Port of ``backend/agents/tools/ssh_tools.py``. Mechanical changes:

  - Drop ``models.models.Asset`` — handler takes ``AuditContext`` and
    reads asset fields off ``ctx.asset`` (a plain dict).
  - Drop ``services.credential_manager.load_credentials`` —
    credentials arrive on ``ctx.credentials`` (resolved upstream by
    the backend's ``services.audit_runner`` or by an OSS YAML loader).
  - Drop ``services.relay_broker.get_relay_broker`` — replaced by
    ``relay_client.get_relay_client``, an HTTP client to a single
    relay node. Same ``send_task`` signature, different transport.
  - Handler signature changes from ``(db, params)`` to ``(ctx, params)``.

Each tool dispatches a ``method=ssh_query`` task to the relay. The
relay handler (``hakuna-relay-agent/agent/ssh_query.py``) opens one
paramiko SSHClient per target and routes the task's ``op`` to a
HARDCODED command or ALLOWLISTED file read. There is no
``run_command`` escape hatch — the safety boundary is the fact that
the agent can't submit arbitrary shell input.

  - ``op="sys_info"``           — uname + /etc/os-release + uptime
  - ``op="read_file"``          — one allowlisted path (see _FILE_ALLOWLIST on relay)
  - ``op="users"``              — /etc/passwd + /etc/group + /etc/shadow status
  - ``op="sshd_config"``        — parsed sshd_config directives
  - ``op="sudoers_effective"``  — sudo -ln + sudoers files
  - ``op="find_suid"``          — SUID/SGID binaries (find -perm)
  - ``op="listening_ports"``    — ss -tlnp
  - ``op="installed_packages"`` — dpkg/rpm/apk
  - ``op="cron_scan"``          — crontab files
  - ``op="process_list"``       — ps
  - ``op="authorized_keys"``    — root + home authorized_keys metadata
"""

from __future__ import annotations

import logging
from typing import Any

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool
from scanner.audit.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from scanner.audit.relay_client import RelayDispatchError, get_relay_client
from scanner.audit.tools._target_utils import resolve_asset_target

logger = logging.getLogger(__name__)


_SSH_TIMEOUT_S = 60


# ── Dispatch helper ───────────────────────────────────────────────


async def _dispatch_ssh(
    ctx: AuditContext,
    op: str,
    op_params: dict | None = None,
) -> dict:
    """Send one ssh_query task to the relay. Raises ``RelayDispatchError``
    on transport failure; the tool wrapper converts that into a
    structured result the LLM can reason about."""
    if not ctx.target:
        raise ValueError("audit context has no target host")

    target_port = ctx.target_port
    if target_port is None:
        # Re-derive from asset.easm_data['audit_target_port'] for runs
        # where the worker didn't pre-set it.
        _, target_port = resolve_asset_target(ctx.asset)

    raw_creds = ctx.credentials or {}
    if not raw_creds.get("username"):
        raise ValueError("ssh credentials missing or have no username")

    ssh_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", "") or "",
        "private_key": raw_creds.get("private_key", "") or "",
        "private_key_passphrase": raw_creds.get("private_key_passphrase", "") or "",
        "port": target_port or raw_creds.get("port") or 22,
    }

    client = get_relay_client()
    return await client.send_task(
        agent_id=ctx.relay_agent_id,
        method="ssh_query",
        config={"target": ctx.target},
        credentials=ssh_creds,
        params={"op": op, "op_params": op_params or {}, "timeout_s": _SSH_TIMEOUT_S},
    )


def _trim(rows: list, limit: int = 40) -> list:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [{"_truncated": True, "_total": len(rows)}]


def _safe_dispatch(coro):
    """Helpers below are async; the engine awaits coroutine handlers
    natively. This wrapper only exists to translate
    ``RelayDispatchError`` into a structured tool result so the LLM
    sees an explainable error rather than the call raising into the
    engine."""
    raise NotImplementedError("use the async helpers — engine awaits them")


# ── Orientation ───────────────────────────────────────────────────


@agent_tool(
    "ssh_get_system_info",
    "Return kernel (uname -a), OS release (/etc/os-release parsed: ID, NAME, "
    "VERSION_ID, PRETTY_NAME), and uptime. Call once at the start of every "
    "audit — the distro and version determine what findings matter.",
    {},
)
async def ssh_get_system_info_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        return await _dispatch_ssh(ctx, "sys_info")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}


@agent_tool(
    "ssh_read_file",
    "Read one file from the target's allowlist (/etc/os-release, sshd_config, "
    "/etc/passwd, /etc/group, /etc/shadow, sudoers, crontabs, /etc/hosts, "
    "/etc/resolv.conf, /etc/login.defs, pam.d/*, authorized_keys). Paths "
    "outside the allowlist are rejected by the relay. 256 KB cap.",
    {
        "path": {"type": "string", "description": "Absolute path; must match allowlist"},
    },
)
async def ssh_read_file_tool(ctx: AuditContext, params: dict) -> dict:
    path = (params.get("path") or "").strip()
    try:
        return await _dispatch_ssh(ctx, "read_file", {"path": path})
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}


# ── Identity ──────────────────────────────────────────────────────


@agent_tool(
    "ssh_list_users",
    "Parse /etc/passwd + /etc/group + /etc/shadow. Returns login-capable user "
    "count, every UID=0 account (should only be root — anything else is critical), "
    "and shadow entry STATUS only (empty / locked / disabled / hashed_<algo>). "
    "Password hashes themselves are never returned.",
    {},
)
async def ssh_list_users_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "users")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
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
    {},
)
async def ssh_get_sudoers_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        return await _dispatch_ssh(ctx, "sudoers_effective")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}


@agent_tool(
    "ssh_scan_authorized_keys",
    "Walk /root/.ssh/authorized_keys and every /home/*/.ssh/authorized_keys. "
    "Returns per-key metadata: file, line number, key type, SHA256 fingerprint, "
    "whether options (command=, from=, restrict) are present. Flag: keys "
    "with no restrictions on root; ecdsa/ssh-dss weak keys; keys with no comment.",
    {},
)
async def ssh_scan_authorized_keys_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "authorized_keys")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    keys = result.get("keys") or []
    return {
        "files": result.get("files") or [],
        "total_keys": len(keys),
        "keys": _trim(keys, 60),
        "weak_key_types": [k for k in keys if k.get("key_type") in ("ssh-dss", "ssh-rsa")],
    }


# ── Hardening ─────────────────────────────────────────────────────


@agent_tool(
    "ssh_get_sshd_config",
    "Return the parsed sshd_config directives relevant for audit: "
    "PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, "
    "ChallengeResponseAuthentication, MaxAuthTries, Ciphers, MACs, "
    "KexAlgorithms, X11Forwarding, UsePAM, ClientAliveInterval, and more. "
    "Flag: PermitRootLogin yes, PasswordAuthentication yes with no MFA, "
    "PermitEmptyPasswords yes, weak ciphers (arcfour, 3des-cbc, etc.).",
    {},
)
async def ssh_get_sshd_config_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        return await _dispatch_ssh(ctx, "sshd_config")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}


@agent_tool(
    "ssh_find_suid_binaries",
    "Find all SUID/SGID files on the root filesystem. Returns path, octal "
    "mode, owner, group. Flag: SUID on non-standard paths (/home, /tmp, /opt), "
    "SUID on known-exploitable binaries (nmap, vim, find, awk — GTFOBins), "
    "or SGID on anything in a user-writable directory.",
    {},
)
async def ssh_find_suid_binaries_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "find_suid")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    binaries = result.get("binaries") or []
    return {"total": len(binaries), "binaries": _trim(binaries, 80)}


@agent_tool(
    "ssh_list_listening_ports",
    "Run `ss -tlnp` (netstat fallback) and return every listening TCP socket "
    "with its process. Flag: unexpected services on public interfaces, "
    "sensitive services (mysql, postgres, redis, memcached, docker API) on "
    "0.0.0.0, or processes running as root that shouldn't.",
    {},
)
async def ssh_list_listening_ports_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "listening_ports")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    listeners = result.get("listeners") or []
    return {"total": len(listeners), "listeners": _trim(listeners, 80)}


@agent_tool(
    "ssh_list_installed_packages",
    "Detect the package manager (dpkg/rpm/apk) and list installed packages "
    "with versions. Useful for CVE correlation against the Software inventory. "
    "Capped at 5000 rows on the relay.",
    {},
)
async def ssh_list_installed_packages_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "installed_packages")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
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
    {},
)
async def ssh_scan_cron_jobs_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "cron_scan")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    crontabs = result.get("crontabs") or []
    return {"total": len(crontabs), "crontabs": _trim(crontabs, 40)}


@agent_tool(
    "ssh_list_processes",
    "Run `ps -eo pid,user,comm,cmd` and return up to 400 processes. Useful "
    "after listening-port analysis to understand what's running.",
    {},
)
async def ssh_list_processes_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "process_list")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    processes = result.get("processes") or []
    return {"total": len(processes), "processes": _trim(processes, 80)}


# ── Firewall state ────────────────────────────────────────────────


@agent_tool(
    "ssh_firewall_state",
    "Detect active firewall (nftables / iptables / ufw / firewalld) and "
    "return the current rule set + default policies. An empty result "
    "(`no_firewall_detected=true`) on a non-containerized host is a "
    "finding. Compare default policies to the host's exposure — e.g., a "
    "public-facing host with default-ACCEPT INPUT chain is critical.",
    {},
)
async def ssh_firewall_state_tool(ctx: AuditContext, params: dict) -> dict:
    try:
        result = await _dispatch_ssh(ctx, "firewall")
    except RelayDispatchError as e:
        return {"error": f"relay_dispatch_failed: {e}"}
    for key in ("nftables", "iptables_v4", "iptables_v6"):
        if key in result and isinstance(result[key], dict):
            rules = result[key].get("rules") or ""
            if len(rules) > 4000:
                result[key]["rules"] = rules[:4000]
                result[key]["_truncated"] = True
    return result


# Phase-2 ports (sysctl/PAM/shadow/SELinux/systemd/containers/auditd/
# world-writable/cloud-metadata) follow the same mechanical edit:
# rename the handler signature, replace ``db`` lookups with
# ``ctx.asset``, replace credential vault calls with ``ctx.credentials``,
# replace ``get_relay_broker`` with ``get_relay_client``. Left out of
# the phase-1 skeleton to keep the diff reviewable.


# ── Registry ──────────────────────────────────────────────────────


_SSH_TOOL_NAMES = [
    # Orientation
    "ssh_get_system_info", "ssh_read_file",
    # Identity
    "ssh_list_users", "ssh_get_sudoers", "ssh_scan_authorized_keys",
    # Hardening
    "ssh_get_sshd_config", "ssh_find_suid_binaries",
    "ssh_list_listening_ports", "ssh_list_installed_packages",
    "ssh_scan_cron_jobs", "ssh_list_processes",
    # Firewall
    "ssh_firewall_state",
    # Shared
    "emit_finding",
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
    required_ports=(22,),
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
    ],
))

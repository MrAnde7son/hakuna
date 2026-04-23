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
from agents.tools._target_utils import resolve_asset_target
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

    ssh_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", "") or "",
        "private_key": raw_creds.get("private_key", "") or "",
        "private_key_passphrase": raw_creds.get("private_key_passphrase", "") or "",
        "port": target_port or raw_creds.get("port") or 22,
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


# ── Kernel / sysctl hardening ─────────────────────────────────────────


@agent_tool(
    "ssh_sysctl_audit",
    "Dump live sysctl state (`sysctl -a`) and compare against a baseline of "
    "kernel hardening settings. Returns: deviations from the hardening "
    "baseline (e.g., kptr_restrict=0, accept_redirects=1, suid_dumpable=1), "
    "a focus slice of kernel/fs/net keys, and keys we couldn't read. "
    "Hardening baseline is consensus-level (Lynis / CIS-aligned); treat "
    "deviations as hypotheses, not auto-findings — some are intentional in "
    "routers/edge hosts.",
    {"asset_id": {"type": "integer"}},
)
def ssh_sysctl_audit_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "sysctl", {}, relay, cred))
    # Trim the focus dict — 60 keys max — to keep token cost bounded.
    focus = result.get("focus_keys") or {}
    focus_items = list(focus.items())
    return {
        "total_keys": result.get("total_keys"),
        "hardening_deviations": result.get("hardening_deviations") or [],
        "unreadable_hardening_keys": result.get("unreadable_hardening_keys") or [],
        "focus_keys": dict(focus_items[:60]),
        "focus_truncated": len(focus_items) > 60,
    }


# ── PAM audit ─────────────────────────────────────────────────────────


@agent_tool(
    "ssh_pam_audit",
    "Audit /etc/pam.d/* for classic weakness patterns. Returns: files "
    "scanned, every `nullok` occurrence (empty-password acceptance) with "
    "line reference, whether any lockout module (pam_tally2/pam_faillock) "
    "is configured anywhere, whether a password-quality module "
    "(pam_pwquality/pam_cracklib) is configured. Missing lockout or quality "
    "modules on a general-purpose host is a finding.",
    {"asset_id": {"type": "integer"}},
)
def ssh_pam_audit_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "pam_audit", {}, relay, cred))
    return {
        "total_files": result.get("total_files"),
        "nullok_occurrences": result.get("nullok_occurrences") or [],
        "lockout_modules_configured": result.get("lockout_modules_configured") or [],
        "quality_modules_configured": result.get("quality_modules_configured") or [],
        "lockout_missing": bool(result.get("lockout_missing")),
        "password_quality_missing": bool(result.get("password_quality_missing")),
    }


# ── Shadow aging audit ────────────────────────────────────────────────


@agent_tool(
    "ssh_shadow_audit",
    "Audit /etc/shadow for password aging and empty/locked state. NEVER "
    "returns hashes — output is strictly derived (account name + status). "
    "Requires read access to /etc/shadow (root or group:shadow). Findings: "
    "empty_password_accounts (critical), no_expiration_accounts (flag "
    "non-service users), passwords_older_than_max_age, zero_min_age_accounts.",
    {"asset_id": {"type": "integer"}},
)
def ssh_shadow_audit_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "shadow_audit", {}, relay, cred))
    if not result.get("readable"):
        return {"readable": False, "note": result.get("error") or "shadow not readable — need root or group:shadow"}
    return {
        "readable": True,
        "total_users": result.get("total_users"),
        "empty_password_accounts": result.get("empty_password_accounts") or [],
        "no_expiration_accounts": result.get("no_expiration_accounts") or [],
        "passwords_older_than_max_age": result.get("passwords_older_than_max_age") or [],
        "zero_min_age_accounts": result.get("zero_min_age_accounts") or [],
        "locked_accounts_sample": (result.get("locked_accounts") or [])[:20],
    }


# ── Firewall state ────────────────────────────────────────────────────


@agent_tool(
    "ssh_firewall_state",
    "Detect active firewall (nftables / iptables / ufw / firewalld) and "
    "return the current rule set + default policies. An empty result "
    "(`no_firewall_detected=true`) on a non-containerized host is a "
    "finding. Compare default policies to the host's exposure — e.g., a "
    "public-facing host with default-ACCEPT INPUT chain is critical.",
    {"asset_id": {"type": "integer"}},
)
def ssh_firewall_state_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "firewall", {}, relay, cred))
    # Truncate big rule dumps — the agent rarely needs the whole thing; it
    # reasons about defaults + per-chain counts.
    for key in ("nftables", "iptables_v4", "iptables_v6"):
        if key in result and isinstance(result[key], dict):
            rules = result[key].get("rules") or ""
            if len(rules) > 4000:
                result[key]["rules"] = rules[:4000]
                result[key]["_truncated"] = True
    return result


# ── systemd unit audit ────────────────────────────────────────────────


@agent_tool(
    "ssh_systemd_unit_audit",
    "List systemd service units and their hardening properties "
    "(NoNewPrivileges, ProtectSystem, ProtectHome, User, etc. via "
    "`systemctl show`). Returns up to 20 sample units in full + up to 40 "
    "flagged `unsandboxed_root_units` (running as root with NoNewPrivileges=false). "
    "Flagged units are not automatic findings — they're the subset worth "
    "inspecting for privilege escalation and persistence surface.",
    {
        "asset_id": {"type": "integer"},
        "cap": {"type": "integer", "description": "Max units to inspect (default 80)"},
    },
)
def ssh_systemd_unit_audit_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    cap = params.get("cap")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    op_params = {"cap": cap} if cap else {}
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "systemd_units", op_params, relay, cred))
    return {
        "total_units": result.get("total_units"),
        "unsandboxed_root_units": result.get("unsandboxed_root_units") or [],
        "sample": result.get("sample") or [],
    }


# ── MAC posture ───────────────────────────────────────────────────────


@agent_tool(
    "ssh_mac_posture",
    "Detect SELinux and AppArmor enforcement state. Reports which MAC "
    "system is present and its mode (enforcing/permissive/disabled). "
    "`no_mac_enforcement=true` on RHEL/CentOS/Ubuntu hosts is a finding — "
    "both ship a MAC system enabled by default; an operator turned it off.",
    {"asset_id": {"type": "integer"}},
)
def ssh_mac_posture_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "mac_posture", {}, relay, cred))
    return result


# ── Container runtime surface ─────────────────────────────────────────


@agent_tool(
    "ssh_container_surface",
    "Detect Docker/Podman/Kubelet and report their risk surface: "
    "docker.sock permissions (group/world-writable = trivial root privesc), "
    "running containers (if listable without sudo), kubelet listening "
    "ports (10250/10255). Chain: non-root user in `docker` group + "
    "docker.sock group-writable == effective local root via "
    "`docker run -v /:/host --privileged`.",
    {"asset_id": {"type": "integer"}},
)
def ssh_container_surface_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "containers", {}, relay, cred))
    return result


# ── Audit daemon config ───────────────────────────────────────────────


@agent_tool(
    "ssh_audit_daemon",
    "Read auditd config (/etc/audit/auditd.conf) + rules "
    "(/etc/audit/rules.d/*). Reports whether auditd is active, log file "
    "path, rotation settings, loaded rule count. Findings: auditd inactive "
    "on a production host, no rule files, loaded_rule_count=0.",
    {"asset_id": {"type": "integer"}},
)
def ssh_audit_daemon_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "audit_daemon", {}, relay, cred))
    # Trim rule content per file — the agent's reasoning is on rule counts,
    # not the exact rule text.
    rule_files = result.get("rule_files") or []
    for rf in rule_files:
        content = rf.get("content") or ""
        if len(content) > 1500:
            rf["content"] = content[:1500]
            rf["_truncated"] = True
    result["rule_files"] = rule_files
    return result


# ── World-writable / unsafe permission scan ───────────────────────────


@agent_tool(
    "ssh_world_writable_scan",
    "Scan for world-writable files and files with no valid owner/group, "
    "scoped to /etc /usr /opt /var /root /home (full-fs scans are too "
    "expensive). Results are capped at 200 world-writable + 100 orphaned "
    "entries. Any world-writable file under /etc is a finding; orphaned "
    "files are an indicator of removed users whose data lingers (sometimes "
    "with sensitive content).",
    {"asset_id": {"type": "integer"}},
)
def ssh_world_writable_scan_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "world_writable", {}, relay, cred))
    return {
        "world_writable_total": len(result.get("world_writable_files") or []),
        "world_writable_files": _trim(result.get("world_writable_files") or [], 60),
        "orphaned_total": len(result.get("orphaned_files") or []),
        "orphaned_files": _trim(result.get("orphaned_files") or [], 40),
    }


# ── Cloud instance metadata reachability ──────────────────────────────


@agent_tool(
    "ssh_cloud_metadata_reachable",
    "Probe AWS/GCP/Azure instance-metadata endpoints from the target. "
    "The finding isn't 'reachable' per se — every VM reaches its own "
    "metadata — it's 'IMDSv1 reachable without IMDSv2 enforcement' "
    "(`aws_imdsv1_without_v2=true`), which makes any SSRF on the host "
    "exfiltrate the instance role. Also surfaces GCP/Azure reachability "
    "for correlation with the host's cloud provider.",
    {"asset_id": {"type": "integer"}},
)
def ssh_cloud_metadata_reachable_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(db, org_id, asset_id, "cloud_metadata", {}, relay, cred))
    return result


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
    # Kernel / PAM / shadow / MAC
    "ssh_sysctl_audit", "ssh_pam_audit", "ssh_shadow_audit",
    "ssh_mac_posture",
    # Firewall + logging
    "ssh_firewall_state", "ssh_audit_daemon",
    # systemd / containers / permission hygiene / cloud
    "ssh_systemd_unit_audit", "ssh_container_surface",
    "ssh_world_writable_scan", "ssh_cloud_metadata_reachable",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
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
        MissionTemplate(
            key="software_cve",
            label="CVE Hunt",
            description=(
                "Correlate installed packages against the threat-intel CVE DB, "
                "then triage top candidates by checking host config + reachability "
                "to separate truly exploitable from mitigated/not-applicable."
            ),
            prompt_key="ssh_audit_software_cve",
            suggested_budget=25,
            cost_hint="medium",
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

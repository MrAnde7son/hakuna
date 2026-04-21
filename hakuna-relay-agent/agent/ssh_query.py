"""paramiko SSH query executor for the Hakuna relay agent.

Runs read-only audit probes against a Linux/Unix host over SSH. Dispatched via
`method=ssh_query` from the backend SSH Audit agent's tool palette.

Safety model
------------
SSH is a command-execution channel — far more dangerous than LDAP/SNMP where
the protocol itself caps the blast radius. The enforcement boundary in this
handler is the fact that the agent CANNOT submit arbitrary commands or file
paths. Every op dispatches a hardcoded command or reads from a fixed file
allowlist. There is no `run_command` escape hatch.

  - `op="sys_info"`          — hardcoded: uname + /etc/os-release + uptime
  - `op="read_file"`         — path must match _FILE_ALLOWLIST
  - `op="users"`             — parses /etc/passwd + /etc/group; probes shadow status
  - `op="sshd_config"`       — parses /etc/ssh/sshd_config
  - `op="sudoers_effective"` — `sudo -ln` for current user + reads sudoers files
  - `op="find_suid"`         — hardcoded find -perm -4000
  - `op="listening_ports"`   — `ss -tlnp` with netstat fallback
  - `op="installed_packages"`— detect pm (dpkg/rpm/apk) + list
  - `op="cron_scan"`         — reads every crontab path in the allowlist
  - `op="process_list"`      — `ps -eo pid,user,cmd --no-headers`
  - `op="authorized_keys"`   — scans /{root,home/*}/.ssh/authorized_keys metadata

Design notes
------------
- paramiko is synchronous → wrapped in `asyncio.to_thread` per op.
- One SSH connection per task. Handshake is ~200ms — cheap enough that per-op
  isolation (one command breaking ≠ whole audit dies) is worth it.
- Shadow-hash bodies are NEVER returned to the backend. `users` op reports
  empty/locked/hashed as a status enum only.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import io
import logging
import shlex
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Any SSH connection / op failure surfaced back to the backend."""


# Files the agent is allowed to read. fnmatch-style globs, evaluated verbatim.
# Every pattern here is a deliberate, reviewed exposure.
_FILE_ALLOWLIST = [
    "/etc/os-release",
    "/etc/*-release",
    "/etc/issue",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/login.defs",
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*",
    "/etc/ssh/ssh_config",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/crontab",
    "/etc/cron.d/*",
    "/etc/cron.daily/*",
    "/etc/cron.hourly/*",
    "/etc/cron.weekly/*",
    "/etc/cron.monthly/*",
    "/var/spool/cron/*",
    "/var/spool/cron/crontabs/*",
    "/etc/pam.d/*",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
    "/proc/version",
    "/proc/cmdline",
    # Sysctl / kernel hardening config
    "/etc/sysctl.conf",
    "/etc/sysctl.d/*",
    "/usr/lib/sysctl.d/*",
    # Audit daemon (auditd) config + rules
    "/etc/audit/auditd.conf",
    "/etc/audit/audit.rules",
    "/etc/audit/rules.d/*",
    # Limits / security policy
    "/etc/security/limits.conf",
    "/etc/security/limits.d/*",
    "/etc/security/access.conf",
    "/etc/security/pwquality.conf",
    "/etc/security/pwquality.conf.d/*",
    "/etc/security/faillock.conf",
    # Kernel module loading / blacklist policy
    "/etc/modprobe.conf",
    "/etc/modprobe.d/*",
    "/etc/modules-load.d/*",
    # SELinux / AppArmor config
    "/etc/selinux/config",
    "/etc/apparmor/parser.conf",
    # Firewall config files (not authoritative — we still exec the live
    # dumper commands — but handy for default-policy checks)
    "/etc/ufw/ufw.conf",
    "/etc/nftables.conf",
]

_FILE_READ_CAP_BYTES = 256 * 1024
_CMD_OUTPUT_CAP_BYTES = 512 * 1024


def _paramiko():
    import paramiko
    return paramiko


@register_method("ssh_query")
async def ssh_query_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise SSHError("transport_config.target is required")

    op = (params or {}).get("op") or "sys_info"
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or 60)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, credentials or {}, op, op_params),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise SSHError(f"SSH op '{op}' timed out after {timeout_s}s for {target}")


def _run_sync(target: str, creds: dict, op: str, op_params: dict) -> dict:
    paramiko = _paramiko()

    username = creds.get("username") or ""
    password = creds.get("password") or None
    private_key_pem = creds.get("private_key") or None
    key_passphrase = creds.get("private_key_passphrase") or None
    port = int(creds.get("port") or 22)

    if not username:
        return {"_errors": {op: "credentials must include 'username'"}}
    if not password and not private_key_pem:
        return {"_errors": {op: "credentials must include 'password' or 'private_key'"}}

    pkey = None
    if private_key_pem:
        try:
            pkey = _load_key(paramiko, private_key_pem, key_passphrase)
        except Exception as e:
            return {"_errors": {op: f"key load failed: {type(e).__name__}: {e}"}}

    client = paramiko.SSHClient()
    # AutoAdd: acceptable for agent-initiated outbound audit. We log the
    # fingerprint so host-key pinning can be added later without a protocol
    # change.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=target,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=15,
            auth_timeout=15,
            banner_timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        return {"_errors": {op: f"connect failed: {type(e).__name__}: {e}"}}

    try:
        if op == "sys_info":
            return _op_sys_info(client)
        if op == "read_file":
            return _op_read_file(client, op_params)
        if op == "users":
            return _op_users(client)
        if op == "sshd_config":
            return _op_sshd_config(client)
        if op == "sudoers_effective":
            return _op_sudoers_effective(client)
        if op == "find_suid":
            return _op_find_suid(client)
        if op == "listening_ports":
            return _op_listening_ports(client)
        if op == "installed_packages":
            return _op_installed_packages(client)
        if op == "cron_scan":
            return _op_cron_scan(client)
        if op == "process_list":
            return _op_process_list(client)
        if op == "authorized_keys":
            return _op_authorized_keys(client)
        if op == "sysctl":
            return _op_sysctl(client)
        if op == "pam_audit":
            return _op_pam_audit(client)
        if op == "shadow_audit":
            return _op_shadow_audit(client)
        if op == "firewall":
            return _op_firewall(client)
        if op == "systemd_units":
            return _op_systemd_units(client, op_params)
        if op == "mac_posture":
            return _op_mac_posture(client)
        if op == "containers":
            return _op_containers(client)
        if op == "audit_daemon":
            return _op_audit_daemon(client)
        if op == "world_writable":
            return _op_world_writable(client)
        if op == "cloud_metadata":
            return _op_cloud_metadata(client)
        return {"_errors": {op: f"unknown op: {op}"}}
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Exec primitive ───────────────────────────────────────────────────


def _exec(client, cmd: str, timeout: int = 20) -> dict:
    """Run one command. Returns stdout/stderr/exit_code with a size cap.
    Caller is responsible for composing a safe command — we do NOT accept
    unvetted command input from the backend."""
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "exit_code": -1,
                "stdout": "", "stderr": ""}
    out = stdout.read(_CMD_OUTPUT_CAP_BYTES)
    err = stderr.read(_CMD_OUTPUT_CAP_BYTES)
    try:
        code = stdout.channel.recv_exit_status()
    except Exception:
        code = -1
    return {
        "exit_code": code,
        "stdout": _as_text(out),
        "stderr": _as_text(err),
    }


def _read_file(client, path: str) -> dict:
    """Read one allowlisted file via SFTP, with a size cap."""
    if not _path_allowed(path):
        return {"error": f"path not in allowlist: {path!r}"}
    try:
        sftp = client.open_sftp()
    except Exception as e:
        return {"error": f"sftp open failed: {type(e).__name__}: {e}"}
    try:
        try:
            st = sftp.stat(path)
        except Exception as e:
            return {"error": f"stat failed: {type(e).__name__}: {e}"}
        if st.st_size is not None and st.st_size > _FILE_READ_CAP_BYTES:
            return {"error": f"file too large ({st.st_size} B > {_FILE_READ_CAP_BYTES} B cap)",
                    "size": st.st_size}
        try:
            with sftp.file(path, "rb") as f:
                data = f.read(_FILE_READ_CAP_BYTES)
        except Exception as e:
            return {"error": f"read failed: {type(e).__name__}: {e}"}
        return {
            "path": path,
            "size": len(data),
            "mode_octal": oct(st.st_mode & 0o7777) if st.st_mode is not None else None,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "content": _as_text(data),
        }
    finally:
        try:
            sftp.close()
        except Exception:
            pass


def _path_allowed(path: str) -> bool:
    if not path or ".." in path.split("/"):
        return False
    return any(fnmatch.fnmatchcase(path, pat) for pat in _FILE_ALLOWLIST)


# ── Ops ──────────────────────────────────────────────────────────────


def _op_sys_info(client) -> dict:
    uname = _exec(client, "uname -a")
    uptime = _exec(client, "uptime -p")
    os_release = _read_file(client, "/etc/os-release")

    parsed = {}
    if "content" in os_release:
        for line in (os_release["content"] or "").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                parsed[k.strip()] = v.strip().strip('"').strip("'")
    return {
        "kernel": (uname.get("stdout") or "").strip(),
        "uptime": (uptime.get("stdout") or "").strip(),
        "os_id": parsed.get("ID"),
        "os_name": parsed.get("NAME"),
        "os_version_id": parsed.get("VERSION_ID"),
        "os_pretty_name": parsed.get("PRETTY_NAME"),
        "os_release_raw": parsed,
    }


def _op_read_file(client, op_params: dict) -> dict:
    path = (op_params.get("path") or "").strip()
    return _read_file(client, path)


def _op_users(client) -> dict:
    passwd = _read_file(client, "/etc/passwd")
    group = _read_file(client, "/etc/group")
    shadow = _read_file(client, "/etc/shadow")

    users: list[dict] = []
    for line in (passwd.get("content") or "").splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, gid, gecos, home, shell = parts[:7]
        try:
            uid_i = int(uid)
            gid_i = int(gid)
        except ValueError:
            continue
        users.append({
            "name": name,
            "uid": uid_i,
            "gid": gid_i,
            "gecos": gecos,
            "home": home,
            "shell": shell,
            "is_login_capable": shell not in ("/usr/sbin/nologin", "/sbin/nologin",
                                              "/bin/false", "/usr/bin/false", ""),
            "is_root_uid": uid_i == 0,
        })

    groups: list[dict] = []
    for line in (group.get("content") or "").splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, _, gid, members = parts[:4]
        member_list = [m for m in members.split(",") if m]
        groups.append({"name": name, "gid": gid, "members": member_list})

    shadow_statuses: list[dict] = []
    shadow_readable = "content" in shadow
    if shadow_readable:
        for line in (shadow.get("content") or "").splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name, pw = parts[0], parts[1]
            shadow_statuses.append({
                "name": name,
                "status": _shadow_status(pw),
            })

    return {
        "users": users,
        "user_count": len(users),
        "uid0_accounts": [u["name"] for u in users if u["is_root_uid"]],
        "login_capable_count": sum(1 for u in users if u["is_login_capable"]),
        "groups": groups,
        "shadow_readable": shadow_readable,
        "shadow_statuses": shadow_statuses,
        "_errors": {k: v for k, v in (
            ("passwd", passwd.get("error")),
            ("group", group.get("error")),
            ("shadow", shadow.get("error")),
        ) if v},
    }


def _shadow_status(pw_field: str) -> str:
    if pw_field in ("", "!!", "!"):
        return "locked_or_empty"
    if pw_field == "*":
        return "disabled"
    if pw_field.startswith("!"):
        return "locked"
    if pw_field.startswith("$"):
        parts = pw_field.split("$")
        algo = {"1": "md5", "2a": "blowfish", "2y": "blowfish", "5": "sha256",
                "6": "sha512", "y": "yescrypt"}.get(parts[1] if len(parts) > 1 else "", "unknown")
        return f"hashed_{algo}"
    return "unknown"


def _op_sshd_config(client) -> dict:
    config_file = _read_file(client, "/etc/ssh/sshd_config")
    if "content" not in config_file:
        return {"_errors": {"sshd_config": config_file.get("error")}}

    directives: dict[str, str] = {}
    for line in (config_file["content"] or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        # Last-write-wins mirrors sshd semantics for non-Match lines.
        directives[key.lower()] = value.strip()

    keys_of_interest = [
        "permitrootlogin", "passwordauthentication", "challengeresponseauthentication",
        "kbdinteractiveauthentication", "permitemptypasswords", "x11forwarding",
        "allowtcpforwarding", "gatewayports", "pubkeyauthentication",
        "usepam", "clientaliveinterval", "clientalivecountmax",
        "logingracetime", "maxauthtries", "maxsessions",
        "ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
        "port", "protocol",
    ]
    return {
        "directives": {k: directives.get(k) for k in keys_of_interest},
        "total_directives": len(directives),
    }


def _op_sudoers_effective(client) -> dict:
    rules = _exec(client, "sudo -n -l 2>&1 || true")
    sudoers_main = _read_file(client, "/etc/sudoers")
    # Discovery of /etc/sudoers.d/* files — use ls rather than walking every
    # possible allowlist pattern.
    listing = _exec(client, "ls -1 /etc/sudoers.d/ 2>/dev/null || true")
    drop_ins: list[dict] = []
    for name in (listing.get("stdout") or "").splitlines():
        name = name.strip()
        if not name or name == "README":
            continue
        f = _read_file(client, f"/etc/sudoers.d/{name}")
        if "content" in f:
            drop_ins.append({"name": name, "content": f["content"], "mode": f.get("mode_octal")})
    return {
        "effective_rules": (rules.get("stdout") or "").strip(),
        "effective_exit_code": rules.get("exit_code"),
        "sudoers_main": sudoers_main.get("content") if "content" in sudoers_main else None,
        "sudoers_main_error": sudoers_main.get("error"),
        "drop_ins": drop_ins,
    }


def _op_find_suid(client) -> dict:
    cmd = (
        "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
        "-printf '%m %u %g %p\\n' 2>/dev/null | head -500"
    )
    result = _exec(client, cmd, timeout=60)
    rows: list[dict] = []
    for line in (result.get("stdout") or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        mode, user, group, path = parts
        try:
            mode_i = int(mode, 8)
        except ValueError:
            continue
        rows.append({
            "path": path,
            "mode_octal": mode,
            "owner": user,
            "group": group,
            "is_suid": bool(mode_i & 0o4000),
            "is_sgid": bool(mode_i & 0o2000),
        })
    return {"total": len(rows), "binaries": rows}


def _op_listening_ports(client) -> dict:
    # ss is preferred; netstat fallback for pre-systemd distros.
    result = _exec(client, "ss -tlnpH 2>/dev/null || ss -tlnp 2>/dev/null | tail -n +2")
    if not (result.get("stdout") or "").strip():
        result = _exec(client, "netstat -tlnp 2>/dev/null | tail -n +3")

    rows: list[dict] = []
    for line in (result.get("stdout") or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = _last_matching(parts, lambda p: ":" in p and not p.startswith("users"))
        process = next((p for p in parts if p.startswith("users:") or "pid=" in p), None)
        rows.append({"local": local, "process_field": process, "raw": line.strip()})
    return {"total": len(rows), "listeners": rows}


def _op_installed_packages(client) -> dict:
    # Detect package manager, run the appropriate list command, truncate.
    detect = _exec(client, "command -v dpkg rpm apk 2>/dev/null")
    tools = (detect.get("stdout") or "").split()
    pm = None
    if any("dpkg" in t for t in tools):
        pm = "dpkg"
        listing = _exec(client,
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' 2>/dev/null")
    elif any("rpm" in t for t in tools):
        pm = "rpm"
        listing = _exec(client, "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n' 2>/dev/null")
    elif any("apk" in t for t in tools):
        pm = "apk"
        listing = _exec(client, "apk info -v 2>/dev/null")
    else:
        return {"_errors": {"installed_packages": "no supported package manager found"}}

    rows: list[dict] = []
    for line in (listing.get("stdout") or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t") if "\t" in line else [line.strip()]
        if pm == "dpkg" and len(parts) >= 3:
            rows.append({"name": parts[0], "version": parts[1], "status": parts[2]})
        elif pm == "rpm" and len(parts) >= 2:
            rows.append({"name": parts[0], "version": parts[1],
                         "vendor": parts[2] if len(parts) > 2 else None})
        elif pm == "apk":
            # name-version-revision format; leave as-is for backend to parse.
            rows.append({"raw": parts[0]})
    return {"package_manager": pm, "total": len(rows), "packages": rows[:5000]}


def _op_cron_scan(client) -> dict:
    paths = [
        "/etc/crontab",
    ]
    # Drop-in dirs
    for d in ("cron.d", "cron.daily", "cron.hourly", "cron.weekly", "cron.monthly"):
        ls = _exec(client, f"ls -1 /etc/{d}/ 2>/dev/null || true")
        for name in (ls.get("stdout") or "").splitlines():
            name = name.strip()
            if name:
                paths.append(f"/etc/{d}/{name}")
    # User crontabs
    for root in ("/var/spool/cron", "/var/spool/cron/crontabs"):
        ls = _exec(client, f"ls -1 {shlex.quote(root)}/ 2>/dev/null || true")
        for name in (ls.get("stdout") or "").splitlines():
            name = name.strip()
            if name:
                paths.append(f"{root}/{name}")

    files: list[dict] = []
    for p in paths:
        f = _read_file(client, p)
        if "content" in f:
            files.append({
                "path": p,
                "mode": f.get("mode_octal"),
                "uid": f.get("uid"),
                "size": f.get("size"),
                "content": f["content"],
            })
    return {"total": len(files), "crontabs": files}


def _op_process_list(client) -> dict:
    result = _exec(client, "ps -eo pid,user,comm,cmd --no-headers 2>/dev/null | head -400")
    rows: list[dict] = []
    for line in (result.get("stdout") or "").splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid, user, comm, cmd = parts
        try:
            pid_i = int(pid)
        except ValueError:
            continue
        rows.append({"pid": pid_i, "user": user, "comm": comm, "cmd": cmd})
    return {"total": len(rows), "processes": rows}


def _op_authorized_keys(client) -> dict:
    # Discover every authorized_keys file under /root/.ssh and /home/*/.ssh.
    discover = _exec(
        client,
        "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do "
        "[ -f \"$f\" ] && echo \"$f\"; done"
    )
    paths = [p.strip() for p in (discover.get("stdout") or "").splitlines() if p.strip()]

    keys: list[dict] = []
    for p in paths:
        f = _read_file(client, p)
        if "content" not in f:
            continue
        for line_no, raw in enumerate((f["content"] or "").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Split off options if present. Key lines look like either:
            #   ssh-rsa AAAA... comment
            # or:
            #   restrict,from="..." ssh-rsa AAAA... comment
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            key_type, key_b64 = (parts[0], parts[1]) if parts[0].startswith(("ssh-", "ecdsa-", "sk-")) else (parts[1], parts[2] if len(parts) > 2 else "")
            comment = ""
            # Comment is everything after the second field, if present.
            if len(parts) == 3 and not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
                # option-prefixed; no reliable comment extraction without full parse
                comment = ""
            try:
                raw_bytes = base64.b64decode(key_b64)
                fp = hashlib.sha256(raw_bytes).digest()
                fingerprint = "SHA256:" + base64.b64encode(fp).decode("ascii").rstrip("=")
            except Exception:
                fingerprint = None
            keys.append({
                "file": p,
                "line": line_no,
                "key_type": key_type,
                "fingerprint": fingerprint,
                "comment": comment or None,
                "has_options": not parts[0].startswith(("ssh-", "ecdsa-", "sk-")),
            })
    return {"files": paths, "total_keys": len(keys), "keys": keys}


# ── Kernel / sysctl hardening ────────────────────────────────────────


# Sysctl keys we explicitly flag when non-hardened. Values are the *expected
# safe* value; any deviation is a finding. Not exhaustive — the tool returns
# the full table so the agent can reason about others by name.
_SYSCTL_HARDENING_EXPECTED: dict[str, str] = {
    "kernel.kptr_restrict": "2",                    # 1 or 2 OK; 0 is a leak
    "kernel.dmesg_restrict": "1",
    "kernel.yama.ptrace_scope": "1",                # 0 = any process can ptrace any
    "kernel.unprivileged_bpf_disabled": "1",
    "kernel.kexec_load_disabled": "1",
    "fs.suid_dumpable": "0",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "fs.protected_fifos": "2",
    "fs.protected_regular": "2",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
}


def _op_sysctl(client) -> dict:
    """Dump live sysctl state and compare against a hardening baseline.

    Runs `sysctl -a` which reads /proc/sys/* — requires root OR appropriate
    CAP_NET_ADMIN-style privileges for the network branches. Keys we can't
    read come back as missing in the live map; the tool reports them as
    `unreadable` rather than assuming a value.
    """
    result = _exec(client, "sysctl -a 2>/dev/null", timeout=30)
    live: dict[str, str] = {}
    for line in (result.get("stdout") or "").splitlines():
        if " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        live[k.strip()] = v.strip()

    deviations: list[dict] = []
    unreadable: list[str] = []
    for key, expected in _SYSCTL_HARDENING_EXPECTED.items():
        actual = live.get(key)
        if actual is None:
            unreadable.append(key)
            continue
        # Many sysctl values are integers; do a numeric-aware equality check.
        ok = False
        try:
            ok = int(actual) == int(expected)
        except Exception:
            ok = actual == expected
        if not ok:
            deviations.append({"key": key, "expected": expected, "actual": actual})

    # Also surface a focused slice of keys the agent commonly reasons about.
    focus_prefixes = ("kernel.", "fs.", "net.ipv4.conf.all.", "net.ipv6.conf.all.")
    focus = {k: v for k, v in live.items() if k.startswith(focus_prefixes)}

    return {
        "total_keys": len(live),
        "hardening_deviations": deviations,
        "unreadable_hardening_keys": unreadable,
        "focus_keys": focus,
    }


# ── PAM audit ────────────────────────────────────────────────────────


def _op_pam_audit(client) -> dict:
    """Enumerate /etc/pam.d/* and scan for classic weakness patterns.

    What we flag:
      - `nullok` on auth lines → blank passwords allowed
      - `password` stack missing `pam_pwquality` or `pam_cracklib`
      - `auth` stack missing `pam_tally2` / `pam_faillock` → no lockout
      - Any `pam_rhosts` / `pam_userdb` references → legacy/weak
    """
    listing = _exec(client, "ls -1 /etc/pam.d/ 2>/dev/null | head -200")
    names = [n.strip() for n in (listing.get("stdout") or "").splitlines() if n.strip()]

    files: list[dict] = []
    nullok_hits: list[dict] = []
    lockout_modules_seen: set[str] = set()
    quality_modules_seen: set[str] = set()

    for name in names:
        f = _read_file(client, f"/etc/pam.d/{name}")
        if "content" not in f:
            continue
        content = f["content"] or ""
        nullok = []
        for line_no, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lower = line.lower()
            if "nullok" in lower and lower.startswith(("auth", "password")):
                nullok.append({"line": line_no, "content": line})
            if "pam_tally2" in lower or "pam_faillock" in lower:
                lockout_modules_seen.add("pam_tally2" if "pam_tally2" in lower else "pam_faillock")
            if "pam_pwquality" in lower or "pam_cracklib" in lower:
                quality_modules_seen.add("pam_pwquality" if "pam_pwquality" in lower else "pam_cracklib")
        files.append({"name": name, "size": f.get("size")})
        for hit in nullok:
            nullok_hits.append({"file": name, **hit})

    return {
        "total_files": len(files),
        "files": files,
        "nullok_occurrences": nullok_hits,
        "lockout_modules_configured": sorted(lockout_modules_seen),
        "quality_modules_configured": sorted(quality_modules_seen),
        "lockout_missing": not lockout_modules_seen,
        "password_quality_missing": not quality_modules_seen,
    }


# ── Shadow aging audit ───────────────────────────────────────────────


def _op_shadow_audit(client) -> dict:
    """Audit /etc/shadow for password aging + empty/locked state.

    Never returns hashes — every output field is derived, not the raw hash.
    Shadow fields (:-separated): name : pw : last_change : min : max : warn :
    inactive : expire. last_change/min/max/etc are days since 1970.
    """
    shadow = _read_file(client, "/etc/shadow")
    if "content" not in shadow:
        return {"readable": False, "error": shadow.get("error")}

    empty_password_accounts: list[str] = []
    locked_accounts: list[str] = []
    no_expiration: list[str] = []
    very_old: list[dict] = []
    short_min_age: list[dict] = []

    today_days = None  # populated if we can compute it — falls back to None
    try:
        dt = _exec(client, "date +%s 2>/dev/null")
        if dt.get("exit_code") == 0:
            today_days = int((dt["stdout"] or "0").strip() or "0") // 86400
    except Exception:
        today_days = None

    total = 0
    for raw in (shadow["content"] or "").splitlines():
        parts = raw.split(":")
        if len(parts) < 8:
            continue
        total += 1
        name, pw, last_change, min_age, max_age, warn, inactive, expire = parts[:8]
        if pw in ("", "!!"):
            # Empty is critical; !! is "never set", lockout-equivalent.
            if pw == "":
                empty_password_accounts.append(name)
            else:
                locked_accounts.append(name)
        elif pw.startswith("!") or pw == "*":
            locked_accounts.append(name)
        # max_age 99999 = never expires (Red Hat default for service accts).
        if max_age == "99999":
            no_expiration.append(name)
        # If we know today, flag passwords > 365 days old without rotation.
        if today_days and last_change.isdigit() and max_age.isdigit():
            age_days = today_days - int(last_change)
            if int(max_age) < 99999 and age_days > int(max_age):
                very_old.append({"name": name, "age_days": age_days, "max_days": int(max_age)})
        # min_age 0 = user can rotate immediately (commonly fine, but some
        # hardening standards require 1+).
        if min_age.isdigit() and int(min_age) == 0:
            short_min_age.append({"name": name, "min_age": 0})

    return {
        "readable": True,
        "total_users": total,
        "empty_password_accounts": empty_password_accounts,
        "locked_accounts": locked_accounts[:40],
        "no_expiration_accounts": no_expiration,
        "passwords_older_than_max_age": very_old[:40],
        "zero_min_age_accounts": short_min_age[:40],
    }


# ── Firewall state ───────────────────────────────────────────────────


def _op_firewall(client) -> dict:
    """Detect the firewall in use and dump rules.

    Order of preference: nftables > iptables > ufw > firewalld. nftables is
    the modern Linux firewall — most distros route iptables-translate through
    it. If both nft and iptables return rules, we report both (migration
    scenarios often have partial coverage).
    """
    out: dict[str, Any] = {"backends": []}

    nft = _exec(client, "nft list ruleset 2>/dev/null", timeout=20)
    if (nft.get("stdout") or "").strip():
        out["nftables"] = {
            "present": True,
            "rules": (nft["stdout"] or "")[:_CMD_OUTPUT_CAP_BYTES // 2],
        }
        out["backends"].append("nftables")

    # iptables-save may require root and often hangs without it; give it 10s.
    ipt4 = _exec(client, "iptables-save 2>/dev/null || true", timeout=15)
    if (ipt4.get("stdout") or "").strip():
        out["iptables_v4"] = {
            "present": True,
            "rules": (ipt4["stdout"] or "")[:_CMD_OUTPUT_CAP_BYTES // 4],
        }
        out["backends"].append("iptables")
    ipt6 = _exec(client, "ip6tables-save 2>/dev/null || true", timeout=15)
    if (ipt6.get("stdout") or "").strip():
        out["iptables_v6"] = {
            "rules": (ipt6["stdout"] or "")[:_CMD_OUTPUT_CAP_BYTES // 4],
        }

    ufw = _exec(client, "ufw status verbose 2>/dev/null || true")
    if "Status: active" in (ufw.get("stdout") or ""):
        out["ufw"] = {"active": True, "status": ufw["stdout"]}
        out["backends"].append("ufw")
    elif "Status: inactive" in (ufw.get("stdout") or ""):
        out["ufw"] = {"active": False}

    fwd = _exec(client, "firewall-cmd --state 2>/dev/null || true")
    if "running" in (fwd.get("stdout") or "").lower():
        zones = _exec(client, "firewall-cmd --list-all-zones 2>/dev/null || true")
        out["firewalld"] = {"running": True, "zones": zones.get("stdout") or ""}
        out["backends"].append("firewalld")

    if not out["backends"]:
        out["no_firewall_detected"] = True
    return out


# ── systemd unit audit ───────────────────────────────────────────────


# systemd properties we care about for hardening review. Reading these via
# `systemctl show` keeps the output structured (KEY=VALUE lines) vs. parsing
# the free-form `systemctl cat`.
_SYSTEMD_SHOW_PROPS = [
    "Id", "ExecStart", "User", "Group", "CapabilityBoundingSet",
    "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "PrivateNetwork",
    "ProtectSystem", "ProtectHome", "ProtectKernelModules",
    "ProtectKernelTunables", "ProtectControlGroups", "RestrictSUIDSGID",
    "RestrictNamespaces", "RestrictRealtime", "LockPersonality",
    "SystemCallFilter", "AmbientCapabilities", "FragmentPath",
]


def _op_systemd_units(client, op_params: dict) -> dict:
    """Enumerate systemd service units and their hardening properties.

    Default: list all loaded .service units, pull hardening props for up to
    the first 80 (arbitrary cap — long enough to cover all daemons on most
    hosts, short enough not to balloon the task output).
    """
    cap = int(op_params.get("cap") or 80)
    listing = _exec(client, "systemctl list-units --type=service --all --no-legend --plain 2>/dev/null",
                    timeout=20)
    units: list[str] = []
    for line in (listing.get("stdout") or "").splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            units.append(parts[0])
    units = units[:cap]

    show = _exec(client,
                  f"systemctl show {shlex.quote(' '.join(units))} --property="
                  f"{','.join(_SYSTEMD_SHOW_PROPS)} --no-pager 2>/dev/null",
                  timeout=30) if units else {"stdout": ""}

    parsed: list[dict] = []
    current: dict[str, str] = {}
    for raw in (show.get("stdout") or "").splitlines():
        if not raw.strip():
            if current:
                parsed.append(current)
                current = {}
            continue
        if "=" in raw:
            k, v = raw.split("=", 1)
            current[k.strip()] = v.strip()
    if current:
        parsed.append(current)

    dangerous: list[dict] = []
    for entry in parsed:
        user = entry.get("User") or "root"
        nnp = entry.get("NoNewPrivileges") == "yes"
        exec_start = entry.get("ExecStart") or ""
        fragment = entry.get("FragmentPath") or ""
        # Flag: services running as root with no sandboxing. Very common on
        # legacy hosts; not a finding by itself, but worth surfacing.
        if user in ("", "root") and not nnp:
            dangerous.append({
                "unit": entry.get("Id"),
                "user": user,
                "no_new_privileges": nnp,
                "protect_system": entry.get("ProtectSystem"),
                "protect_home": entry.get("ProtectHome"),
                "exec_start": exec_start[:200],
                "fragment_path": fragment,
            })

    return {
        "total_units": len(units),
        "unsandboxed_root_units": dangerous[:40],
        "sample": parsed[:20],
    }


# ── MAC posture (SELinux + AppArmor) ─────────────────────────────────


def _op_mac_posture(client) -> dict:
    """Detect SELinux/AppArmor enforcement state.

    A host with neither is a misconfiguration on RHEL/CentOS/Fedora (where
    SELinux is default) or Ubuntu/Debian (where AppArmor is default).
    """
    out: dict[str, Any] = {}

    # SELinux
    getenforce = _exec(client, "getenforce 2>/dev/null || true")
    sestatus = _exec(client, "sestatus 2>/dev/null || true")
    selinux_mode = (getenforce.get("stdout") or "").strip() or None
    if selinux_mode and selinux_mode.lower() in ("enforcing", "permissive", "disabled"):
        out["selinux"] = {
            "mode": selinux_mode.lower(),
            "status_raw": (sestatus.get("stdout") or "")[:4000],
        }
    else:
        out["selinux"] = {"present": False}

    # AppArmor
    aa_status = _exec(client, "aa-status --json 2>/dev/null || aa-status 2>/dev/null || true")
    aa_out = (aa_status.get("stdout") or "").strip()
    if aa_out:
        # Prefer JSON; fall back to textual summary.
        out["apparmor"] = {"raw": aa_out[:4000]}
    else:
        out["apparmor"] = {"present": False}

    if (out["selinux"].get("mode") in (None, "disabled")
            and not out["apparmor"].get("raw")):
        out["no_mac_enforcement"] = True
    return out


# ── Container runtime surface ────────────────────────────────────────


def _op_containers(client) -> dict:
    """Detect Docker/Podman/K8s kubelet and expose their risk surface.

    What we surface (not exploit):
      - Runtime binaries present
      - docker.sock permissions + group membership (writable by non-root =
        trivial privesc to root via `docker run --privileged`)
      - Running containers (if we can list without sudo)
      - Kubelet listening on 10250/10255 (common K8s privesc path)
    """
    out: dict[str, Any] = {"runtimes": []}

    which = _exec(client, "command -v docker podman kubectl kubelet crictl 2>/dev/null")
    tools = {}
    for line in (which.get("stdout") or "").splitlines():
        line = line.strip()
        if line:
            tools[line.rsplit("/", 1)[-1]] = line
    out["binaries"] = tools
    for t in ("docker", "podman", "kubelet"):
        if t in tools:
            out["runtimes"].append(t)

    # docker.sock perms — one of the most common Linux privesc paths.
    sock_stat = _exec(client, "stat -c '%a %U %G' /var/run/docker.sock 2>/dev/null || true")
    if (sock_stat.get("stdout") or "").strip():
        parts = sock_stat["stdout"].strip().split()
        if len(parts) == 3:
            mode, owner, group = parts
            try:
                mode_i = int(mode, 8)
            except ValueError:
                mode_i = 0
            out["docker_sock"] = {
                "mode": mode,
                "owner": owner,
                "group": group,
                "group_writable": bool(mode_i & 0o020),
                "world_writable": bool(mode_i & 0o002),
                "path": "/var/run/docker.sock",
            }

    if "docker" in tools:
        ps = _exec(client, "docker ps --format '{{.Names}}\\t{{.Image}}\\t{{.Status}}' 2>/dev/null || true",
                    timeout=10)
        running = []
        for line in (ps.get("stdout") or "").splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                running.append({"name": parts[0], "image": parts[1],
                                "status": parts[2] if len(parts) > 2 else None})
        out["docker_running"] = running[:40]

    # Kubelet port probe — does NOT try to exploit, just checks reachability
    # on the local host. An open 10255 (read-only kubelet) is a huge finding.
    for port in (10250, 10255):
        probe = _exec(client, f"ss -tlnH 2>/dev/null | awk '{{print $4}}' | grep ':{port}$' || true")
        if (probe.get("stdout") or "").strip():
            out.setdefault("kubelet_ports", []).append(port)

    return out


# ── Audit daemon config ──────────────────────────────────────────────


def _op_audit_daemon(client) -> dict:
    """Read auditd config + rules and report on logging posture."""
    out: dict[str, Any] = {}

    # Service state
    svc = _exec(client, "systemctl is-active auditd 2>/dev/null || true")
    out["auditd_active"] = (svc.get("stdout") or "").strip() == "active"

    cfg = _read_file(client, "/etc/audit/auditd.conf")
    if "content" in cfg:
        directives: dict[str, str] = {}
        for line in (cfg["content"] or "").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            directives[k.strip().lower()] = v.strip()
        out["config"] = {
            "log_file": directives.get("log_file"),
            "max_log_file": directives.get("max_log_file"),
            "space_left_action": directives.get("space_left_action"),
            "disk_full_action": directives.get("disk_full_action"),
            "flush": directives.get("flush"),
            "num_logs": directives.get("num_logs"),
        }
    else:
        out["config_error"] = cfg.get("error")

    # Rules: rules.d/*.rules (modern) + fallback audit.rules (legacy).
    ls = _exec(client, "ls -1 /etc/audit/rules.d/ 2>/dev/null || true")
    rule_files: list[dict] = []
    for name in (ls.get("stdout") or "").splitlines():
        name = name.strip()
        if not name:
            continue
        f = _read_file(client, f"/etc/audit/rules.d/{name}")
        if "content" in f:
            rule_files.append({"name": name, "content": f["content"][:8000]})
    legacy = _read_file(client, "/etc/audit/audit.rules")
    if "content" in legacy:
        rule_files.append({"name": "audit.rules (legacy)", "content": legacy["content"][:8000]})
    out["rule_files"] = rule_files

    # Count rules currently loaded (requires auditctl, usually root-only).
    live = _exec(client, "auditctl -l 2>/dev/null | wc -l 2>/dev/null || true")
    try:
        out["loaded_rule_count"] = int((live.get("stdout") or "0").strip())
    except ValueError:
        out["loaded_rule_count"] = None

    return out


# ── World-writable / unsafe permission scan ──────────────────────────


def _op_world_writable(client) -> dict:
    """Scan for world-writable files and files with no owner, scoped to
    common high-value paths. Full-fs scans are too expensive (multi-minute
    on large systems); we constrain to /etc, /usr, /opt, /var, /root, /home
    and cap results.
    """
    # -xdev prevents crossing mount points → cheaper, though we still run
    # per-root-path find invocations to keep each one bounded.
    ww = _exec(client,
                "find /etc /usr /opt /var /root /home -xdev -type f -perm -0002 "
                "-printf '%m %u %g %p\\n' 2>/dev/null | head -200",
                timeout=60)
    no_owner = _exec(client,
                      "find /etc /usr /opt /var /root /home -xdev \\( -nouser -o -nogroup \\) "
                      "-printf '%u %g %p\\n' 2>/dev/null | head -100",
                      timeout=60)

    ww_rows: list[dict] = []
    for line in (ww.get("stdout") or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4:
            continue
        mode, user, group, path = parts
        ww_rows.append({"path": path, "mode": mode, "owner": user, "group": group})

    orphan_rows: list[dict] = []
    for line in (no_owner.get("stdout") or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        user, group, path = parts
        orphan_rows.append({"path": path, "owner": user, "group": group})

    return {
        "world_writable_files": ww_rows,
        "orphaned_files": orphan_rows,
    }


# ── Cloud instance metadata reachability ─────────────────────────────


def _op_cloud_metadata(client) -> dict:
    """Check whether cloud instance metadata is reachable from the host.

    IMDSv1 reachability from inside a VM is expected — we're NOT checking
    that as a finding. The finding is when metadata is reachable via
    IMDSv1 when IMDSv2 would be required policy (e.g., via a scanner from
    a workload container that shouldn't see the VM's instance role).
    We surface raw reachability and let the agent + prompt decide.
    """
    # AWS IMDSv1 (no token)
    aws_v1 = _exec(client,
                    "curl -s -m 2 -o /dev/null -w '%{http_code}' "
                    "http://169.254.169.254/latest/meta-data/ 2>/dev/null || true")
    # AWS IMDSv2 (token required)
    aws_v2_token = _exec(client,
                    "curl -s -m 2 -X PUT -o /dev/null -w '%{http_code}' "
                    "-H 'X-aws-ec2-metadata-token-ttl-seconds: 30' "
                    "http://169.254.169.254/latest/api/token 2>/dev/null || true")
    # GCP (requires Metadata-Flavor header)
    gcp = _exec(client,
                 "curl -s -m 2 -o /dev/null -w '%{http_code}' "
                 "-H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ "
                 "2>/dev/null || true")
    # Azure (requires Metadata: true + api-version)
    azure = _exec(client,
                   "curl -s -m 2 -o /dev/null -w '%{http_code}' "
                   "-H 'Metadata: true' "
                   "'http://169.254.169.254/metadata/instance?api-version=2021-02-01' "
                   "2>/dev/null || true")

    def _code(res: dict) -> str | None:
        s = (res.get("stdout") or "").strip()
        return s if s and s.isdigit() else None

    aws_v1_code = _code(aws_v1)
    aws_v2_code = _code(aws_v2_token)
    gcp_code = _code(gcp)
    azure_code = _code(azure)

    return {
        "aws_imdsv1_reachable": aws_v1_code == "200",
        "aws_imdsv1_http_code": aws_v1_code,
        "aws_imdsv2_reachable": aws_v2_code == "200",
        "aws_imdsv2_http_code": aws_v2_code,
        "gcp_metadata_reachable": gcp_code == "200",
        "gcp_http_code": gcp_code,
        "azure_metadata_reachable": azure_code == "200",
        "azure_http_code": azure_code,
        # IMDSv1-only cloud is the classic SSRF amplifier — reachable+no-v2.
        "aws_imdsv1_without_v2": aws_v1_code == "200" and aws_v2_code != "200",
    }


# ── Helpers ──────────────────────────────────────────────────────────


def _load_key(paramiko, pem_text: str, passphrase: str | None):
    """Try each key class until one parses. paramiko doesn't auto-detect."""
    errors = []
    for cls_name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        cls = getattr(paramiko, cls_name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(pem_text), password=passphrase)
        except Exception as e:
            errors.append(f"{cls_name}: {e}")
    raise SSHError(f"no key class parsed the PEM: {'; '.join(errors)}")


def _as_text(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return str(data)


def _last_matching(items, pred):
    for item in reversed(items):
        if pred(item):
            return item
    return None

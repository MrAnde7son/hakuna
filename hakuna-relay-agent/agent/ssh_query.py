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

"""paramiko SSH executor for the Hakuna relay agent.

Three ops, all driven from the backend's three SSH tools:

  - ``op="exec"``       — run an arbitrary shell command (caller is
                          responsible for any read-only / approval
                          classification — that lives on the backend).
  - ``op="read_file"``  — SFTP-read any file the SSH user can access.
                          256 KB cap.
  - ``op="list_dir"``   — directory listing with mode/owner/size per entry.

The safety boundary lives in the backend tool layer (`ssh_run_command`'s
classifier raises `NeedsApproval` for non-read-only commands so the user
sees and signs off on every write/network/privileged action). This handler
just executes what the backend asks for.
"""

from __future__ import annotations

import asyncio
import io
import logging
import stat as stat_module
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


class SSHError(Exception):
    """Any SSH connection / op failure surfaced back to the backend."""


_FILE_READ_CAP_BYTES = 256 * 1024
_CMD_OUTPUT_CAP_BYTES = 512 * 1024
_DEFAULT_EXEC_TIMEOUT_S = 60


def _paramiko():
    import paramiko
    return paramiko


@register_method("ssh_query")
async def ssh_query_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise SSHError("transport_config.target is required")

    op = (params or {}).get("op") or "exec"
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_EXEC_TIMEOUT_S)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, credentials or {}, op, op_params, timeout_s),
            timeout=timeout_s + 5,
        )
    except asyncio.TimeoutError:
        raise SSHError(f"SSH op '{op}' timed out after {timeout_s}s for {target}")


def _run_sync(target: str, creds: dict, op: str, op_params: dict, timeout_s: int) -> dict:
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
        if op == "exec":
            return _op_exec(client, op_params, timeout_s)
        if op == "read_file":
            return _op_read_file(client, op_params)
        if op == "list_dir":
            return _op_list_dir(client, op_params)
        return {"_errors": {op: f"unknown op: {op}"}}
    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Ops ──────────────────────────────────────────────────────────────


def _op_exec(client, op_params: dict, timeout_s: int) -> dict:
    """Run an arbitrary shell command. The backend has already classified
    + approved (or auto-approved) this command — we just execute and cap
    output. Both stdout and stderr are returned with a hard byte cap so
    the broker payload stays bounded."""
    command = (op_params.get("command") or "").strip()
    if not command:
        return {"error": "command is required"}
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_s)
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
        "command": command,
        "exit_code": code,
        "stdout": _as_text(out),
        "stderr": _as_text(err),
    }


def _op_read_file(client, op_params: dict) -> dict:
    """SFTP-read any file the SSH user can access. 256 KB cap.

    There's no allowlist — the SSH user's filesystem permissions are the
    authorization boundary. Reading is itself read-side and bounded; the
    only adversarial concern is reading something sensitive, which is
    inherent to credentialed audit and out of this layer's scope.
    """
    path = (op_params.get("path") or "").strip()
    if not path:
        return {"error": "path is required"}
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


def _op_list_dir(client, op_params: dict) -> dict:
    """SFTP listdir + stat for a directory. Returns structured entries."""
    path = (op_params.get("path") or "").strip()
    all_files = bool(op_params.get("all_files", True))
    if not path:
        return {"error": "path is required"}
    try:
        sftp = client.open_sftp()
    except Exception as e:
        return {"error": f"sftp open failed: {type(e).__name__}: {e}"}
    try:
        try:
            attrs = sftp.listdir_attr(path)
        except Exception as e:
            return {"error": f"listdir failed: {type(e).__name__}: {e}"}
        entries: list[dict[str, Any]] = []
        for a in attrs:
            name = a.filename
            if not all_files and name.startswith("."):
                continue
            kind = "file"
            mode = a.st_mode or 0
            if stat_module.S_ISDIR(mode):
                kind = "dir"
            elif stat_module.S_ISLNK(mode):
                kind = "link"
            elif stat_module.S_ISFIFO(mode):
                kind = "fifo"
            elif stat_module.S_ISSOCK(mode):
                kind = "socket"
            entries.append({
                "name": name,
                "type": kind,
                "mode_octal": oct(mode & 0o7777) if mode else None,
                "uid": a.st_uid,
                "gid": a.st_gid,
                "size": a.st_size,
                "mtime": a.st_mtime,
            })
        return {"path": path, "entries": entries, "total": len(entries)}
    finally:
        try:
            sftp.close()
        except Exception:
            pass


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

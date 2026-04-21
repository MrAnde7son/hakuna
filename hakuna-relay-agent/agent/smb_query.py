"""impacket SMB query executor for the Hakuna relay agent.

Runs read-only SMB probes against a Windows/Samba host using impacket's
SMBConnection. Dispatched via `method=smb_query` from the backend SMB Audit
agent's tool palette.

Design notes
------------
- impacket is synchronous → wrapped in `asyncio.to_thread` per op.
- Every op uses a fresh connection. SMB connections are cheap; per-op isolation
  means one broken op doesn't poison a whole session.
- NEVER writes to the remote host. We bind to shares for read-access probes,
  open-then-close named pipes for reachability probes, and read a small bounded
  number of bytes via `openFile` for `read_file`. No share creation / writes /
  deletes.
- Anonymous / null-session mode is triggered by `params.anonymous=True`; we
  pass empty username/password strings, which impacket correctly treats as
  anonymous auth.

Result shape (per op):
    { <op-specific fields>, "_errors": { <op>: "..." } }
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


class SMBError(Exception):
    """Any SMB failure surfaced back to the backend."""


def _impacket():
    from impacket.smbconnection import SMBConnection, SessionError
    return SMBConnection, SessionError


@register_method("smb_query")
async def smb_query_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise SMBError("transport_config.target is required")

    op = (params or {}).get("op") or "server_info"
    op_params = (params or {}).get("op_params") or {}
    anonymous = bool((params or {}).get("anonymous"))
    timeout_s = int((params or {}).get("timeout_s") or 45)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, credentials or {}, op, op_params, anonymous),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise SMBError(f"SMB op '{op}' timed out after {timeout_s}s for {target}")


def _run_sync(target: str, creds: dict, op: str, op_params: dict, anonymous: bool) -> dict:
    SMBConnection, SessionError = _impacket()

    username = "" if anonymous else (creds.get("username", "") or "")
    password = "" if anonymous else (creds.get("password", "") or "")
    domain = "" if anonymous else (creds.get("domain", "") or "")
    lmhash = "" if anonymous else (creds.get("lmhash", "") or "")
    nthash = "" if anonymous else (creds.get("nthash", "") or "")

    try:
        conn = SMBConnection(target, target, sess_port=445, timeout=20)
    except Exception as e:
        return {"_errors": {op: f"connect failed: {type(e).__name__}: {e}"}}

    try:
        try:
            conn.login(username, password, domain, lmhash, nthash)
        except SessionError as e:
            return {"_errors": {op: f"login failed: {e}"}, "login_failed": True}
        except Exception as e:
            return {"_errors": {op: f"login failed: {type(e).__name__}: {e}"}, "login_failed": True}

        if op == "server_info":
            return _op_server_info(conn)
        if op == "null_bind":
            # If we reached here with anonymous=True, the login succeeded.
            return {"null_session": True, "dialect": _dialect(conn)}
        if op == "guest_bind":
            return _op_guest_bind(target, SMBConnection, SessionError)
        if op == "list_shares":
            return _op_list_shares(conn)
        if op == "list_contents":
            return _op_list_contents(conn, op_params)
        if op == "read_file":
            return _op_read_file(conn, op_params)
        if op == "check_pipe":
            return _op_check_pipe(conn, op_params)
        if op == "samr_enum_anon":
            return _op_samr_enum_anon(conn, target)
        return {"_errors": {op: f"unknown op: {op}"}}
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# ── Ops ──────────────────────────────────────────────────────────────


def _op_server_info(conn) -> dict:
    dialect_str = _dialect(conn)
    # Signing state from impacket: isSigningRequired() is SMB1-era; for SMB2+
    # we read from the negotiate response flags via conn.getSMBServer().
    signing = _signing_state(conn)

    info = {
        "dialect": dialect_str,
        "signing": signing,
        "server_name": conn.getServerName(),
        "dns_host_name": conn.getServerDNSHostName() or None,
        "dns_domain_name": conn.getServerDNSDomainName() or None,
        "server_os": conn.getServerOS() or None,
        "remote_name": conn.getRemoteName(),
        "remote_host": conn.getRemoteHost(),
    }
    return info


def _op_list_shares(conn) -> dict:
    try:
        raw = conn.listShares()
    except Exception as e:
        return {"_errors": {"list_shares": f"{type(e).__name__}: {e}"}, "shares": []}

    shares: list[dict] = []
    for s in raw:
        try:
            name = s["shi1_netname"][:-1] if s["shi1_netname"].endswith("\x00") else s["shi1_netname"]
        except Exception:
            name = str(s.get("shi1_netname", "")).rstrip("\x00")
        try:
            remark = s["shi1_remark"]
            remark = remark[:-1] if isinstance(remark, str) and remark.endswith("\x00") else remark
        except Exception:
            remark = None
        access = _probe_access(conn, name)
        shares.append({
            "name": name,
            "remark": remark,
            "access": access,
            "is_default": name.endswith("$"),
        })
    return {"shares": shares}


def _probe_access(conn, share: str) -> str:
    """Try a TreeConnect + a trivial list to classify read access. Writes are
    never probed — a "write" probe would require creating a file."""
    try:
        tid = conn.connectTree(share)
    except Exception:
        return "denied"
    try:
        try:
            conn.listPath(share, "*")
            return "read"
        except Exception:
            return "connect_only"
    finally:
        try:
            conn.disconnectTree(tid)
        except Exception:
            pass


def _op_list_contents(conn, op_params: dict) -> dict:
    share = op_params.get("share") or ""
    path = op_params.get("path") or "*"
    if not share:
        return {"_errors": {"list_contents": "share is required"}}
    try:
        entries = conn.listPath(share, path)
    except Exception as e:
        return {"_errors": {"list_contents": f"{type(e).__name__}: {e}"}, "entries": []}

    out = []
    for e in entries:
        try:
            name = e.get_longname()
        except Exception:
            name = None
        if not name or name in (".", ".."):
            continue
        out.append({
            "name": name,
            "size": getattr(e, "get_filesize", lambda: None)(),
            "is_directory": bool(getattr(e, "is_directory", lambda: False)()),
            "is_readonly": bool(getattr(e, "is_readonly", lambda: False)()),
        })
    return {"entries": out}


def _op_read_file(conn, op_params: dict) -> dict:
    """Read a bounded-size file. Cap hardcoded at 64 KB."""
    share = op_params.get("share") or ""
    path = op_params.get("path") or ""
    max_bytes = min(int(op_params.get("max_bytes") or 65536), 65536)
    if not share or not path:
        return {"_errors": {"read_file": "share and path are required"}}
    try:
        fid = conn.openFile(
            share, path, desiredAccess=0x80,  # FILE_READ_ATTRIBUTES | READ
        )
    except Exception as e:
        return {"_errors": {"read_file": f"open: {type(e).__name__}: {e}"}}
    try:
        data = conn.readFile(share, fid, offset=0, bytesToRead=max_bytes)
    except Exception as e:
        return {"_errors": {"read_file": f"read: {type(e).__name__}: {e}"}}
    finally:
        try:
            conn.closeFile(share, fid)
        except Exception:
            pass
    import base64
    return {
        "share": share, "path": path,
        "bytes_read": len(data or b""),
        "content_b64": base64.b64encode(data or b"").decode("ascii"),
    }


def _op_check_pipe(conn, op_params: dict) -> dict:
    """Open-then-close \\PIPE\\<name> on IPC$ to test reachability. No RPC bind."""
    pipe = (op_params.get("pipe_name") or "").strip()
    if not pipe:
        return {"_errors": {"check_pipe": "pipe_name is required"}}
    # Path shape: \PIPE\<name>
    full = f"\\{pipe}" if not pipe.startswith("\\") else pipe
    try:
        fid = conn.openFile("IPC$", full, desiredAccess=0x00100080)  # MAXIMUM_ALLOWED
    except Exception as e:
        return {"pipe": pipe, "reachable": False, "error": f"{type(e).__name__}: {e}"}
    try:
        return {"pipe": pipe, "reachable": True}
    finally:
        try:
            conn.closeFile("IPC$", fid)
        except Exception:
            pass


def _op_samr_enum_anon(conn, target: str) -> dict:
    """Enumerate users via SAMR RPC over \\PIPE\\samr — null session path."""
    try:
        from impacket.dcerpc.v5 import transport, samr
    except Exception as e:
        return {"_errors": {"samr_enum_anon": f"impacket import: {e}"}}

    rpctransport = transport.SMBTransport(conn.getRemoteName(), conn.getRemoteHost(),
                                           filename=r"\samr", smb_connection=conn)
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
    except Exception as e:
        return {"_errors": {"samr_enum_anon": f"bind: {type(e).__name__}: {e}"},
                "anonymous_access": False}

    users: list[dict] = []
    try:
        server_handle = samr.hSamrConnect(dce)["ServerHandle"]
        domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"]
        for d in domains:
            try:
                sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, d["Name"])["DomainId"]
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=sid)["DomainHandle"]
                enum = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
                for u in enum["Buffer"]["Buffer"]:
                    users.append({"rid": int(u["RelativeId"]), "name": str(u["Name"])})
                samr.hSamrCloseHandle(dce, domain_handle)
            except Exception:
                continue
        samr.hSamrCloseHandle(dce, server_handle)
    except Exception as e:
        return {"_errors": {"samr_enum_anon": f"enum: {type(e).__name__}: {e}"},
                "anonymous_access": True, "users": users}
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return {"anonymous_access": True, "users": users}


def _op_guest_bind(target: str, SMBConnection, SessionError) -> dict:
    """Open a fresh connection and try logging in as Guest."""
    try:
        c = SMBConnection(target, target, sess_port=445, timeout=15)
        c.login("guest", "", "")
        ok = True
    except Exception as e:
        ok = False
        err = f"{type(e).__name__}: {e}"
        return {"guest_accepted": False, "error": err}
    try:
        return {"guest_accepted": True}
    finally:
        try:
            c.logoff()
            c.close()
        except Exception:
            pass


# ── Helpers ──────────────────────────────────────────────────────────


def _dialect(conn) -> str:
    try:
        dialect = conn.getDialect()
    except Exception:
        return "unknown"
    # Impacket dialect codes — normalize to human labels.
    return {
        0x02ff: "SMB1",
        0x0202: "SMB2_002",
        0x0210: "SMB2_1",
        0x0300: "SMB3_0",
        0x0302: "SMB3_0_2",
        0x0311: "SMB3_1_1",
    }.get(dialect, f"0x{dialect:04x}") if isinstance(dialect, int) else str(dialect)


def _signing_state(conn) -> str:
    """Classify signing: 'required' | 'enabled' | 'disabled'.

    Impacket exposes isSigningRequired() for SMB1 and SMB2+; for SMB2+ the flag
    encodes 'enforced'. If we can't tell, return 'unknown'.
    """
    try:
        required = bool(conn.isSigningRequired())
    except Exception:
        return "unknown"
    return "required" if required else "disabled"

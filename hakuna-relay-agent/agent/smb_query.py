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
        if op == "reg_read":
            return _op_reg_read(conn, op_params)
        if op == "samr_password_policy":
            return _op_samr_password_policy(conn)
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


def _op_samr_password_policy(conn) -> dict:
    """Read domain password/lockout policy via SAMR over \\PIPE\\samr.

    Returns the effective policy for every enumerable domain on the target
    (typically the Builtin domain and the account domain — on a member host
    the account domain is the local SAM, on a DC it's the AD domain). This
    is a *credentialed* query: unlike _op_samr_enum_anon, we don't set
    anonymous=True at dispatch time, so it uses the authenticated SMB session.

    Policy fields come from SamrQueryInformationDomain (DOMAIN_PASSWORD_INFORMATION
    and DOMAIN_LOCKOUT_INFORMATION levels). Time fields are NT filetime deltas
    — negative int64 representing 100ns intervals. We convert to seconds for
    readability; the backend tool converts to days.
    """
    try:
        from impacket.dcerpc.v5 import transport, samr
    except Exception as e:
        return {"_errors": {"samr_password_policy": f"impacket import: {e}"}}

    rpctransport = transport.SMBTransport(
        conn.getRemoteName(), conn.getRemoteHost(),
        filename=r"\samr", smb_connection=conn,
    )
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
    except Exception as e:
        return {"_errors": {"samr_password_policy": f"bind: {type(e).__name__}: {e}"}}

    out_domains: list[dict] = []
    try:
        server_handle = samr.hSamrConnect(dce)["ServerHandle"]
        try:
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"]
        except Exception as e:
            return {"_errors": {"samr_password_policy": f"enum_domains: {type(e).__name__}: {e}"}}

        for d in domains:
            name = str(d["Name"])
            # Skip the Builtin domain — its password policy isn't user-facing.
            if name.lower() == "builtin":
                continue
            try:
                sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, name)["DomainId"]
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=sid)["DomainHandle"]
            except Exception as e:
                out_domains.append({"domain": name, "error": f"open: {type(e).__name__}: {e}"})
                continue
            entry: dict[str, Any] = {"domain": name}
            try:
                pw_info = samr.hSamrQueryInformationDomain(
                    dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
                )["Buffer"]["Password"]
                entry["min_password_length"] = int(pw_info["MinPasswordLength"])
                entry["password_history_length"] = int(pw_info["PasswordHistoryLength"])
                entry["password_properties"] = int(pw_info["PasswordProperties"])
                # DOMAIN_PASSWORD_COMPLEX = 0x1.
                entry["complexity_required"] = bool(int(pw_info["PasswordProperties"]) & 0x1)
                entry["max_password_age_seconds"] = _filetime_delta_seconds(pw_info["MaxPasswordAge"])
                entry["min_password_age_seconds"] = _filetime_delta_seconds(pw_info["MinPasswordAge"])
            except Exception as e:
                entry["password_error"] = f"{type(e).__name__}: {e}"
            try:
                lock_info = samr.hSamrQueryInformationDomain(
                    dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
                )["Buffer"]["Lockout"]
                entry["lockout_threshold"] = int(lock_info["LockoutThreshold"])
                entry["lockout_duration_seconds"] = _filetime_delta_seconds(lock_info["LockoutDuration"])
                entry["lockout_observation_seconds"] = _filetime_delta_seconds(lock_info["LockoutObservationWindow"])
            except Exception as e:
                entry["lockout_error"] = f"{type(e).__name__}: {e}"
            try:
                samr.hSamrCloseHandle(dce, domain_handle)
            except Exception:
                pass
            out_domains.append(entry)
        try:
            samr.hSamrCloseHandle(dce, server_handle)
        except Exception:
            pass
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return {"domains": out_domains}


def _filetime_delta_seconds(ft) -> int | None:
    """Convert SAMR's int64 FILETIME delta (100-ns intervals, negative) to seconds.

    SAMR returns -1 for "never" on things like MaxPasswordAge when disabled.
    We map that to None so the agent can reason about it explicitly.
    """
    try:
        # impacket wraps these in LARGE_INTEGER with HighPart/LowPart.
        high = int(ft["HighPart"])
        low = int(ft["LowPart"]) & 0xFFFFFFFF
        val = (high << 32) | low
        # Treat the two-complement high bit as signed.
        if high & 0x80000000:
            val -= 1 << 64
        if val == -1 or val == 0:
            return None
        # Delta is negative for "X time from now"; flip to positive seconds.
        return abs(val) // 10_000_000
    except Exception:
        return None


# ── Remote registry (MS-RRP over \PIPE\winreg) ──────────────────────

# Human hive name → rrp open-hive function. We bind these lazily inside
# _op_reg_read because impacket isn't importable at module load on relays
# that don't do SMB audits.
_HIVE_OPENERS = {
    "HKLM": "hOpenLocalMachine",
    "HKEY_LOCAL_MACHINE": "hOpenLocalMachine",
    "HKU": "hOpenUsers",
    "HKEY_USERS": "hOpenUsers",
    "HKCR": "hOpenClassesRoot",
    "HKEY_CLASSES_ROOT": "hOpenClassesRoot",
}

# Numeric registry value types → human label. Used to normalize rrp output.
_REG_TYPE_LABELS = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def _op_reg_read(conn, op_params: dict) -> dict:
    """Execute a batch of registry read ops over \\PIPE\\winreg (MS-RRP).

    `op_params.reads` is a list of `{op, hive, key, value_name?}` entries.
    The connection is shared across all reads in the batch so we pay the pipe
    open + RPC bind cost once. Per-op errors are captured, not raised —
    permission-denied on one key shouldn't wipe out a 10-read batch.

    RemoteRegistry must be running on the target (modern Windows sets it to
    Manual/Trigger Start; opening \\PIPE\\winreg as an admin usually
    trigger-starts it). If it's disabled, the first bind fails with a clear
    error that the agent can surface as a finding.
    """
    reads = (op_params or {}).get("reads") or []
    if not isinstance(reads, list) or not reads:
        return {"_errors": {"reg_read": "reads must be a non-empty list"}}

    try:
        from impacket.dcerpc.v5 import transport, rrp
    except Exception as e:
        return {"_errors": {"reg_read": f"impacket import: {e}"}}

    rpctransport = transport.SMBTransport(
        conn.getRemoteName(), conn.getRemoteHost(),
        filename=r"\winreg", smb_connection=conn,
    )
    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
    except Exception as e:
        # Common failure: RemoteRegistry service is Disabled. The agent can
        # turn this into a finding ("credentialed registry audit unavailable")
        # but we still return structured detail.
        return {"_errors": {"reg_read": f"bind \\winreg failed: {type(e).__name__}: {e}"},
                "remote_registry_available": False}

    results: list[dict] = []
    try:
        # Cache open hive handles across reads — opening HKLM 20 times is
        # wasteful. `dce` owns the handles; they're closed implicitly when
        # we disconnect in finally.
        hive_handles: dict[str, Any] = {}
        for req in reads[:20]:  # hard cap mirrors the backend tool
            results.append(_do_reg_read(dce, rrp, req, hive_handles))
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return {"remote_registry_available": True, "results": results}


def _do_reg_read(dce, rrp, req: dict, hive_handles: dict) -> dict:
    """Run one registry op. All exceptions map to `{error: ...}` on the result."""
    op = (req.get("op") or "get_value").strip()
    hive_name = (req.get("hive") or "HKLM").strip().upper()
    key = (req.get("key") or "").strip()
    if not key:
        return {**req, "error": "key is required"}
    opener = _HIVE_OPENERS.get(hive_name)
    if not opener:
        return {**req, "error": f"unknown hive: {hive_name}"}

    try:
        if hive_name not in hive_handles:
            hive_handles[hive_name] = getattr(rrp, opener)(dce)["phKey"]
        hive_h = hive_handles[hive_name]
    except Exception as e:
        return {**req, "error": f"open hive failed: {type(e).__name__}: {e}"}

    try:
        sub_h = rrp.hBaseRegOpenKey(dce, hive_h, key)["phkResult"]
    except Exception as e:
        return {**req, "error": f"open key failed: {type(e).__name__}: {e}"}

    try:
        if op == "get_value":
            return _reg_get_value(dce, rrp, sub_h, hive_name, key, req.get("value_name") or "")
        if op == "enum_keys":
            return {"op": op, "hive": hive_name, "key": key,
                    "subkeys": _reg_enum_keys(dce, rrp, sub_h)}
        if op == "enum_values":
            return {"op": op, "hive": hive_name, "key": key,
                    "values": _reg_enum_values(dce, rrp, sub_h)}
        return {**req, "error": f"unknown op: {op}"}
    except Exception as e:
        return {**req, "error": f"{op} failed: {type(e).__name__}: {e}"}
    finally:
        try:
            rrp.hBaseRegCloseKey(dce, sub_h)
        except Exception:
            pass


def _reg_get_value(dce, rrp, sub_h, hive_name: str, key: str, value_name: str) -> dict:
    try:
        type_code, data = rrp.hBaseRegQueryValue(dce, sub_h, value_name)
    except Exception as e:
        msg = str(e)
        # ERROR_FILE_NOT_FOUND — value doesn't exist. Not an error per se.
        if "ERROR_FILE_NOT_FOUND" in msg or "0x2 " in msg or "0x80000002" in msg:
            return {"op": "get_value", "hive": hive_name, "key": key,
                    "value_name": value_name, "found": False}
        raise

    out: dict[str, Any] = {
        "op": "get_value", "hive": hive_name, "key": key, "value_name": value_name,
        "found": True, "type": _REG_TYPE_LABELS.get(int(type_code), f"type_{int(type_code)}"),
    }
    # rrp.hBaseRegQueryValue already decodes string/int types. Binary comes
    # back as bytes — encode as hex for JSON transport.
    if isinstance(data, (bytes, bytearray)):
        out["data"] = bytes(data).hex()
    elif isinstance(data, list):
        out["data"] = [str(x).rstrip("\x00") for x in data]
    elif isinstance(data, str):
        out["data"] = data.rstrip("\x00")
    else:
        out["data"] = data
    return out


def _reg_enum_keys(dce, rrp, sub_h) -> list[str]:
    names: list[str] = []
    i = 0
    while True:
        try:
            r = rrp.hBaseRegEnumKey(dce, sub_h, i)
        except Exception:
            break
        name = r["lpNameOut"] if isinstance(r, dict) else getattr(r, "lpNameOut", None)
        if not name:
            break
        # Impacket returns names with a trailing NUL — strip it for JSON safety.
        names.append(str(name).rstrip("\x00"))
        i += 1
        if i >= 1000:  # sanity cap
            break
    return names


def _reg_enum_values(dce, rrp, sub_h) -> list[dict]:
    vals: list[dict] = []
    i = 0
    while True:
        try:
            r = rrp.hBaseRegEnumValue(dce, sub_h, i)
        except Exception:
            break
        # hBaseRegEnumValue returns (name, type, data). Names carry a NUL.
        try:
            name, type_code, _ = r
        except Exception:
            break
        vals.append({
            "name": str(name).rstrip("\x00"),
            "type": _REG_TYPE_LABELS.get(int(type_code), f"type_{int(type_code)}"),
            "type_id": int(type_code),
        })
        i += 1
        if i >= 500:
            break
    return vals


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

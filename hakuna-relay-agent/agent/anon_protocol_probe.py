"""Anonymous-protocol probe executor for the Hakuna relay agent (Phase 4.1).

Single relay method (`anon_protocol_probe`) covering the legacy
anon-misconfig family:

  - op="ftp"        — FTP anonymous-login (default 21)
  - op="vnc"        — VNC RFB security-type list (default 5900)
  - op="dns_axfr"   — DNS zone transfer (default TCP 53)
  - op="kerberos"   — Kerberos KDC reachability fingerprint (default TCP 88)
  - op="tftp"       — TFTP common-files probe (default UDP 69)

## Design notes
- All probes are **anonymous** by spec. No credentials accepted.
- Every op is bounded: per-op timeout, per-op result cap (record count,
  byte budget). No iteration, no writes.
- Stdlib `socket` / `ftplib` for FTP, VNC, TFTP, Kerberos. `dnspython`
  optional for AXFR — graceful degrade if not installed.
- Per-op timeout is enforced at the handler level (default 8s).
- Filename list for TFTP is hardcoded at the relay; the backend tool
  cannot supply paths. Defense in depth against prompt injection.

## Result shape (per op)
Each op returns a dict whose top-level key states the misconfig signal:
  - ftp → ``anonymous_login_allowed: bool``
  - vnc → ``auth_required: bool``
  - dns_axfr → ``axfr_allowed: bool``
  - kerberos → ``kdc_reachable: bool``
  - tftp → ``readable_files: [str]`` (non-empty = finding lead)
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 8


class AnonProtocolProbeError(Exception):
    """Any anon-protocol probe failure surfaced back to the backend."""


@register_method("anon_protocol_probe")
async def anon_protocol_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch one anon-protocol probe based on ``params.op``.

    The relay-side allowlist of legal ops is the keys of ``_OP_HANDLERS``
    below — anything else is rejected before any network code runs.
    """
    target = (transport_config or {}).get("target")
    if not target:
        raise AnonProtocolProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise AnonProtocolProbeError(
            f"unknown anon protocol probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 2,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── FTP ──────────────────────────────────────────────────────────────


def _probe_ftp(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Try anonymous FTP login + a small LIST sample.

    The text protocol is well-defined: connect, read 220 banner, send
    USER anonymous, expect 331 or 230, send PASS, expect 230 on success
    or 530 on rejection. We never download files.
    """
    port = port or 21
    out: dict[str, Any] = {"anonymous_login_allowed": False, "banner": "", "sample_listing": []}
    try:
        sock = socket.create_connection((target, port), timeout=timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"ftp": f"connect failed: {type(e).__name__}: {e}"}}

    try:
        sock.settimeout(timeout_s)
        banner = _ftp_read(sock)
        out["banner"] = banner.strip()
        if not banner.startswith("220"):
            return {"_errors": {"ftp": f"unexpected greeting: {banner!r}"}}

        sock.sendall(b"USER anonymous\r\n")
        user_resp = _ftp_read(sock)
        if not (user_resp.startswith("331") or user_resp.startswith("230")):
            # Most servers reply 530 to refuse anon outright.
            return out
        if user_resp.startswith("331"):
            sock.sendall(b"PASS anonymous@hakuna\r\n")
            pass_resp = _ftp_read(sock)
            if not pass_resp.startswith("230"):
                return out
        out["anonymous_login_allowed"] = True

        # Best-effort LIST: many anon servers are passive-only and the
        # full data-channel dance is overkill. Some servers do support
        # `STAT` which returns a directory listing on the control channel.
        try:
            sock.sendall(b"STAT\r\n")
            stat_resp = _ftp_read(sock, max_lines=20)
            # Typical: "211-status of /:" then file lines then "211 End"
            for line in stat_resp.splitlines():
                stripped = line.strip()
                # Skip the protocol envelope lines (2xx-/2xx).
                if stripped[:3].isdigit() and (stripped[3:4] in (" ", "-", "")):
                    continue
                if stripped:
                    out["sample_listing"].append(stripped[:120])
                if len(out["sample_listing"]) >= 5:
                    break
        except (socket.timeout, OSError) as e:
            out.setdefault("_errors", {})["stat"] = f"{type(e).__name__}: {e}"

        try:
            sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _ftp_read(sock: socket.socket, max_bytes: int = 8192, max_lines: int = 1) -> str:
    """Read an FTP control-channel response. Multi-line responses are
    delimited by `<code>-...<code> ` per RFC 959; for our purposes a
    single read is enough for the simple replies we trigger."""
    buf = bytearray()
    lines = 0
    while len(buf) < max_bytes:
        chunk = sock.recv(min(2048, max_bytes - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
        if buf.endswith(b"\r\n") or buf.endswith(b"\n"):
            lines += buf.count(b"\n")
            if lines >= max_lines:
                break
    return buf.decode("ascii", "replace")


# ── VNC ──────────────────────────────────────────────────────────────


def _probe_vnc(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Read RFB protocol version + security-type list.

    Wire shape:
      server → 12-byte version banner: `RFB <maj>.<min>\\n`
      client → echo a supported version (use whatever server announced,
                clamped to a known major)
      server (>= 3.7) → 1 byte count + N security-type bytes
      server (3.3) → 4-byte big-endian security type
    Type 1 = None (no auth); type 2 = VNC password challenge; etc.
    """
    port = port or 5900
    out: dict[str, Any] = {"auth_required": None, "rfb_version": None, "security_types": []}
    try:
        sock = socket.create_connection((target, port), timeout=timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"vnc": f"connect failed: {type(e).__name__}: {e}"}}

    try:
        sock.settimeout(timeout_s)
        version = _recv_exact(sock, 12)
        if not version.startswith(b"RFB ") or not version.endswith(b"\n"):
            return {"_errors": {"vnc": f"not an RFB banner: {version!r}"}}
        out["rfb_version"] = version[:11].decode("ascii", "replace").strip()

        # Echo back a safe version. The client picks the lower of its
        # supported version and the server's. We claim 3.8 unless the
        # server is older.
        try:
            major, minor = (int(version[4:7]), int(version[8:11]))
        except ValueError:
            major, minor = 3, 8
        chosen = b"RFB 003.008\n"
        if (major, minor) < (3, 7):
            chosen = b"RFB 003.003\n"
        sock.sendall(chosen)

        if chosen == b"RFB 003.003\n":
            # 4-byte security type
            sec = _recv_exact(sock, 4)
            sec_type = struct.unpack(">I", sec)[0]
            out["security_types"] = [sec_type] if sec_type else []
        else:
            count_byte = _recv_exact(sock, 1)
            count = count_byte[0] if count_byte else 0
            if count == 0:
                # Per RFB, this means failure — server sends a reason. We
                # don't read it; the type list is just empty.
                out["security_types"] = []
            else:
                # Cap at a sane upper bound; real servers offer < 8.
                count = min(count, 16)
                types_bytes = _recv_exact(sock, count)
                out["security_types"] = list(types_bytes)
        # Type 1 is "None" — no authentication step.
        out["auth_required"] = 1 not in out["security_types"]
    except (socket.timeout, OSError) as e:
        out["_errors"] = {"vnc": f"{type(e).__name__}: {e}"}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or raise. Bounded by socket timeout."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("short read")
        buf.extend(chunk)
    return bytes(buf)


# ── DNS AXFR ─────────────────────────────────────────────────────────


def _probe_dns_axfr(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Attempt a zone transfer over TCP.

    Uses dnspython if available — building an AXFR query by hand is
    doable but the response parser would dwarf this module. Without the
    library we surface a clear error rather than silently lying.
    """
    try:
        import dns.query  # type: ignore
        import dns.zone  # type: ignore
        import dns.exception  # type: ignore
    except ImportError:
        return {"_errors": {"dns_axfr": "dnspython not installed on relay"}}

    zone = (op_params or {}).get("zone")
    if not zone:
        return {"_errors": {"dns_axfr": "zone parameter required (no fqdn on asset)"}}
    # Strip trailing dot for dnspython's from_xfr; it expects a string.
    zone = zone.rstrip(".")
    port = port or 53
    out: dict[str, Any] = {"axfr_allowed": False, "zone": zone, "record_count": 0, "sample_records": []}
    try:
        # dnspython's xfr() returns an iterator over messages — we wrap
        # it in from_xfr to materialize a Zone. timeout is per-message.
        xfr = dns.query.xfr(target, zone, port=port, timeout=timeout_s, lifetime=timeout_s)
        zone_obj = dns.zone.from_xfr(xfr)
    except dns.exception.FormError:
        # Server refused / returned a non-AXFR — i.e., zone transfer denied.
        return out
    except (dns.exception.DNSException, OSError) as e:
        return {"_errors": {"dns_axfr": f"{type(e).__name__}: {e}"}}

    out["axfr_allowed"] = True
    records: list[str] = []
    for name, rdataset in zone_obj.iterate_rdatasets():
        try:
            line = f"{name} {rdataset.rdtype.name} {rdataset.to_text()}"
        except Exception:
            line = str(name)
        records.append(line[:160])
        if len(records) >= 50:
            break
    out["record_count"] = len(records)
    out["sample_records"] = records
    return out


# ── Kerberos ─────────────────────────────────────────────────────────


def _probe_kerberos(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Confirm a Kerberos KDC is listening and try to read its realm.

    We send a deliberately malformed AS-REQ-shaped TCP message. The KDC
    will respond with KRB-ERROR (a structured ASN.1 reply) whose
    `crealm` field carries the realm string. Best-effort parser: we
    scan the reply for the printable realm tag rather than building a
    full ASN.1 decoder. If we can't recover the realm, ``kdc_reachable``
    is still True as long as we got *any* well-shaped reply.

    NEVER performs username enumeration or AS-REP roasting — those
    require well-formed AS-REQs targeting real principals and live in a
    separate consent-gated mission.
    """
    port = port or 88
    out: dict[str, Any] = {"kdc_reachable": False, "realm": None}
    try:
        sock = socket.create_connection((target, port), timeout=timeout_s)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"_errors": {"kerberos": f"connect failed: {type(e).__name__}: {e}"}}

    try:
        sock.settimeout(timeout_s)
        # Krb5 over TCP is length-prefixed (4-byte big-endian). Send a
        # 16-byte garbage payload — enough that the KDC parses it as
        # malformed and returns KRB-ERROR rather than dropping us.
        payload = b"\x6a\x10" + b"\x00" * 14  # tag-shape hint, not a valid AS-REQ
        sock.sendall(struct.pack(">I", len(payload)) + payload)
        # Read the 4-byte length prefix + the body. KRB-ERROR is small.
        header = sock.recv(4)
        if len(header) < 4:
            return out
        body_len = struct.unpack(">I", header)[0]
        if body_len == 0 or body_len > 8192:
            return out
        body = bytearray()
        while len(body) < body_len:
            chunk = sock.recv(min(2048, body_len - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        out["kdc_reachable"] = True
        out["realm"] = _extract_kerberos_realm(bytes(body))
    except (socket.timeout, OSError) as e:
        out["_errors"] = {"kerberos": f"{type(e).__name__}: {e}"}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _extract_kerberos_realm(body: bytes) -> str | None:
    """Pull the realm string out of a KRB-ERROR.

    Realms are ASCII uppercase like ``EXAMPLE.COM`` or ``CORP.AD``.
    Inside a KRB-ERROR they appear as a GeneralString tagged ``[9]``
    (crealm). We scan for the printable run that looks like a realm.
    Best-effort: if nothing matches we return None.
    """
    # Walk every printable run and pick the longest that contains a dot
    # and is all-uppercase + digits + dots.
    candidates: list[str] = []
    cur = bytearray()
    for b in body:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if cur:
                candidates.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if cur:
        candidates.append(cur.decode("ascii", "replace"))

    best: str | None = None
    for s in candidates:
        # split on non-realm characters and inspect each run
        token = bytearray()
        for ch in s.encode("ascii", "replace"):
            if (0x41 <= ch <= 0x5A) or (0x30 <= ch <= 0x39) or ch == 0x2E or ch == 0x2D or ch == 0x5F:
                token.append(ch)
            else:
                _maybe = token.decode("ascii", "replace") if token else ""
                if "." in _maybe and len(_maybe) >= 3 and (best is None or len(_maybe) > len(best)):
                    best = _maybe
                token = bytearray()
        _maybe = token.decode("ascii", "replace") if token else ""
        if "." in _maybe and len(_maybe) >= 3 and (best is None or len(_maybe) > len(best)):
            best = _maybe
    return best


# ── TFTP ─────────────────────────────────────────────────────────────


# Hardcoded common-filename list. Anything LLM-supplied is ignored —
# this is the single source of truth for which paths the relay will
# probe. Keep it short and high-signal.
_TFTP_COMMON_FILES: tuple[str, ...] = (
    "running-config",
    "startup-config",
    "boot.cfg",
    "config.cfg",
    "router.cfg",
    "switch.cfg",
    "pxelinux.cfg/default",
    "/etc/passwd",
)


def _probe_tftp(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send TFTP RRQ for each filename in the hardcoded list.

    TFTP wire shape (RFC 1350):
      RRQ:  opcode(=1, 2 bytes) + filename + 0 + mode + 0
      DATA: opcode(=3, 2 bytes) + block# + payload
      ERROR: opcode(=5, 2 bytes) + errcode + msg + 0

    We never ACK the data block, so the server gives up after one DATA
    packet — no actual file content streams. The presence of DATA = the
    file is readable; ERROR = it isn't.
    """
    port = port or 69
    out: dict[str, Any] = {"readable_files": [], "probed_count": 0}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout_s, 2))
    except OSError as e:
        return {"_errors": {"tftp": f"socket: {e}"}}

    try:
        for filename in _TFTP_COMMON_FILES:
            packet = b"\x00\x01" + filename.encode("ascii", "replace") + b"\x00octet\x00"
            try:
                sock.sendto(packet, (target, port))
                data, _peer = sock.recvfrom(1024)
            except socket.timeout:
                out["probed_count"] += 1
                continue
            except OSError as e:
                out.setdefault("_errors", {})[filename] = f"{type(e).__name__}: {e}"
                out["probed_count"] += 1
                continue
            out["probed_count"] += 1
            if len(data) >= 4 and data[0] == 0 and data[1] == 3:
                out["readable_files"].append(filename)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


# ── Relay-side allowlist ─────────────────────────────────────────────
#
# The set of legal ops is exactly the keys of this dict. Anything else
# raises AnonProtocolProbeError before any network code runs.
_OP_HANDLERS: dict[str, Any] = {
    "ftp": _probe_ftp,
    "vnc": _probe_vnc,
    "dns_axfr": _probe_dns_axfr,
    "kerberos": _probe_kerberos,
    "tftp": _probe_tftp,
}

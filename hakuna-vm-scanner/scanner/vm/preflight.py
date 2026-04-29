"""Liveness preflight for scan targets.

Runs once per scan entry point, before any LLM tokens burn or any
specialist tool fires. A down target is classified here — the rest of
the worker sees a clean "unreachable" short-circuit instead of the LLM
politely summarising over N failing tool calls and the result envelope
being indistinguishable from "scanned clean."

Scope is deliberately narrow: TCP-level connectivity + a single HTTP
HEAD (falling back to GET if HEAD is not allowed). Any HTTP status
counts as reachable — a 401 / 403 / 500 means the server is alive and
the specialists can work with it. Only DNS failure, connection refusal,
TLS handshake failure, or timeout marks the target unreachable.
"""

from __future__ import annotations

import socket
import time
from dataclasses import asdict, dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx


# Default probe timeout — matches nuclei's -timeout 10 so that any host
# nuclei would consider live also passes preflight. 3s was tight enough
# that cross-region cold connects (Azure → GCP me-west1) regularly hit
# the deadline despite the host being healthy.
DEFAULT_PREFLIGHT_TIMEOUT = 10.0


@dataclass
class PreflightResult:
    reachable: bool
    reason: str          # "ok" | "dns_fail" | "connect_refused" | "timeout" | "tls_fail" | "invalid_target" | "other"
    detail: str
    probed_at: str       # ISO-8601 UTC
    elapsed_ms: int
    status_code: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def probe_http(
    url: str, timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
) -> PreflightResult:
    """Probe an HTTP(S) URL for liveness.

    Uses HEAD first, falling back to GET if the server returns 405/501
    (common on apps that only route HEAD through some paths). Any
    response — including 4xx / 5xx — marks the target reachable; the
    specialists can work with a server that refuses auth or errors out.

    Unreachable classifications:
      - ``dns_fail``         — hostname did not resolve
      - ``connect_refused``  — TCP connect rejected
      - ``timeout``          — TCP or HTTP deadline exceeded
      - ``tls_fail``         — TLS handshake failed
      - ``invalid_target``   — URL parse failed / unsupported scheme
      - ``other``            — anything else (captured in ``detail``)
    """
    start = time.monotonic()
    probed_at = _now_iso()

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return PreflightResult(
            reachable=False, reason="invalid_target",
            detail=f"unsupported target url: {url!r}",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )

    # Issue HEAD; on 405/501 retry once with GET. One httpx client so
    # keep-alive covers both calls.
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout) as client:
            resp = client.request("HEAD", url)
            if resp.status_code in (405, 501):
                resp = client.request("GET", url)
    except httpx.ConnectError as e:
        msg = str(e).lower()
        if "name or service not known" in msg or "temporary failure in name resolution" in msg or "nodename nor servname" in msg:
            reason = "dns_fail"
        elif "ssl" in msg or "tls" in msg or "certificate" in msg:
            reason = "tls_fail"
        else:
            reason = "connect_refused"
        return PreflightResult(
            reachable=False, reason=reason, detail=str(e)[:200],
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except httpx.TimeoutException as e:
        return PreflightResult(
            reachable=False, reason="timeout", detail=str(e)[:200] or "probe timed out",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except (socket.gaierror, socket.herror) as e:
        return PreflightResult(
            reachable=False, reason="dns_fail", detail=str(e)[:200],
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except Exception as e:
        return PreflightResult(
            reachable=False, reason="other", detail=f"{type(e).__name__}: {str(e)[:200]}",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )

    return PreflightResult(
        reachable=True, reason="ok", detail=f"HTTP {resp.status_code}",
        status_code=resp.status_code,
        probed_at=probed_at,
        elapsed_ms=int((time.monotonic() - start) * 1000),
    )


def should_preflight(target: str) -> bool:
    """Only HTTP(S) targets get preflighted here. Non-HTTP targets
    (bare IPs with unknown scheme, internal SMB/LDAP handles) are out
    of scope for this module — those belong to protocol-aware preflights
    in the audit engine's dispatch layer."""
    if not target:
        return False
    return target.startswith(("http://", "https://"))


def probe_tcp(
    host: str, port: int, timeout: float = DEFAULT_PREFLIGHT_TIMEOUT,
) -> PreflightResult:
    """Protocol-agnostic TCP connect probe.

    Used by scanners that speak non-HTTP protocols (SMB/LDAP/SSH/WMI/
    SNMP) and by the nuclei asset path when the target is a bare IP or
    hostname with a known open port. A successful ``connect()`` proves
    the remote process is listening — classification matches
    ``probe_http`` so the envelope shape is uniform.
    """
    start = time.monotonic()
    probed_at = _now_iso()

    if not host or not isinstance(port, int) or port <= 0 or port > 65535:
        return PreflightResult(
            reachable=False, reason="invalid_target",
            detail=f"invalid host/port: {host!r}:{port!r}",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )

    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except socket.gaierror as e:
        return PreflightResult(
            reachable=False, reason="dns_fail", detail=str(e)[:200],
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except socket.timeout as e:
        return PreflightResult(
            reachable=False, reason="timeout", detail=str(e)[:200] or "tcp connect timed out",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except ConnectionRefusedError as e:
        return PreflightResult(
            reachable=False, reason="connect_refused", detail=str(e)[:200],
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except OSError as e:
        # Catch-all for "no route to host", "network unreachable",
        # "host is down" — all indistinguishable to the caller.
        return PreflightResult(
            reachable=False, reason="connect_refused", detail=str(e)[:200],
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )
    except Exception as e:
        return PreflightResult(
            reachable=False, reason="other", detail=f"{type(e).__name__}: {str(e)[:200]}",
            probed_at=probed_at,
            elapsed_ms=int((time.monotonic() - start) * 1000),
        )

    return PreflightResult(
        reachable=True, reason="ok", detail=f"tcp connect ok {host}:{port}",
        probed_at=probed_at,
        elapsed_ms=int((time.monotonic() - start) * 1000),
    )

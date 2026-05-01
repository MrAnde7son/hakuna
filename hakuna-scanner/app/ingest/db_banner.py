"""PostgreSQL and MySQL banner-version probes.

Auth-required databases are not in scope for the `exposed_datastore` family
(Phase 1 deferred them precisely because they need creds), but their
*banner version* matters for CVE correlation: a public-facing PostgreSQL
14.0 maps to CVE-2022-1552 etc.

* **PostgreSQL 5432** — server doesn't volunteer a version on TCP connect.
  We send an SSLRequest packet (8 bytes); the server replies 'S' (TLS
  available) or 'N' (not). For version, we send a deliberately-malformed
  StartupMessage with a non-existent user; the ErrorResponse it returns
  carries the server version in the SFATAL field (`PG_VERSION_NUM`-style
  marker on most builds). Some hardened builds suppress this — accepted
  as best-effort.

* **MySQL 3306** — server *does* send a Greeting packet on connect with
  protocol version + server version + auth-plugin name. Single read;
  no auth attempt. We close immediately after parsing so no failed-login
  metric increments.

Neither emits a finding by itself — these are pure CVE-correlation feeds.
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5
_IO_TIMEOUT = 5


# ── PostgreSQL ─────────────────────────────────────────────────────────────

# SSLRequest: int32(8) length, int32(80877103) magic.
_PG_SSL_REQUEST = struct.pack(">II", 8, 80877103)


def _pg_startup(user: str = "hakuna_probe", database: str = "postgres") -> bytes:
    """Build a StartupMessage with the given user/db."""
    body = struct.pack(">I", 196608)  # protocol 3.0
    for key, value in (("user", user), ("database", database)):
        body += key.encode() + b"\x00" + value.encode() + b"\x00"
    body += b"\x00"
    return struct.pack(">I", len(body) + 4) + body


def _pg_parse_error(payload: bytes) -> dict:
    """Parse an ErrorResponse 'E' message body into its (code, value) fields."""
    fields: dict[str, str] = {}
    i = 0
    while i < len(payload):
        code = payload[i:i+1]
        i += 1
        if code == b"\x00":
            break
        end = payload.find(b"\x00", i)
        if end == -1:
            break
        try:
            fields[code.decode("ascii", "replace")] = payload[i:end].decode("utf-8", "replace")
        except Exception:
            pass
        i = end + 1
    return fields


async def _probe_postgres(host: str, port: int = 5432) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    ssl_supported: bool | None = None
    error_fields: dict[str, str] = {}
    try:
        # SSL probe.
        writer.write(_PG_SSL_REQUEST)
        await writer.drain()
        try:
            byte = await asyncio.wait_for(reader.readexactly(1), timeout=_IO_TIMEOUT)
            ssl_supported = byte == b"S"
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            ssl_supported = None
            return None  # server hung up; not a real Postgres
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    # Reopen for the version probe (we can't continue after sending
    # SSLRequest without doing the TLS handshake).
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        writer.write(_pg_startup())
        await writer.drain()
        try:
            header = await asyncio.wait_for(reader.readexactly(5), timeout=_IO_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            header = b""
        if len(header) == 5 and header[0:1] == b"E":
            length = struct.unpack(">I", header[1:5])[0] - 4
            try:
                body = await asyncio.wait_for(reader.readexactly(length), timeout=_IO_TIMEOUT)
                error_fields = _pg_parse_error(body)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return {
        "protocol": "postgresql",
        "port": port,
        "banner": error_fields.get("M"),  # error message often includes version
        "version": {
            "server_version": error_fields.get("V"),
            "sqlstate": error_fields.get("C"),
        },
        "metadata": {
            "ssl_supported": ssl_supported,
            "error_fields": error_fields,
        },
    }


# ── MySQL ──────────────────────────────────────────────────────────────────

async def _probe_mysql(host: str, port: int = 3306) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=_IO_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None

        # 3-byte little-endian length + 1-byte sequence id
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        if length == 0 or length > 4096:
            return None
        try:
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=_IO_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None

        if not payload:
            return None
        protocol_version = payload[0]
        # MySQL protocol v10 is the modern one. v9 still seen on ancient builds.
        if protocol_version not in (9, 10):
            return None

        # Null-terminated server-version string
        end = payload.find(b"\x00", 1)
        if end == -1:
            return None
        server_version = payload[1:end].decode("utf-8", errors="replace")

        return {
            "protocol": "mysql",
            "port": port,
            "banner": server_version,
            "version": {
                "protocol_version": protocol_version,
                "server_version": server_version,
            },
            "metadata": {},
        }
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── Dispatch ───────────────────────────────────────────────────────────────

# PR #2: each probe row carries ``service_types`` (preferred) +
# ``legacy_ports`` (fallback). Kept as a tuple-list so the legacy
# ``ports == {5432, 3306}`` test in test_banner_grab.py keeps working
# (it iterates ``[(p, fn) for p, fn, *_ in _DISPATCH]``).
_DISPATCH = [
    (5432, _probe_postgres, {"postgres"}, {5432}),
    (3306, _probe_mysql, {"mysql"}, {3306}),
]


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    """Banner-probe Postgres / MySQL on every typed port.

    PR #2: each dispatch row gates on ``service_type IN
    {postgres,mysql}`` (preferred) OR the legacy port (fallback).
    Catches DBs on alt ports (e.g. MySQL on 33060) once PR #1 has
    stamped them.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    async def _run_one(asset: dict):
        target = asset.get("ip") or asset.get("hostname")
        if not target:
            return
        open_ports = asset.get("open_ports") or []
        st_map = asset.get("port_service_types") or {}
        hits: list[dict] = []
        for _legacy_port, fn, service_types, legacy_ports in _DISPATCH:
            for port in open_ports:
                try:
                    p = int(port)
                except (TypeError, ValueError):
                    continue
                svc = st_map.get(p)
                if svc is not None:
                    if svc not in service_types:
                        continue
                else:
                    if p not in legacy_ports:
                        continue
                async with semaphore:
                    hit = await fn(target, p)
                if hit:
                    hits.append(hit)
        if hits:
            results[asset["hostname"]] = hits

    await asyncio.gather(
        *(_run_one(a) for a in assets),
        return_exceptions=True,
    )
    return results

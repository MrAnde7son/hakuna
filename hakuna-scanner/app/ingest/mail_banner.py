"""SMTP / IMAP / POP3 banner + capability + auth-hygiene probes.

Three protocols share a single module because the wire pattern is identical:
connect, server greets, send a capability command, parse response. We
bundle the auth-hygiene checks (SMTP VRFY/EXPN, STARTTLS presence) into the
same round-trip rather than open a second connection.

Per protocol:

* SMTP 25/587 — read 220 banner, send EHLO, look for STARTTLS, then
  optionally VRFY postmaster (server returning 250/252 = info disclosure).
* IMAP 143/993 — read greeting, send CAPABILITY. STARTTLS missing on 143
  is a finding.
* POP3 110/995 — read greeting, send CAPA. STLS missing on 110 is a finding.

Implicit-TLS ports (465 SMTPS, 993 IMAPS, 995 POP3S) wrap with ssl on
connect; STARTTLS gating doesn't apply.

Open-relay testing is intentionally NOT done here — it requires sending a
test message which is not safe-by-default.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 5
_IO_TIMEOUT = 5
_MAX_READ = 4096


# Loose per-protocol version extractors. Banner formats vary wildly; we
# capture the implementation name (Postfix, Sendmail, Dovecot, Exim, etc.)
# without forcing a strict regex that would fail on customized banners.
_SMTP_BANNER_RE = re.compile(r"220[- ]\S+\s+(?P<software>.+?)(?:\r?\n|$)")
_IMAP_BANNER_RE = re.compile(r"\* OK\s+(?P<software>.+?)(?:\r?\n|$)")
_POP3_BANNER_RE = re.compile(r"\+OK\s+(?P<software>.+?)(?:\r?\n|$)")


async def _open(host: str, port: int, *, use_tls: bool):
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=_CONNECT_TIMEOUT,
        )
    return await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=_CONNECT_TIMEOUT,
    )


async def _read_chunk(reader: asyncio.StreamReader) -> str:
    try:
        data = await asyncio.wait_for(reader.read(_MAX_READ), timeout=_IO_TIMEOUT)
    except asyncio.TimeoutError:
        return ""
    return data.decode("utf-8", errors="replace")


async def _smtp_probe(host: str, port: int, *, use_tls: bool) -> dict | None:
    try:
        reader, writer = await _open(host, port, use_tls=use_tls)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    try:
        greeting = await _read_chunk(reader)
        if not greeting.startswith("220"):
            return None

        writer.write(b"EHLO hakuna.local\r\n")
        await writer.drain()
        ehlo = await _read_chunk(reader)

        capabilities = [
            line[4:].strip().upper()
            for line in ehlo.splitlines()
            if line.startswith(("250-", "250 "))
        ]

        starttls_advertised = any(c.startswith("STARTTLS") for c in capabilities)

        # VRFY probe — only on cleartext port and only if EHLO succeeded.
        vrfy_response: str | None = None
        if not use_tls:
            writer.write(b"VRFY postmaster\r\n")
            await writer.drain()
            vrfy_response = (await _read_chunk(reader)).split("\r\n", 1)[0]

        writer.write(b"QUIT\r\n")
        await writer.drain()

        m = _SMTP_BANNER_RE.match(greeting)
        software = m.group("software").strip() if m else None

        result: dict = {
            "protocol": "smtp",
            "port": port,
            "banner": greeting.split("\r\n", 1)[0],
            "version": {"software": software},
            "metadata": {
                "capabilities": capabilities,
                "starttls_advertised": starttls_advertised,
                "vrfy_response": vrfy_response,
                "implicit_tls": use_tls,
            },
        }

        # Findings.
        if not use_tls and not starttls_advertised:
            result["severity"] = "medium"
            result["finding_title"] = "SMTP server does not advertise STARTTLS"
        elif vrfy_response and vrfy_response.startswith(("250", "252")):
            result["severity"] = "low"
            result["finding_title"] = "SMTP VRFY enabled (user enumeration)"

        return result
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _imap_probe(host: str, port: int, *, use_tls: bool) -> dict | None:
    try:
        reader, writer = await _open(host, port, use_tls=use_tls)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    try:
        greeting = await _read_chunk(reader)
        if not greeting.startswith("* OK"):
            return None

        writer.write(b"a001 CAPABILITY\r\n")
        await writer.drain()
        cap_resp = await _read_chunk(reader)
        cap_line = next(
            (l for l in cap_resp.splitlines() if l.startswith("* CAPABILITY")),
            "",
        )
        capabilities = cap_line.replace("* CAPABILITY", "").strip().split()

        writer.write(b"a002 LOGOUT\r\n")
        await writer.drain()

        m = _IMAP_BANNER_RE.match(greeting)
        software = m.group("software").strip() if m else None
        starttls = "STARTTLS" in (c.upper() for c in capabilities)

        result: dict = {
            "protocol": "imap",
            "port": port,
            "banner": greeting.split("\r\n", 1)[0],
            "version": {"software": software},
            "metadata": {
                "capabilities": capabilities,
                "starttls_advertised": starttls,
                "implicit_tls": use_tls,
            },
        }
        if not use_tls and not starttls:
            result["severity"] = "medium"
            result["finding_title"] = "IMAP server does not advertise STARTTLS"
        return result
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _pop3_probe(host: str, port: int, *, use_tls: bool) -> dict | None:
    try:
        reader, writer = await _open(host, port, use_tls=use_tls)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return None
    try:
        greeting = await _read_chunk(reader)
        if not greeting.startswith("+OK"):
            return None

        writer.write(b"CAPA\r\n")
        await writer.drain()
        capa_resp = await _read_chunk(reader)
        capabilities = [
            l.strip() for l in capa_resp.splitlines()
            if l and not l.startswith(("+OK", ".", "-ERR"))
        ]

        writer.write(b"QUIT\r\n")
        await writer.drain()

        m = _POP3_BANNER_RE.match(greeting)
        software = m.group("software").strip() if m else None
        stls = any(c.upper().startswith("STLS") for c in capabilities)

        result: dict = {
            "protocol": "pop3",
            "port": port,
            "banner": greeting.split("\r\n", 1)[0],
            "version": {"software": software},
            "metadata": {
                "capabilities": capabilities,
                "stls_advertised": stls,
                "implicit_tls": use_tls,
            },
        }
        if not use_tls and not stls:
            result["severity"] = "medium"
            result["finding_title"] = "POP3 server does not advertise STLS"
        return result
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# (port, probe_fn, use_tls)
_DISPATCH: list[tuple[int, callable, bool]] = [
    (25, _smtp_probe, False),
    (587, _smtp_probe, False),
    (465, _smtp_probe, True),
    (143, _imap_probe, False),
    (993, _imap_probe, True),
    (110, _pop3_probe, False),
    (995, _pop3_probe, True),
]


async def probe_batch(
    assets: list[dict],
    concurrency: int = 10,
) -> dict[str, list[dict]]:
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}

    async def _run_one(asset: dict):
        ports = set(asset.get("open_ports") or [])
        target = asset.get("ip") or asset.get("hostname")
        if not target or not ports:
            return
        hits: list[dict] = []
        for port, fn, use_tls in _DISPATCH:
            if port not in ports:
                continue
            async with semaphore:
                hit = await fn(target, port, use_tls=use_tls)
            if hit:
                hits.append(hit)
        if hits:
            results[asset["hostname"]] = hits

    await asyncio.gather(
        *(_run_one(a) for a in assets),
        return_exceptions=True,
    )
    return results

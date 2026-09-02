"""Extension 2: Asset liveness validation gate.

Checks DNS resolution, port response, and HTTP probe to determine
whether assets are alive, unconfirmed, or likely dead.
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone

import aiohttp
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingest.cloud_ranges import identify_cloud_provider

logger = logging.getLogger(__name__)

# Liveness score (0–100, capped). Bumped on a confirmed_alive check,
# decayed on missed/failed checks. Values calibrated so a single bad
# scan doesn't suppress an asset but a sustained outage does (~4
# consecutive misses = below the 30 suppression threshold). The decay
# applied to assets that aren't validated at all this cycle is in
# app.ingest.delta.decay_unseen_assets.
#
# The bump must not be much smaller than the decays. It originally was
# (+5 against -15/-25), which made the score a one-way ratchet: any host
# with an occasionally flaky probe — CDN-fronted hosts that drop SYN, a
# rate-limited httpx batch — lost ground faster than it could recover and
# eventually pinned at 0 while still being confirmed_alive every cycle.
# That drove 85% of production assets under the suppression threshold.
_LIVENESS_BUMP_ALIVE = 20
_LIVENESS_DECAY_UNCONFIRMED = 15
_LIVENESS_DECAY_DEAD = 25
_LIVENESS_SUPPRESS_THRESHOLD = 30

# Floor applied when a check comes back confirmed_alive. A host we just
# reached is by definition not stale, so its score may never sit below
# the suppression threshold — the score and the state can't contradict
# each other. Decay from here still suppresses after a few clean misses.
_LIVENESS_ALIVE_FLOOR = _LIVENESS_SUPPRESS_THRESHOLD

# Path to the takeover fingerprint database. Loaded lazily so tests can
# reload it (see `reload_takeover_db`).
_TAKEOVER_DB_PATH = os.path.join(os.path.dirname(__file__), "takeover_fingerprints.json")

# Cap the body read to avoid pulling large pages; the fingerprint strings
# we care about always appear in the first few KB.
_TAKEOVER_MAX_BODY_BYTES = 16_000

# Per-probe HTTP timeout. Short enough that a hundred dangling hosts don't
# stall discovery; long enough to catch slow cloud error pages.
_TAKEOVER_HTTP_TIMEOUT = 5.0

def _load_takeover_db() -> list[dict]:
    """Load the takeover fingerprint database from disk."""
    try:
        with open(_TAKEOVER_DB_PATH) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("takeover fingerprints: failed to load %s: %s", _TAKEOVER_DB_PATH, exc)
        return []
    return data.get("services", [])


_TAKEOVER_DB: list[dict] = _load_takeover_db()


def reload_takeover_db() -> None:
    """Force-reload the takeover fingerprint DB. For tests."""
    global _TAKEOVER_DB
    _TAKEOVER_DB = _load_takeover_db()


# Severity labels in the JSON are the same strings the Finding table stores,
# but we normalize defensively in case the DB is ever edited.
_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "info": "info",
}


def _match_cname_service(cname_targets: list[str]) -> dict | None:
    """Return the first service entry whose cname_patterns match any target."""
    if not cname_targets or not _TAKEOVER_DB:
        return None
    lowered = [c.lower().rstrip(".") for c in cname_targets if c]
    for service in _TAKEOVER_DB:
        for pattern in service.get("cname_patterns", []):
            pat = pattern.lower()
            for target in lowered:
                if pat in target:
                    return service
    return None


def _match_body_service(status: int, body: str) -> dict | None:
    """Return the first service entry whose http_fingerprints match."""
    if not body or not _TAKEOVER_DB:
        return None
    for service in _TAKEOVER_DB:
        allowed_codes = service.get("status_codes") or []
        if allowed_codes and status not in allowed_codes:
            continue
        for fp in service.get("http_fingerprints", []):
            if fp and fp in body:
                return service
    return None


async def _fetch_probe(url: str, session: aiohttp.ClientSession) -> tuple[int, str] | None:
    """Lightweight GET used only for takeover fingerprinting. Never raises."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=_TAKEOVER_HTTP_TIMEOUT),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            raw = await resp.content.read(_TAKEOVER_MAX_BODY_BYTES)
            body = raw.decode("utf-8", errors="replace")
            return resp.status, body
    except Exception:
        return None


async def check_takeover_fingerprint(
    hostname: str,
    cname_targets: list[str] | None = None,
    session: aiohttp.ClientSession | None = None,
) -> dict | None:
    """Probe a dangling hostname for a known takeover fingerprint.

    Strategy:
      1. If the CNAME target matches a known service, that's a strong pre-filter
         — try HTTP and confirm with a body fingerprint. If the body matches,
         return the service entry with the HTTP evidence attached. If the
         body doesn't match (or HTTP fails), fall back to the CNAME-only
         match so we still flag the dangling record.
      2. If no CNAME match, try both http:// and https:// and match body
         fingerprints against any service in the DB.

    Returns a dict augmenting the matched service entry with probe evidence,
    or None if nothing matched. Never raises.
    """
    if not _TAKEOVER_DB:
        return None

    owns_session = session is None
    try:
        if owns_session:
            connector = aiohttp.TCPConnector(limit=5, ssl=False)
            session = aiohttp.ClientSession(
                connector=connector,
                headers={"User-Agent": "Mozilla/5.0 (compatible; HakunaScanner/1.0 takeover-probe)"},
            )

        cname_match = _match_cname_service(cname_targets or [])

        # Always try HTTP + HTTPS to grab a body fingerprint.
        http_result = None
        for scheme in ("https", "http"):
            probe = await _fetch_probe(f"{scheme}://{hostname}", session)
            if probe is not None:
                http_result = (scheme, probe[0], probe[1])
                break

        body_match = None
        if http_result is not None:
            _, status, body = http_result
            body_match = _match_body_service(status, body)

        # Prefer body-fingerprint match (strongest evidence); fall back to
        # CNAME-only match which is still actionable but weaker.
        matched = body_match or cname_match
        if matched is None:
            return None

        severity = _SEVERITY_ALIASES.get(
            str(matched.get("severity", "")).lower(), "high",
        )
        evidence = {
            "service": matched.get("name"),
            "severity": severity,
            "description": matched.get("description", ""),
            "matched_by": "http_fingerprint" if body_match else "cname_pattern",
        }
        if cname_match and cname_match is matched:
            evidence["cname_pattern_matched"] = True
        if http_result is not None:
            scheme, status, body = http_result
            evidence["http_status"] = status
            evidence["http_scheme"] = scheme
            if body_match:
                # Record which fingerprint triggered for downstream triage.
                for fp in body_match.get("http_fingerprints", []):
                    if fp in body:
                        evidence["matched_fingerprint"] = fp
                        break
        return evidence
    finally:
        if owns_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


def check_dns_resolution(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses. Returns list of IPs or empty list."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list({r[4][0] for r in results})
        return ips
    except (socket.gaierror, OSError):
        return []


# Cap on concurrent DNS lookups. Each call blocks a worker in the asyncio
# default executor (~32 threads on cpython). 64 is enough to saturate the
# pool and keeps the resolver from rate-limiting us.
_DNS_RESOLVE_CONCURRENCY = 64

# Per-lookup hard timeout. `socket.getaddrinfo` ignores Python's socket
# timeout and will block its executor thread forever on an unresponsive
# resolver — that's how the liveness gate stalled in prod 2026-05-12.
# `asyncio.wait_for` returns even though the underlying thread keeps
# blocking; we contain that leak by running DNS on a dedicated executor
# we can dispose with wait=False (see `_resolve_in_dedicated_executor`).
_DNS_RESOLVE_TIMEOUT_SECONDS = 5.0

# Chunk size for the bulk UPDATE … FROM (VALUES …) statement. Keeps the
# parsed query size bounded for very large scans.
_LIVENESS_UPDATE_CHUNK = 500


async def _resolve_in_dedicated_executor(
    hostnames: list[str],
    concurrency: int = _DNS_RESOLVE_CONCURRENCY,
) -> dict[str, list[str]]:
    """Resolve hostnames concurrently on a disposable executor.

    Why a dedicated executor: `check_dns_resolution` is a blocking
    `socket.getaddrinfo`, which ignores Python timeouts. `asyncio.wait_for`
    lets us stop waiting, but the thread itself stays pinned on the C call.
    If we used the default asyncio executor (max ~32 threads), a single
    scan against an org with a flaky resolver would permanently leak
    threads and poison every subsequent DNS lookup in the worker process.

    By spinning up our own pool and tearing it down with `wait=False`,
    leaked threads die with the worker — they don't accumulate across
    scans.
    """
    loop = asyncio.get_running_loop()
    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=concurrency,
        thread_name_prefix="easm-dns",
    )
    sem = asyncio.Semaphore(concurrency)

    async def _one(host: str) -> tuple[str, list[str]]:
        async with sem:
            try:
                ips = await asyncio.wait_for(
                    loop.run_in_executor(executor, check_dns_resolution, host),
                    timeout=_DNS_RESOLVE_TIMEOUT_SECONDS,
                )
                return host, ips
            except asyncio.TimeoutError:
                logger.warning("DNS resolution timed out for %s", host)
                return host, []
            except Exception:
                logger.debug("DNS resolution failed for %s", host, exc_info=True)
                return host, []

    try:
        pairs = await asyncio.gather(*[_one(h) for h in hostnames])
        return dict(pairs)
    finally:
        # cancel_futures discards queued lookups; threads already running
        # `getaddrinfo` can't be preempted but exit with the pool.
        executor.shutdown(wait=False, cancel_futures=True)


async def _resolve_hostnames_async(hostnames: list[str]) -> dict[str, list[str]]:
    """Resolve many hostnames concurrently with bounded timeouts.

    The LOAD_GLOBAL on `check_dns_resolution` happens at call time inside
    the executor wrapper, so test patches on
    `app.ingest.liveness.check_dns_resolution` still take effect.
    """
    return await _resolve_in_dedicated_executor(hostnames)


async def _resolve_one_bounded(hostname: str) -> list[str]:
    """Single-hostname DNS lookup with the same hard timeout."""
    result = await _resolve_in_dedicated_executor([hostname], concurrency=1)
    return result.get(hostname, [])


async def validate_and_update_assets(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_ids: list[uuid.UUID],
    port_check_results: dict[str, bool],
    http_check_results: dict[str, bool],
) -> dict:
    """Run liveness checks and update asset state.

    DNS resolution runs concurrently across all assets. Port and HTTP
    checks are passed in from the caller (Naabu recheck + httpx probe).
    The whole batch issues one SELECT and one chunked UPDATE — for an N-asset
    scan that's O(1) DB round-trips, not O(N).

    Returns summary dict with counts per state.
    """
    now = datetime.now(timezone.utc)
    summary = {"confirmed_alive": 0, "unconfirmed": 0, "likely_dead": 0, "dangling_dns": 0}

    if not asset_ids:
        return summary

    result = await db.execute(
        text("""
            SELECT id, hostname, host(ip) as ip, open_ports, consecutive_failures,
                   liveness_state, tags, cdn_provider
            FROM assets WHERE id = ANY(:ids) AND org_id = :org_id
        """),
        {"ids": list(asset_ids), "org_id": org_id},
    )
    assets = result.fetchall()
    if not assets:
        return summary

    dns_map = await _resolve_hostnames_async([a.hostname for a in assets])

    updates: list[dict] = []
    for asset in assets:
        hostname = asset.hostname
        resolved_ips = dns_map.get(hostname, [])
        dns_ok = len(resolved_ips) > 0
        port_ok = port_check_results.get(hostname, False)
        http_ok = http_check_results.get(hostname, False)
        checks_passed = int(dns_ok) + int(port_ok) + int(http_ok)

        old_failures = asset.consecutive_failures or 0
        tags = list(asset.tags or [])

        # CDN-fronted assets often block raw SYN probes (naabu), so
        # DNS + HTTP is sufficient to confirm liveness.
        is_cdn = bool(asset.cdn_provider) or "cdn" in tags
        threshold = 1 if (is_cdn and dns_ok and http_ok) else 2

        if checks_passed >= threshold:
            new_state = "confirmed_alive"
            new_failures = 0
            score_delta = _LIVENESS_BUMP_ALIVE
            score_floor = _LIVENESS_ALIVE_FLOOR
            summary["confirmed_alive"] += 1
        elif checks_passed == 1:
            new_state = "unconfirmed"
            new_failures = old_failures + 1
            score_delta = -_LIVENESS_DECAY_UNCONFIRMED
            score_floor = 0
            summary["unconfirmed"] += 1
        else:
            new_failures = old_failures + 1
            score_floor = 0
            if new_failures >= 3:
                new_state = "likely_dead"
                score_delta = -_LIVENESS_DECAY_DEAD
            else:
                new_state = "unconfirmed"
                score_delta = -_LIVENESS_DECAY_UNCONFIRMED
            summary["likely_dead" if new_state == "likely_dead" else "unconfirmed"] += 1

        # Cloud-provider attribution runs for every asset that resolved to
        # at least one IP — not just dangling ones. This drives the
        # inventory cloud filter, the takeover-severity bump below, and
        # tenant attribution downstream. First non-None match wins so a
        # multi-record (A) asset is attributed to whichever provider
        # answered first.
        cloud_provider: str | None = None
        for ip in resolved_ips:
            cloud_provider = identify_cloud_provider(ip)
            if cloud_provider:
                break

        is_dangling = dns_ok and not port_ok
        if is_dangling:
            if "dangling_dns" not in tags:
                tags.append("dangling_dns")
            summary["dangling_dns"] += 1
            if cloud_provider and "potential_takeover" not in tags:
                tags.append("potential_takeover")
        else:
            tags = [t for t in tags if t not in ("dangling_dns", "potential_takeover")]

        updates.append({
            "id": asset.id,
            "state": new_state,
            "failures": new_failures,
            "tags": tags,
            "did_resolve": dns_ok,
            "cloud_provider": cloud_provider,
            "score_delta": score_delta,
            "score_floor": score_floor,
        })

    # One UPDATE per chunk via a VALUES-driven join. cloud_provider is only
    # overwritten when DNS actually resolved (CASE WHEN v.did_resolve) — a
    # failed lookup leaves the previous classification alone, since the
    # absence of an answer isn't a signal that the asset moved off the cloud.
    # SQLAlchemy's text() bind parser refuses to bind `:name` when it's
    # followed by `::` (the parser disambiguates against Postgres casts), so
    # we wrap each bind in CAST(... AS type) instead. The casts are needed
    # so Postgres can infer column types for the synthetic VALUES table.
    for start in range(0, len(updates), _LIVENESS_UPDATE_CHUNK):
        chunk = updates[start:start + _LIVENESS_UPDATE_CHUNK]
        values_parts: list[str] = []
        params: dict = {"now": now}
        for i, u in enumerate(chunk):
            values_parts.append(
                f"(CAST(:id_{i} AS uuid), CAST(:state_{i} AS text), "
                f"CAST(:failures_{i} AS int), CAST(:tags_{i} AS text[]), "
                f"CAST(:did_resolve_{i} AS bool), "
                f"CAST(:cloud_provider_{i} AS text), "
                f"CAST(:score_delta_{i} AS int), "
                f"CAST(:score_floor_{i} AS int))"
            )
            params[f"id_{i}"] = u["id"]
            params[f"state_{i}"] = u["state"]
            params[f"failures_{i}"] = u["failures"]
            params[f"tags_{i}"] = u["tags"]
            params[f"did_resolve_{i}"] = u["did_resolve"]
            params[f"cloud_provider_{i}"] = u["cloud_provider"]
            params[f"score_delta_{i}"] = u["score_delta"]
            params[f"score_floor_{i}"] = u["score_floor"]

        sql = f"""
            UPDATE assets SET
                liveness_state = v.state,
                consecutive_failures = v.failures,
                last_validated_at = :now,
                tags = v.tags,
                cloud_provider = CASE WHEN v.did_resolve
                    THEN v.cloud_provider ELSE assets.cloud_provider END,
                liveness_score = LEAST(100, GREATEST(v.score_floor,
                    COALESCE(assets.liveness_score, 100) + v.score_delta))
            FROM (VALUES {', '.join(values_parts)})
                AS v(id, state, failures, tags, did_resolve, cloud_provider,
                     score_delta, score_floor)
            WHERE assets.id = v.id
        """
        await db.execute(text(sql), params)

    await db.commit()
    logger.info("org=%s liveness validation: %s", org_id, summary)
    return summary


# Sentinel telling create_dangling_dns_finding to run the probe itself.
# Distinct from None, which is a valid pre-computed result meaning "probed
# and found nothing." Lets callers gather probes in parallel and pass the
# results through without the helper re-probing serially.
_PROBE_PENDING = object()


async def probe_dangling_asset(
    hostname: str,
    cname_targets: list[str] | None,
    session: aiohttp.ClientSession,
) -> tuple[list[str], str | None, dict | None]:
    """Run all I/O for a single dangling asset: DNS, cloud attribution, takeover probe.

    Returns ``(resolved_ips, cloud_provider, takeover_evidence)``. Designed to
    be safe under ``asyncio.gather`` with a shared ``ClientSession`` so a
    batch of dangling hosts isn't probed serially. Never raises — a probe
    failure becomes ``takeover_evidence = None`` so the caller still creates
    the legacy dangling-DNS finding.
    """
    resolved_ips = await _resolve_one_bounded(hostname)
    cloud_provider: str | None = None
    for ip in resolved_ips:
        cloud_provider = identify_cloud_provider(ip)
        if cloud_provider:
            break
    try:
        evidence = await check_takeover_fingerprint(
            hostname, cname_targets=cname_targets, session=session,
        )
    except Exception:
        logger.debug("takeover fingerprint probe failed for %s", hostname, exc_info=True)
        evidence = None
    return resolved_ips, cloud_provider, evidence


async def create_dangling_dns_finding(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    hostname: str,
    resolved_ips: list[str],
    cloud_provider: str | None,
    cname_targets: list[str] | None = None,
    session: aiohttp.ClientSession | None = None,
    takeover_evidence: dict | None | object = _PROBE_PENDING,
) -> uuid.UUID:
    """Create a finding record for dangling DNS / potential subdomain takeover.

    When CNAME targets are known, attempts a lightweight HTTP probe against
    the hostname and cross-references the response with
    ``takeover_fingerprints.json`` to confirm a specific vulnerable service
    (S3, GitHub Pages, Heroku, etc.). A confirmed fingerprint promotes the
    finding to ``subdomain_takeover`` with severity taken from the fingerprint
    entry. Falls back to the legacy cloud-provider IP-prefix heuristic when
    no fingerprint matches.

    Pass ``takeover_evidence`` (a dict or None) when the caller has already
    probed — this skips the internal probe so a batch of dangling hosts can
    be processed without re-probing serially.
    """
    finding_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    if takeover_evidence is _PROBE_PENDING:
        try:
            takeover_evidence = await check_takeover_fingerprint(
                hostname, cname_targets=cname_targets, session=session,
            )
        except Exception as exc:
            # Never let probe errors break finding creation.
            logger.debug("takeover fingerprint probe failed for %s: %s", hostname, exc)
            takeover_evidence = None

    if takeover_evidence is not None:
        service_name = takeover_evidence.get("service") or "unknown-service"
        severity = takeover_evidence.get("severity") or "high"
        finding_type = "subdomain_takeover"
        title = f"Subdomain takeover ({service_name}): {hostname}"
        description = (
            f"Hostname {hostname} is vulnerable to subdomain takeover via {service_name}.\n\n"
            f"{takeover_evidence.get('description', '')}"
        ).strip()
        matched_by = takeover_evidence.get("matched_by")
        if matched_by == "http_fingerprint":
            description += (
                f"\n\nConfirmed by HTTP response fingerprint "
                f"(status {takeover_evidence.get('http_status')}): "
                f"'{takeover_evidence.get('matched_fingerprint', '')}'."
            )
        elif matched_by == "cname_pattern":
            description += (
                "\n\nMatched by CNAME target pattern; HTTP body fingerprint was "
                "not conclusive but the CNAME points at an unclaimed provider "
                "endpoint."
            )
        meta = {
            "resolved_ips": resolved_ips,
            "cloud_provider": cloud_provider,
            "hostname": hostname,
            "cname_targets": cname_targets or [],
            "takeover": takeover_evidence,
        }
    else:
        severity = "high" if cloud_provider else "medium"
        finding_type = "dangling_dns"
        title = f"Dangling DNS: {hostname}"
        if cloud_provider:
            title = f"Potential subdomain takeover ({cloud_provider}): {hostname}"

        description = (
            f"Hostname {hostname} resolves to {', '.join(resolved_ips)} but no ports respond. "
            f"This may indicate a dangling DNS record pointing to a decommissioned resource."
        )
        if cloud_provider:
            description += (
                f" The resolved IP belongs to {cloud_provider}, suggesting the underlying "
                f"cloud resource may have been released. An attacker could claim this resource "
                f"and serve content on {hostname}."
            )
        meta = {
            "resolved_ips": resolved_ips,
            "cloud_provider": cloud_provider,
            "hostname": hostname,
            "cname_targets": cname_targets or [],
        }

    await db.execute(
        text("""
            INSERT INTO findings (id, org_id, asset_id, finding_type, severity, title, description, metadata, status, created_at, updated_at)
            VALUES (:id, :org_id, :asset_id, :finding_type, :severity, :title, :desc, cast(:meta as jsonb), 'open', :now, :now)
            ON CONFLICT DO NOTHING
        """),
        {
            "id": finding_id,
            "org_id": org_id,
            "asset_id": asset_id,
            "finding_type": finding_type,
            "severity": severity,
            "title": title,
            "desc": description,
            "meta": json.dumps(meta),
            "now": now,
        },
    )
    return finding_id


async def quarantine_asset(db: AsyncSession, asset_id: uuid.UUID):
    """Move a likely_dead asset to archived/quarantine state."""
    await db.execute(
        text("UPDATE assets SET liveness_state = 'archived' WHERE id = :id AND liveness_state = 'likely_dead'"),
        {"id": asset_id},
    )

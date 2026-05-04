"""WAF / rate-limit evasion policy for the VM scanner.

Pure policy module — no I/O. Decides whether a Nuclei invocation should
go through a proxy and/or carry header tricks, and rewrites a Nuclei
command list accordingly. The worker calls ``decide_evasion`` once per
attempt and ``apply_to_nuclei_cmd`` at command-build time.

What this module does NOT do:

  - HTTP request smuggling. Smuggling exploits the upstream proxy/CDN
    itself, with blast radius onto other tenants of shared edge
    infrastructure. It belongs in a finding ("your CDN is vulnerable
    to CL.TE desync"), not as a transport for other findings.
  - Origin discovery (Censys/Shodan SSL pivots). The ``prefer_origin``
    flag is plumbed through but the resolver returns ``None`` until the
    discovery service ships — see ``resolve_origin``.
  - Base64 payload encoding. Nuclei has no body-encoding flag; it would
    require per-template rewrites and is deferred until proxy rotation
    alone proves insufficient.

Tiering (matches the design discussion):

  * Auto on first attempt when preflight detected a CDN — proxy + UA
    rotation + forwarded headers. CDN-fronted targets historically
    burned the full SCAN_TIMEOUT_SECONDS budget at ~5 rps and produced
    misleading "timeout" rows; the prior code short-circuited via
    ``NUCLEI_SKIP_CDN_TARGETS``. With a proxy pool configured the new
    default is "try with evasion first, short-circuit only if that
    also fails."
  * Auto on retry after status in ``{blocked, timeout, cdn_blocked}``.
    One retry only; if evasion also fails the target is genuinely
    inspecting deeper than headers/proxies can route around.
  * Opt-in via scan_plan flags — ``prefer_origin`` and (future)
    ``payload_encoding``.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from typing import Optional


# Statuses that mean "the first attempt was blocked at the network/edge,
# not at the application". A retry through a proxy with rotated headers
# has a real chance of succeeding. Anything else (unreachable, error,
# complete, partial) is either succeeding already or cannot be helped by
# evasion.
RETRYABLE_STATUSES: frozenset[str] = frozenset({"blocked", "timeout", "cdn_blocked"})


# Realistic browser User-Agents. Nuclei's default UA (``Nuclei - Open-source
# project (...)``) is on every commercial WAF's signature list; rotating
# through real Chrome/Firefox/Safari strings dodges the cheapest layer of
# fingerprint-based blocking. Kept small on purpose — a pool of 100 UAs
# would not improve evasion meaningfully and would make logs unreadable.
_BROWSER_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
)


@dataclass(frozen=True)
class EvasionConfig:
    """Static, env-driven configuration. One instance per worker process.

    ``proxy_pool`` is a list of full proxy URLs (``http://user:pw@host:port``,
    ``socks5://host:port``); empty means proxy rotation is unavailable and
    only header-level tricks can be applied. ``enabled`` is the master
    kill switch — when False, ``decide_evasion`` always returns None and
    the worker behaves identically to its pre-evasion shape.
    """

    enabled: bool = True
    proxy_pool: tuple[str, ...] = ()
    auto_on_cdn: bool = True
    auto_on_retry: bool = True

    @classmethod
    def from_env(cls) -> "EvasionConfig":
        enabled = os.environ.get("HAKUNA_EVASION_ENABLED", "true").lower() in {"1", "true", "yes"}
        raw = os.environ.get("HAKUNA_PROXY_POOL", "")
        pool = tuple(p.strip() for p in raw.split(",") if p.strip())
        auto_cdn = os.environ.get("HAKUNA_EVASION_AUTO_ON_CDN", "true").lower() in {"1", "true", "yes"}
        auto_retry = os.environ.get("HAKUNA_EVASION_AUTO_ON_RETRY", "true").lower() in {"1", "true", "yes"}
        return cls(enabled=enabled, proxy_pool=pool, auto_on_cdn=auto_cdn, auto_on_retry=auto_retry)


@dataclass
class EvasionPlan:
    """The concrete set of rewrites to apply to one Nuclei invocation.

    ``proxy_url`` is None when no proxy pool is configured — in that
    case header tricks alone are applied. ``extra_headers`` is a list
    of ``(name, value)`` tuples appended as ``-H`` flags after the
    credentials block, so credential headers always win on duplicates.
    ``label`` is a short tag (``"cdn-auto"``, ``"retry"``) surfaced in
    the result payload so the UI can show *why* the scan ran in
    evasion mode.
    """

    label: str
    proxy_url: Optional[str] = None
    extra_headers: list[tuple[str, str]] = field(default_factory=list)
    user_agent: Optional[str] = None
    prefer_origin: bool = False


def _pick_proxy(pool: tuple[str, ...], rng: random.Random) -> Optional[str]:
    if not pool:
        return None
    return rng.choice(pool)


def _pick_user_agent(rng: random.Random) -> str:
    return rng.choice(_BROWSER_USER_AGENTS)


def _spoof_ip(rng: random.Random) -> str:
    """Plausible-looking public-IP for X-Forwarded-For et al.

    Avoid private ranges (10/8, 172.16/12, 192.168/16) — many WAFs flag
    public-facing requests that claim a private origin as obviously
    forged and drop them. Reserved/loopback ranges are similarly
    suspicious. The pool here is intentionally narrow: a handful of
    well-known datacenter ASNs that look like legitimate cloud egress
    when proxied via a residential network.
    """
    # First octet drawn from a curated set; lower octets random.
    first = rng.choice([3, 13, 18, 35, 52, 54, 104, 142, 173, 199])
    return f"{first}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _build_header_set(
    rng: random.Random,
    *,
    target_host: Optional[str],
    prefer_origin: bool,
) -> tuple[list[tuple[str, str]], str]:
    """Synthesize the header pack + chosen UA for one scan attempt."""
    ua = _pick_user_agent(rng)
    spoof = _spoof_ip(rng)
    headers: list[tuple[str, str]] = [
        # X-Forwarded-* family — first hop most WAFs inspect for
        # client-IP attribution. Setting them all consistently dodges
        # the "missing companion header" detection some commercial
        # WAFs use.
        ("X-Forwarded-For", spoof),
        ("X-Real-IP", spoof),
        ("X-Originating-IP", spoof),
        ("X-Client-IP", spoof),
        ("X-Remote-IP", spoof),
        ("X-Remote-Addr", spoof),
    ]
    if prefer_origin and target_host:
        # Origin-direct scanning: we hit the origin server's IP but
        # claim the public hostname so the origin's vhost routing
        # picks the right app. This couples to origin discovery
        # (currently stubbed) — without a resolved origin IP it does
        # nothing harmful, so we set the headers unconditionally and
        # let the resolver gate target rewriting.
        headers.append(("X-Forwarded-Host", target_host))
        headers.append(("Host", target_host))
    return headers, ua


def decide_evasion(
    *,
    config: EvasionConfig,
    attempt: int,
    preflight_cdn: Optional[str],
    prior_status: Optional[str],
    plan_flags: Optional[dict] = None,
    target_host: Optional[str] = None,
    rng: Optional[random.Random] = None,
) -> Optional[EvasionPlan]:
    """Return an EvasionPlan when this attempt should run with evasion.

    ``attempt`` is 0-indexed (0 = first try, 1 = retry).
    ``preflight_cdn`` is the vendor name from the preflight probe, or None.
    ``prior_status`` is the status of attempt N-1; None on the first try.
    ``plan_flags`` are scan_plan opt-ins like ``prefer_origin``.
    """
    if not config.enabled:
        return None

    flags = plan_flags or {}
    prefer_origin = bool(flags.get("prefer_origin"))

    is_first = attempt == 0
    triggered_by_cdn = is_first and config.auto_on_cdn and bool(preflight_cdn)
    triggered_by_retry = (
        not is_first and config.auto_on_retry and prior_status in RETRYABLE_STATUSES
    )
    triggered_by_optin = is_first and prefer_origin

    if not (triggered_by_cdn or triggered_by_retry or triggered_by_optin):
        return None

    rng = rng or random.Random()
    headers, ua = _build_header_set(
        rng, target_host=target_host, prefer_origin=prefer_origin,
    )
    proxy = _pick_proxy(config.proxy_pool, rng)

    if triggered_by_retry:
        label = f"retry-after-{prior_status}"
    elif triggered_by_cdn:
        label = f"cdn-auto-{preflight_cdn}"
    else:
        label = "optin-prefer-origin"

    return EvasionPlan(
        label=label,
        proxy_url=proxy,
        extra_headers=headers,
        user_agent=ua,
        prefer_origin=prefer_origin,
    )


def apply_to_nuclei_cmd(cmd: list[str], plan: EvasionPlan) -> list[str]:
    """Return a new Nuclei command list with the evasion plan applied.

    Inserts ``-proxy <url>`` (when set) and ``-H`` pairs for every
    synthesised header plus the chosen UA. Does not touch existing
    ``-H`` flags from the credentials block — those are appended
    earlier in the command and we explicitly want credential headers
    to win when names collide (the credential's Authorization header
    must not be overridden by an evasion-side User-Agent override
    or similar).

    The returned list is a shallow copy; the caller can pass it to
    ``asyncio.create_subprocess_exec`` directly.
    """
    out: list[str] = list(cmd)
    if plan.proxy_url:
        out.extend(["-proxy", plan.proxy_url])
    if plan.user_agent:
        out.extend(["-H", f"User-Agent: {plan.user_agent}"])
    for name, value in plan.extra_headers:
        out.extend(["-H", f"{name}: {value}"])
    return out


def resolve_origin(target: str) -> Optional[str]:  # noqa: ARG001
    """Stub. Real implementation lands with the origin-discovery service.

    Plumbed in so ``prefer_origin`` does not silently no-op when the
    flag is set — the call site gets ``None`` today and the worker
    proceeds with the public CDN hostname. When this returns an IP,
    the worker rewrites the target and the synthesised Host header
    keeps vhost routing intact on the origin.
    """
    return None

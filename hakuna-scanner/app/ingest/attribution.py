"""Tenant attribution for cloud-hosted assets.

When an asset's IP belongs to a shared cloud provider (AWS, Azure, GCP,
Cloudflare, etc.), the IP itself doesn't identify *who* controls the
underlying resource. The signals that do — in roughly descending order
of strength:

* TLS cert SAN/CN on 443 (or any TLS port). The cert is presented by
  whoever set up the listener, so SAN naming the tenant's registrable
  domain is the strongest external signal.
* rDNS PTR. Sometimes a tenant sets a custom PTR; usually it's a generic
  cloud-provider-issued name (``ec2-*.compute.amazonaws.com``,
  ``*.cloudapp.azure.com``) that confirms the cloud but not the tenant.
* Favicon hash / HTTP banner — distinctive defaults can fingerprint the
  app or company. (Not implemented in v1; the slot in ``signals`` is
  reserved for it.)
* IP-side passive DNS (OTX, etc.) — historical hostnames that resolved
  here. Aggregate by registrable domain; multiple matches on one parent
  is a strong tenant signal. (Not implemented in v1; same reservation.)

Confidence weights are deliberately conservative — the worst failure
mode is attributing someone else's tenant to your org and missing the
takeover risk, so we keep wildcard SANs and generic cloud PTRs in the
"low confidence" bucket.

The function is pure (no I/O), so callers feed it pre-fetched cert and
rDNS data and the tests don't need a network or DB.
"""

from __future__ import annotations

import logging
from typing import Iterable

import tldextract

logger = logging.getLogger(__name__)


# Registrable domains that always belong to cloud/SaaS providers rather
# than to a specific tenant. A SAN or PTR ending in any of these names
# confirms the platform but not the controller — confidence is capped
# accordingly.
GENERIC_CLOUD_DOMAINS: frozenset[str] = frozenset({
    # AWS
    "amazonaws.com", "aws.amazon.com", "elasticbeanstalk.com",
    "cloudfront.net", "awsglobalaccelerator.com",
    # Azure
    "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
    "trafficmanager.net", "azureedge.net", "azurefd.net", "windows.net",
    # GCP
    "googleusercontent.com", "appspot.com", "run.app", "cloudfunctions.net",
    "cloud.goog", "gcp.cloud.goog",
    # Cloudflare
    "cloudflare.com", "pages.dev", "workers.dev", "cloudflareaccess.com",
    # Hosted PaaS
    "herokuapp.com", "herokussl.com", "netlify.app", "vercel.app",
    "now.sh", "fly.dev", "render.com", "railway.app",
    # Code hosting (default GitHub/GitLab pages)
    "github.io", "gitlab.io",
    # Object storage / static site
    "digitaloceanspaces.com", "linodeusercontent.com",
})


# Confidence weights (0..1). See module docstring for rationale.
_W_TLS_SAN_ORG = 0.95          # SAN/CN matches a target_domain exactly
_W_TLS_SAN_REGISTRABLE = 0.80  # SAN/CN registrable domain matches target_domain
_W_TLS_SAN_OTHER = 0.75        # SAN/CN points to a non-target, non-generic name
_W_TLS_SAN_WILDCARD_PENALTY = 0.20  # subtract this if SAN is wildcard-only
_W_TLS_SAN_GENERIC_CLOUD = 0.25     # SAN is *.cloudfront.net etc.
_W_RDNS_OTHER = 0.70                # PTR points to a non-generic name
_W_RDNS_GENERIC_CLOUD = 0.20        # PTR is the generic cloud-issued name


# tldextract caches the public-suffix list on disk on first use; pin a
# single extractor so we don't refetch the list on every call. Falls
# back to a snapshot bundled with tldextract when offline.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


def _registrable(name: str | None) -> str | None:
    """Return the registrable (eTLD+1) form of ``name``, or None.

    Strips wildcards and trailing dots. Returns None for empty inputs,
    bare-IP inputs, and names with no public suffix.
    """
    if not name:
        return None
    cleaned = name.strip().lower().lstrip("*.").rstrip(".")
    if not cleaned or "." not in cleaned:
        return None
    parts = _TLD_EXTRACTOR(cleaned)
    # tldextract>=5.2 renamed `registered_domain` to
    # `top_domain_under_public_suffix`; fall back for older installs.
    reg = getattr(parts, "top_domain_under_public_suffix", None) or getattr(
        parts, "registered_domain", None
    )
    return reg or None


def _is_generic_cloud(name: str | None) -> bool:
    reg = _registrable(name)
    return reg is not None and reg in GENERIC_CLOUD_DOMAINS


def _is_wildcard(san: str) -> bool:
    return san.startswith("*.")


def _collect_san_candidates(
    tls_certs: Iterable[dict | None],
    target_domains_lower: set[str],
) -> list[dict]:
    """Walk every per-port TLS cert and emit one candidate per SAN/CN.

    Deduplicates by (registrable, signal_kind) so a cert with five SANs
    pointing to the same registrable domain doesn't overweight the
    aggregation later.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    for cert in tls_certs:
        if not isinstance(cert, dict):
            continue
        names: list[str] = []
        for san in cert.get("sans") or cert.get("san") or []:
            if isinstance(san, str):
                names.append(san)
        # Subject CN — sometimes lives at top level, sometimes parsed out.
        cn = cert.get("subject_cn") or cert.get("subject")
        if isinstance(cn, str) and cn:
            names.append(cn)

        for raw in names:
            reg = _registrable(raw)
            if reg is None:
                continue
            wildcard = _is_wildcard(raw.strip())
            generic = reg in GENERIC_CLOUD_DOMAINS

            # Pick a confidence based on what we matched and how.
            if reg in target_domains_lower:
                confidence = _W_TLS_SAN_ORG
            elif generic:
                confidence = _W_TLS_SAN_GENERIC_CLOUD
            else:
                confidence = _W_TLS_SAN_OTHER
            if wildcard and not generic:
                # Wildcard certs are sometimes shared across many tenants
                # of the same SaaS — downgrade slightly. Keep the
                # generic-cloud cap as-is since we already capped it.
                confidence = max(0.0, confidence - _W_TLS_SAN_WILDCARD_PENALTY)

            key = (reg, "tls_san")
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "name": reg,
                "signal": "tls_san",
                "confidence": round(confidence, 3),
                "raw": raw,
                "wildcard": wildcard,
                "generic_cloud": generic,
            })
    return out


def _collect_rdns_candidate(rdns: str | None) -> dict | None:
    reg = _registrable(rdns)
    if reg is None:
        return None
    confidence = _W_RDNS_GENERIC_CLOUD if reg in GENERIC_CLOUD_DOMAINS else _W_RDNS_OTHER
    return {
        "name": reg,
        "signal": "rdns",
        "confidence": round(confidence, 3),
        "raw": rdns,
        "generic_cloud": reg in GENERIC_CLOUD_DOMAINS,
    }


def attribute_asset(
    hostname: str,
    cloud_provider: str | None,
    tls_certs: Iterable[dict | None] = (),
    target_domains: Iterable[str] = (),
    rdns: str | None = None,
) -> dict:
    """Compute tenant attribution for a single asset.

    Returns the structure documented in migration 020. ``best_guess`` is
    None when no signal exceeded the noise floor (e.g. cloud-only PTR
    with no cert). Always returns a dict so callers can JSONB-encode it
    unconditionally.
    """
    target_domains_lower: set[str] = {d.strip().lower() for d in target_domains if d}

    candidates = _collect_san_candidates(tls_certs, target_domains_lower)
    rdns_cand = _collect_rdns_candidate(rdns)
    if rdns_cand is not None:
        candidates.append(rdns_cand)

    # Aggregate by name — the same registrable domain seen via multiple
    # signals is more credible than either alone. We take the max of
    # the per-signal confidences and add a small bonus per additional
    # corroborating signal, capped at 0.99.
    by_name: dict[str, dict] = {}
    for cand in candidates:
        name = cand["name"]
        existing = by_name.get(name)
        if existing is None:
            by_name[name] = {
                "name": name,
                "confidence": cand["confidence"],
                "signals": {cand["signal"]},
                "is_self": name in target_domains_lower,
            }
        else:
            existing["signals"].add(cand["signal"])
            existing["confidence"] = max(existing["confidence"], cand["confidence"])
            # Multi-signal corroboration bonus.
            existing["confidence"] = min(0.99, existing["confidence"] + 0.05)

    # Build the public-shape candidate list and pick a best guess.
    owner_candidates: list[dict] = []
    for entry in by_name.values():
        owner_candidates.append({
            "name": entry["name"],
            "confidence": round(entry["confidence"], 3),
            "signals": sorted(entry["signals"]),
            "is_self": entry["is_self"],
        })
    owner_candidates.sort(
        key=lambda c: (c["is_self"], c["confidence"]),
        reverse=True,
    )

    best_guess = owner_candidates[0]["name"] if owner_candidates else None
    confidence = owner_candidates[0]["confidence"] if owner_candidates else 0.0
    is_self = owner_candidates[0]["is_self"] if owner_candidates else False

    # Collect raw signals for downstream display / debugging.
    tls_sans_raw: list[str] = []
    for cert in tls_certs:
        if not isinstance(cert, dict):
            continue
        for san in cert.get("sans") or cert.get("san") or []:
            if isinstance(san, str):
                tls_sans_raw.append(san)

    return {
        "best_guess": best_guess,
        "confidence": confidence,
        "is_self": is_self,
        "cloud_provider": cloud_provider,
        "owner_candidates": owner_candidates,
        "signals": {
            "tls_sans": sorted(set(tls_sans_raw)),
            "rdns": rdns,
            # Reserved for v2:
            "favicon_hash": None,
            "passive_dns": [],
        },
    }

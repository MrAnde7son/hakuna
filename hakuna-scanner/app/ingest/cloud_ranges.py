"""Cloud-provider IP-range matching.

Loads per-provider CIDR lists from ``settings.cloud_ranges_dir`` (refreshed
nightly by ``app.tasks.cloud_ranges``) into a pytricia radix tree. The tree
gives sub-microsecond longest-prefix-match for every asset's IP, which
matters at 10k+ assets per scan — a linear scan of ~7000 AWS prefixes per
asset would otherwise dominate liveness wall-time.

Falls back to a bundled seed list (the prefix dict that previously lived in
``liveness.py``) when the directory is empty — so a fresh deploy still
classifies the major Cloudflare/AWS/Azure/GCP ranges before the first
fetch task has run.

Order matters in the seed: providers with highly specific prefixes
(Cloudflare, GCP) are inserted before broad ones (Azure, AWS) so the
longest-prefix match wins on ambiguous /8 overlaps.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Iterable

from app.config import settings

logger = logging.getLogger(__name__)

# Bundled seed: hand-curated CIDR prefixes covering the popular ranges of
# each provider. Used when ``cloud_ranges_dir`` is empty (fresh deploy,
# fetcher hasn't run yet, or fetch is failing). These are the same string
# prefixes that previously lived in liveness.CLOUD_PROVIDER_PREFIXES,
# converted to proper CIDR form.
_SEED_PREFIXES: list[tuple[str, list[str]]] = [
    # Cloudflare /16s — all very specific, safe to match first.
    ("cloudflare", [
        "104.16.0.0/12", "104.16.0.0/16", "104.17.0.0/16", "104.18.0.0/16",
        "104.19.0.0/16", "104.20.0.0/16", "104.21.0.0/16", "104.22.0.0/16",
        "104.23.0.0/16", "104.24.0.0/16", "104.25.0.0/16",
        "172.64.0.0/16", "172.65.0.0/16", "172.66.0.0/16", "172.67.0.0/16",
        "173.245.0.0/16", "188.114.0.0/16", "190.93.0.0/16",
        "197.234.0.0/16", "198.41.0.0/16",
    ]),
    # GCP — mostly /16s, plus 35.0.0.0/8 (broad, last resort).
    ("gcp", [
        "34.64.0.0/16", "34.80.0.0/16", "34.96.0.0/16", "34.104.0.0/16",
        "34.120.0.0/16", "34.128.0.0/16",
        "35.0.0.0/8",
    ]),
    # AWS — broad /8s. Heuristic only; the fetcher replaces these with
    # the precise published prefixes.
    ("aws", [
        "3.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8",
        "44.0.0.0/8", "50.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "63.0.0.0/8",
        "99.0.0.0/8", "100.0.0.0/8", "107.0.0.0/8", "108.0.0.0/8",
        "142.0.0.0/8", "143.0.0.0/8", "150.0.0.0/8", "157.0.0.0/8",
        "160.0.0.0/8", "161.0.0.0/8", "162.0.0.0/8", "168.0.0.0/8",
        "170.0.0.0/8", "174.0.0.0/8", "175.0.0.0/8", "176.0.0.0/8",
        "177.0.0.0/8", "178.0.0.0/8", "184.0.0.0/8", "185.0.0.0/8",
        "192.0.2.0/24",
        "46.51.0.0/16", "72.44.0.0/16", "75.2.0.0/16", "76.223.0.0/16",
    ]),
    # Azure — mix of /16s and /8s. The fetcher does not refresh Azure
    # (their download URL rotates weekly and requires HTML scraping), so
    # this seed is the long-term source of truth for Azure.
    ("azure", [
        "13.64.0.0/16", "13.65.0.0/16", "13.66.0.0/16", "13.67.0.0/16",
        "13.68.0.0/16", "13.69.0.0/16", "13.70.0.0/16", "13.71.0.0/16",
        "13.72.0.0/16", "13.73.0.0/16", "13.74.0.0/16", "13.75.0.0/16",
        "13.76.0.0/16", "13.77.0.0/16", "13.78.0.0/16", "13.79.0.0/16",
        "13.80.0.0/16", "13.81.0.0/16", "13.82.0.0/16", "13.83.0.0/16",
        "13.84.0.0/16", "13.85.0.0/16", "13.86.0.0/16", "13.87.0.0/16",
        "13.88.0.0/16", "13.89.0.0/16", "13.90.0.0/16", "13.91.0.0/16",
        "13.92.0.0/16", "13.93.0.0/16",
        "20.0.0.0/8", "23.0.0.0/8", "40.0.0.0/8", "51.0.0.0/8", "52.0.0.0/8",
        "65.0.0.0/8", "70.0.0.0/8", "102.0.0.0/8", "104.0.0.0/8",
        "137.0.0.0/8", "138.0.0.0/8", "157.0.0.0/8", "168.0.0.0/8",
        "191.0.0.0/8",
    ]),
]


# Providers known to the system. Used by the fetcher and by reload to
# decide which JSON files to consult.
KNOWN_PROVIDERS: tuple[str, ...] = (
    "cloudflare", "gcp", "aws", "azure", "oracle", "digitalocean", "fastly",
)


_lock = threading.Lock()
_tree4 = None  # PyTricia or None
_tree6 = None
_loaded_from: str | None = None


def _new_pytricia(width: int):
    """Return a new PyTricia tree, or None if pytricia isn't installed.

    Graceful fallback: when the C extension can't be imported (e.g. local
    dev on a fresh checkout where requirements haven't been reinstalled),
    callers see ``None`` and ``identify_cloud_provider`` returns ``None``
    rather than crashing the liveness pipeline.
    """
    try:
        from pytricia import PyTricia  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "pytricia not installed; cloud-provider attribution disabled. "
            "Install pytricia>=1.0.2 to enable."
        )
        return None
    return PyTricia(width)


def _load_dir_cidrs(directory: str) -> list[tuple[str, Iterable[str]]]:
    """Load (provider, cidrs) pairs from per-provider JSON files.

    Each file is named ``{provider}.json`` with shape
    ``{"updated_at": "...", "cidrs": ["1.2.3.0/24", ...]}``. Missing
    files are silently skipped — the seed covers them.
    """
    pairs: list[tuple[str, Iterable[str]]] = []
    if not directory or not os.path.isdir(directory):
        return pairs
    for provider in KNOWN_PROVIDERS:
        path = os.path.join(directory, f"{provider}.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("cloud_ranges: failed to load %s: %s", path, exc)
            continue
        cidrs = data.get("cidrs") or []
        if cidrs:
            pairs.append((provider, cidrs))
    return pairs


def _build_trees() -> tuple[object, object, str]:
    """Build the IPv4/IPv6 trees from disk + seed.

    Disk wins: any provider with a fetched JSON file replaces the seed
    entry for that provider. Returned source string is purely
    informational ("seed", "disk", "disk+seed").
    """
    tree4 = _new_pytricia(32)
    tree6 = _new_pytricia(128)

    disk_pairs = _load_dir_cidrs(settings.cloud_ranges_dir)
    disk_providers = {p for p, _ in disk_pairs}

    # Seed entries first, but skip any provider we'll overwrite from disk.
    seed_used = False
    for provider, cidrs in _SEED_PREFIXES:
        if provider in disk_providers:
            continue
        seed_used = True
        for cidr in cidrs:
            try:
                _insert(tree4, tree6, cidr, provider)
            except Exception as exc:
                logger.debug("cloud_ranges: skip seed %s: %s", cidr, exc)

    for provider, cidrs in disk_pairs:
        for cidr in cidrs:
            try:
                _insert(tree4, tree6, cidr, provider)
            except Exception as exc:
                logger.debug("cloud_ranges: skip %s/%s: %s", provider, cidr, exc)

    if disk_pairs and seed_used:
        source = "disk+seed"
    elif disk_pairs:
        source = "disk"
    else:
        source = "seed"
    return tree4, tree6, source


def _insert(tree4, tree6, cidr: str, provider: str) -> None:
    if tree4 is None and tree6 is None:
        return
    # PyTricia accepts both IPv4 and IPv6 in the same tree, but we keep
    # them separate to avoid version-mixing surprises.
    if ":" in cidr:
        if tree6 is not None:
            tree6.insert(cidr, provider)
    else:
        if tree4 is not None:
            tree4.insert(cidr, provider)


def _ensure_loaded() -> None:
    global _tree4, _tree6, _loaded_from
    if _tree4 is not None or _tree6 is not None:
        return
    with _lock:
        if _tree4 is not None or _tree6 is not None:
            return
        _tree4, _tree6, _loaded_from = _build_trees()
        logger.info("cloud_ranges: loaded from %s", _loaded_from)


def reload() -> None:
    """Force a rebuild of the trees. Called by the fetcher after writing
    fresh JSON files, and by tests that mutate the on-disk seed.
    """
    global _tree4, _tree6, _loaded_from
    with _lock:
        _tree4, _tree6, _loaded_from = _build_trees()


def identify_cloud_provider(ip: str | None) -> str | None:
    """Return the cloud provider name that owns ``ip``, or None.

    Stable signature — drop-in replacement for the function that
    previously lived in liveness.py.
    """
    if not ip:
        return None
    _ensure_loaded()
    tree = _tree6 if ":" in ip else _tree4
    if tree is None:
        return None
    try:
        return tree.get(ip)
    except (KeyError, ValueError):
        return None

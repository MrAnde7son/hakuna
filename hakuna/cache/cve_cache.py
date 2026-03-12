"""
CVE Semantic Cache — avoids redundant LLM calls for CVE enrichment lookups.

Key: CVE ID + enrichment type
Value: agent response + token count + timestamp
TTL: 24 hours for KEV status, 7 days for CVSS/exploit data

Usage:
    from hakuna.cache.cve_cache import CVECache

    cache = CVECache()                        # or CVECache(path="custom/path.json")

    entry = cache.get("CVE-2021-44228", "exploit_data")
    if entry:
        result, tokens_saved = entry["response"], entry["tokens"]
    else:
        # make the LLM call
        response = ...
        cache.set("CVE-2021-44228", "exploit_data", response, tokens_used=800)

    stats = cache.get_stats()                 # hits, misses, tokens_saved
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ── TTL policy ────────────────────────────────────────────────────────

_DEFAULT_TTLS: Dict[str, timedelta] = {
    # KEV status changes daily (CISA pushes updates)
    "kev_status": timedelta(hours=24),
    # Exploit data (Metasploit/nuclei availability) — changes weekly
    "exploit_data": timedelta(days=7),
    # CVSS scores are permanent once assigned
    "cvss": timedelta(days=30),
    # EPSS scores update daily
    "epss": timedelta(hours=24),
    # Threat group / campaign correlation — stable over a week
    "threat_intel": timedelta(days=7),
    # Generic enrichment fallback
    "enrichment": timedelta(days=7),
}

_DEFAULT_CACHE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "reports", "cve_cache.json"
)


class CVECache:
    """Persistent JSON-backed semantic cache for CVE enrichment responses.

    Thread-safe. Persists to disk on every write so it survives process restarts.
    Entries expire according to TTL policy above.
    """

    def __init__(self, path: Optional[str] = None):
        self._path = os.path.abspath(path or _DEFAULT_CACHE_PATH)
        self._lock = threading.Lock()
        self._store: Dict[str, Any] = {}
        self._stats = {"hits": 0, "misses": 0, "tokens_saved": 0, "calls_avoided": 0}
        self._load()

    # ── Public API ────────────────────────────────────────────────────

    def get(self, cve_id: str, enrichment_type: str) -> Optional[Dict[str, Any]]:
        """Return cached entry if present and not expired.

        Returns None on miss (caller should make the LLM call and then cache.set()).
        """
        key = self._make_key(cve_id, enrichment_type)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._stats["misses"] += 1
                logger.debug("CVECache miss: %s", key)
                return None

            # Check TTL
            ttl = _DEFAULT_TTLS.get(enrichment_type, timedelta(days=7))
            cached_at = datetime.fromisoformat(entry["cached_at"])
            if datetime.utcnow() - cached_at > ttl:
                del self._store[key]
                self._stats["misses"] += 1
                logger.debug("CVECache expired: %s (age=%s)", key, datetime.utcnow() - cached_at)
                return None

            self._stats["hits"] += 1
            self._stats["tokens_saved"] += entry.get("tokens", 0)
            self._stats["calls_avoided"] += 1
            logger.debug("CVECache hit: %s (tokens_saved=%d)", key, entry.get("tokens", 0))
            return entry

    def set(
        self,
        cve_id: str,
        enrichment_type: str,
        response: Any,
        tokens_used: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store an enrichment response in the cache."""
        key = self._make_key(cve_id, enrichment_type)
        entry = {
            "cve_id": cve_id,
            "enrichment_type": enrichment_type,
            "response": response,
            "tokens": tokens_used,
            "cached_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }
        with self._lock:
            self._store[key] = entry
            self._persist()

    def invalidate(self, cve_id: str, enrichment_type: Optional[str] = None) -> int:
        """Remove cache entries for a CVE (all types if enrichment_type is None).

        Returns number of entries removed.
        """
        with self._lock:
            if enrichment_type:
                key = self._make_key(cve_id, enrichment_type)
                removed = 1 if self._store.pop(key, None) else 0
            else:
                prefix = f"{cve_id}::"
                to_remove = [k for k in self._store if k.startswith(prefix)]
                for k in to_remove:
                    del self._store[k]
                removed = len(to_remove)
            if removed:
                self._persist()
        return removed

    def get_stats(self) -> Dict[str, Any]:
        """Return cache hit/miss statistics for this session."""
        with self._lock:
            total = self._stats["hits"] + self._stats["misses"]
            hit_rate = round(self._stats["hits"] / max(total, 1) * 100, 1)
            return {
                **self._stats,
                "total_lookups": total,
                "hit_rate_pct": hit_rate,
                "cache_size": len(self._store),
                "cache_path": self._path,
            }

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        removed = 0
        now = datetime.utcnow()
        with self._lock:
            keys_to_remove = []
            for key, entry in self._store.items():
                enrichment_type = entry.get("enrichment_type", "enrichment")
                ttl = _DEFAULT_TTLS.get(enrichment_type, timedelta(days=7))
                cached_at = datetime.fromisoformat(entry["cached_at"])
                if now - cached_at > ttl:
                    keys_to_remove.append(key)
            for k in keys_to_remove:
                del self._store[k]
            removed = len(keys_to_remove)
            if removed:
                self._persist()
        logger.info("CVECache: purged %d expired entries", removed)
        return removed

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _make_key(cve_id: str, enrichment_type: str) -> str:
        return f"{cve_id.upper()}::{enrichment_type}"

    def _load(self) -> None:
        """Load cache from disk. Silent on missing file."""
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            self._store = data.get("store", {})
            logger.debug("CVECache loaded %d entries from %s", len(self._store), self._path)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("CVECache: failed to load from %s: %s", self._path, e)
            self._store = {}

    def _persist(self) -> None:
        """Write cache to disk. Must be called with self._lock held."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        try:
            with open(self._path, "w") as f:
                json.dump(
                    {"store": self._store, "saved_at": datetime.utcnow().isoformat()},
                    f,
                    indent=2,
                    default=str,
                )
        except IOError as e:
            logger.warning("CVECache: failed to persist to %s: %s", self._path, e)


# ── Singleton ─────────────────────────────────────────────────────────

_cve_cache_instance: Optional[CVECache] = None
_cve_cache_lock = threading.Lock()


def get_cve_cache() -> CVECache:
    """Return the process-level singleton CVECache."""
    global _cve_cache_instance
    if _cve_cache_instance is None:
        with _cve_cache_lock:
            if _cve_cache_instance is None:
                _cve_cache_instance = CVECache()
    return _cve_cache_instance

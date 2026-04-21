"""Typed capability store — foundation for exploit composition.

Specialists today exchange hints through ``AgentContext.shared_memory``
(a flat ``dict[str, str]``). That works for prose hints but can't carry
the structure a downstream agent actually needs: which user was leaked,
what scheme credentials are in, whether an SSRF reaches internal hosts.
Composition requires typed primitives.

A ``Capability`` is a typed, scoped, provenanced fact about the target.
Specialists produce them on emit; later specialists consume them from
the store. The type taxonomy is deliberately small and closed — adding
a new type is a schema change and should be deliberate. Unknown facts
fall through to the ``NOTE`` type (free-form string) so we don't lose
information that doesn't yet have a typed slot.

Step 1 scope (this module):

  - Define ``Capability`` and ``CapabilityStore``.
  - Auto-mirror the handful of well-known ``memory_set`` keys the
    existing specialist prompts already use (``valid_credentials``,
    ``valid_user_id``, ``internal_host_reachable``, ``web_root``,
    ``csrf_token_missing_on``, ``jwt_leaked_in_body``, ``waf_present``)
    into typed capabilities. Everything else becomes a ``NOTE``.
  - Render a compact summary for the initial-message builder so the
    prompt block is stable across runs.

Out of scope for step 1: scheduler changes, specialist ``requires``/
``produces`` contracts, identity re-auth, non-HTTP transports. Those
build on this foundation.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)


# ── Capability type registry ─────────────────────────────────────
# Closed enum-like set. A new type here is a deliberate schema change:
# downstream consumers (future specialist ``requires`` predicates,
# prompt renderers, persistence) switch on ``type``, so silently adding
# unfamiliar strings would produce invisible capabilities.


class CapabilityType:
    # Auth / identity
    CRED = "credentials"          # value: {"scheme": "basic|bearer|cookie", "username"?, "password"?, "token"?}
    SESSION = "session"           # value: {"cookie": str} or {"jwt": str}
    IDENTIFIER = "identifier"     # value: {"kind": "user_id|org_id|email|...", "value": str}

    # Exploit primitives
    SQL_READ = "sql_read"         # confirmed read-only SQLi
    SQL_WRITE = "sql_write"       # confirmed write-capable SQLi
    CMD_EXEC = "cmd_exec"         # command execution confirmed
    FILE_READ = "file_read"       # LFI / path traversal read primitive
    FILE_WRITE = "file_write"     # write primitive
    SSRF_PRIMITIVE = "ssrf_primitive"  # server fetches arbitrary URLs
    CSRF_WEAK = "csrf_weak"       # a specific endpoint missing/weak CSRF

    # Reconnaissance facts
    INTERNAL_HOST = "internal_host"   # value: {"host": str, "port": int?}
    WEB_ROOT = "web_root"             # value: {"path": str}
    WAF = "waf"                       # value: {"vendor": str?}

    # Fallback — any string fact that doesn't fit a typed slot.
    NOTE = "note"


_KNOWN_TYPES = frozenset({
    CapabilityType.CRED, CapabilityType.SESSION, CapabilityType.IDENTIFIER,
    CapabilityType.SQL_READ, CapabilityType.SQL_WRITE, CapabilityType.CMD_EXEC,
    CapabilityType.FILE_READ, CapabilityType.FILE_WRITE,
    CapabilityType.SSRF_PRIMITIVE, CapabilityType.CSRF_WEAK,
    CapabilityType.INTERNAL_HOST, CapabilityType.WEB_ROOT, CapabilityType.WAF,
    CapabilityType.NOTE,
})


# ── Risk levels ──────────────────────────────────────────────────
# Used later by the scheduler to gate destructive chains behind explicit
# scan authorization. Step 1 just records the level; nothing enforces it
# yet. Default ``read_only`` so unclassified caps don't accidentally
# unlock future destructive automation.


class RiskLevel:
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    DESTRUCTIVE = "destructive"


_KNOWN_RISK = frozenset({
    RiskLevel.READ_ONLY, RiskLevel.STATE_CHANGE, RiskLevel.DESTRUCTIVE,
})


# ── Capability ───────────────────────────────────────────────────


@dataclass(frozen=True)
class Capability:
    """A typed, scoped fact about the target.

    Immutable. To "update" a capability (e.g. higher confidence from a
    second confirmation), insert a new one — ``CapabilityStore.add``
    dedups by (type, scope, canonical value) and keeps the higher-
    confidence record.
    """
    type: str
    scope: str
    value: dict
    confidence: float = 1.0
    risk_level: str = RiskLevel.READ_ONLY
    ttl_sec: int | None = None
    provenance: str | None = None
    created_at: float = field(default_factory=time.monotonic)

    def is_expired(self, now: float | None = None) -> bool:
        if self.ttl_sec is None:
            return False
        now = now if now is not None else time.monotonic()
        return (now - self.created_at) >= self.ttl_sec

    def dedup_key(self) -> tuple:
        # Canonicalize the value for dedup. Order-insensitive on top-level
        # keys; nested dicts/lists serialise by their repr, which is fine
        # because well-known types have shallow, fixed shapes.
        canon = tuple(sorted((k, repr(v)) for k, v in self.value.items()))
        return (self.type, self.scope, canon)


# ── Store ────────────────────────────────────────────────────────

_DEFAULT_MAX_CAPABILITIES = 128


@dataclass
class CapabilityStore:
    """Per-scan, per-asset typed fact store.

    Bounded to keep the prompt payload and the post-scan result blob
    small — a pathological specialist can't turn this into an exfil
    channel. When full, new inserts are rejected (not LRU-evicted)
    because evicting a leaked-credential fact to make room for a
    low-value note would be the wrong default.
    """
    max_capabilities: int = _DEFAULT_MAX_CAPABILITIES
    _caps: list[Capability] = field(default_factory=list)
    _index: dict[tuple, int] = field(default_factory=dict)  # dedup_key -> list index

    def add(self, cap: Capability) -> bool:
        """Insert or upgrade. Returns True if the store changed."""
        if cap.type not in _KNOWN_TYPES:
            logger.warning("capability rejected: unknown type=%r", cap.type)
            return False
        if cap.risk_level not in _KNOWN_RISK:
            logger.warning("capability rejected: unknown risk_level=%r", cap.risk_level)
            return False
        if not (0.0 <= cap.confidence <= 1.0):
            logger.warning("capability rejected: confidence out of range: %r", cap.confidence)
            return False

        key = cap.dedup_key()
        existing_idx = self._index.get(key)
        if existing_idx is not None:
            existing = self._caps[existing_idx]
            # Upgrade only when the new record is meaningfully more
            # confident. Ties keep the earlier provenance so the audit
            # trail points at the first discoverer.
            if cap.confidence > existing.confidence:
                self._caps[existing_idx] = cap
                return True
            return False

        if len(self._caps) >= self.max_capabilities:
            logger.info("capability store full (%d) — dropping %s:%s",
                        self.max_capabilities, cap.type, cap.scope)
            return False

        self._index[key] = len(self._caps)
        self._caps.append(cap)
        return True

    def query(
        self,
        *,
        type: str | None = None,
        scope: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[Capability]:
        """Return matching non-expired capabilities in insertion order."""
        now = time.monotonic()
        out: list[Capability] = []
        for cap in self._caps:
            if cap.is_expired(now):
                continue
            if type is not None and cap.type != type:
                continue
            if scope is not None and cap.scope != scope:
                continue
            if cap.confidence < min_confidence:
                continue
            out.append(cap)
        return out

    def all(self) -> list[Capability]:
        return self.query()

    def __len__(self) -> int:
        return sum(1 for _ in self.all())

    def summarize(self, *, include_notes: bool = True) -> list[dict]:
        """Compact per-capability view for prompt rendering / logs.

        Keeps fields the LLM can actually act on (type, scope, value,
        confidence). Skips internals (``created_at``, dedup key).
        Notes are optional so a caller rendering the capabilities
        block can separate typed primitives from free-form strings.
        """
        out: list[dict] = []
        for cap in self.all():
            if not include_notes and cap.type == CapabilityType.NOTE:
                continue
            out.append({
                "type": cap.type,
                "scope": cap.scope,
                "value": cap.value,
                "confidence": round(cap.confidence, 2),
                "provenance": cap.provenance,
            })
        return out


# ── Legacy memory_set → typed capability bridge ──────────────────
# The existing specialist prompts tell the model to store a handful of
# well-known keys. Mirror each into a typed capability so downstream
# tooling sees structured facts even though the prompts themselves are
# unchanged in this step.


_CRED_RE = re.compile(r"^\s*([^:\s]+)\s*:\s*(.+?)\s*$")


def _parse_credentials_value(raw: str) -> dict | None:
    m = _CRED_RE.match(raw)
    if not m:
        return None
    user, pw = m.group(1), m.group(2)
    if not user or not pw:
        return None
    return {"scheme": "basic", "username": user, "password": pw}


def _parse_internal_host_value(raw: str) -> dict:
    """Accept either a bare boolean-ish flag or an explicit host[:port]."""
    stripped = raw.strip()
    if stripped.lower() in ("true", "1", "yes"):
        return {"reachable": True}
    # host:port or host
    if ":" in stripped:
        host, _, port = stripped.rpartition(":")
        try:
            return {"host": host, "port": int(port)}
        except ValueError:
            return {"host": stripped}
    return {"host": stripped}


def capability_from_legacy_memory(
    key: str, value: str, *, asset_scope: str, provenance: str | None,
) -> Capability | None:
    """Translate a ``memory_set`` call into a typed capability when possible.

    Returns ``None`` for keys that should stay as a NOTE (the caller
    handles the NOTE fallback — centralising it here makes the typed
    mapping easy to audit at a glance).

    Unrecognised keys and keys prefixed with ``_`` (internal bookkeeping
    like ``_oob_tokens``) are never mirrored — they stay in the string
    scratchpad only.
    """
    if not key or key.startswith("_"):
        return None

    lk = key.lower()

    if lk == "valid_credentials":
        parsed = _parse_credentials_value(value)
        if parsed is None:
            return None
        return Capability(
            type=CapabilityType.CRED, scope=asset_scope, value=parsed,
            confidence=0.95, risk_level=RiskLevel.READ_ONLY,
            provenance=provenance,
        )

    if lk in ("valid_user_id", "leaked_identifier", "leaked_user_id"):
        return Capability(
            type=CapabilityType.IDENTIFIER, scope=asset_scope,
            value={"kind": "user_id", "value": value.strip()},
            confidence=0.9, provenance=provenance,
        )

    if lk == "jwt_leaked_in_body":
        return Capability(
            type=CapabilityType.SESSION, scope=asset_scope,
            value={"jwt": value.strip()},
            confidence=0.9, provenance=provenance,
        )

    if lk == "internal_host_reachable":
        return Capability(
            type=CapabilityType.INTERNAL_HOST, scope=asset_scope,
            value=_parse_internal_host_value(value),
            confidence=0.9, provenance=provenance,
        )

    if lk == "web_root":
        return Capability(
            type=CapabilityType.WEB_ROOT, scope=asset_scope,
            value={"path": value.strip()},
            confidence=0.8, provenance=provenance,
        )

    if lk == "waf_present":
        v = value.strip().lower()
        if v in ("false", "0", "no", ""):
            return None
        return Capability(
            type=CapabilityType.WAF, scope=asset_scope,
            value={"vendor": value.strip()} if v not in ("true", "1", "yes") else {"vendor": None},
            confidence=0.7, provenance=provenance,
        )

    if lk == "csrf_token_missing_on":
        return Capability(
            type=CapabilityType.CSRF_WEAK,
            scope=f"endpoint:{value.strip()}",
            value={"endpoint": value.strip(), "reason": "missing_token"},
            confidence=0.8, risk_level=RiskLevel.STATE_CHANGE,
            provenance=provenance,
        )

    return None


def note_capability(
    key: str, value: str, *, asset_scope: str, provenance: str | None,
) -> Capability:
    """Wrap an unclassified memory_set call as a NOTE capability.

    Kept separate from ``capability_from_legacy_memory`` so callers can
    opt in to NOTE mirroring explicitly — some callers want only typed
    facts (e.g. a future consumer that ignores free-form hints)."""
    return Capability(
        type=CapabilityType.NOTE,
        scope=asset_scope,
        value={"key": key, "text": value},
        confidence=0.6,
        provenance=provenance,
    )


def asset_scope(asset_id: str) -> str:
    """Conventional scope string for per-asset capabilities."""
    return f"asset:{asset_id}"


__all__ = [
    "Capability",
    "CapabilityStore",
    "CapabilityType",
    "RiskLevel",
    "asset_scope",
    "capability_from_legacy_memory",
    "note_capability",
]

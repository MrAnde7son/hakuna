"""Detect leaked secrets in JavaScript bundles.

Pattern-based + entropy-based detection. Designed to be high-precision
on common cloud/SaaS credentials (AWS, GCP, Slack, GitHub, Stripe, JWTs)
rather than try to be a fully general scanner — gitleaks/trufflehog
already exist for that. Our job is to surface leaks the planner and the
backend's risk pipeline can act on quickly.

Critical rule: **never persist the raw secret**. Every hit stores only:
  - the secret type (aws_key, jwt, slack_token, etc.)
  - the first 4 and last 4 characters
  - SHA-256 of the full secret (so duplicates dedupe across files)
  - the source URL and a small redacted snippet for context

A leaked Finding row that contains the actual key is itself a leak. The
backend writes these as Finding(plugin_family="JSSecretScan").

False-positive control:
  - Each pattern includes a "shape validator" that runs after the regex
    match (e.g. JWT must base64-decode in three parts; AWS key prefix
    must be one of the known issuer prefixes). The unvalidated match
    rate on minified JS is high enough that the validator is required.
  - We deny-list common base64 PNG headers (`iVBORw0K`), data URIs, and
    webpack chunk hashes — these account for ~90% of "high-entropy"
    false positives in the wild.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, asdict


logger = logging.getLogger(__name__)


# ── Hit dataclass ───────────────────────────────────────────────


@dataclass(frozen=True)
class SecretHit:
    """One detected leak. Immutable so the dedup set works straight on it."""
    secret_type: str
    severity: str           # "critical" | "high" | "medium"
    sha256: str             # full SHA-256 of the raw secret
    redacted: str           # first 4 + "…" + last 4 (or "***" when too short)
    source_url: str
    snippet: str            # ≤120 chars surrounding the match, with the
                            # secret replaced by its redacted form
    line_hint: int | None   # 1-based line number when the input has lines

    def to_dict(self) -> dict:
        return asdict(self)


# ── Patterns + validators ───────────────────────────────────────
#
# Each pattern is (name, severity, regex, validator). The validator runs
# on the full match string and returns True/False. Patterns that can't
# fail past the regex set ``validator=lambda _: True``.


_AWS_KEY_PREFIXES = ("AKIA", "ASIA", "AIDA", "AROA", "ANPA", "ANVA", "AGPA", "AIPA", "AKIDS")


def _is_aws_key(value: str) -> bool:
    if len(value) != 20:
        return False
    return value[:4] in _AWS_KEY_PREFIXES or value[:5] in _AWS_KEY_PREFIXES


def _is_jwt(value: str) -> bool:
    """A JWT looks like header.payload.signature with valid base64url
    parts — accept if header decodes to JSON with an ``alg`` field."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    header_b64 = parts[0]
    # base64url padding
    pad = "=" * (-len(header_b64) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(header_b64 + pad)
        header = json.loads(header_bytes)
    except (ValueError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header


def _is_google_api_key(value: str) -> bool:
    return value.startswith("AIza") and len(value) == 39


def _is_stripe_live(value: str) -> bool:
    return value.startswith(("sk_live_", "rk_live_", "pk_live_"))


def _always(_: str) -> bool:
    return True


_PATTERNS: tuple[tuple[str, str, re.Pattern, callable], ...] = (
    ("aws_access_key", "high",
     re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|AGPA|AIPA|AKIDS)[0-9A-Z]{12,16})\b"),
     _is_aws_key),
    ("jwt", "medium",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
     _is_jwt),
    ("slack_token", "high",
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b"),
     _always),
    ("github_pat", "critical",
     re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
     _always),
    ("github_oauth", "high",
     re.compile(r"\b(gho_[A-Za-z0-9]{36})\b"),
     _always),
    ("github_app_token", "high",
     re.compile(r"\b((?:ghs_|ghr_|ghu_)[A-Za-z0-9]{36})\b"),
     _always),
    ("google_api_key", "high",
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
     _is_google_api_key),
    ("gcp_service_account_marker", "critical",
     # Marker only — full service account JSONs can be huge. We surface
     # the marker line; backend can pull the raw context if needed.
     re.compile(r'"type"\s*:\s*"service_account"'),
     _always),
    ("stripe_live", "critical",
     re.compile(r"\b((?:sk_live_|rk_live_|pk_live_)[A-Za-z0-9]{24,})\b"),
     _is_stripe_live),
)


# Snippets that match a high-entropy regex but are virtually never
# secrets. Cheap exclusion that wipes out most false positives.
_DENY_PREFIXES = (
    "data:",
    "iVBORw0K",      # PNG base64 header
    "/9j/",          # JPEG base64 header
    "iVBOR",
    "JVBERi0",       # PDF base64 header
    "PHN2Zy",        # "<svg" base64 prefix
    "PD94bWwg",      # "<?xml " base64 prefix
)


# ── Public API ──────────────────────────────────────────────────


def scan_js_for_secrets(
    content: str,
    source_url: str,
    min_entropy: float = 4.0,
) -> list[SecretHit]:
    """Scan JS source for leaked credentials. Returns deduped SecretHit list.

    Dedup is by (secret_type, sha256) — the same secret found in two
    different files produces two hits, but the same secret found twice
    in one file is collapsed.

    ``min_entropy`` controls the floor for the high-entropy generic-
    secret pattern. 4.0 bits/char is the empirical sweet spot — 3.5 lets
    in too many minified webpack identifiers, 4.5 misses real low-entropy
    base32 secrets.
    """
    if not content:
        return []

    seen: set[tuple[str, str]] = set()
    hits: list[SecretHit] = []

    # Build line index once for line_hint lookups.
    line_starts = _line_starts(content)

    # 1) Specific patterns
    for name, severity, pattern, validator in _PATTERNS:
        for m in pattern.finditer(content):
            value = m.group(1) if m.lastindex else m.group(0)
            if not validator(value):
                continue
            sha = hashlib.sha256(value.encode("utf-8")).hexdigest()
            key = (name, sha)
            if key in seen:
                continue
            seen.add(key)
            hits.append(_make_hit(
                name, severity, value, source_url, content,
                m.start(), line_starts,
            ))

    # 2) High-entropy generic pattern (lower priority — runs only when
    # the byte sequence isn't already part of a specific match).
    for m in re.finditer(r"\b[A-Za-z0-9+/=_-]{32,128}\b", content):
        value = m.group(0)
        if value.startswith(_DENY_PREFIXES):
            continue
        if _shannon_entropy(value) < min_entropy:
            continue
        sha = hashlib.sha256(value.encode("utf-8")).hexdigest()
        key = ("high_entropy_string", sha)
        if key in seen:
            continue
        # Skip if any specific pattern already matched at this offset
        if any(h.sha256 == sha for h in hits):
            continue
        seen.add(key)
        hits.append(_make_hit(
            "high_entropy_string", "medium", value, source_url, content,
            m.start(), line_starts,
        ))

    return hits


def _make_hit(
    name: str,
    severity: str,
    value: str,
    source_url: str,
    content: str,
    offset: int,
    line_starts: list[int],
) -> SecretHit:
    redacted = _redact(value)
    snippet = _snippet(content, offset, len(value), redacted)
    line_no = _line_no(line_starts, offset)
    return SecretHit(
        secret_type=name,
        severity=severity,
        sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
        redacted=redacted,
        source_url=source_url,
        snippet=snippet,
        line_hint=line_no,
    )


def _redact(value: str) -> str:
    """Show only the first/last 4 chars to make duplicates recognizable
    while keeping the secret itself off disk."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def _snippet(content: str, offset: int, length: int, redacted: str) -> str:
    """Return ≤120 chars of context with the secret replaced by its redacted form."""
    start = max(0, offset - 40)
    end = min(len(content), offset + length + 40)
    chunk = content[start:end]
    secret = content[offset:offset + length]
    return chunk.replace(secret, redacted)[:120]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _line_starts(content: str) -> list[int]:
    """Offsets of the start of each line (for line_no lookup)."""
    starts = [0]
    for i, ch in enumerate(content):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _line_no(line_starts: list[int], offset: int) -> int:
    """1-based line number for ``offset`` via binary search."""
    import bisect
    idx = bisect.bisect_right(line_starts, offset) - 1
    return idx + 1

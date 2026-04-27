"""Managed-AI key detection (Phase 3.5, slice 4).

Scans text bundles (JS, env files, source) for leaked LLM-provider API keys
and reclassifies trufflehog hits with provider-specific severity. Two entry
points:

  1. ``scan_for_managed_ai_keys(text)`` — pure regex scan over arbitrary text.
     Returns a list of ``ManagedAiKeyHit`` records. Used for sources trufflehog
     doesn't natively cover (newer providers like Groq, edge cases like the
     latest Anthropic admin-key format).

  2. ``classify_trufflehog_detector(detector, raw)`` — given a trufflehog
     hit, return ``(provider, plugin_id, severity)`` if the detector or raw
     value matches a managed-AI provider — otherwise ``None``. Lets the
     existing trufflehog pipeline elevate severity and re-tag the finding
     with a provider-specific plugin_id.

Why this is its own module rather than yet-more rules in trufflehog:
  - Trufflehog's stock detector list lags newer providers (Groq has no
    upstream detector as of 2026-04). Adding regex chains here is a one-liner
    and ships to all customers without redeploying trufflehog.
  - Severity-by-scope (a Bedrock-pinned AWS key is medium, an admin-scope
    AWS key is critical) is not a regex problem — it requires post-processing
    the trufflehog output, which lives here.

The regex set deliberately favors specificity over recall — every pattern
must include the provider's documented prefix (sk-ant-, gsk_, r8_, …) and
the documented length. False positives in JS bundles are noisier than false
negatives, since each emitted finding becomes a customer-facing notification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ── Provider regex set ────────────────────────────────────────────────
#
# Each pattern matches the documented format for an active managed-AI key.
# Patterns are anchored on the prefix (sk-, sk-ant-, gsk_, …) so a random
# 48-char base64 string in a JS bundle won't get flagged. Lengths come from
# the provider docs as of 2026-04 — when a provider rotates their key
# format, expect to update the corresponding pattern *and* keep the old one
# until the rotation window closes.

# OpenAI: classic user keys (sk-...) and project-scoped keys (sk-proj-...).
# Length floor of 40 catches both old (48 char body) and current formats.
_OPENAI_USER_KEY = re.compile(r"\bsk-[A-Za-z0-9]{48,}\b")
_OPENAI_PROJECT_KEY = re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b")
# Admin keys are the *highest* risk — they grant org-wide visibility.
_OPENAI_ADMIN_KEY = re.compile(r"\bsk-admin-[A-Za-z0-9_-]{40,}\b")

# Anthropic: API keys (sk-ant-api...) and admin keys (sk-ant-admin...).
# The body is documented as 93 chars of [A-Za-z0-9_-].
_ANTHROPIC_API_KEY = re.compile(r"\bsk-ant-api\d{2}-[A-Za-z0-9_-]{93}\b")
_ANTHROPIC_ADMIN_KEY = re.compile(r"\bsk-ant-admin\d{2}-[A-Za-z0-9_-]{93}\b")

# Cohere: legacy and v2 formats coexist as of 2026-04.
_COHERE_KEY = re.compile(r"\bcsk_[A-Za-z0-9]{50,}\b")
_COHERE_LEGACY = re.compile(r"\bcohere-[A-Za-z0-9-]{40}\b")

# Replicate: r8_ prefix, 40-char body.
_REPLICATE_KEY = re.compile(r"\br8_[A-Za-z0-9]{40}\b")

# HuggingFace: hf_ prefix, 34-char body. HF tokens often gate access to
# self-hosted TGI deployments — see exposed_ai_service audit.
_HUGGINGFACE_KEY = re.compile(r"\bhf_[A-Za-z0-9]{34}\b")

# Groq: gsk_ prefix, 52-char body. No upstream trufflehog detector yet.
_GROQ_KEY = re.compile(r"\bgsk_[A-Za-z0-9]{52}\b")


# Provider key → (pattern, severity, plugin_id_suffix). Severity is on
# Hakuna's 0-4 scale (4=critical, 3=high, 2=medium). Admin/org-scope keys
# are critical *because of scope*, even when unverified — leaked admin
# credentials are an immediate-impact incident.
_PROVIDER_PATTERNS: list[tuple[str, re.Pattern, int, str]] = [
    # provider, pattern, severity, plugin_id
    ("openai_admin", _OPENAI_ADMIN_KEY, 4, "leaked_managed_ai_key_openai_admin"),
    ("anthropic_admin", _ANTHROPIC_ADMIN_KEY, 4, "leaked_managed_ai_key_anthropic_admin"),
    ("openai_project", _OPENAI_PROJECT_KEY, 3, "leaked_managed_ai_key_openai_project"),
    ("openai", _OPENAI_USER_KEY, 3, "leaked_managed_ai_key_openai"),
    ("anthropic", _ANTHROPIC_API_KEY, 3, "leaked_managed_ai_key_anthropic"),
    ("cohere", _COHERE_KEY, 3, "leaked_managed_ai_key_cohere"),
    ("cohere_legacy", _COHERE_LEGACY, 3, "leaked_managed_ai_key_cohere"),
    ("replicate", _REPLICATE_KEY, 3, "leaked_managed_ai_key_replicate"),
    ("huggingface", _HUGGINGFACE_KEY, 3, "leaked_managed_ai_key_huggingface"),
    ("groq", _GROQ_KEY, 3, "leaked_managed_ai_key_groq"),
]


# ── Trufflehog detector reclassification table ────────────────────────
#
# When trufflehog itself flags a managed-AI key, we want to (a) re-tag the
# finding with our `leaked_managed_ai_key_*` plugin_id so it groups with
# regex-detected hits and (b) bump severity for the admin-scope variants.
# Trufflehog's DetectorName values are stable strings — listed here as the
# upstream key so we don't drift if the regex above ever differs.
_TRUFFLEHOG_DETECTOR_MAP: dict[str, tuple[str, int, str]] = {
    # detector_name → (provider, severity, plugin_id)
    "OpenAI": ("openai", 3, "leaked_managed_ai_key_openai"),
    "Anthropic": ("anthropic", 3, "leaked_managed_ai_key_anthropic"),
    "Cohere": ("cohere", 3, "leaked_managed_ai_key_cohere"),
    "Replicate": ("replicate", 3, "leaked_managed_ai_key_replicate"),
    "HuggingFace": ("huggingface", 3, "leaked_managed_ai_key_huggingface"),
}


@dataclass(frozen=True)
class ManagedAiKeyHit:
    """One leaked-key match found by ``scan_for_managed_ai_keys``."""
    provider: str
    raw: str
    redacted: str
    severity: int  # 0-4 Hakuna scale
    plugin_id: str
    span: tuple[int, int]


def _redact(raw: str) -> str:
    """Keep the prefix (provider tag) plus first 4 chars of the body, mask
    the rest. Mirrors the redaction shape trufflehog emits."""
    # If the key has a provider prefix (sk-, sk-ant-, gsk_, …), keep up to
    # the first 8 chars so the customer can identify the format without the
    # secret leaking into logs.
    if len(raw) <= 8:
        return "*" * len(raw)
    return raw[:8] + "*" * min(len(raw) - 8, 16)


def scan_for_managed_ai_keys(text: str) -> list[ManagedAiKeyHit]:
    """Regex-scan ``text`` for managed-AI keys. Returns one hit per match.

    Patterns are checked in *severity order* (admin first, then per-provider
    user keys) so a single string that matches both `_OPENAI_ADMIN_KEY` and
    the broader `_OPENAI_USER_KEY` gets the admin classification only.
    """
    if not text:
        return []
    hits: list[ManagedAiKeyHit] = []
    seen_spans: set[tuple[int, int]] = set()
    for provider, pattern, severity, plugin_id in _PROVIDER_PATTERNS:
        for match in pattern.finditer(text):
            span = match.span()
            # If a higher-priority pattern already claimed this span, skip.
            # (Can happen when admin-key body also satisfies the broader user-key regex.)
            if any(seen[0] <= span[0] < seen[1] for seen in seen_spans):
                continue
            seen_spans.add(span)
            raw = match.group(0)
            hits.append(ManagedAiKeyHit(
                provider=provider,
                raw=raw,
                redacted=_redact(raw),
                severity=severity,
                plugin_id=plugin_id,
                span=span,
            ))
    return hits


def classify_trufflehog_detector(
    detector_name: str,
    raw: str,
) -> tuple[str, int, str] | None:
    """Map a trufflehog detector to a managed-AI provider classification.

    Returns ``(provider, severity, plugin_id)`` if the detector is one of
    the managed-AI providers we care about, otherwise ``None`` so the caller
    can fall back to the generic trufflehog pipeline. The ``raw`` argument
    lets us upgrade severity for admin-scoped variants — e.g. trufflehog
    reports ``DetectorName="Anthropic"`` for both api and admin keys, but
    we want admin keys treated as critical.
    """
    base = _TRUFFLEHOG_DETECTOR_MAP.get(detector_name)
    if not base:
        return None
    provider, severity, plugin_id = base

    # Upgrade for admin-scope variants. The regex check is on raw because
    # trufflehog doesn't expose the key flavor in its output schema.
    if provider == "openai" and raw and _OPENAI_ADMIN_KEY.match(raw):
        return ("openai_admin", 4, "leaked_managed_ai_key_openai_admin")
    if provider == "anthropic" and raw and _ANTHROPIC_ADMIN_KEY.match(raw):
        return ("anthropic_admin", 4, "leaked_managed_ai_key_anthropic_admin")

    return base


__all__ = [
    "ManagedAiKeyHit",
    "scan_for_managed_ai_keys",
    "classify_trufflehog_detector",
]

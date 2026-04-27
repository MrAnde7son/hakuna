"""Tests for managed-AI key detection (Phase 3.5, slice 4).

Critical safety property: no test fixture contains a real secret. The
"keys" used here have valid prefixes and lengths but the body chars are
deliberately deterministic / repeated so they couldn't possibly match a
real provider key. Test severity, dedup-on-overlap, and the trufflehog
reclassification path.
"""

import re

import pytest

from app.ingest.managed_ai_keys import (
    ManagedAiKeyHit,
    classify_trufflehog_detector,
    scan_for_managed_ai_keys,
)


# Synthetic keys — structurally valid for the regex but obviously fake.
# Bodies use repeated char sequences a real key would not have.
FAKE_OPENAI = "sk-" + "A" * 48
FAKE_OPENAI_PROJECT = "sk-proj-" + "B" * 40
FAKE_OPENAI_ADMIN = "sk-admin-" + "C" * 40
FAKE_ANTHROPIC = "sk-ant-api01-" + "D" * 93
FAKE_ANTHROPIC_ADMIN = "sk-ant-admin01-" + "E" * 93
FAKE_COHERE = "csk_" + "F" * 50
FAKE_COHERE_LEGACY = "cohere-" + "G" * 40
FAKE_REPLICATE = "r8_" + "H" * 40
FAKE_HUGGINGFACE = "hf_" + "I" * 34
FAKE_GROQ = "gsk_" + "J" * 52


# ── Pure regex scan ──────────────────────────────────────────────────


@pytest.mark.parametrize("provider,fake_key,expected_severity", [
    ("openai", FAKE_OPENAI, 3),
    ("openai_project", FAKE_OPENAI_PROJECT, 3),
    ("openai_admin", FAKE_OPENAI_ADMIN, 4),
    ("anthropic", FAKE_ANTHROPIC, 3),
    ("anthropic_admin", FAKE_ANTHROPIC_ADMIN, 4),
    ("cohere", FAKE_COHERE, 3),
    ("cohere_legacy", FAKE_COHERE_LEGACY, 3),
    ("replicate", FAKE_REPLICATE, 3),
    ("huggingface", FAKE_HUGGINGFACE, 3),
    ("groq", FAKE_GROQ, 3),
])
def test_scan_detects_provider_with_correct_severity(provider, fake_key, expected_severity):
    text = f"// some js bundle\nconst KEY = {fake_key!r};"
    hits = scan_for_managed_ai_keys(text)
    assert len(hits) == 1, f"expected 1 hit for {provider}, got {len(hits)}: {hits}"
    hit = hits[0]
    assert hit.provider == provider
    assert hit.severity == expected_severity
    assert hit.raw == fake_key
    # Redaction must obscure the body — only the prefix portion is visible.
    assert hit.raw not in hit.redacted
    assert "*" in hit.redacted


def test_scan_handles_empty_input():
    assert scan_for_managed_ai_keys("") == []
    assert scan_for_managed_ai_keys(None) == []


def test_scan_no_match_for_random_string():
    """A 48-char base64 string without the sk- prefix must not match.
    Specificity matters — false positives are louder than misses here."""
    not_a_key = "X" * 48 + "definitelynotopenai"
    assert scan_for_managed_ai_keys(not_a_key) == []


def test_scan_ignores_short_prefixed_strings():
    """sk-abc is too short to be a valid OpenAI key. Must not match."""
    assert scan_for_managed_ai_keys("sk-abc") == []


def test_scan_admin_key_does_not_double_match_user_pattern():
    """sk-admin-... starts with sk- so it could superficially match the
    broader OpenAI user-key pattern. The scanner's priority order +
    span-overlap dedup must claim it as `openai_admin` only — not also
    emit a duplicate `openai` hit for the same span."""
    text = f"const ADMIN = '{FAKE_OPENAI_ADMIN}';"
    hits = scan_for_managed_ai_keys(text)
    providers = [h.provider for h in hits]
    assert providers == ["openai_admin"], f"got {providers}"


def test_scan_finds_multiple_distinct_keys_in_one_blob():
    text = f"""
    const OPENAI = "{FAKE_OPENAI}";
    const ANTHROPIC = "{FAKE_ANTHROPIC}";
    const GROQ = "{FAKE_GROQ}";
    """
    hits = scan_for_managed_ai_keys(text)
    providers = sorted(h.provider for h in hits)
    assert providers == ["anthropic", "groq", "openai"]


def test_scan_returns_span_for_each_hit():
    """Span enables the secrets pipeline to report file offsets so the
    customer can grep their bundle to the exact line."""
    text = "prefix " + FAKE_GROQ + " suffix"
    hits = scan_for_managed_ai_keys(text)
    assert len(hits) == 1
    start, end = hits[0].span
    assert text[start:end] == FAKE_GROQ


# ── Trufflehog detector reclassification ─────────────────────────────


def test_classify_unknown_detector_returns_none():
    assert classify_trufflehog_detector("MailgunPrivateKey", "anything") is None
    assert classify_trufflehog_detector("AWS", "AKIAIOSFODNN7EXAMPLE") is None


def test_classify_openai_user_key_returns_provider_severity():
    result = classify_trufflehog_detector("OpenAI", FAKE_OPENAI)
    assert result is not None
    provider, severity, plugin_id = result
    assert provider == "openai"
    assert severity == 3
    assert plugin_id == "leaked_managed_ai_key_openai"


def test_classify_openai_admin_key_upgrades_to_critical():
    """Trufflehog reports both user and admin OpenAI keys with the same
    DetectorName="OpenAI". Severity must upgrade based on the raw key
    format, since admin scope is the threat regardless of liveness."""
    result = classify_trufflehog_detector("OpenAI", FAKE_OPENAI_ADMIN)
    assert result is not None
    provider, severity, plugin_id = result
    assert provider == "openai_admin"
    assert severity == 4
    assert plugin_id == "leaked_managed_ai_key_openai_admin"


def test_classify_anthropic_admin_key_upgrades_to_critical():
    result = classify_trufflehog_detector("Anthropic", FAKE_ANTHROPIC_ADMIN)
    assert result is not None
    provider, severity, _ = result
    assert provider == "anthropic_admin"
    assert severity == 4


def test_classify_anthropic_api_key_stays_high():
    result = classify_trufflehog_detector("Anthropic", FAKE_ANTHROPIC)
    provider, severity, _ = result
    assert provider == "anthropic"
    assert severity == 3


def test_classify_replicate_groq_huggingface_via_detector_name():
    """Trufflehog's stock detectors cover Replicate and HuggingFace but
    not Groq. The detector-map must include both; Groq is regex-only."""
    assert classify_trufflehog_detector("Replicate", FAKE_REPLICATE) is not None
    assert classify_trufflehog_detector("HuggingFace", FAKE_HUGGINGFACE) is not None
    # Groq has no upstream trufflehog detector — classify should pass.
    assert classify_trufflehog_detector("Groq", FAKE_GROQ) is None


# ── Plugin id stability ──────────────────────────────────────────────


def test_plugin_ids_match_documented_format():
    """Plugin ids are surfaced in the customer's findings stream and used
    for dedup. Lock the format so a downstream rule can match them."""
    expected_pattern = re.compile(r"^leaked_managed_ai_key_[a-z_]+$")
    for fake in (FAKE_OPENAI, FAKE_OPENAI_ADMIN, FAKE_ANTHROPIC, FAKE_ANTHROPIC_ADMIN,
                 FAKE_GROQ, FAKE_REPLICATE, FAKE_HUGGINGFACE, FAKE_COHERE):
        hits = scan_for_managed_ai_keys(fake)
        assert hits, f"no hit for {fake[:20]}"
        assert expected_pattern.match(hits[0].plugin_id), hits[0].plugin_id

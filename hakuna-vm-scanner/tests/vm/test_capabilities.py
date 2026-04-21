"""Tests for the typed capability store and the legacy memory bridge.

Covers the deterministic surface of the composition foundation:

  - Capability dedup / confidence upgrade semantics
  - Type + risk validation (unknown types refused)
  - Size cap behaviour (insert rejected, not LRU-evicted)
  - TTL expiration
  - Legacy memory_set → typed capability translation for the exact key
    set used in the specialist prompts
  - ``note_capability`` fallback for unclassified keys

The goal is to pin down store invariants before layering the scheduler
and requires/produces contracts on top — if dedup or confidence upgrade
breaks, every downstream composition rule breaks with it.
"""

from __future__ import annotations

import time

import pytest

from scanner.vm.capabilities import (
    Capability,
    CapabilityStore,
    CapabilityType,
    RiskLevel,
    asset_scope,
    capability_from_legacy_memory,
    note_capability,
)


def _cred(**overrides) -> Capability:
    defaults = dict(
        type=CapabilityType.CRED,
        scope="asset:a-1",
        value={"scheme": "basic", "username": "admin", "password": "admin"},
        confidence=0.9,
        provenance="specialist:authn",
    )
    defaults.update(overrides)
    return Capability(**defaults)


class TestCapabilityStoreAddDedup:
    def test_insert_new_returns_true(self):
        store = CapabilityStore()
        assert store.add(_cred()) is True
        assert len(store.all()) == 1

    def test_duplicate_is_deduped(self):
        """Same (type, scope, canonical value) at equal confidence must
        not grow the store — stops a chatty LLM from filling the store
        with identical records each probe."""
        store = CapabilityStore()
        store.add(_cred(confidence=0.9))
        assert store.add(_cred(confidence=0.9)) is False
        assert len(store.all()) == 1

    def test_higher_confidence_upgrades_existing(self):
        """Second confirmation (e.g. OOB-validated) should replace the
        weaker record so downstream consumers see the stronger one."""
        store = CapabilityStore()
        store.add(_cred(confidence=0.7, provenance="specialist:authn"))
        assert store.add(_cred(confidence=0.95, provenance="specialist:authn-oob")) is True
        caps = store.query(type=CapabilityType.CRED)
        assert len(caps) == 1
        assert caps[0].confidence == 0.95

    def test_lower_confidence_does_not_downgrade(self):
        store = CapabilityStore()
        store.add(_cred(confidence=0.95))
        assert store.add(_cred(confidence=0.5)) is False
        assert store.query(type=CapabilityType.CRED)[0].confidence == 0.95


class TestCapabilityStoreValidation:
    def test_unknown_type_refused(self):
        """The type taxonomy is closed — silently accepting novel types
        would produce invisible capabilities downstream."""
        store = CapabilityStore()
        cap = Capability(type="novel_type", scope="asset:a-1", value={})
        assert store.add(cap) is False
        assert store.all() == []

    def test_unknown_risk_level_refused(self):
        store = CapabilityStore()
        cap = Capability(
            type=CapabilityType.CRED, scope="asset:a-1", value={},
            risk_level="yolo",
        )
        assert store.add(cap) is False

    def test_confidence_out_of_range_refused(self):
        store = CapabilityStore()
        assert store.add(_cred(confidence=1.5)) is False
        assert store.add(_cred(confidence=-0.1)) is False


class TestCapabilityStoreCap:
    def test_full_store_rejects_new_without_evicting(self):
        """When full, we refuse new inserts rather than LRU-evict.
        Evicting a leaked-credential fact to make room for a low-value
        note would be the wrong default."""
        store = CapabilityStore(max_capabilities=2)
        store.add(_cred(value={"scheme": "basic", "username": "a", "password": "x"}))
        store.add(_cred(value={"scheme": "basic", "username": "b", "password": "x"}))
        new = _cred(value={"scheme": "basic", "username": "c", "password": "x"})
        assert store.add(new) is False
        assert len(store.all()) == 2

    def test_upgrade_works_when_full(self):
        """Hitting the cap shouldn't stop a confidence upgrade to an
        existing key — upgrade replaces in place, doesn't grow."""
        store = CapabilityStore(max_capabilities=1)
        store.add(_cred(confidence=0.5))
        assert store.add(_cred(confidence=0.9)) is True
        assert store.query(type=CapabilityType.CRED)[0].confidence == 0.9


class TestCapabilityQuery:
    def test_filter_by_type(self):
        store = CapabilityStore()
        store.add(_cred())
        store.add(Capability(
            type=CapabilityType.IDENTIFIER, scope="asset:a-1",
            value={"kind": "user_id", "value": "42"},
        ))
        assert len(store.query(type=CapabilityType.CRED)) == 1
        assert len(store.query(type=CapabilityType.IDENTIFIER)) == 1

    def test_filter_by_scope(self):
        store = CapabilityStore()
        store.add(_cred(scope="asset:a-1"))
        store.add(_cred(
            scope="asset:a-2",
            value={"scheme": "basic", "username": "x", "password": "y"},
        ))
        assert len(store.query(scope="asset:a-1")) == 1

    def test_filter_by_min_confidence(self):
        store = CapabilityStore()
        store.add(_cred(confidence=0.6))
        store.add(_cred(
            value={"scheme": "basic", "username": "b", "password": "x"},
            confidence=0.95,
        ))
        assert len(store.query(min_confidence=0.9)) == 1


class TestCapabilityTTL:
    def test_expired_capability_excluded_from_query(self):
        """Sessions expire — a stale cookie shouldn't drive a follow-up
        authz run and produce false negatives."""
        store = CapabilityStore()
        expired = Capability(
            type=CapabilityType.SESSION, scope="asset:a-1",
            value={"cookie": "sid=old"}, ttl_sec=0,
        )
        # Make sure monotonic advances past created_at.
        store.add(expired)
        time.sleep(0.01)
        assert store.query(type=CapabilityType.SESSION) == []


class TestCapabilityStoreSummarize:
    def test_includes_typed_and_notes_by_default(self):
        store = CapabilityStore()
        store.add(_cred())
        store.add(note_capability(
            "waf_vendor", "cloudflare", asset_scope="asset:a-1", provenance="specialist:injection",
        ))
        summary = store.summarize()
        types = {row["type"] for row in summary}
        assert CapabilityType.CRED in types
        assert CapabilityType.NOTE in types

    def test_excludes_notes_when_requested(self):
        """The initial-message renderer uses this to keep typed
        primitives distinct from free-form memory hints."""
        store = CapabilityStore()
        store.add(_cred())
        store.add(note_capability(
            "waf_vendor", "cloudflare", asset_scope="asset:a-1", provenance=None,
        ))
        summary = store.summarize(include_notes=False)
        types = {row["type"] for row in summary}
        assert CapabilityType.CRED in types
        assert CapabilityType.NOTE not in types


class TestLegacyMemoryBridge:
    """Each case is one of the exact keys the specialist prompts use.

    If the prompt's documented key set drifts, the regression lands
    here — the authn prompt no longer stashes ``valid_credentials``
    would silently stop flowing typed credentials downstream.
    """

    def test_valid_credentials_becomes_cred_capability(self):
        cap = capability_from_legacy_memory(
            "valid_credentials", "admin:admin",
            asset_scope="asset:a-1", provenance="specialist:authn",
        )
        assert cap is not None
        assert cap.type == CapabilityType.CRED
        assert cap.value == {
            "scheme": "basic", "username": "admin", "password": "admin",
        }
        assert cap.provenance == "specialist:authn"

    def test_valid_credentials_malformed_returns_none(self):
        """No colon → can't split user from password → stay string-only
        so we don't fabricate a credential shape."""
        assert capability_from_legacy_memory(
            "valid_credentials", "not-a-pair",
            asset_scope="asset:a-1", provenance=None,
        ) is None

    def test_valid_user_id_becomes_identifier(self):
        cap = capability_from_legacy_memory(
            "valid_user_id", "42",
            asset_scope="asset:a-1", provenance="specialist:authn",
        )
        assert cap is not None
        assert cap.type == CapabilityType.IDENTIFIER
        assert cap.value == {"kind": "user_id", "value": "42"}

    def test_leaked_identifier_also_becomes_identifier(self):
        cap = capability_from_legacy_memory(
            "leaked_identifier", "99",
            asset_scope="asset:a-1", provenance=None,
        )
        assert cap is not None
        assert cap.type == CapabilityType.IDENTIFIER

    def test_jwt_leaked_becomes_session(self):
        cap = capability_from_legacy_memory(
            "jwt_leaked_in_body", "eyJhbGciOi...",
            asset_scope="asset:a-1", provenance=None,
        )
        assert cap is not None
        assert cap.type == CapabilityType.SESSION
        assert cap.value["jwt"].startswith("eyJ")

    def test_internal_host_true_flag(self):
        cap = capability_from_legacy_memory(
            "internal_host_reachable", "true",
            asset_scope="asset:a-1", provenance="specialist:ssrf",
        )
        assert cap is not None
        assert cap.type == CapabilityType.INTERNAL_HOST
        assert cap.value == {"reachable": True}

    def test_internal_host_with_port(self):
        """A specialist that confirms SSRF reaches a specific service
        should produce a more useful host:port capability."""
        cap = capability_from_legacy_memory(
            "internal_host_reachable", "10.0.0.5:6379",
            asset_scope="asset:a-1", provenance=None,
        )
        assert cap is not None
        assert cap.value == {"host": "10.0.0.5", "port": 6379}

    def test_web_root_becomes_web_root_capability(self):
        cap = capability_from_legacy_memory(
            "web_root", "/var/www/html",
            asset_scope="asset:a-1", provenance=None,
        )
        assert cap is not None
        assert cap.type == CapabilityType.WEB_ROOT
        assert cap.value == {"path": "/var/www/html"}

    def test_csrf_token_missing_scopes_to_endpoint(self):
        """The CSRF weak cap is per-endpoint, not per-asset, because a
        future scheduler needs to target the specific endpoint."""
        cap = capability_from_legacy_memory(
            "csrf_token_missing_on", "/account/delete",
            asset_scope="asset:a-1", provenance="specialist:csrf",
        )
        assert cap is not None
        assert cap.type == CapabilityType.CSRF_WEAK
        assert cap.scope == "endpoint:/account/delete"
        assert cap.risk_level == RiskLevel.STATE_CHANGE

    def test_waf_false_returns_none(self):
        """``waf_present=false`` is an assertion of absence, not a fact
        to propagate. Returning None keeps the store free of negatives."""
        assert capability_from_legacy_memory(
            "waf_present", "false",
            asset_scope="asset:a-1", provenance=None,
        ) is None

    def test_waf_true_records_presence(self):
        cap = capability_from_legacy_memory(
            "waf_present", "cloudflare",
            asset_scope="asset:a-1", provenance=None,
        )
        assert cap is not None
        assert cap.type == CapabilityType.WAF
        assert cap.value == {"vendor": "cloudflare"}

    def test_underscore_prefixed_key_returns_none(self):
        """Internal bookkeeping (OOB token list) must never leak into
        typed capabilities — they're audit trail, not actionable."""
        assert capability_from_legacy_memory(
            "_oob_tokens", "abc,def",
            asset_scope="asset:a-1", provenance=None,
        ) is None

    def test_empty_key_returns_none(self):
        assert capability_from_legacy_memory(
            "", "value",
            asset_scope="asset:a-1", provenance=None,
        ) is None

    def test_unknown_key_returns_none(self):
        """Unknown keys fall through so callers pick NOTE explicitly —
        the bridge doesn't guess for novel keys."""
        assert capability_from_legacy_memory(
            "made_up_hint", "something",
            asset_scope="asset:a-1", provenance=None,
        ) is None


class TestNoteCapability:
    def test_wraps_arbitrary_key_value(self):
        cap = note_capability(
            "cookie_shape", "PHPSESSID=...",
            asset_scope="asset:a-1", provenance="specialist:authn",
        )
        assert cap.type == CapabilityType.NOTE
        assert cap.value == {"key": "cookie_shape", "text": "PHPSESSID=..."}
        assert cap.provenance == "specialist:authn"


class TestAssetScope:
    def test_formats_asset_id(self):
        assert asset_scope("abc-123") == "asset:abc-123"

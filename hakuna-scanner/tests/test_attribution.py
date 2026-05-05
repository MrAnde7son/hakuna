"""Tests for the tenant attribution module.

Pure-logic tests — no DB, no network. The orchestrator step that pulls
asset_ports and calls this module is exercised by the existing
enrichment-pipeline integration tests.
"""

from app.ingest.attribution import (
    GENERIC_CLOUD_DOMAINS,
    _registrable,
    attribute_asset,
)


def test_registrable_strips_wildcard_and_handles_subdomains():
    assert _registrable("api.acme.com") == "acme.com"
    assert _registrable("*.acme.com") == "acme.com"
    assert _registrable("ACME.com") == "acme.com"
    assert _registrable("foo.bar.baz.example.co.uk") == "example.co.uk"


def test_registrable_returns_none_for_garbage():
    assert _registrable(None) is None
    assert _registrable("") is None
    assert _registrable("not-a-host") is None
    # Bare IP — no public suffix → None.
    assert _registrable("192.168.1.1") is None


def test_san_match_to_target_domain_yields_high_confidence():
    cert = {"sans": ["acme.com", "*.acme.com", "api.acme.com"]}
    result = attribute_asset(
        hostname="api.acme.com",
        cloud_provider="aws",
        tls_certs=[cert],
        target_domains=["acme.com"],
    )
    assert result["best_guess"] == "acme.com"
    assert result["is_self"] is True
    # Multiple SANs collapse to one candidate (dedup by registrable).
    assert len(result["owner_candidates"]) == 1
    # Bonus from corroboration not applied (single signal kind).
    assert result["confidence"] >= 0.95


def test_san_pointing_to_other_tenant_attributes_to_them():
    """If we own acme.com but the cert is for evilcorp.com, that's
    someone else's tenant on a shared cloud IP — we should know."""
    cert = {"sans": ["evilcorp.com", "www.evilcorp.com"]}
    result = attribute_asset(
        hostname="orphan-cloud.example.net",
        cloud_provider="aws",
        tls_certs=[cert],
        target_domains=["acme.com"],
    )
    assert result["best_guess"] == "evilcorp.com"
    assert result["is_self"] is False
    assert result["confidence"] >= 0.7


def test_generic_cloud_san_caps_confidence():
    """A *.cloudfront.net SAN is shared SaaS — confidence stays low."""
    cert = {"sans": ["*.cloudfront.net", "d111111abcdef8.cloudfront.net"]}
    result = attribute_asset(
        hostname="cdn.example.net",
        cloud_provider="aws",
        tls_certs=[cert],
        target_domains=["acme.com"],
    )
    # Best guess might still be cloudfront.net, but confidence is capped.
    assert result["best_guess"] == "cloudfront.net"
    assert result["confidence"] <= 0.30


def test_wildcard_san_downgrade():
    """A bare wildcard SAN gets a confidence penalty vs a specific name."""
    cert_wildcard_only = {"sans": ["*.acme-vendor.com"]}
    cert_specific = {"sans": ["api.acme-vendor.com"]}

    res_wild = attribute_asset(
        hostname="x", cloud_provider="aws",
        tls_certs=[cert_wildcard_only], target_domains=["acme.com"],
    )
    res_specific = attribute_asset(
        hostname="x", cloud_provider="aws",
        tls_certs=[cert_specific], target_domains=["acme.com"],
    )
    assert res_wild["confidence"] < res_specific["confidence"]


def test_rdns_alone_attributes_with_lower_confidence():
    result = attribute_asset(
        hostname="orphan.example.net",
        cloud_provider="aws",
        tls_certs=[],
        target_domains=["acme.com"],
        rdns="server01.acme-internal.io",
    )
    assert result["best_guess"] == "acme-internal.io"
    # rDNS alone should not cross 0.75.
    assert result["confidence"] <= 0.75


def test_generic_cloud_rdns_is_low_signal():
    """Stock AWS PTR doesn't tell us who the tenant is."""
    result = attribute_asset(
        hostname="orphan.example.net",
        cloud_provider="aws",
        tls_certs=[],
        target_domains=["acme.com"],
        rdns="ec2-3-91-22-7.compute-1.amazonaws.com",
    )
    # Either no best guess, or a very low-confidence guess of amazonaws.com.
    if result["best_guess"]:
        assert result["best_guess"] == "amazonaws.com"
        assert result["confidence"] <= 0.3


def test_corroborating_signals_bump_confidence():
    """TLS SAN + rDNS pointing to the same registrable domain is more
    credible than either alone."""
    cert = {"sans": ["api.acme.com"]}
    result = attribute_asset(
        hostname="api.acme.com",
        cloud_provider="aws",
        tls_certs=[cert],
        target_domains=["acme.com"],
        rdns="host.acme.com",
    )
    candidate = result["owner_candidates"][0]
    assert candidate["name"] == "acme.com"
    assert "tls_san" in candidate["signals"]
    assert "rdns" in candidate["signals"]
    # Bonus pushed it above the bare TLS-SAN ceiling.
    assert candidate["confidence"] > 0.95


def test_no_signals_returns_empty_attribution():
    result = attribute_asset(
        hostname="x",
        cloud_provider="aws",
        tls_certs=[],
        target_domains=["acme.com"],
        rdns=None,
    )
    assert result["best_guess"] is None
    assert result["confidence"] == 0.0
    assert result["is_self"] is False
    assert result["owner_candidates"] == []
    # Signal slots are still present so downstream consumers can rely
    # on the JSON shape.
    assert "tls_sans" in result["signals"]
    assert "rdns" in result["signals"]


def test_generic_domain_set_well_formed():
    """The generic-cloud allowlist must be lowercase registrable names —
    not subdomains and not paths. Catches accidental edits."""
    for name in GENERIC_CLOUD_DOMAINS:
        assert name == name.lower()
        assert "/" not in name
        assert not name.startswith("*.")
        # Must be a registrable form (eTLD+1 in most cases).
        parts = name.split(".")
        assert len(parts) >= 2


def test_self_match_beats_other_tenant_even_at_lower_confidence():
    """Sort key: is_self desc, confidence desc. So a 0.80 self-match
    beats a 0.85 third-party — we always prefer claiming the asset
    when the evidence allows it."""
    cert = {
        "sans": [
            "*.acme.com",       # self, but wildcard penalty drops to ~0.6
            "evilcorp.com",     # third-party at ~0.75
        ],
    }
    result = attribute_asset(
        hostname="x",
        cloud_provider="aws",
        tls_certs=[cert],
        target_domains=["acme.com"],
    )
    assert result["best_guess"] == "acme.com"
    assert result["is_self"] is True

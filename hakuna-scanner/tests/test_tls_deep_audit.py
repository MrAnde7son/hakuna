"""Unit tests for app.ingest.tls_deep_audit.grade (pure function).

The sslyze + DNS orchestration (audit_host, _lookup_caa, _parse_sslyze_result)
lives in the same module but is not covered here — those exercise real network
I/O and belong in an integration test suite.
"""

import pytest

from app.ingest.tls_deep_audit import grade, _caa_allows_issuer


# ── CAA authorization ──────────────────────────────────────────────────────


class TestCaaAllowsIssuer:
    def test_no_records_returns_none(self):
        # RFC 8659: absence of CAA records means any CA may issue.
        assert _caa_allows_issuer([], "Let's Encrypt") is None

    def test_matching_domain_authorized(self):
        records = ['0 issue "letsencrypt.org"']
        assert _caa_allows_issuer(records, "Let's Encrypt") is True

    def test_digicert_token_match(self):
        # "DigiCert Inc" vs "digicert.com" — tokenization should match.
        records = ['0 issue "digicert.com"']
        assert _caa_allows_issuer(records, "DigiCert Inc") is True

    def test_non_matching_issuer_denied(self):
        records = ['0 issue "letsencrypt.org"']
        assert _caa_allows_issuer(records, "Sectigo Limited") is False

    def test_issuewild_parsed(self):
        # `issuewild` is parsed identically to `issue` for matching purposes.
        records = ['0 issuewild "sectigo.com"']
        assert _caa_allows_issuer(records, "Sectigo Limited") is True

    def test_brand_mismatch_in_distinct_domains(self):
        # Google's CA uses pki.goog but the issuer name doesn't share tokens.
        # The fuzzy matcher correctly fails closed here — operator should
        # verify manually (this is the intended conservative behavior).
        records = ['0 issuewild "pki.goog"']
        assert _caa_allows_issuer(records, "Google Trust Services") is False

    def test_missing_issuer_org_with_records_fails_closed(self):
        records = ['0 issue "letsencrypt.org"']
        assert _caa_allows_issuer(records, None) is False

    def test_explicit_deny_record_ignored_for_match(self):
        # `0 issue ";"` means "no CA may issue" — should never match.
        records = ['0 issue ";"', '0 issue "letsencrypt.org"']
        assert _caa_allows_issuer(records, "Let's Encrypt") is True


# ── grade() ────────────────────────────────────────────────────────────────


def _base_kwargs(**overrides):
    base = dict(
        host="example.com", port=443,
        ciphers_accepted={"TLSv1.2": ["ECDHE-RSA-AES128-GCM-SHA256"]},
        chain_trusted=True, chain_errors=[],
        ocsp_status="good", ocsp_detail=None,
        caa_records=[], issuer_cn="R3", issuer_org="Let's Encrypt",
    )
    base.update(overrides)
    return base


class TestGrade:
    def test_clean_config_has_no_issues(self):
        result = grade(**_base_kwargs())
        assert result["issues"] == []
        assert result["versions_accepted"] == ["TLSv1.2"]
        assert result["chain"]["trusted"] is True

    def test_sslv3_accepted_is_critical(self):
        result = grade(**_base_kwargs(
            ciphers_accepted={
                "SSLv3": ["DES-CBC3-SHA"],
                "TLSv1.2": ["ECDHE-RSA-AES128-GCM-SHA256"],
            },
        ))
        broken = [i for i in result["issues"] if i["id"] == "tls-broken-version-accepted"]
        assert len(broken) == 1
        assert broken[0]["severity"] == 4
        assert "SSLv3" in broken[0]["detail"]

    def test_tls10_accepted_is_high(self):
        result = grade(**_base_kwargs(
            ciphers_accepted={"TLSv1.0": ["AES128-SHA"], "TLSv1.2": ["AES128-GCM-SHA256"]},
        ))
        deprecated = [i for i in result["issues"] if i["id"] == "tls-deprecated-version-accepted"]
        assert len(deprecated) == 1
        assert deprecated[0]["severity"] == 3

    def test_weak_cipher_accepted(self):
        result = grade(**_base_kwargs(
            ciphers_accepted={"TLSv1.2": ["ECDHE-RSA-AES128-GCM-SHA256", "RC4-MD5"]},
        ))
        weak = [i for i in result["issues"] if i["id"] == "tls-weak-cipher-accepted"]
        assert len(weak) == 1
        assert weak[0]["severity"] == 3
        assert "RC4-MD5" in weak[0]["detail"]

    def test_3des_cipher_detected(self):
        result = grade(**_base_kwargs(
            ciphers_accepted={"TLSv1.2": ["DES-CBC3-SHA"]},
        ))
        ids = {i["id"] for i in result["issues"]}
        assert "tls-weak-cipher-accepted" in ids

    def test_chain_untrusted(self):
        result = grade(**_base_kwargs(
            chain_trusted=False, chain_errors=["Mozilla: self-signed certificate"],
        ))
        chain = [i for i in result["issues"] if i["id"] == "cert-chain-untrusted"]
        assert len(chain) == 1
        assert chain[0]["severity"] == 3
        assert "self-signed" in chain[0]["detail"]

    def test_ocsp_revoked_is_critical(self):
        result = grade(**_base_kwargs(
            ocsp_status="revoked", ocsp_detail="key_compromise",
        ))
        revoked = [i for i in result["issues"] if i["id"] == "cert-revoked"]
        assert len(revoked) == 1
        assert revoked[0]["severity"] == 4

    def test_ocsp_error_is_low(self):
        result = grade(**_base_kwargs(
            ocsp_status="error", ocsp_detail="connection timeout",
        ))
        err = [i for i in result["issues"] if i["id"] == "cert-ocsp-check-failed"]
        assert len(err) == 1
        assert err[0]["severity"] == 1

    def test_ocsp_unknown_is_not_flagged(self):
        # "unknown" is common (no OCSP URL) and non-actionable — don't grade.
        result = grade(**_base_kwargs(ocsp_status="unknown"))
        ids = {i["id"] for i in result["issues"]}
        assert "cert-ocsp-check-failed" not in ids
        assert "cert-revoked" not in ids

    def test_caa_mismatch_detected(self):
        result = grade(**_base_kwargs(
            caa_records=['0 issue "letsencrypt.org"'],
            issuer_org="DigiCert Inc",
        ))
        caa = [i for i in result["issues"] if i["id"] == "cert-caa-mismatch"]
        assert len(caa) == 1
        assert caa[0]["severity"] == 2
        assert "DigiCert" in caa[0]["detail"]

    def test_caa_match_no_issue(self):
        result = grade(**_base_kwargs(
            caa_records=['0 issue "letsencrypt.org"'],
            issuer_org="Let's Encrypt",
        ))
        ids = {i["id"] for i in result["issues"]}
        assert "cert-caa-mismatch" not in ids
        assert result["caa"]["authorized"] is True

    def test_no_caa_records_not_flagged(self):
        # Absence of CAA means any CA is allowed — no finding.
        result = grade(**_base_kwargs(caa_records=[]))
        ids = {i["id"] for i in result["issues"]}
        assert "cert-caa-mismatch" not in ids

    def test_multiple_issues_all_surface(self):
        result = grade(**_base_kwargs(
            ciphers_accepted={
                "TLSv1.0": ["AES128-SHA"],
                "TLSv1.2": ["RC4-SHA"],
            },
            chain_trusted=False, chain_errors=["expired"],
            ocsp_status="revoked", ocsp_detail="cessation_of_operation",
            caa_records=['0 issue "pki.goog"'], issuer_org="Let's Encrypt",
        ))
        ids = {i["id"] for i in result["issues"]}
        assert "tls-deprecated-version-accepted" in ids
        assert "tls-weak-cipher-accepted" in ids
        assert "cert-chain-untrusted" in ids
        assert "cert-revoked" in ids
        assert "cert-caa-mismatch" in ids

    def test_output_shape_stable(self):
        result = grade(**_base_kwargs())
        for key in (
            "host", "port", "ciphers_accepted", "versions_accepted",
            "weak_ciphers_accepted", "chain", "ocsp", "caa", "issues",
        ):
            assert key in result

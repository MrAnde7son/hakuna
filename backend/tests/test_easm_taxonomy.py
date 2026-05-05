"""PR 0c — EASM taxonomy registry + ingest field coverage.

Pins the metadata layer that compliance mappings depend on:
  - Every emitted EASM plugin_id resolves to a stable plugin_family.
  - Each plugin_id carries the canonical CWE list expected by frameworks.
  - HEADER/COOKIE bundled findings union CWEs from their sub-issues.
  - ctx_* fields are seeded for every EASM finding (internet_facing/public).
  - Stub finding types (subdomain takeover etc.) emit when the scanner
    surfaces the corresponding signal field.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime

from models.models import Scan, Asset, Finding
from services.easm import _generate_easm_findings, _easm_metadata_kwargs
from services.easm_taxonomy import (
    cwe_ids_for_subissues,
    metadata_for,
    references_dict,
    seed_easm_context,
)


# ─── Registry lookups ──────────────────────────────────────────

class TestMetadataFor:
    def test_exact_match_tls_cert(self):
        m = metadata_for("EASM-TLS-CERT")
        assert m["family"] == "EASM: TLS/SSL"
        assert "CWE-295" in m["cwe_ids"]
        assert m["references"]

    def test_prefix_match_exposed_db(self):
        m = metadata_for("EASM-EXPOSED-DB-3306")
        assert m["family"] == "EASM: Exposed Service"
        assert "CWE-284" in m["cwe_ids"]
        assert "CWE-668" in m["cwe_ids"]

    def test_prefix_match_cve(self):
        m = metadata_for("EASM-CVE-CVE-2021-44228")
        assert m["family"] == "EASM: CVE"
        # CVE → CWE comes from threat_intel_sync, not the registry.
        assert m["cwe_ids"] == []

    def test_stub_subdomain_takeover(self):
        m = metadata_for("EASM-SUBDOMAIN-TAKEOVER")
        assert m["family"] == "EASM: Takeover"
        assert m["cwe_ids"] == ["CWE-1385"]

    def test_stub_leaked_credential(self):
        m = metadata_for("EASM-LEAKED-CREDENTIAL")
        assert "CWE-798" in m["cwe_ids"]
        assert "CWE-522" in m["cwe_ids"]

    def test_unknown_falls_back_to_other(self):
        m = metadata_for("EASM-UNKNOWN-THING")
        assert m["family"] == "EASM: Other"
        assert m["cwe_ids"] == []

    def test_empty_string_safe(self):
        m = metadata_for("")
        assert m["family"] == "EASM: Other"


# ─── Sub-issue CWE union ───────────────────────────────────────

class TestCweIdsForSubissues:
    def test_hsts_missing(self):
        assert cwe_ids_for_subissues(["hsts-missing"]) == ["CWE-319"]

    def test_csp_missing_yields_two(self):
        cwes = cwe_ids_for_subissues(["csp-missing"])
        assert "CWE-1021" in cwes
        assert "CWE-79" in cwes

    def test_cookie_insecure_yields_614(self):
        assert cwe_ids_for_subissues(["cookie-insecure"]) == ["CWE-614"]

    def test_union_dedupes(self):
        cwes = cwe_ids_for_subissues(
            ["csp-missing", "clickjacking-protection-missing"]
        )
        # CWE-1021 appears in both and should appear once.
        assert cwes.count("CWE-1021") == 1

    def test_unknown_subissue_ignored(self):
        assert cwe_ids_for_subissues(["unknown-subissue"]) == []

    def test_empty_input(self):
        assert cwe_ids_for_subissues([]) == []


# ─── References shape ──────────────────────────────────────────

class TestReferencesDict:
    def test_wraps_under_urls(self):
        assert references_dict(["https://a.com", "https://b.com"]) == {
            "urls": ["https://a.com", "https://b.com"]
        }

    def test_empty_yields_empty_dict(self):
        assert references_dict([]) == {}

    def test_filters_non_strings(self):
        assert references_dict(["https://a.com", None, ""]) == {
            "urls": ["https://a.com"]
        }


# ─── ctx_* seeding ─────────────────────────────────────────────

class TestSeedEasmContext:
    def test_default_unauthenticated(self):
        ctx = seed_easm_context()
        assert ctx == {
            "ctx_reachability": "internet_facing",
            "ctx_accessibility": "public",
            "ctx_exploitability": None,
        }

    def test_kev_lifts_exploitability(self):
        ctx = seed_easm_context(is_kev=True)
        assert ctx["ctx_exploitability"] == "easily_exploitable"

    def test_public_exploit_lifts_exploitability(self):
        ctx = seed_easm_context(exploit_available=True)
        assert ctx["ctx_exploitability"] == "easily_exploitable"


# ─── _easm_metadata_kwargs glue ────────────────────────────────

class TestEasmMetadataKwargs:
    def test_returns_family_and_ctx(self):
        kw = _easm_metadata_kwargs("EASM-TLS-WEAK")
        assert kw["plugin_family"] == "EASM: TLS/SSL"
        assert "CWE-327" in kw["cwe_ids"]
        assert kw["references"] == {
            "urls": [
                "https://cwe.mitre.org/data/definitions/327.html",
                "https://wiki.mozilla.org/Security/Server_Side_TLS",
            ]
        }
        assert kw["ctx_reachability"] == "internet_facing"
        assert kw["ctx_accessibility"] == "public"
        # ctx_exploitability omitted when no KEV/exploit signal.
        assert "ctx_exploitability" not in kw

    def test_extra_cwes_unioned(self):
        kw = _easm_metadata_kwargs(
            "EASM-COOKIE-WEAK", extra_cwes=["CWE-614", "CWE-1004"]
        )
        assert set(kw["cwe_ids"]) == {"CWE-614", "CWE-1004"}

    def test_kev_signal_sets_exploitability(self):
        kw = _easm_metadata_kwargs("EASM-CVE-CVE-2021-44228", is_kev=True)
        assert kw["ctx_exploitability"] == "easily_exploitable"


# ─── Ingest end-to-end (DB-backed) ─────────────────────────────

def _make_scan_and_asset(db, *, is_internet_facing=True):
    scan = Scan(filename="easm.json", scan_name="easm", source_type="easm")
    db.add(scan)
    db.flush()
    asset = Asset(
        scan_id=scan.id,
        ip="203.0.113.10",
        hostname="external.example.com",
        is_internet_facing=is_internet_facing,
        environment_tag="external",
    )
    db.add(asset)
    db.flush()
    return scan, asset


class TestGenerateEasmFindingsTaxonomy:
    def test_exposed_db_carries_cwes(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "open_ports": [3306],
            "services": {"3306": {"name": "mysql", "product": "MySQL"}},
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-EXPOSED-DB-3306"
        ).one()
        assert f.plugin_family == "EASM: Exposed Service"
        assert "CWE-284" in f.cwe_ids
        assert "CWE-668" in f.cwe_ids
        assert f.references == {
            "urls": [
                "https://cwe.mitre.org/data/definitions/284.html",
                "https://cwe.mitre.org/data/definitions/668.html",
            ]
        }

    def test_tls_weak_carries_327(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "tls_cert": {"version": "TLSv1", "cipher": "RC4-MD5", "expiry": "2030-01-01T00:00:00Z"},
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        weak = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-TLS-WEAK"
        ).one()
        assert weak.plugin_family == "EASM: TLS/SSL"
        assert "CWE-327" in weak.cwe_ids

    def test_header_finding_unions_subissue_cwes(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "security_audit": {
                "url": "https://external.example.com/",
                "issues": [
                    {"id": "hsts-missing",                    "severity": 2, "detail": "no HSTS"},
                    {"id": "csp-missing",                     "severity": 2, "detail": "no CSP"},
                    {"id": "clickjacking-protection-missing", "severity": 2, "detail": "no XFO"},
                ],
            },
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-HTTP-HEADER-WEAK"
        ).one()
        assert "CWE-319" in f.cwe_ids   # HSTS
        assert "CWE-1021" in f.cwe_ids  # XFO + CSP
        assert "CWE-79" in f.cwe_ids    # CSP

    def test_cookie_finding_unions_subissue_cwes(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "security_audit": {
                "issues": [
                    {"id": "cookie-insecure",     "severity": 2, "detail": "no Secure"},
                    {"id": "cookie-not-httponly", "severity": 2, "detail": "no HttpOnly"},
                ],
            },
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-COOKIE-WEAK"
        ).one()
        assert "CWE-614" in f.cwe_ids
        assert "CWE-1004" in f.cwe_ids

    def test_internal_asset_seeds_internal_only(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        # EASM by definition treats every asset as internet-facing — the
        # registry-level helper unconditionally seeds internet_facing/public.
        # Asset.is_internet_facing flag isn't read by the helper.
        ea = {
            "hostname": "external.example.com",
            "open_ports": [3306],
            "services": {"3306": {"name": "mysql", "product": "MySQL"}},
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)
        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-EXPOSED-DB-3306"
        ).one()
        assert f.ctx_reachability == "internet_facing"
        assert f.ctx_accessibility == "public"


class TestStubFindingTypes:
    def test_subdomain_takeover_emitted_when_signal_present(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "subdomain_takeovers": [
                {"target": "old.example.com", "cname": "old.example.com.s3.amazonaws.com",
                 "fingerprint": "AWS S3 NoSuchBucket"},
            ],
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-SUBDOMAIN-TAKEOVER"
        ).one()
        assert f.severity == 4
        assert f.cwe_ids == ["CWE-1385"]
        assert f.ctx_exploitability == "easily_exploitable"

    def test_exposed_admin_panel(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "exposed_admin_panels": [
                {"url": "https://external.example.com/admin", "panel_type": "Grafana"},
            ],
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-EXPOSED-ADMIN-PANEL"
        ).one()
        assert f.cwe_ids == ["CWE-284"]
        assert f.severity == 3

    def test_directory_listing(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "directory_listings": [
                {"url": "https://external.example.com/backup/", "files_count": 12},
            ],
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-DIRECTORY-LISTING"
        ).one()
        assert f.cwe_ids == ["CWE-548"]

    def test_leaked_credential(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        ea = {
            "hostname": "external.example.com",
            "leaked_credentials": [
                {"source": "GitHub gist", "snippet": "AKIA... redacted"},
            ],
        }
        _generate_easm_findings(db_session, scan.id, asset, ea)

        f = db_session.query(Finding).filter(
            Finding.plugin_id == "EASM-LEAKED-CREDENTIAL"
        ).one()
        assert "CWE-798" in f.cwe_ids
        assert "CWE-522" in f.cwe_ids
        assert f.severity == 4
        assert f.ctx_exploitability == "easily_exploitable"

    def test_no_signal_no_emission(self, db_session):
        scan, asset = _make_scan_and_asset(db_session)
        # Empty ea → none of the four stub types should emit
        _generate_easm_findings(db_session, scan.id, asset, {"hostname": "external.example.com"})
        for pid in (
            "EASM-SUBDOMAIN-TAKEOVER",
            "EASM-EXPOSED-ADMIN-PANEL",
            "EASM-DIRECTORY-LISTING",
            "EASM-LEAKED-CREDENTIAL",
        ):
            assert db_session.query(Finding).filter(Finding.plugin_id == pid).first() is None

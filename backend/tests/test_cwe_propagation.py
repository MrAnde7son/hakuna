"""
Tests for CWE handling on Finding:
  1. Finding.cwe_ids and cwe_names columns persist correctly.
  2. rule_engine `finding.cwe`, `finding.has_cwe` evaluate as expected.
  3. threat_intel_sync.enrich_findings_from_threat_intel unions
     ThreatCVE.cwe_ids onto Finding.cwe_ids without clobbering scanner-set
     values.
"""
import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.models import Scan, Asset, Finding
from models.threat_intel_models import ThreatCVE
from services.rule_engine import evaluate_condition_for_finding
from threat_intel.threat_intel_sync import enrich_findings_from_threat_intel


# ─── helpers ───────────────────────────────────────────────────

def _make_finding(db, *, cves=None, cwe_ids=None, cwe_names=None):
    scan = Scan(filename="test.nessus", scan_name="t", source_type="nessus")
    db.add(scan)
    db.flush()
    asset = Asset(scan_id=scan.id, ip="10.0.0.1", hostname="h1")
    db.add(asset)
    db.flush()
    f = Finding(
        scan_id=scan.id,
        asset_id=asset.id,
        plugin_id="test",
        severity=3,
        cves=cves or [],
        cwe_ids=cwe_ids or [],
        cwe_names=cwe_names or [],
    )
    db.add(f)
    db.flush()
    return f


# ─── column persistence ────────────────────────────────────────

class TestCweColumns:
    def test_defaults_are_empty_lists(self, db_session):
        f = _make_finding(db_session)
        assert f.cwe_ids == []
        assert f.cwe_names == []

    def test_roundtrip(self, db_session):
        f = _make_finding(
            db_session,
            cwe_ids=["CWE-79", "CWE-89"],
            cwe_names=["XSS", "SQLi"],
        )
        db_session.expire(f)
        assert f.cwe_ids == ["CWE-79", "CWE-89"]
        assert f.cwe_names == ["XSS", "SQLi"]


# ─── rule_engine evaluation ────────────────────────────────────

class TestRuleEngineCwe:
    def test_has_cwe_true(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79"])
        assert evaluate_condition_for_finding(
            {"field": "finding.has_cwe", "op": "is_true"}, f
        ) is True

    def test_has_cwe_false_when_empty(self, db_session):
        f = _make_finding(db_session)
        assert evaluate_condition_for_finding(
            {"field": "finding.has_cwe", "op": "is_true"}, f
        ) is False
        assert evaluate_condition_for_finding(
            {"field": "finding.has_cwe", "op": "is_false"}, f
        ) is True

    def test_cwe_eq_single_match(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79", "CWE-89"])
        assert evaluate_condition_for_finding(
            {"field": "finding.cwe", "op": "eq", "value": "CWE-79"}, f
        ) is True

    def test_cwe_eq_no_match(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79"])
        assert evaluate_condition_for_finding(
            {"field": "finding.cwe", "op": "eq", "value": "CWE-22"}, f
        ) is False

    def test_cwe_case_insensitive(self, db_session):
        f = _make_finding(db_session, cwe_ids=["cwe-79"])
        assert evaluate_condition_for_finding(
            {"field": "finding.cwe", "op": "eq", "value": "CWE-79"}, f
        ) is True

    def test_cwe_contains_any_list_input(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-89"])
        assert evaluate_condition_for_finding(
            {
                "field": "finding.cwe",
                "op": "contains_any",
                "value": ["CWE-79", "CWE-89", "CWE-22"],
            },
            f,
        ) is True

    def test_cwe_contains_any_comma_string(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-22"])
        assert evaluate_condition_for_finding(
            {
                "field": "finding.cwe",
                "op": "contains_any",
                "value": "CWE-79,CWE-22,CWE-89",
            },
            f,
        ) is True

    def test_cwe_contains_all_match(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79", "CWE-89", "CWE-22"])
        assert evaluate_condition_for_finding(
            {
                "field": "finding.cwe",
                "op": "contains_all",
                "value": ["CWE-79", "CWE-89"],
            },
            f,
        ) is True

    def test_cwe_contains_all_partial(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79"])
        assert evaluate_condition_for_finding(
            {
                "field": "finding.cwe",
                "op": "contains_all",
                "value": ["CWE-79", "CWE-89"],
            },
            f,
        ) is False


# ─── CVE → CWE propagation ─────────────────────────────────────

class TestCvePropagation:
    def _seed_threat_cve(self, db, cve_id, cwe_ids, cwe_names=None):
        tc = ThreatCVE(
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            cwe_names=cwe_names or [],
        )
        db.add(tc)
        db.flush()
        return tc

    def test_union_from_single_cve(self, db_session):
        self._seed_threat_cve(
            db_session, "CVE-2021-44228", ["CWE-20", "CWE-502"], ["Input Validation", "Deserialization"]
        )
        f = _make_finding(db_session, cves=["CVE-2021-44228"])
        db_session.commit()

        result = enrich_findings_from_threat_intel(db_session, scan_id=f.scan_id)

        assert result["enriched"] >= 1
        db_session.refresh(f)
        assert set(f.cwe_ids) == {"CWE-20", "CWE-502"}
        assert set(f.cwe_names) == {"Input Validation", "Deserialization"}

    def test_union_preserves_scanner_cwes(self, db_session):
        """Scanner-set CWE must survive the enrichment pass (no clobber)."""
        self._seed_threat_cve(db_session, "CVE-2022-1234", ["CWE-79"])
        f = _make_finding(
            db_session, cves=["CVE-2022-1234"], cwe_ids=["CWE-89"]
        )
        db_session.commit()

        enrich_findings_from_threat_intel(db_session, scan_id=f.scan_id)
        db_session.refresh(f)

        assert set(f.cwe_ids) == {"CWE-79", "CWE-89"}

    def test_no_cves_leaves_cwe_untouched(self, db_session):
        f = _make_finding(db_session, cwe_ids=["CWE-79"])
        db_session.commit()
        enrich_findings_from_threat_intel(db_session, scan_id=f.scan_id)
        db_session.refresh(f)
        assert f.cwe_ids == ["CWE-79"]

    def test_cve_without_threat_cve_row_no_change(self, db_session):
        """A CVE that isn't in ThreatCVE leaves CWE empty."""
        f = _make_finding(db_session, cves=["CVE-9999-9999"])
        db_session.commit()
        enrich_findings_from_threat_intel(db_session, scan_id=f.scan_id)
        db_session.refresh(f)
        assert f.cwe_ids == []

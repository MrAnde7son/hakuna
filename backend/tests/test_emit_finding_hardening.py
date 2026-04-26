"""PR 0d — agentic emit_finding compliance-readiness.

Pins the audit-agent ingestion path:
  - plugin_family is a closed registry, not freeform per protocol.
  - cwe_ids / references / ctx_* are accepted from agent input.
  - CVE / CWE inputs are normalized (case, prefix).
  - Soft-accept: Medium+ findings without CVE/CWE persist with
    custom_fields.compliance_evaluable = False (no rejection).
  - ctx_* values off-list are dropped silently, finding still persists.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import patch

from models.models import Scan, Asset, Finding
from agents.tools.emit_finding import (
    emit_finding_tool,
    _normalize_cwes,
    _normalize_cves,
    _coerce_ctx,
    _coerce_references,
    _PROTOCOL_PLUGIN_FAMILIES,
    _CTX_REACHABILITY,
)


# ─── Pure-function helpers ─────────────────────────────────────

class TestNormalizeCwes:
    def test_uppercases_and_dedupes(self):
        assert _normalize_cwes(["cwe-79", "CWE-79", "CWE-89"]) == ["CWE-79", "CWE-89"]

    def test_accepts_bare_numbers(self):
        assert _normalize_cwes(["79", "89"]) == ["CWE-79", "CWE-89"]

    def test_accepts_comma_string(self):
        assert _normalize_cwes("CWE-79, CWE-89") == ["CWE-79", "CWE-89"]

    def test_drops_non_cwe_values(self):
        assert _normalize_cwes(["CVE-2021-1234", "not a cwe", "CWE-79"]) == ["CWE-79"]

    def test_empty_input(self):
        assert _normalize_cwes(None) == []
        assert _normalize_cwes([]) == []
        assert _normalize_cwes("") == []


class TestNormalizeCves:
    def test_uppercases_and_dedupes(self):
        assert _normalize_cves(["cve-2021-44228", "CVE-2021-44228"]) == ["CVE-2021-44228"]

    def test_drops_non_cve(self):
        assert _normalize_cves(["CWE-79", "CVE-2022-1"]) == ["CVE-2022-1"]

    def test_comma_string(self):
        assert _normalize_cves("CVE-2021-1, CVE-2022-2") == ["CVE-2021-1", "CVE-2022-2"]


class TestCoerceCtx:
    def test_accepts_listed_value(self):
        assert _coerce_ctx("internet_facing", _CTX_REACHABILITY) == "internet_facing"

    def test_case_insensitive(self):
        assert _coerce_ctx("INTERNET_FACING", _CTX_REACHABILITY) == "internet_facing"

    def test_drops_unknown_value(self):
        assert _coerce_ctx("totally-bogus", _CTX_REACHABILITY) is None

    def test_drops_non_string(self):
        assert _coerce_ctx(42, _CTX_REACHABILITY) is None
        assert _coerce_ctx(None, _CTX_REACHABILITY) is None


class TestCoerceReferences:
    def test_list_wrapped_under_urls(self):
        assert _coerce_references(["https://a.com"]) == {"urls": ["https://a.com"]}

    def test_dict_passthrough(self):
        assert _coerce_references({"urls": ["a"], "advisory": "b"}) == {
            "urls": ["a"], "advisory": "b"
        }

    def test_dict_drops_falsy(self):
        assert _coerce_references({"urls": ["a"], "advisory": ""}) == {"urls": ["a"]}

    def test_empty_yields_empty_dict(self):
        assert _coerce_references(None) == {}
        assert _coerce_references([]) == {}


# ─── Plugin family registry ────────────────────────────────────

class TestPluginFamilyRegistry:
    def test_known_protocols_have_canonical_families(self):
        for protocol in ("wmi", "ldap", "smb", "kerberos", "snmp", "winrm",
                         "ssh", "aws", "azure", "gcp"):
            assert protocol in _PROTOCOL_PLUGIN_FAMILIES
            family = _PROTOCOL_PLUGIN_FAMILIES[protocol]
            assert family.startswith("Audit:"), \
                f"plugin_family for {protocol} must use 'Audit:' namespace"


# ─── End-to-end emit_finding_tool ──────────────────────────────

def _seed_asset(db):
    scan = Scan(filename="audit.json", scan_name="audit", source_type="wmi_audit")
    db.add(scan)
    db.flush()
    asset = Asset(scan_id=scan.id, ip="10.0.0.5", hostname="dc1.corp.local")
    db.add(asset)
    db.flush()
    return scan, asset


def _emit(db, **overrides):
    """Call emit_finding_tool with finalize_batch stubbed (avoids
    threat-intel side effects in the unit test)."""
    params = {
        "protocol": "wmi",
        "mission": "identity",
        "asset_id": overrides.pop("asset_id"),
        "finding_type": "weak_password_policy",
        "severity": "medium",
        "title": "Weak password policy",
        "description": "minimum length 4",
        "evidence": {"min_length": 4},
        "recommended_fix": "Set minimum to 14",
    }
    params.update(overrides)
    with patch("services.post_ingest.finalize_batch", return_value={}):
        return emit_finding_tool(db, params)


class TestEmitFindingPersistsNewFields:
    def test_plugin_family_from_registry(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id)
        assert "error" not in result
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.plugin_family == "Audit: Windows"

    def test_unknown_protocol_falls_back_to_audit_namespace(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id, protocol="zigbee")
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.plugin_family == "Audit: ZIGBEE"

    def test_cwe_ids_persisted_and_normalized(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id,
            cwe_ids=["cwe-521", "521", "CWE-798"],
        )
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.cwe_ids == ["CWE-521", "CWE-798"]

    def test_cves_persisted_and_normalized(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id,
            cves=["cve-2021-44228", "CVE-2021-44228"],
        )
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.cves == ["CVE-2021-44228"]

    def test_references_persisted(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.references == {"urls": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]}

    def test_ctx_fields_persisted_when_valid(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id,
            ctx_reachability="internet_facing",
            ctx_exploitability="easily_exploitable",
            ctx_accessibility="public",
        )
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.ctx_reachability == "internet_facing"
        assert f.ctx_exploitability == "easily_exploitable"
        assert f.ctx_accessibility == "public"

    def test_ctx_fields_dropped_when_invalid_finding_still_persists(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id,
            ctx_reachability="totally-bogus",
        )
        # Soft-accept: finding emitted, bad ctx dropped silently.
        assert "error" not in result
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.ctx_reachability is None


class TestComplianceEvaluableFlag:
    def test_medium_with_cwe_is_evaluable(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id, cwe_ids=["CWE-521"])
        assert result["compliance_evaluable"] is True
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.custom_fields["compliance_evaluable"] is True

    def test_medium_with_cve_is_evaluable(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id, cves=["CVE-2021-1"])
        assert result["compliance_evaluable"] is True

    def test_medium_with_neither_is_not_evaluable_but_still_persists(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id)  # no cves, no cwe_ids
        assert "error" not in result
        assert result["compliance_evaluable"] is False
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.custom_fields["compliance_evaluable"] is False
        # Soft-accept: severity preserved, no downgrade.
        assert f.severity == 2

    def test_info_without_cve_or_cwe_is_not_evaluable_no_warning_intent(self, db_session):
        # Info-severity findings are never expected to map to compliance —
        # the flag still tracks state but the log/warning path doesn't fire.
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id, severity="info",
        )
        assert result["compliance_evaluable"] is False
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.severity == 0

    def test_critical_without_metadata_still_persists(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(
            db_session, asset_id=asset.id, severity="critical",
        )
        assert "error" not in result
        assert result["compliance_evaluable"] is False
        f = db_session.query(Finding).filter(Finding.id == result["finding_id"]).one()
        assert f.severity == 4


class TestRequiredInputs:
    def test_missing_protocol_returns_error(self, db_session):
        _, asset = _seed_asset(db_session)
        result = _emit(db_session, asset_id=asset.id, protocol="")
        assert "error" in result

    def test_missing_asset_id_returns_error(self, db_session):
        with patch("services.post_ingest.finalize_batch", return_value={}):
            result = emit_finding_tool(db_session, {
                "protocol": "wmi", "finding_type": "x", "title": "y",
            })
        assert "error" in result

    def test_unknown_asset_returns_error(self, db_session):
        result = _emit(db_session, asset_id=99999)
        assert "error" in result

"""Tests for user-defined custom fields on Asset and Finding."""
from __future__ import annotations

import pytest

from models.models import (
    Asset, Finding, CustomFieldDefinition, AssetObservation, FindingObservation,
)
from services.custom_field_resolver import apply_custom_fields, load_custom_field_defs
from services.upsert_handler import upsert_batch


# ─────────────────────────────────────────────
# Resolver unit tests
# ─────────────────────────────────────────────


def _mk_def(db_session, org_id, **kwargs):
    defaults = dict(
        org_id=org_id,
        entity_type="asset",
        key="cfg",
        label="CFG",
        data_type="string",
        source_type="manual",
        is_active=True,
    )
    defaults.update(kwargs)
    d = CustomFieldDefinition(**defaults)
    db_session.add(d)
    db_session.flush()
    return d


def test_resolver_mapping_dot_path(db_session, test_org, test_assets):
    asset = test_assets[0]
    definition = _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="vendor", label="Vendor",
        source_type="mapping", mapping_source="raw.vendor",
    )
    record = {"raw": {"vendor": "VMware", "other": 42}}
    assert apply_custom_fields(asset, record, [definition]) is True
    assert asset.custom_fields == {"vendor": "VMware"}


def test_resolver_mapping_with_transform(db_session, test_org, test_assets):
    asset = test_assets[0]
    definition = _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="is_prod", label="Is Prod",
        data_type="boolean", source_type="mapping",
        mapping_source="environment",
        mapping_transform={"type": "map", "mapping": {"production": "true", "prod": "true"}},
    )
    apply_custom_fields(asset, {"environment": "prod"}, [definition])
    # data_type=boolean coerces the "true" string
    assert asset.custom_fields == {"is_prod": True}


def test_resolver_formula_uses_merged_entity(db_session, test_org, test_assets):
    asset = test_assets[0]
    asset.criticality = 9
    definition = _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="tier", label="Tier",
        source_type="formula",
        formula_expression="'top' if record['criticality'] >= 8 else 'low'",
    )
    apply_custom_fields(asset, {}, [definition])
    assert asset.custom_fields == {"tier": "top"}


def test_resolver_manual_is_skipped(db_session, test_org, test_assets):
    asset = test_assets[0]
    definition = _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="owner", label="Owner",
        source_type="manual",
    )
    asset.custom_fields = {"owner": "alice"}
    updated = apply_custom_fields(asset, {"owner": "should-not-overwrite"}, [definition])
    assert updated is False
    assert asset.custom_fields == {"owner": "alice"}


def test_resolver_user_edited_fields_protected(db_session, test_org, test_assets):
    asset = test_assets[0]
    asset.custom_fields = {"vendor": "manual-vendor"}
    asset.user_edited_fields = ["custom_fields.vendor"]
    definition = _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="vendor", label="Vendor",
        source_type="mapping", mapping_source="raw.vendor",
    )
    updated = apply_custom_fields(asset, {"raw": {"vendor": "auto-vendor"}}, [definition])
    assert updated is False
    assert asset.custom_fields == {"vendor": "manual-vendor"}


def test_resolver_skip_when_no_defs(db_session, test_assets):
    asset = test_assets[0]
    assert apply_custom_fields(asset, {"raw": {"x": 1}}, []) is False
    assert not asset.custom_fields


def test_load_defs_filters_by_entity_and_active(db_session, test_org):
    _mk_def(db_session, test_org.id, entity_type="asset", key="a1", label="A1")
    _mk_def(db_session, test_org.id, entity_type="finding", key="f1", label="F1")
    _mk_def(db_session, test_org.id, entity_type="asset", key="inactive", label="X", is_active=False)
    defs = load_custom_field_defs(db_session, test_org.id, "asset")
    assert {d.key for d in defs} == {"a1"}


# ─────────────────────────────────────────────
# Upsert integration
# ─────────────────────────────────────────────


def test_upsert_batch_populates_custom_fields(db_session, test_org, test_scan):
    _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="vendor", label="Vendor",
        source_type="mapping", mapping_source="raw.vendor",
    )
    db_session.flush()

    records = [{
        "hostname": "new-host-1",
        "ip_address": "10.99.0.1",
        "raw": {"vendor": "Dell"},
        "source_system": "nessus",
        "source_id": "nessus:1",
    }]
    result = upsert_batch(
        db_session, "asset", records,
        dedup_key=["source_system", "source_id"],
        integration_id="test", scan_id=test_scan.id,
    )
    assert result["inserted"] == 1
    created_id = result["new_asset_ids"][0]
    asset = db_session.query(Asset).filter(Asset.id == created_id).first()
    assert asset.custom_fields == {"vendor": "Dell"}


def test_upsert_batch_updates_custom_fields_on_rescan(db_session, test_org, test_scan):
    _mk_def(
        db_session, test_org.id,
        entity_type="asset", key="vendor", label="Vendor",
        source_type="mapping", mapping_source="raw.vendor",
    )
    db_session.flush()

    records = [{
        "hostname": "resc-host",
        "ip_address": "10.88.0.1",
        "raw": {"vendor": "Old"},
        "source_system": "nessus",
        "source_id": "nessus:resc",
    }]
    r1 = upsert_batch(
        db_session, "asset", records, dedup_key=["source_system", "source_id"],
        integration_id="test", scan_id=test_scan.id,
    )
    assert r1["inserted"] == 1

    # Second ingest with a new raw.vendor value — should update
    records[0]["raw"] = {"vendor": "New"}
    r2 = upsert_batch(
        db_session, "asset", records, dedup_key=["source_system", "source_id"],
        integration_id="test", scan_id=test_scan.id,
    )
    assert r2["updated"] == 1
    asset = db_session.query(Asset).filter(Asset.id == r1["new_asset_ids"][0]).first()
    assert asset.custom_fields == {"vendor": "New"}


# ─────────────────────────────────────────────
# API tests
# ─────────────────────────────────────────────


def test_create_list_delete_custom_field(authed_client, test_org):
    # Create
    resp = authed_client.post("/api/custom-fields", json={
        "entity_type": "asset",
        "key": "data_center",
        "label": "Data Center",
        "data_type": "string",
        "source_type": "manual",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    def_id = body["id"]
    assert body["key"] == "data_center"

    # List
    resp = authed_client.get("/api/custom-fields?entity_type=asset")
    assert resp.status_code == 200
    assert any(d["id"] == def_id for d in resp.json())

    # Delete
    resp = authed_client.delete(f"/api/custom-fields/{def_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    # Verify gone
    resp = authed_client.get("/api/custom-fields?entity_type=asset")
    assert not any(d["id"] == def_id for d in resp.json())


def test_create_custom_field_validation(authed_client):
    # Bad key pattern
    resp = authed_client.post("/api/custom-fields", json={
        "entity_type": "asset",
        "key": "Bad-Key!",
        "label": "X",
        "source_type": "manual",
    })
    assert resp.status_code == 400

    # Mapping without mapping_source
    resp = authed_client.post("/api/custom-fields", json={
        "entity_type": "asset",
        "key": "ok_key",
        "label": "X",
        "source_type": "mapping",
    })
    assert resp.status_code == 400


def test_preview_formula(authed_client):
    resp = authed_client.post("/api/custom-fields/preview", json={
        "entity_type": "finding",
        "source_type": "formula",
        "data_type": "boolean",
        "formula_expression": "record['priority_score'] > 7",
        "sample_record": {"priority_score": 8.5},
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["coerced_value"] is True
    assert body["error"] is None


def test_list_assets_custom_field_filter(authed_client, db_session, test_org, test_scan, test_assets):
    # Set custom_fields directly then filter via ?cf_vendor=
    test_assets[0].custom_fields = {"vendor": "VMware"}
    test_assets[1].custom_fields = {"vendor": "Dell"}
    db_session.flush()

    resp = authed_client.get("/api/assets?cf_vendor=vmware")
    assert resp.status_code == 200
    assets = resp.json()["assets"]
    ips = {a["ip"] for a in assets}
    assert test_assets[0].ip in ips
    assert test_assets[1].ip not in ips


def test_patch_manual_custom_field_blocks_computed(
    authed_client, db_session, test_org, test_assets
):
    # Create one manual and one mapping def
    _mk_def(db_session, test_org.id, entity_type="asset", key="owner",
            label="Owner", source_type="manual")
    _mk_def(db_session, test_org.id, entity_type="asset", key="vendor",
            label="Vendor", source_type="mapping", mapping_source="raw.vendor")
    db_session.flush()

    asset_id = test_assets[0].id

    # Allowed: manual
    resp = authed_client.patch(
        f"/api/assets/{asset_id}",
        json={"custom_fields": {"owner": "platform-team"}},
    )
    assert resp.status_code == 200, resp.text
    asset = db_session.query(Asset).filter(Asset.id == asset_id).first()
    db_session.refresh(asset)
    assert asset.custom_fields.get("owner") == "platform-team"
    assert "custom_fields.owner" in (asset.user_edited_fields or [])

    # Blocked: computed
    resp = authed_client.patch(
        f"/api/assets/{asset_id}",
        json={"custom_fields": {"vendor": "illegal"}},
    )
    assert resp.status_code == 400


# ─────────────────────────────────────────────
# Rule engine integration (advanced search)
# ─────────────────────────────────────────────


def test_catalog_includes_custom_fields(db_session, test_org):
    """get_condition_catalog should expose active custom fields as groups."""
    from services.rule_engine import get_condition_catalog

    _mk_def(db_session, test_org.id, entity_type="asset", key="vendor",
            label="Vendor", data_type="string", source_type="mapping",
            mapping_source="raw.vendor")
    _mk_def(db_session, test_org.id, entity_type="finding", key="risk_tier",
            label="Risk Tier", data_type="number", source_type="formula",
            formula_expression="record.get('priority_score', 0)")
    _mk_def(db_session, test_org.id, entity_type="asset", key="inactive",
            label="X", is_active=False)
    db_session.flush()

    catalog = get_condition_catalog(db_session, [test_org.id])
    asset_group = next((g for g in catalog if g.get("group") == "Custom Fields (Asset)"), None)
    finding_group = next((g for g in catalog if g.get("group") == "Custom Fields (Finding)"), None)

    assert asset_group is not None
    asset_fields = {c["field"] for c in asset_group["conditions"]}
    assert "cf:vendor" in asset_fields
    assert "cf:inactive" not in asset_fields  # inactive defs excluded

    assert finding_group is not None
    finding_fields = {c["field"] for c in finding_group["conditions"]}
    assert "finding.cf:risk_tier" in finding_fields
    # number data_type → numeric ops
    risk_cond = next(c for c in finding_group["conditions"] if c["field"] == "finding.cf:risk_tier")
    assert risk_cond["value_type"] == "number"
    assert "gte" in risk_cond["ops"]


def test_eval_asset_custom_field_string(db_session, test_org):
    from services.rule_engine import evaluate_conditions

    asset_dict = {"ip": "10.0.0.1", "custom_fields": {"vendor": "VMware"}}
    conds = [{"field": "cf:vendor", "op": "contains", "value": "mware"}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is True

    conds = [{"field": "cf:vendor", "op": "eq", "value": "Dell"}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is False


def test_eval_asset_custom_field_numeric(db_session):
    from services.rule_engine import evaluate_conditions

    asset_dict = {"custom_fields": {"score": 85}}
    conds = [{"field": "cf:score", "op": "gte", "value": 80}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is True
    conds = [{"field": "cf:score", "op": "lt", "value": 80}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is False


def test_eval_asset_custom_field_missing_key(db_session):
    from services.rule_engine import evaluate_conditions

    asset_dict = {"custom_fields": {}}
    # String ops against a missing custom field = empty string comparison
    conds = [{"field": "cf:nope", "op": "eq", "value": ""}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is True
    conds = [{"field": "cf:nope", "op": "contains", "value": "x"}]
    assert evaluate_conditions(conds, "AND", asset_dict=asset_dict) is False


def test_get_matching_assets_with_custom_field(db_session, test_org, test_scan):
    """End-to-end: custom_fields must flow into the asset_dict used by get_matching_assets."""
    from services.rule_engine import get_matching_assets

    a1 = Asset(scan_id=test_scan.id, ip="10.0.1.1", hostname="h1", custom_fields={"vendor": "VMware"})
    a2 = Asset(scan_id=test_scan.id, ip="10.0.1.2", hostname="h2", custom_fields={"vendor": "Dell"})
    a3 = Asset(scan_id=test_scan.id, ip="10.0.1.3", hostname="h3", custom_fields={})
    db_session.add_all([a1, a2, a3])
    db_session.flush()
    from sqlalchemy import text
    for aid in (a1.id, a2.id, a3.id):
        db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :i"),
                           {"o": test_org.id, "i": aid})
    db_session.flush()

    conds = [{"field": "cf:vendor", "op": "eq", "value": "VMware"}]
    matches = get_matching_assets(conds, "AND", db_session)
    matched_ips = {a.ip for a in matches}
    assert "10.0.1.1" in matched_ips
    assert "10.0.1.2" not in matched_ips
    assert "10.0.1.3" not in matched_ips


def test_eval_finding_custom_field(db_session, test_org, test_scan):
    """finding.cf:<key> should read from the Finding.custom_fields column."""
    from services.rule_engine import _eval_finding_row

    finding = Finding(
        scan_id=test_scan.id, asset_id=1, plugin_id="1001",
        plugin_name="Test", severity=3, priority_score=8.0,
        custom_fields={"tier": "high"},
    )

    assert _eval_finding_row({"field": "finding.cf:tier", "op": "eq", "value": "high"}, finding) is True
    assert _eval_finding_row({"field": "finding.cf:tier", "op": "eq", "value": "low"}, finding) is False

    # Missing key on the finding
    finding.custom_fields = None
    assert _eval_finding_row({"field": "finding.cf:tier", "op": "contains", "value": "anything"}, finding) is False

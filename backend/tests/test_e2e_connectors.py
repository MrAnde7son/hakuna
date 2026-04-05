"""End-to-end connector tests for the Integration Builder.

Tests the full pipeline: connector JSON -> field mapping -> upsert -> DB verification,
plus the run engine E2E flow with mock transports.

Adding a new connector? Add its sample records to CONNECTOR_FIXTURES in conftest_e2e.py
and every test here picks it up automatically.
"""

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

# conftest_e2e is in the same directory
sys.path.insert(0, os.path.dirname(__file__))
from conftest_e2e import CONNECTOR_FIXTURES, MockTransport
from services.field_mapper import map_record
from services.upsert_handler import upsert, upsert_batch

CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

# ── Helpers ─────────────────────────────────────────────────────────


def _load_connector(connector_id: str) -> dict:
    path = CONNECTORS_DIR / f"{connector_id}.json"
    assert path.exists(), f"Connector file not found: {path}"
    with open(path) as f:
        return json.load(f)


ALL_CONNECTOR_IDS = sorted(p.stem for p in CONNECTORS_DIR.glob("*.json"))
PULL_CONNECTOR_IDS_WITH_FIXTURES = [
    cid for cid in CONNECTOR_FIXTURES
    if _load_connector(cid)["direction"] == "pull"
]
ASSET_CONNECTOR_IDS_WITH_FIXTURES = [
    cid for cid in PULL_CONNECTOR_IDS_WITH_FIXTURES
    if _load_connector(cid)["entity"] == "asset"
]
FINDING_CONNECTOR_IDS_WITH_FIXTURES = [
    cid for cid in PULL_CONNECTOR_IDS_WITH_FIXTURES
    if _load_connector(cid)["entity"] == "finding"
]


# ── Fixture: integration_factory (inline, since conftest_e2e isn't auto-discovered) ──

@pytest.fixture
def integration_factory(db_session, test_org, test_scan):
    """Factory: creates Integration + IntegrationRun DB records for testing."""
    from models.models import Integration, IntegrationRun

    def _make(
        name="Test Integration", direction="pull", entity="asset",
        transport_type="mock", template_id="test",
        field_map=None, dedup_key=None, transport_config=None, params=None,
    ):
        integration = Integration(
            id=str(uuid.uuid4()), org_id=test_org.id, name=name,
            direction=direction, entity=entity, transport_type=transport_type,
            transport_config=transport_config or {}, field_map=field_map or [],
            dedup_key=dedup_key or [], params=params or {},
            template_id=template_id, enabled=True,
        )
        db_session.add(integration)
        db_session.flush()

        run = IntegrationRun(
            id=str(uuid.uuid4()), integration_id=integration.id,
            status="running", triggered_by="test", started_at=datetime.utcnow(),
            records_fetched=0, records_inserted=0, records_updated=0,
            records_skipped=0, errors=[], step_log=[],
        )
        db_session.add(run)
        db_session.flush()
        return integration, run

    return _make


# =====================================================================
# 1. Contract tests -- connector JSON -> map_record -> upsert -> DB
# =====================================================================

class TestConnectorContractE2E:
    """For each connector with fixture data, run the full map -> upsert pipeline."""

    @pytest.mark.parametrize("connector_id", PULL_CONNECTOR_IDS_WITH_FIXTURES)
    def test_map_record_produces_valid_output(self, connector_id):
        """Field map produces mapped records with no error-level issues."""
        spec = _load_connector(connector_id)
        field_map = spec["default_field_map"]

        for i, raw in enumerate(CONNECTOR_FIXTURES[connector_id]):
            result = map_record(raw, field_map)
            errors = [e for e in result["errors"] if e["level"] == "error"]
            assert not errors, f"{connector_id} record {i}: mapping errors: {errors}"
            assert isinstance(result["mapped"], dict)

    @pytest.mark.parametrize("connector_id", ASSET_CONNECTOR_IDS_WITH_FIXTURES)
    def test_asset_has_hostname(self, connector_id):
        """Asset connectors must produce a hostname for every record."""
        spec = _load_connector(connector_id)
        for i, raw in enumerate(CONNECTOR_FIXTURES[connector_id]):
            mapped = map_record(raw, spec["default_field_map"])["mapped"]
            assert mapped.get("hostname") is not None, (
                f"{connector_id} record {i}: missing hostname"
            )

    @pytest.mark.parametrize("connector_id", FINDING_CONNECTOR_IDS_WITH_FIXTURES)
    def test_finding_has_severity(self, connector_id):
        """Finding connectors must produce a severity for every record."""
        spec = _load_connector(connector_id)
        for i, raw in enumerate(CONNECTOR_FIXTURES[connector_id]):
            mapped = map_record(raw, spec["default_field_map"])["mapped"]
            assert mapped.get("severity") is not None, (
                f"{connector_id} record {i}: missing severity"
            )

    @pytest.mark.parametrize("connector_id", PULL_CONNECTOR_IDS_WITH_FIXTURES)
    def test_upsert_inserts_then_dedup(self, connector_id, db_session, test_org, test_scan):
        """First upsert inserts; second with same data deduplicates (update/skip)."""
        spec = _load_connector(connector_id)
        raw = CONNECTOR_FIXTURES[connector_id][0]

        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        mapped["source_system"] = connector_id
        # Ensure source_id exists (run_engine normally injects this)
        if not mapped.get("source_id"):
            mapped["source_id"] = f"test-{connector_id}-001"

        r1 = upsert(db_session, spec["entity"], mapped, spec["dedup_key"],
                     "test-integ", scan_id=test_scan.id)
        db_session.flush()
        assert r1.action == "inserted", f"{connector_id}: expected inserted, got {r1.action}"
        assert r1.id is not None

        r2 = upsert(db_session, spec["entity"], mapped, spec["dedup_key"],
                     "test-integ", scan_id=test_scan.id)
        db_session.flush()
        assert r2.action in ("updated", "skipped"), (
            f"{connector_id}: expected dedup, got {r2.action}"
        )

    @pytest.mark.parametrize("connector_id", ASSET_CONNECTOR_IDS_WITH_FIXTURES)
    def test_asset_written_to_db(self, connector_id, db_session, test_org, test_scan):
        """Verify upserted asset is queryable in the DB with correct field values."""
        from models.models import Asset

        spec = _load_connector(connector_id)
        raw = CONNECTOR_FIXTURES[connector_id][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        mapped["source_system"] = connector_id
        if not mapped.get("source_id"):
            mapped["source_id"] = f"test-{connector_id}-001"

        result = upsert(db_session, "asset", mapped, spec["dedup_key"],
                         "test-integ", scan_id=test_scan.id)
        db_session.flush()

        asset = db_session.query(Asset).filter(Asset.id == result.id).first()
        assert asset is not None
        assert asset.source_system == connector_id
        assert asset.hostname == mapped.get("hostname", "")

    @pytest.mark.parametrize("connector_id", FINDING_CONNECTOR_IDS_WITH_FIXTURES)
    def test_finding_written_to_db(self, connector_id, db_session, test_org, test_scan):
        """Verify upserted finding is queryable in the DB."""
        from models.models import Finding

        spec = _load_connector(connector_id)
        raw = CONNECTOR_FIXTURES[connector_id][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        mapped["source_system"] = connector_id
        if not mapped.get("source_id"):
            mapped["source_id"] = f"test-{connector_id}-001"

        result = upsert(db_session, "finding", mapped, spec["dedup_key"],
                         "test-integ", scan_id=test_scan.id)
        db_session.flush()

        finding = db_session.query(Finding).filter(Finding.id == result.id).first()
        assert finding is not None
        assert finding.source_system == connector_id


# =====================================================================
# 2. Completeness -- validate every connector JSON (not just fixtures)
# =====================================================================

class TestConnectorFieldMapCompleteness:
    """Structural validation for every connector template on disk."""

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_field_map_rules_well_formed(self, connector_id):
        spec = _load_connector(connector_id)
        for i, rule in enumerate(spec.get("default_field_map", [])):
            assert "source" in rule, f"{connector_id} rule {i}: missing 'source'"
            assert "target" in rule, f"{connector_id} rule {i}: missing 'target'"

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_pull_asset_maps_required_fields(self, connector_id):
        spec = _load_connector(connector_id)
        if spec["direction"] != "pull" or spec["entity"] != "asset":
            pytest.skip("Not a pull/asset connector")
        targets = [r["target"] for r in spec["default_field_map"]]
        assert "source_id" in targets, f"{connector_id}: must map source_id"
        assert "hostname" in targets, f"{connector_id}: must map hostname"

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_pull_finding_maps_severity(self, connector_id):
        """Finding connectors must map severity."""
        spec = _load_connector(connector_id)
        if spec["direction"] != "pull" or spec["entity"] != "finding":
            pytest.skip("Not a pull/finding connector")
        targets = [r["target"] for r in spec["default_field_map"]]
        assert "severity" in targets, f"{connector_id}: must map severity"

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_pull_finding_maps_identity(self, connector_id):
        """Finding connectors must map at least plugin_id or source_id for dedup."""
        spec = _load_connector(connector_id)
        if spec["direction"] != "pull" or spec["entity"] != "finding":
            pytest.skip("Not a pull/finding connector")
        targets = set(r["target"] for r in spec["default_field_map"])
        has_identity = "source_id" in targets or "plugin_id" in targets
        assert has_identity, f"{connector_id}: must map source_id or plugin_id"

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_dedup_key_present_for_pull(self, connector_id):
        """Pull connectors must have a non-empty dedup_key."""
        spec = _load_connector(connector_id)
        if spec["direction"] != "pull":
            pytest.skip("Not a pull connector")
        assert spec.get("dedup_key"), f"{connector_id}: pull connector must have dedup_key"

    @pytest.mark.parametrize("connector_id", ALL_CONNECTOR_IDS)
    def test_has_credential_acquisition(self, connector_id):
        spec = _load_connector(connector_id)
        acq = spec.get("credential_acquisition")
        if acq is None:
            # File-based connectors may not need credentials
            assert spec.get("transport_type") == "file" or "file" in connector_id, (
                f"{connector_id}: non-file connector must have credential_acquisition"
            )
            return
        assert "pattern" in acq, f"{connector_id}: credential_acquisition missing pattern"


# =====================================================================
# 3. Upsert idempotency -- batch twice, no duplicates
# =====================================================================

class TestConnectorUpsertIdempotency:

    @pytest.mark.parametrize("connector_id", PULL_CONNECTOR_IDS_WITH_FIXTURES)
    def test_batch_upsert_idempotent(self, connector_id, db_session, test_org, test_scan):
        """Running the same batch twice should not create extra rows on second pass."""
        from models.models import Asset, Finding

        spec = _load_connector(connector_id)
        entity = spec["entity"]
        records = CONNECTOR_FIXTURES[connector_id]

        mapped_batch = []
        for idx, raw in enumerate(records):
            m = map_record(raw, spec["default_field_map"])["mapped"]
            m["source_system"] = connector_id
            if not m.get("source_id"):
                m["source_id"] = f"test-{connector_id}-{idx:03d}"
            mapped_batch.append(m)

        # First batch
        c1 = upsert_batch(db_session, entity, mapped_batch, spec["dedup_key"],
                           "test-integ", scan_id=test_scan.id)
        first_total = c1["inserted"] + c1["updated"] + c1["skipped"]
        assert first_total == len(records), (
            f"{connector_id}: first batch processed {first_total}/{len(records)}. "
            f"Errors: {c1['errors']}"
        )

        # Second batch -- same data, should insert 0 new rows
        c2 = upsert_batch(db_session, entity, mapped_batch, spec["dedup_key"],
                           "test-integ", scan_id=test_scan.id)
        assert c2["inserted"] == 0, (
            f"{connector_id}: second batch should insert 0, got {c2['inserted']}"
        )


# =====================================================================
# 4. Transform chain tests -- verify real connector transforms work
# =====================================================================

class TestFieldMapTransformChains:

    def test_cloudflare_extract_cloud_workload_gcp(self):
        """CNAME to *.run.app should produce GCP Cloud Run workload."""
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][1]  # app.example.com -> my-app.run.app
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        easm = mapped.get("easm_data", {}).get("cloudflare_dns", {})
        target = easm.get("target")
        assert target is not None
        assert target["provider"] == "gcp"
        assert target["service"] == "cloud_run"

    def test_cloudflare_extract_cloud_workload_aws(self):
        """CNAME to *.elb.amazonaws.com should produce AWS ALB workload."""
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][2]  # api.example.com -> ALB
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        easm = mapped.get("easm_data", {}).get("cloudflare_dns", {})
        target = easm.get("target")
        assert target is not None
        assert target["provider"] == "aws"
        assert target["service"] == "alb"

    def test_cloudflare_expression_asset_identity(self):
        """Expression transform produces asset_identity dict."""
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        ai = mapped.get("asset_identity")
        assert isinstance(ai, dict)
        assert ai["hostname"] == "www.example.com"
        assert ai["ip"] == "203.0.113.10"

    def test_cloudflare_expression_asset_attributes(self):
        """Expression transform produces asset_attributes dict."""
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        attrs = mapped.get("asset_attributes")
        assert isinstance(attrs, dict)
        assert attrs["dns_record_type"] == "A"
        assert attrs["cdn_provider"] == "cloudflare"

    def test_cloudflare_boolean_transform(self):
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][0]  # proxied=True
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        proxied = mapped.get("easm_data", {}).get("cloudflare_dns", {}).get("proxied")
        assert proxied is True

    def test_cloudflare_integer_transform(self):
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][1]  # ttl=300
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        ttl = mapped.get("easm_data", {}).get("cloudflare_dns", {}).get("ttl")
        assert ttl == 300

    def test_cloudflare_datetime_transform(self):
        spec = _load_connector("cloudflare_api")
        raw = CONNECTOR_FIXTURES["cloudflare_api"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        last_seen = mapped.get("last_seen")
        assert last_seen is not None
        assert "2026-03-15" in str(last_seen)

    def test_crowdstrike_expression_asset_attributes(self):
        spec = _load_connector("crowdstrike_assets")
        raw = CONNECTOR_FIXTURES["crowdstrike_assets"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        attrs = mapped.get("asset_attributes")
        assert isinstance(attrs, dict)
        assert attrs["platform_name"] == "Windows"
        assert attrs["system_manufacturer"] == "Dell Inc."
        assert attrs["tags"] == ["production", "finance"]

    def test_crowdstrike_expression_asset_identity(self):
        spec = _load_connector("crowdstrike_assets")
        raw = CONNECTOR_FIXTURES["crowdstrike_assets"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        ai = mapped.get("asset_identity")
        assert isinstance(ai, dict)
        assert ai["hostname"] == "WORKSTATION-01"
        assert ai["ip"] == "10.10.1.50"
        assert ai["device_id"] == "cs-dev-001"

    def test_nessus_severity_map_transform(self):
        """Nessus severity map: 4->'critical', 3->'high', 0->'info'."""
        spec = _load_connector("nessus_api")
        field_map = spec["default_field_map"]

        for raw, expected in [
            (CONNECTOR_FIXTURES["nessus_api"][0], "critical"),
            (CONNECTOR_FIXTURES["nessus_api"][1], "high"),
            (CONNECTOR_FIXTURES["nessus_api"][2], "info"),
        ]:
            mapped = map_record(raw, field_map)["mapped"]
            assert mapped["severity"] == expected

    def test_nessus_float_transform(self):
        spec = _load_connector("nessus_api")
        raw = CONNECTOR_FIXTURES["nessus_api"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        assert mapped["cvss_score"] == 9.8

    def test_nessus_boolean_transform(self):
        spec = _load_connector("nessus_api")
        m1 = map_record(CONNECTOR_FIXTURES["nessus_api"][0], spec["default_field_map"])["mapped"]
        m2 = map_record(CONNECTOR_FIXTURES["nessus_api"][1], spec["default_field_map"])["mapped"]
        assert m1["exploit_available"] is True
        assert m2["exploit_available"] is False

    def test_crowdstrike_findings_nested_paths(self):
        spec = _load_connector("crowdstrike_findings")
        raw = CONNECTOR_FIXTURES["crowdstrike_findings"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]

        assert mapped["cve_id"] == "CVE-2024-1234"
        assert mapped["cvss_score"] == 9.8
        assert mapped["exploit_available"] is True
        assert mapped["severity"] == "critical"
        assert mapped["asset"]["hostname"] == "web-server-03"
        assert mapped["asset"]["ip_address"] == "10.10.2.100"

    def test_nessus_array_index_path(self):
        spec = _load_connector("nessus_api")
        raw = CONNECTOR_FIXTURES["nessus_api"][0]
        mapped = map_record(raw, spec["default_field_map"])["mapped"]
        assert mapped["cve_id"] == "CVE-2023-43622"


# =====================================================================
# 5. Run engine E2E -- full execute() with mock transport
# =====================================================================

class TestRunEngineE2E:

    def _run_with_mock(self, db_session, integration, run, mock_transport):
        """Execute a run with the mock transport patched in."""
        from services import run_engine

        class _Factory:
            def __call__(self):
                return mock_transport

        original = run_engine.TRANSPORTS.copy()
        run_engine.TRANSPORTS["mock"] = _Factory()
        try:
            with patch("services.post_ingest.finalize_scan"):
                return asyncio.run(
                    run_engine.execute(db_session, integration.id, run_id=run.id)
                )
        finally:
            run_engine.TRANSPORTS.clear()
            run_engine.TRANSPORTS.update(original)

    def test_pull_execute_creates_assets(self, db_session, test_org, test_scan, integration_factory):
        """Full pull run: execute() -> fetch_all -> map -> upsert -> DB assets."""
        from models.models import Asset, IntegrationRun

        spec = _load_connector("cloudflare_api")
        records = CONNECTOR_FIXTURES["cloudflare_api"]

        integration, run = integration_factory(
            name="Cloudflare E2E", direction="pull", entity="asset",
            transport_type="mock", template_id="cloudflare_api",
            field_map=spec["default_field_map"], dedup_key=spec["dedup_key"],
        )

        self._run_with_mock(db_session, integration, run, MockTransport(records))

        db_session.expire_all()
        updated_run = db_session.query(IntegrationRun).filter(IntegrationRun.id == run.id).first()

        assert updated_run.status in ("success", "partial")
        assert updated_run.records_fetched == len(records)
        assert updated_run.records_inserted > 0

        assets = db_session.query(Asset).filter(Asset.source_system == "cloudflare_api").all()
        assert len(assets) > 0

    def test_pull_execute_creates_findings(self, db_session, test_org, test_scan, integration_factory):
        """Full pull run for finding connector."""
        from models.models import Finding, IntegrationRun

        spec = _load_connector("nessus_api")
        records = CONNECTOR_FIXTURES["nessus_api"]

        integration, run = integration_factory(
            name="Nessus E2E", direction="pull", entity="finding",
            transport_type="mock", template_id="nessus_api",
            field_map=spec["default_field_map"], dedup_key=spec["dedup_key"],
        )

        self._run_with_mock(db_session, integration, run, MockTransport(records))

        db_session.expire_all()
        updated_run = db_session.query(IntegrationRun).filter(IntegrationRun.id == run.id).first()

        assert updated_run.status in ("success", "partial")
        assert updated_run.records_fetched == len(records)
        assert updated_run.records_inserted > 0

    def test_push_execute_calls_transport(self, db_session, test_org, test_scan,
                                          test_assets, test_findings, integration_factory):
        """Full push run: loads findings -> renders template -> calls transport.push()."""
        from models.models import IntegrationRun

        integration, run = integration_factory(
            name="Slack E2E", direction="push", entity="action",
            transport_type="mock", template_id="slack_alert",
            transport_config={
                "body": {"text": "[{{finding.severity}}] {{finding.title}} on {{asset.hostname}}"}
            },
        )

        mock = MockTransport()
        self._run_with_mock(db_session, integration, run, mock)

        db_session.expire_all()
        updated_run = db_session.query(IntegrationRun).filter(IntegrationRun.id == run.id).first()

        assert updated_run.status == "success"
        assert len(mock.push_calls) > 0
        assert updated_run.records_inserted == len(mock.push_calls)

    def test_pull_run_dedup_on_rerun(self, db_session, test_org, test_scan, integration_factory):
        """Running the same pull integration twice should dedup, not double records."""
        from models.models import Asset

        spec = _load_connector("crowdstrike_assets")
        records = CONNECTOR_FIXTURES["crowdstrike_assets"]

        def _run_once():
            integration, run = integration_factory(
                name="CS E2E", direction="pull", entity="asset",
                transport_type="mock", template_id="crowdstrike_assets",
                field_map=spec["default_field_map"], dedup_key=spec["dedup_key"],
            )
            self._run_with_mock(db_session, integration, run, MockTransport(records))

        _run_once()
        count_first = db_session.query(Asset).filter(
            Asset.source_system == "crowdstrike_assets").count()

        _run_once()
        count_second = db_session.query(Asset).filter(
            Asset.source_system == "crowdstrike_assets").count()

        assert count_first == count_second, f"Dedup failed: {count_first} -> {count_second}"


# =====================================================================
# 6. Smoke test -- run all fixtures through entire pipeline
# =====================================================================

class TestAllFixturesEndToEnd:

    def test_every_fixture_maps_without_errors(self):
        """Smoke test: every fixture record maps cleanly through its connector."""
        failures = []
        for connector_id, records in CONNECTOR_FIXTURES.items():
            spec = _load_connector(connector_id)
            for i, raw in enumerate(records):
                result = map_record(raw, spec["default_field_map"])
                errors = [e for e in result["errors"] if e["level"] == "error"]
                if errors:
                    failures.append(f"{connector_id}[{i}]: {errors}")

        assert not failures, "Mapping errors:\n" + "\n".join(failures)

    def test_every_fixture_upserts_cleanly(self, db_session, test_org, test_scan):
        """Every fixture record can be upserted without exceptions."""
        for connector_id, records in CONNECTOR_FIXTURES.items():
            spec = _load_connector(connector_id)

            mapped_batch = []
            for idx, raw in enumerate(records):
                m = map_record(raw, spec["default_field_map"])["mapped"]
                m["source_system"] = connector_id
                if not m.get("source_id"):
                    m["source_id"] = f"smoke-{connector_id}-{idx:03d}"
                mapped_batch.append(m)

            result = upsert_batch(
                db_session, spec["entity"], mapped_batch, spec["dedup_key"],
                f"e2e-{connector_id}", scan_id=test_scan.id,
            )
            total = result["inserted"] + result["updated"] + result["skipped"]
            assert total == len(records), (
                f"{connector_id}: expected {len(records)} processed, got {total}. "
                f"Errors: {result['errors']}"
            )

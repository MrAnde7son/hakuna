"""Tests for cloud provider connector templates — validates JSON structure and field maps."""

import json
import os
import pytest
from pathlib import Path

CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

CLOUD_CONNECTORS = [
    "cloudflare_api",
    "aws_route53_api",
    "gcp_clouddns_api",
    "azure_dns_api",
    "godaddy_api",
]

REQUIRED_TOP_LEVEL_KEYS = [
    "id", "name", "description", "logo", "direction", "entity",
    "transport_type", "transport_config", "credential_acquisition",
    "default_field_map", "dedup_key", "params_schema",
]

ASSET_SCHEMA_FIELDS = {
    "source_id", "source_system", "hostname", "ip_address", "fqdn",
    "os", "os_version", "environment", "tags", "criticality", "last_seen",
}


def _load_connector(connector_id: str) -> dict:
    path = CONNECTORS_DIR / f"{connector_id}.json"
    assert path.exists(), f"Connector file not found: {path}"
    with open(path) as f:
        return json.load(f)


class TestCloudConnectorsLoadCorrectly:
    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_json_loads(self, connector_id):
        data = _load_connector(connector_id)
        assert isinstance(data, dict)
        assert data["id"] == connector_id

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_required_keys(self, connector_id):
        data = _load_connector(connector_id)
        for key in REQUIRED_TOP_LEVEL_KEYS:
            assert key in data, f"Missing required key '{key}' in {connector_id}"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_is_pull_asset(self, connector_id):
        data = _load_connector(connector_id)
        assert data["direction"] == "pull"
        assert data["entity"] == "asset"
        assert data["transport_type"] == "api"


class TestCloudConnectorsFieldMaps:
    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_field_map_has_source_id(self, connector_id):
        data = _load_connector(connector_id)
        targets = [rule["target"] for rule in data["default_field_map"]]
        assert "source_id" in targets, f"{connector_id} must map source_id"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_field_map_has_hostname(self, connector_id):
        data = _load_connector(connector_id)
        targets = [rule["target"] for rule in data["default_field_map"]]
        assert "hostname" in targets, f"{connector_id} must map hostname"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_field_map_has_easm_data(self, connector_id):
        data = _load_connector(connector_id)
        targets = [rule["target"] for rule in data["default_field_map"]]
        easm_targets = [t for t in targets if t.startswith("easm_data.")]
        assert len(easm_targets) > 0, f"{connector_id} must map at least one easm_data field"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_field_map_rules_have_source_and_target(self, connector_id):
        data = _load_connector(connector_id)
        for i, rule in enumerate(data["default_field_map"]):
            assert "source" in rule, f"Rule {i} in {connector_id} missing 'source'"
            assert "target" in rule, f"Rule {i} in {connector_id} missing 'target'"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_dedup_key_includes_source_system(self, connector_id):
        data = _load_connector(connector_id)
        assert "source_system" in data["dedup_key"]
        assert "source_id" in data["dedup_key"]


class TestCloudConnectorsAuth:
    def test_cloudflare_bearer_auth(self):
        data = _load_connector("cloudflare_api")
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "guided_generation"
        assert any(s.get("capture", {}).get("field") == "api_token" for s in acq["steps"])

    def test_aws_sigv4_auth(self):
        data = _load_connector("aws_route53_api")
        assert data["transport_config"]["auth_strategy"] == "aws_sigv4"
        acq = data["credential_acquisition"]
        fields = [s.get("capture", {}).get("field") for s in acq["steps"] if "capture" in s]
        assert "access_key_id" in fields
        assert "secret_access_key" in fields

    def test_gcp_service_account_auth(self):
        data = _load_connector("gcp_clouddns_api")
        assert data["transport_config"]["auth_strategy"] == "gcp_service_account"
        acq = data["credential_acquisition"]
        fields = [s.get("capture", {}).get("field") for s in acq["steps"] if "capture" in s]
        assert "service_account_email" in fields
        assert "private_key" in fields

    def test_azure_client_credentials(self):
        data = _load_connector("azure_dns_api")
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "client_credentials"
        assert "token_url" in acq
        field_names = [f["field"] for f in acq["fields"]]
        assert "client_id" in field_names
        assert "client_secret" in field_names

    def test_godaddy_api_key(self):
        data = _load_connector("godaddy_api")
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "guided_generation"
        fields = [s.get("capture", {}).get("field") for s in acq["steps"] if "capture" in s]
        assert "api_key" in fields
        assert "api_secret" in fields


class TestCloudConnectorsPagination:
    def test_cloudflare_page_pagination(self):
        data = _load_connector("cloudflare_api")
        pag = data["transport_config"]["pagination"]
        assert pag["strategy"] == "page"

    def test_aws_cursor_pagination(self):
        data = _load_connector("aws_route53_api")
        pag = data["transport_config"]["pagination"]
        assert pag["strategy"] == "cursor"

    def test_gcp_cursor_pagination(self):
        data = _load_connector("gcp_clouddns_api")
        pag = data["transport_config"]["pagination"]
        assert pag["strategy"] == "cursor"
        assert pag["cursor_field"] == "nextPageToken"

    def test_azure_cursor_pagination(self):
        data = _load_connector("azure_dns_api")
        pag = data["transport_config"]["pagination"]
        assert pag["strategy"] == "cursor"

    def test_godaddy_no_pagination(self):
        data = _load_connector("godaddy_api")
        pag = data["transport_config"]["pagination"]
        assert pag["strategy"] == "none"


class TestConnectorLoaderDiscovery:
    def test_loader_finds_cloud_connectors(self):
        from integrations.connector_loader import load_connectors, get_all_connectors, get_connector
        load_connectors()
        all_connectors = get_all_connectors()
        ids = [c["id"] for c in all_connectors]
        for cid in CLOUD_CONNECTORS:
            assert cid in ids, f"Connector loader did not discover {cid}"

    @pytest.mark.parametrize("connector_id", CLOUD_CONNECTORS)
    def test_loader_returns_full_detail(self, connector_id):
        from integrations.connector_loader import load_connectors, get_connector
        load_connectors()
        detail = get_connector(connector_id)
        assert detail is not None
        assert detail["id"] == connector_id
        assert "default_field_map" in detail

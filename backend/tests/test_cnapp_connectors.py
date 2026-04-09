"""Tests for CNAPP cloud workload & identity connector templates (AWS, Azure, GCP)."""

import json
import pytest
from pathlib import Path

CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

# CNAPP cloud workload connectors (compute, serverless, storage)
WORKLOAD_CONNECTORS = [
    "aws_ec2_instances",
    "aws_lambda_functions",
    "aws_s3_buckets",
    "azure_virtual_machines",
    "azure_storage_accounts",
    "azure_function_apps",
    "gcp_compute_instances",
    "gcp_storage_buckets",
    "gcp_cloud_functions",
]

# CNAPP cloud identity connectors (CIEM)
IDENTITY_CONNECTORS = [
    "aws_iam_users",
    "aws_iam_roles",
    "azure_role_assignments",
    "gcp_iam_service_accounts",
]

# CNAPP cloud entitlement connectors (permission sets / policies)
ENTITLEMENT_CONNECTORS = [
    "aws_iam_policies",
    "azure_role_definitions",
    "gcp_project_iam_bindings",
]

ALL_CNAPP_CONNECTORS = WORKLOAD_CONNECTORS + IDENTITY_CONNECTORS + ENTITLEMENT_CONNECTORS

REQUIRED_TOP_LEVEL_KEYS = [
    "id", "name", "description", "logo", "direction", "entity",
    "transport_type", "transport_config", "credential_acquisition",
    "default_field_map", "dedup_key", "params_schema",
]


def _load_connector(connector_id: str) -> dict:
    path = CONNECTORS_DIR / f"{connector_id}.json"
    assert path.exists(), f"Connector file not found: {path}"
    with open(path) as f:
        return json.load(f)


class TestCnappConnectorsStructure:
    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_json_loads(self, connector_id):
        data = _load_connector(connector_id)
        assert isinstance(data, dict)
        assert data["id"] == connector_id

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_required_keys(self, connector_id):
        data = _load_connector(connector_id)
        for key in REQUIRED_TOP_LEVEL_KEYS:
            assert key in data, f"Missing required key '{key}' in {connector_id}"

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_is_pull_asset_api(self, connector_id):
        data = _load_connector(connector_id)
        assert data["direction"] == "pull"
        assert data["entity"] == "asset"
        assert data["transport_type"] == "api"

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_category_is_cloud_security(self, connector_id):
        data = _load_connector(connector_id)
        assert data["category"] == "Cloud Security", (
            f"{connector_id} must be in 'Cloud Security' category"
        )

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_field_map_rules_are_valid(self, connector_id):
        data = _load_connector(connector_id)
        for i, rule in enumerate(data["default_field_map"]):
            assert "source" in rule, f"Rule {i} in {connector_id} missing 'source'"
            assert "target" in rule, f"Rule {i} in {connector_id} missing 'target'"

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_field_map_has_required_targets(self, connector_id):
        data = _load_connector(connector_id)
        targets = [rule["target"] for rule in data["default_field_map"]]
        # Every CNAPP connector must produce these core fields
        for required in ["source_id", "hostname", "asset_type", "asset_identity", "asset_attributes"]:
            assert required in targets, (
                f"{connector_id} field_map must include target '{required}'"
            )

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_dedup_key_valid(self, connector_id):
        data = _load_connector(connector_id)
        dk = data["dedup_key"]
        assert isinstance(dk, list) and len(dk) > 0
        assert "source_system" in dk
        assert "source_id" in dk


class TestCnappWorkloadConnectors:
    """Workload connectors emit asset_type='cloud_instance'."""

    @pytest.mark.parametrize("connector_id", WORKLOAD_CONNECTORS)
    def test_workload_emits_cloud_instance_type(self, connector_id):
        data = _load_connector(connector_id)
        rules = data["default_field_map"]
        type_rules = [r for r in rules if r["target"] == "asset_type"]
        assert type_rules, f"{connector_id} must set asset_type"
        # Each rule should resolve to 'cloud_instance' (via expression)
        for r in type_rules:
            transform = r.get("transform", {})
            expr = transform.get("expr", "")
            assert "cloud_instance" in expr, (
                f"{connector_id} asset_type rule must produce 'cloud_instance', got: {expr}"
            )


class TestCnappIdentityConnectors:
    """Identity connectors emit asset_type='identity'."""

    @pytest.mark.parametrize("connector_id", IDENTITY_CONNECTORS)
    def test_identity_emits_identity_type(self, connector_id):
        data = _load_connector(connector_id)
        rules = data["default_field_map"]
        type_rules = [r for r in rules if r["target"] == "asset_type"]
        assert type_rules, f"{connector_id} must set asset_type"
        for r in type_rules:
            expr = r.get("transform", {}).get("expr", "")
            assert "'identity'" in expr, (
                f"{connector_id} asset_type rule must produce 'identity', got: {expr}"
            )


class TestCnappEntitlementConnectors:
    """Entitlement connectors (CIEM permission sets) emit asset_type='cloud_entitlement'."""

    @pytest.mark.parametrize("connector_id", ENTITLEMENT_CONNECTORS)
    def test_entitlement_emits_cloud_entitlement_type(self, connector_id):
        data = _load_connector(connector_id)
        rules = data["default_field_map"]
        type_rules = [r for r in rules if r["target"] == "asset_type"]
        assert type_rules, f"{connector_id} must set asset_type"
        for r in type_rules:
            expr = r.get("transform", {}).get("expr", "")
            assert "'cloud_entitlement'" in expr, (
                f"{connector_id} asset_type must produce 'cloud_entitlement', got: {expr}"
            )

    @pytest.mark.parametrize("connector_id", ENTITLEMENT_CONNECTORS)
    def test_entitlement_attributes_declare_kind(self, connector_id):
        data = _load_connector(connector_id)
        attr_rules = [r for r in data["default_field_map"] if r["target"] == "asset_attributes"]
        assert attr_rules
        for r in attr_rules:
            expr = r.get("transform", {}).get("expr", "")
            assert "entitlement_kind" in expr, (
                f"{connector_id} asset_attributes must declare 'entitlement_kind'"
            )


class TestAwsCnappConnectorsAuth:
    """All AWS CNAPP connectors must use SigV4."""

    AWS_CONNECTORS = [
        "aws_ec2_instances", "aws_lambda_functions", "aws_s3_buckets",
        "aws_iam_users", "aws_iam_roles", "aws_iam_policies",
    ]

    @pytest.mark.parametrize("connector_id", AWS_CONNECTORS)
    def test_aws_uses_sigv4(self, connector_id):
        data = _load_connector(connector_id)
        tc = data["transport_config"]
        assert tc.get("auth_strategy") == "aws_sigv4"
        assert "aws_service" in tc, f"{connector_id} must declare aws_service"

    @pytest.mark.parametrize("connector_id", AWS_CONNECTORS)
    def test_aws_credential_fields(self, connector_id):
        data = _load_connector(connector_id)
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "guided_generation"
        captured = [s.get("capture", {}).get("field") for s in acq["steps"] if "capture" in s]
        assert "access_key_id" in captured
        assert "secret_access_key" in captured
        assert "region" in captured


class TestAzureCnappConnectorsAuth:
    """All Azure CNAPP connectors must use OAuth2 client_credentials."""

    AZURE_CONNECTORS = [
        "azure_virtual_machines", "azure_storage_accounts",
        "azure_role_assignments", "azure_function_apps",
        "azure_role_definitions",
    ]

    @pytest.mark.parametrize("connector_id", AZURE_CONNECTORS)
    def test_azure_client_credentials(self, connector_id):
        data = _load_connector(connector_id)
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "client_credentials"
        assert "token_url" in acq
        field_names = [f["field"] for f in acq["fields"]]
        for required in ("client_id", "client_secret", "tenant_id"):
            assert required in field_names, (
                f"{connector_id} missing credential field '{required}'"
            )

    @pytest.mark.parametrize("connector_id", AZURE_CONNECTORS)
    def test_azure_subscription_param(self, connector_id):
        data = _load_connector(connector_id)
        params = data["params_schema"]
        assert "subscription_id" in params, (
            f"{connector_id} must require subscription_id param"
        )


class TestGcpCnappConnectorsAuth:
    """All GCP CNAPP connectors must use service account auth."""

    GCP_CONNECTORS = [
        "gcp_compute_instances", "gcp_iam_service_accounts",
        "gcp_storage_buckets", "gcp_cloud_functions",
        "gcp_project_iam_bindings",
    ]

    @pytest.mark.parametrize("connector_id", GCP_CONNECTORS)
    def test_gcp_service_account_strategy(self, connector_id):
        data = _load_connector(connector_id)
        tc = data["transport_config"]
        assert tc.get("auth_strategy") == "gcp_service_account"
        assert "gcp_scopes" in tc, f"{connector_id} must declare gcp_scopes"
        assert isinstance(tc["gcp_scopes"], list) and len(tc["gcp_scopes"]) > 0

    @pytest.mark.parametrize("connector_id", GCP_CONNECTORS)
    def test_gcp_credential_fields(self, connector_id):
        data = _load_connector(connector_id)
        acq = data["credential_acquisition"]
        assert acq["pattern"] == "guided_generation"
        captured = [s.get("capture", {}).get("field") for s in acq["steps"] if "capture" in s]
        assert "service_account_email" in captured
        assert "private_key" in captured

    @pytest.mark.parametrize("connector_id", GCP_CONNECTORS)
    def test_gcp_project_param(self, connector_id):
        data = _load_connector(connector_id)
        assert "project_id" in data["params_schema"], (
            f"{connector_id} must require project_id param"
        )


class TestCnappConnectorsLoaderDiscovery:
    def test_loader_discovers_all_cnapp_connectors(self):
        from integrations.connector_loader import load_connectors, get_all_connectors
        load_connectors()
        result = get_all_connectors(page_size=500)
        ids = [c["id"] for c in result["items"]]
        for cid in ALL_CNAPP_CONNECTORS:
            assert cid in ids, f"Connector loader did not discover {cid}"

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_loader_returns_full_detail(self, connector_id):
        from integrations.connector_loader import load_connectors, get_connector
        load_connectors()
        detail = get_connector(connector_id)
        assert detail is not None
        assert detail["id"] == connector_id
        assert "default_field_map" in detail


class TestCnappAssetIdentityShape:
    """Verify identity payloads carry cloud_provider for downstream filtering."""

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_asset_identity_has_cloud_provider_marker(self, connector_id):
        data = _load_connector(connector_id)
        rules = data["default_field_map"]
        identity_rules = [r for r in rules if r["target"] == "asset_identity"]
        assert identity_rules
        # Should reference cloud_provider key in the expression
        for r in identity_rules:
            expr = r.get("transform", {}).get("expr", "")
            assert "cloud_provider" in expr, (
                f"{connector_id} asset_identity must include cloud_provider key"
            )

    @pytest.mark.parametrize("connector_id", ALL_CNAPP_CONNECTORS)
    def test_asset_attributes_has_resource_type(self, connector_id):
        data = _load_connector(connector_id)
        rules = data["default_field_map"]
        attr_rules = [r for r in rules if r["target"] == "asset_attributes"]
        assert attr_rules
        for r in attr_rules:
            expr = r.get("transform", {}).get("expr", "")
            assert "resource_type" in expr, (
                f"{connector_id} asset_attributes must include resource_type key"
            )

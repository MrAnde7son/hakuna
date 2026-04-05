"""Tests for construct_fqdn and extract_cloud_workload transform types."""

import pytest
from services.field_mapper import _apply_transform, _extract_cloud_workload


# ═══════════════════════════════════════════════════════════
# construct_fqdn
# ═══════════════════════════════════════════════════════════

class TestConstructFqdn:
    def _transform(self, value, record, zone_field="zone_name"):
        return _apply_transform(value, {"type": "construct_fqdn", "zone_field": zone_field}, record)

    def test_basic_fqdn(self):
        result, err = self._transform("www", {"zone_name": "example.com"})
        assert result == "www.example.com"
        assert err is None

    def test_subdomain(self):
        result, err = self._transform("api", {"zone_name": "example.com"})
        assert result == "api.example.com"
        assert err is None

    def test_apex_at_sign(self):
        result, err = self._transform("@", {"zone_name": "example.com"})
        assert result == "example.com"
        assert err is None

    def test_already_fqdn(self):
        result, err = self._transform("www.example.com", {"zone_name": "example.com"})
        assert result == "www.example.com"
        assert err is None

    def test_name_equals_zone(self):
        result, err = self._transform("example.com", {"zone_name": "example.com"})
        assert result == "example.com"
        assert err is None

    def test_custom_zone_field(self):
        result, err = self._transform("blog", {"_domain": "acme.io"}, zone_field="_domain")
        assert result == "blog.acme.io"
        assert err is None

    def test_missing_zone(self):
        result, err = self._transform("www", {})
        assert result == "www"  # Falls through, no zone to join
        assert err is None

    def test_none_value(self):
        result, err = self._transform(None, {"zone_name": "example.com"})
        assert result is None
        assert err is None

    def test_deep_subdomain(self):
        result, err = self._transform("a.b.c", {"zone_name": "example.com"})
        assert result == "a.b.c.example.com"
        assert err is None


# ═══════════════════════════════════════════════════════════
# extract_cloud_workload
# ═══════════════════════════════════════════════════════════

class TestExtractCloudWorkload:
    # ── AWS ──
    def test_aws_alb(self):
        result = _extract_cloud_workload("dualstack.my-alb-123.us-east-1.elb.amazonaws.com")
        assert result is not None
        assert result["provider"] == "aws"
        assert result["service"] == "alb"

    def test_aws_alb_with_region(self):
        result = _extract_cloud_workload("my-alb.us-west-2.elb.amazonaws.com")
        assert result["provider"] == "aws"
        assert result["service"] == "alb"
        assert result["region"] == "us-west-2"

    def test_aws_cloudfront(self):
        result = _extract_cloud_workload("d1234abcdef.cloudfront.net")
        assert result["provider"] == "aws"
        assert result["service"] == "cloudfront"
        assert result["dist_id"] == "d1234abcdef"

    def test_aws_s3_website(self):
        result = _extract_cloud_workload("s3-website-us-east-1.amazonaws.com")
        assert result["provider"] == "aws"
        assert result["service"] == "s3"
        assert result["region"] == "us-east-1"

    def test_aws_s3_bucket(self):
        result = _extract_cloud_workload("my-bucket.s3.amazonaws.com")
        assert result["provider"] == "aws"
        assert result["service"] == "s3"
        assert result["bucket"] == "my-bucket"

    def test_aws_api_gateway(self):
        result = _extract_cloud_workload("abc123.execute-api.eu-west-1.amazonaws.com")
        assert result["provider"] == "aws"
        assert result["service"] == "api_gateway"
        assert result["api_id"] == "abc123"
        assert result["region"] == "eu-west-1"

    def test_aws_lambda_url(self):
        result = _extract_cloud_workload("abc123def.lambda-url.us-east-1.on.aws")
        assert result["provider"] == "aws"
        assert result["service"] == "lambda"
        assert result["region"] == "us-east-1"

    # ── GCP ──
    def test_gcp_cloud_run(self):
        result = _extract_cloud_workload("my-service-abc123-uc.run.app")
        assert result["provider"] == "gcp"
        assert result["service"] == "cloud_run"

    def test_gcp_app_engine(self):
        result = _extract_cloud_workload("my-project.appspot.com")
        assert result["provider"] == "gcp"
        assert result["service"] == "app_engine"
        assert result["app"] == "my-project"

    def test_gcp_cloud_functions(self):
        result = _extract_cloud_workload("us-central1-my-project.cloudfunctions.net")
        assert result["provider"] == "gcp"
        assert result["service"] == "cloud_functions"

    def test_gcp_firebase_hosting(self):
        result = _extract_cloud_workload("my-app.web.app")
        assert result["provider"] == "gcp"
        assert result["service"] == "firebase_hosting"

    # ── Azure ──
    def test_azure_app_service(self):
        result = _extract_cloud_workload("my-app.azurewebsites.net")
        assert result["provider"] == "azure"
        assert result["service"] == "app_service"
        assert result["app"] == "my-app"

    def test_azure_traffic_manager(self):
        result = _extract_cloud_workload("my-profile.trafficmanager.net")
        assert result["provider"] == "azure"
        assert result["service"] == "traffic_manager"
        assert result["profile"] == "my-profile"

    def test_azure_front_door(self):
        result = _extract_cloud_workload("my-fd.azurefd.net")
        assert result["provider"] == "azure"
        assert result["service"] == "front_door"
        assert result["name"] == "my-fd"

    def test_azure_api_management(self):
        result = _extract_cloud_workload("my-apim.azure-api.net")
        assert result["provider"] == "azure"
        assert result["service"] == "api_management"
        assert result["name"] == "my-apim"

    def test_azure_blob_storage(self):
        result = _extract_cloud_workload("myaccount.blob.core.windows.net")
        assert result["provider"] == "azure"
        assert result["service"] == "blob_storage"
        assert result["account"] == "myaccount"

    def test_azure_cdn(self):
        result = _extract_cloud_workload("my-endpoint.azureedge.net")
        assert result["provider"] == "azure"
        assert result["service"] == "cdn"

    def test_azure_sql(self):
        result = _extract_cloud_workload("myserver.database.windows.net")
        assert result["provider"] == "azure"
        assert result["service"] == "sql_database"
        assert result["server"] == "myserver"

    # ── Edge cases ──
    def test_trailing_dot(self):
        result = _extract_cloud_workload("my-app.azurewebsites.net.")
        assert result is not None
        assert result["provider"] == "azure"

    def test_none_input(self):
        assert _extract_cloud_workload(None) is None

    def test_empty_string(self):
        assert _extract_cloud_workload("") is None

    def test_regular_domain(self):
        assert _extract_cloud_workload("www.example.com") is None

    def test_ip_address(self):
        assert _extract_cloud_workload("192.168.1.1") is None

    def test_non_string_input(self):
        assert _extract_cloud_workload(12345) is None

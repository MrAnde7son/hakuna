"""Tests for AWS SigV4 auth injection in ApiTransport."""

import pytest


class TestAwsSigv4Injection:
    def test_sigv4_produces_authorization_header(self):
        """Verify _inject_aws_sigv4 adds Authorization and X-Amz-Date headers."""
        try:
            from services.transports.api_transport import _inject_aws_sigv4
        except ImportError:
            pytest.skip("requests-aws4auth not installed")

        headers = {"Content-Type": "application/json"}
        credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        config = {
            "aws_service": "route53",
            "params": {"region": "us-east-1"},
        }

        _inject_aws_sigv4(
            headers, credentials, config,
            method="GET",
            url="https://route53.amazonaws.com/2013-04-01/hostedzone",
        )

        assert "Authorization" in headers
        assert "AWS4-HMAC-SHA256" in headers["Authorization"]
        assert "x-amz-date" in headers or "X-Amz-Date" in headers

    def test_sigv4_uses_region_from_params(self):
        """Region should come from credentials first, then params."""
        try:
            from services.transports.api_transport import _inject_aws_sigv4
        except ImportError:
            pytest.skip("requests-aws4auth not installed")

        headers = {}
        credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }
        config = {
            "aws_service": "route53",
            "params": {"region": "eu-west-1"},
        }

        _inject_aws_sigv4(headers, credentials, config, "GET", "https://route53.amazonaws.com/test")

        # The signed header should be present (region is embedded in credential scope)
        auth_header = headers.get("Authorization", "")
        assert "eu-west-1" in auth_header

    def test_sigv4_with_body(self):
        """SigV4 should handle POST requests with body."""
        try:
            from services.transports.api_transport import _inject_aws_sigv4
        except ImportError:
            pytest.skip("requests-aws4auth not installed")

        headers = {"Content-Type": "application/json"}
        credentials = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
        }
        config = {"aws_service": "route53", "params": {}}

        _inject_aws_sigv4(
            headers, credentials, config,
            method="POST",
            url="https://route53.amazonaws.com/test",
            body={"key": "value"},
        )

        assert "Authorization" in headers

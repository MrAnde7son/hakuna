"""Tests for GCP service account auth injection in ApiTransport."""

import sys
import pytest
from unittest.mock import patch, MagicMock


def _mock_google_modules():
    """Pre-mock google.oauth2.service_account and google.auth.transport.requests
    to avoid importing cryptography (which may be broken in some environments)."""
    mock_sa = MagicMock()
    mock_transport = MagicMock()

    modules = {
        "google.oauth2.service_account": mock_sa,
        "google.auth.transport.requests": mock_transport,
        "google.auth.crypt": MagicMock(),
        "google.auth.crypt.es": MagicMock(),
        "google.auth._service_account_info": MagicMock(),
    }
    return mock_sa, mock_transport, modules


class TestGcpServiceAccountInjection:
    def test_injects_bearer_token(self):
        """Verify _inject_gcp_service_account adds a Bearer token to headers."""
        mock_sa, mock_transport, modules = _mock_google_modules()

        mock_creds = MagicMock()
        mock_creds.token = "ya29.mock-access-token-12345"
        mock_sa.Credentials.from_service_account_info.return_value = mock_creds

        with patch.dict(sys.modules, modules):
            from services.transports.api_transport import _inject_gcp_service_account

            headers = {}
            credentials = {
                "service_account_email": "test@project.iam.gserviceaccount.com",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            }
            config = {
                "gcp_scopes": ["https://www.googleapis.com/auth/ndev.clouddns.readonly"],
            }

            _inject_gcp_service_account(headers, credentials, config)

            assert headers["Authorization"] == "Bearer ya29.mock-access-token-12345"

    def test_uses_correct_scopes(self):
        """Verify the correct scopes are passed to credentials."""
        mock_sa, mock_transport, modules = _mock_google_modules()

        mock_creds = MagicMock()
        mock_creds.token = "ya29.test"
        mock_sa.Credentials.from_service_account_info.return_value = mock_creds

        with patch.dict(sys.modules, modules):
            from services.transports.api_transport import _inject_gcp_service_account

            headers = {}
            credentials = {
                "service_account_email": "test@project.iam.gserviceaccount.com",
                "private_key": "fake-key",
            }
            config = {
                "gcp_scopes": ["https://www.googleapis.com/auth/ndev.clouddns.readonly"],
            }

            _inject_gcp_service_account(headers, credentials, config)

            call_args = mock_sa.Credentials.from_service_account_info.call_args
            info = call_args[0][0]
            assert info["client_email"] == "test@project.iam.gserviceaccount.com"
            assert info["type"] == "service_account"
            assert call_args[1]["scopes"] == ["https://www.googleapis.com/auth/ndev.clouddns.readonly"]

    def test_default_scopes_when_none_provided(self):
        """When no gcp_scopes in config, use cloud-platform scope."""
        mock_sa, mock_transport, modules = _mock_google_modules()

        mock_creds = MagicMock()
        mock_creds.token = "ya29.test"
        mock_sa.Credentials.from_service_account_info.return_value = mock_creds

        with patch.dict(sys.modules, modules):
            from services.transports.api_transport import _inject_gcp_service_account

            headers = {}
            credentials = {
                "service_account_email": "test@project.iam.gserviceaccount.com",
                "private_key": "fake-key",
            }
            config = {}  # no gcp_scopes

            _inject_gcp_service_account(headers, credentials, config)

            call_args = mock_sa.Credentials.from_service_account_info.call_args
            assert call_args[1]["scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]

    def test_refresh_is_called(self):
        """Verify that credentials.refresh() is called to obtain a token."""
        mock_sa, mock_transport, modules = _mock_google_modules()

        mock_creds = MagicMock()
        mock_creds.token = "ya29.test"
        mock_sa.Credentials.from_service_account_info.return_value = mock_creds

        with patch.dict(sys.modules, modules):
            from services.transports.api_transport import _inject_gcp_service_account

            headers = {}
            credentials = {
                "service_account_email": "test@project.iam.gserviceaccount.com",
                "private_key": "fake-key",
            }
            config = {}

            _inject_gcp_service_account(headers, credentials, config)

            mock_creds.refresh.assert_called_once()

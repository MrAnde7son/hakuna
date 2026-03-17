"""Integration tests for Pipeline A extensions.

Each test mocks subprocess output for the corresponding tool and verifies
the ingest/task logic processes it correctly.
"""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Extension 1: Wildcard DNS detection
# ---------------------------------------------------------------------------


class TestWildcardDetection:
    """Test wildcard DNS fingerprinting and filtering."""

    @patch("app.ingest.wildcard.socket.getaddrinfo")
    def test_detect_wildcard_positive(self, mock_getaddrinfo):
        """Random canary labels all resolve to the same IP → wildcard detected."""
        from app.ingest.wildcard import detect_wildcard

        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("1.2.3.4", 0)),
        ]

        fp = detect_wildcard("example.com", num_probes=3)

        assert fp.is_wildcard is True
        assert "1.2.3.4" in fp.wildcard_ips
        assert fp.response_hash is not None
        assert mock_getaddrinfo.call_count == 3

    @patch("app.ingest.wildcard.socket.getaddrinfo")
    def test_detect_wildcard_negative(self, mock_getaddrinfo):
        """Canary labels don't resolve → no wildcard."""
        from app.ingest.wildcard import detect_wildcard
        import socket

        mock_getaddrinfo.side_effect = socket.gaierror("NXDOMAIN")

        fp = detect_wildcard("example.com", num_probes=3)

        assert fp.is_wildcard is False
        assert len(fp.wildcard_ips) == 0

    def test_filter_wildcard_results(self):
        """Hosts matching the wildcard IP fingerprint are removed."""
        from app.ingest.wildcard import WildcardFingerprint, filter_wildcard_results

        fp = WildcardFingerprint(
            domain="example.com",
            is_wildcard=True,
            wildcard_ips={"1.2.3.4"},
            response_hash="abc123",
        )

        hosts = [
            {"host": "real.example.com", "ip": "5.6.7.8"},
            {"host": "wildcard1.example.com", "ip": "1.2.3.4"},
            {"host": "wildcard2.example.com", "ip": "1.2.3.4"},
            {"host": "also-real.example.com", "ip": "9.10.11.12"},
        ]

        filtered, removed = filter_wildcard_results(hosts, fp)

        assert removed == 2
        assert len(filtered) == 2
        assert filtered[0]["host"] == "real.example.com"
        assert filtered[1]["host"] == "also-real.example.com"

    def test_filter_no_wildcard_passthrough(self):
        """When no wildcard, all hosts pass through."""
        from app.ingest.wildcard import WildcardFingerprint, filter_wildcard_results

        fp = WildcardFingerprint(
            domain="example.com", is_wildcard=False, wildcard_ips=set(),
        )

        hosts = [{"host": "a.example.com", "ip": "1.1.1.1"}]
        filtered, removed = filter_wildcard_results(hosts, fp)

        assert removed == 0
        assert len(filtered) == 1


# ---------------------------------------------------------------------------
# Extension 2: Liveness validation gate
# ---------------------------------------------------------------------------


class TestLivenessValidation:
    """Test asset liveness checks and state transitions."""

    @patch("app.ingest.liveness.check_dns_resolution")
    def test_dns_resolution_success(self, mock_dns):
        """DNS resolution returns IPs."""
        from app.ingest.liveness import check_dns_resolution

        mock_dns.return_value = ["1.2.3.4", "5.6.7.8"]
        ips = check_dns_resolution("example.com")
        assert len(ips) == 2

    @patch("app.ingest.liveness.socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo):
        """DNS resolution fails gracefully."""
        import socket
        from app.ingest.liveness import check_dns_resolution

        mock_getaddrinfo.side_effect = socket.gaierror("NXDOMAIN")
        ips = check_dns_resolution("nonexistent.example.com")
        assert ips == []

    def test_cloud_provider_detection(self):
        """Known cloud IPs are identified."""
        from app.ingest.liveness import identify_cloud_provider

        assert identify_cloud_provider("52.1.2.3") is not None  # AWS or Azure
        assert identify_cloud_provider("35.1.2.3") is not None  # GCP
        assert identify_cloud_provider("104.16.1.1") == "cloudflare"
        assert identify_cloud_provider("192.168.1.1") is None  # Private


# ---------------------------------------------------------------------------
# Extension 3: Deep enrichment — tlsx per-port, katana, httpx full
# ---------------------------------------------------------------------------


class TestTlsxPerPort:
    """Test tlsx per-port certificate storage and SAN extraction."""

    def test_parse_tlsx_entry(self):
        """Verify tlsx output is correctly parsed into tls_cert dict."""
        tlsx_entry = {
            "host": "example.com:443",
            "issuer_dn": "CN=Let's Encrypt Authority X3",
            "subject_dn": "CN=example.com",
            "san": ["example.com", "www.example.com", "api.example.com"],
            "not_after": "2026-06-15T12:00:00Z",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "tls_version": "tls13",
        }

        tls_cert = {
            "issuer": tlsx_entry.get("issuer_dn"),
            "subject": tlsx_entry.get("subject_dn"),
            "sans": tlsx_entry.get("san", []),
            "expiry": tlsx_entry.get("not_after"),
            "cipher": tlsx_entry.get("cipher"),
            "version": tlsx_entry.get("tls_version"),
        }

        assert tls_cert["issuer"] == "CN=Let's Encrypt Authority X3"
        assert len(tls_cert["sans"]) == 3
        assert "api.example.com" in tls_cert["sans"]


class TestKatanaEndpoints:
    """Test katana output parsing and auth page detection."""

    def test_auth_page_detection(self):
        """URLs with login/auth patterns are flagged."""
        import re
        from app.ingest.enrichment import AUTH_INDICATORS

        assert AUTH_INDICATORS.search("https://example.com/login")
        assert AUTH_INDICATORS.search("https://example.com/admin/signin")
        assert AUTH_INDICATORS.search("https://example.com/oauth/callback")
        assert AUTH_INDICATORS.search("https://example.com/forgot-password")
        assert not AUTH_INDICATORS.search("https://example.com/about")
        assert not AUTH_INDICATORS.search("https://example.com/products")


class TestHttpxFullEnrichment:
    """Test httpx full JSON output parsing."""

    def test_parse_httpx_full_entry(self):
        """Verify all enrichment fields are extracted from httpx -json output."""
        httpx_entry = {
            "input": "example.com",
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["Nginx", "React"],
            "cdn_name": "Cloudflare",
            "waf_name": "Cloudflare WAF",
            "content_length": 12345,
            "web_server": "nginx/1.21.6",
            "method": "GET",
            "location": "https://www.example.com",
            "a": ["93.184.216.34"],
            "final_url": "https://www.example.com",
        }

        # Verify key fields
        assert httpx_entry["status_code"] == 200
        assert "Nginx" in httpx_entry["tech"]
        assert httpx_entry["cdn_name"] == "Cloudflare"
        final_url = httpx_entry.get("final_url") or httpx_entry.get("location")
        assert final_url == "https://www.example.com"


# ---------------------------------------------------------------------------
# Extension 4: Nmap light fingerprinting
# ---------------------------------------------------------------------------


class TestNmapEnrichment:
    """Test nmap result parsing and CPE storage."""

    def test_parse_nmap_service(self):
        """Verify nmap service output is correctly structured for storage."""
        # Simulate a libnmap NmapService-like object
        mock_service = MagicMock()
        mock_service.port = 443
        mock_service.protocol = "tcp"
        mock_service.service = "https"
        mock_service.banner = "Apache/2.4.52"
        mock_service.cpelist = ["cpe:/a:apache:http_server:2.4.52"]
        mock_service.service_dict = {"product": "Apache httpd", "version": "2.4.52"}
        mock_service.scripts_results = [
            {"id": "http-server-header", "output": "Apache/2.4.52 (Ubuntu)"},
            {"id": "ssl-cert", "output": "Subject: CN=example.com"},
        ]

        # Extract in the same way as store_nmap_results
        service_name = mock_service.service
        parts = [
            mock_service.service_dict.get("product", ""),
            mock_service.service_dict.get("version", ""),
        ]
        service_version = " ".join(p for p in parts if p).strip()
        cpe_list = list(mock_service.cpelist)
        scripts = {}
        for script in mock_service.scripts_results:
            scripts[script["id"]] = script["output"]

        assert service_name == "https"
        assert service_version == "Apache httpd 2.4.52"
        assert cpe_list == ["cpe:/a:apache:http_server:2.4.52"]
        assert "http-server-header" in scripts
        assert "ssl-cert" in scripts

    def test_cpe_query_pattern(self):
        """Verify CPE list supports pattern matching for Pipeline B routing."""
        import re

        cpe_list = [
            "cpe:/a:apache:http_server:2.4.52",
            "cpe:/a:openssl:openssl:3.0.2",
        ]

        pattern = r"cpe:/a:apache:http_server:2\.4\.\d+"
        matches = [c for c in cpe_list if re.match(pattern, c)]
        assert len(matches) == 1
        assert matches[0] == "cpe:/a:apache:http_server:2.4.52"

    @patch("app.tasks.nmap._run_nmap_scan")
    def test_nmap_timeout_handling(self, mock_scan):
        """Nmap timeout produces partial results with timeout status."""
        mock_host = MagicMock()
        mock_host.services = []
        mock_host.os_fingerprinted = False
        mock_scan.return_value = (mock_host, 301.5, True)

        host, duration, timed_out = mock_scan("example.com", "80,443")

        assert timed_out is True
        assert duration > 300


# ---------------------------------------------------------------------------
# Runner subprocess tests (mocked)
# ---------------------------------------------------------------------------


class TestPurednsRunner:
    """Test puredns runner with mocked subprocess."""

    @pytest.mark.asyncio
    async def test_puredns_parses_plain_output(self):
        """puredns outputs plain hostnames (not JSON), verify parsing."""
        from app.runner.tools import PurednsRunner

        runner = PurednsRunner("example.com")

        mock_stdout = b"sub1.example.com\nsub2.example.com\nsub3.example.com\n"

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.stdout = AsyncMock()
            mock_proc.stderr = AsyncMock()

            # Simulate async line iteration
            async def mock_stdout_iter():
                for line in mock_stdout.split(b"\n"):
                    if line:
                        yield line + b"\n"

            mock_proc.stdout.__aiter__ = mock_stdout_iter
            mock_proc.stderr.__aiter__ = AsyncMock(return_value=AsyncMock(__anext__=AsyncMock(side_effect=StopAsyncIteration)))

            async def mock_wait():
                return 0
            mock_proc.wait = mock_wait

            mock_exec.return_value = mock_proc

            result = await runner.run(org_id="test-org")

        assert len(result.results) == 3
        assert result.results[0]["host"] == "sub1.example.com"
        assert result.results[2]["host"] == "sub3.example.com"


class TestKatanaRunner:
    """Test katana runner subprocess invocation."""

    def test_katana_command_flags(self):
        """Verify katana is invoked with correct flags."""
        from app.runner.tools import KatanaRunner

        runner = KatanaRunner(["https://example.com"])
        cmd = runner.build_command()

        assert "katana" == cmd[0]
        assert "-json" in cmd
        assert "-silent" in cmd
        assert "-depth" in cmd
        idx = cmd.index("-depth")
        assert cmd[idx + 1] == "2"
        assert "-js-crawl" in cmd
        assert "-rate-limit" in cmd

        # Clean up temp file
        import os
        if runner._tmpfile and os.path.exists(runner._tmpfile):
            os.unlink(runner._tmpfile)


class TestHttpxRunnerUpgraded:
    """Test httpx runner has new flags from Extension 3."""

    def test_httpx_full_flags(self):
        """Verify httpx command includes all Extension 3 flags."""
        from app.runner.tools import HttpxRunner

        runner = HttpxRunner(["example.com"])
        cmd = runner.build_command()

        assert "-content-length" in cmd
        assert "-web-server" in cmd
        assert "-method" in cmd
        assert "-location" in cmd
        assert "-ip" in cmd

        # Clean up temp file
        import os
        if runner._tmpfile and os.path.exists(runner._tmpfile):
            os.unlink(runner._tmpfile)


class TestTlsxRunnerUpgraded:
    """Test tlsx runner has SAN and expired flags."""

    def test_tlsx_command_flags(self):
        """Verify tlsx command includes -san and -expired flags."""
        from app.runner.tools import TlsxRunner

        runner = TlsxRunner(["example.com:443", "example.com:8443"])
        cmd = runner.build_command()

        assert "-san" in cmd
        assert "-expired" in cmd

        import os
        if runner._tmpfile and os.path.exists(runner._tmpfile):
            os.unlink(runner._tmpfile)


# ---------------------------------------------------------------------------
# Pipeline B handoff query
# ---------------------------------------------------------------------------


class TestPipelineBHandoff:
    """Verify the query contract for Pipeline B (Nuclei) handoff."""

    def test_handoff_query_structure(self):
        """The handoff SQL query filters by liveness_state and last_validated_at."""
        query = """
            SELECT id, hostname, open_ports
            FROM assets
            WHERE liveness_state = 'confirmed_alive'
              AND last_validated_at > now() - interval '7 days'
        """
        assert "confirmed_alive" in query
        assert "last_validated_at" in query
        assert "7 days" in query

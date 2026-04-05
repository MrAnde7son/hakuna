"""Shared fixtures for integration-builder E2E tests.

Provides:
- connector_fixture_data — realistic sample API responses keyed by connector_id
- mock_transport_factory — creates MockTransport instances from fixture data
- integration_factory — creates Integration + IntegrationRun DB records for testing
"""

import uuid
from datetime import datetime
from typing import AsyncIterator, List

import pytest

from services.transports.base import BaseTransport, ConnectResult, PushResult


# ── CONNECTOR_FIXTURES ──────────────────────────────────────────────
# Map of connector_id -> list of realistic raw API response records.
# Field names match each connector's default_field_map[].source paths.

CONNECTOR_FIXTURES = {
    "cloudflare_api": [
        {
            "id": "cf-rec-001",
            "zone_id": "zone-abc123",
            "zone_name": "example.com",
            "name": "www.example.com",
            "type": "A",
            "content": "203.0.113.10",
            "proxied": True,
            "ttl": 1,
            "modified_on": "2026-03-15T10:30:00Z",
        },
        {
            "id": "cf-rec-002",
            "zone_id": "zone-abc123",
            "zone_name": "example.com",
            "name": "app.example.com",
            "type": "CNAME",
            "content": "my-app.run.app",
            "proxied": False,
            "ttl": 300,
            "modified_on": "2026-03-20T08:00:00Z",
        },
        {
            "id": "cf-rec-003",
            "zone_id": "zone-abc123",
            "zone_name": "example.com",
            "name": "api.example.com",
            "type": "CNAME",
            "content": "api-lb-123456.us-east-1.elb.amazonaws.com",
            "proxied": True,
            "ttl": 1,
            "modified_on": "2026-03-22T14:15:00Z",
        },
    ],
    "crowdstrike_assets": [
        {
            "device_id": "cs-dev-001",
            "hostname": "WORKSTATION-01",
            "local_ip": "10.10.1.50",
            "external_ip": "198.51.100.5",
            "os_product_name": "Windows 11 Enterprise",
            "os_version": "23H2",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "platform_name": "Windows",
            "product_type_desc": "Workstation",
            "agent_version": "7.10.16303.0",
            "status": "normal",
            "system_manufacturer": "Dell Inc.",
            "system_product_name": "Latitude 5540",
            "serial_number": "SN12345",
            "bios_version": "1.20.0",
            "kernel_version": "",
            "os_build": "22631",
            "site_name": "US-East",
            "tags": ["production", "finance"],
            "last_seen": "2026-04-01T12:00:00Z",
            "groups": ["group-001"],
            "device_policies": {
                "prevention": {"policy_id": "pol-prev-001"},
            },
        },
        {
            "device_id": "cs-dev-002",
            "hostname": "web-server-03",
            "local_ip": "10.10.2.100",
            "external_ip": "198.51.100.10",
            "os_product_name": "Ubuntu 22.04 LTS",
            "os_version": "22.04",
            "mac_address": "AA:BB:CC:DD:EE:02",
            "platform_name": "Linux",
            "product_type_desc": "Server",
            "agent_version": "7.10.16303.0",
            "status": "normal",
            "system_manufacturer": "VMware, Inc.",
            "system_product_name": "VMware Virtual Platform",
            "serial_number": "VMW-SN-002",
            "bios_version": "6.00",
            "kernel_version": "5.15.0-91-generic",
            "os_build": "",
            "site_name": "US-East",
            "tags": ["production", "web"],
            "last_seen": "2026-04-02T08:30:00Z",
            "groups": [],
            "device_policies": {},
        },
    ],
    "crowdstrike_findings": [
        {
            "id": "cs-vuln-001",
            "cve": {
                "id": "CVE-2024-1234",
                "description": "Remote code execution in OpenSSL",
                "base_score": 9.8,
                "exploit_status": "available",
            },
            "host_info": {
                "hostname": "web-server-03",
                "local_ip": "10.10.2.100",
                "os_version": "Ubuntu 22.04",
            },
            "status": "critical",
            "remediation": {"action": "Upgrade OpenSSL to version 3.1.5 or later"},
            "created_timestamp": "2026-03-01T09:00:00Z",
            "updated_timestamp": "2026-04-01T09:00:00Z",
        },
        {
            "id": "cs-vuln-002",
            "cve": {
                "id": "CVE-2024-5678",
                "description": "Privilege escalation in Linux kernel",
                "base_score": 7.8,
                "exploit_status": "unproven",
            },
            "host_info": {
                "hostname": "web-server-03",
                "local_ip": "10.10.2.100",
                "os_version": "Ubuntu 22.04",
            },
            "status": "high",
            "remediation": {"action": "Update kernel to 5.15.0-92 or later"},
            "created_timestamp": "2026-03-10T14:00:00Z",
            "updated_timestamp": "2026-03-28T14:00:00Z",
        },
    ],
    "nessus_api": [
        {
            "plugin_id": "97993",
            "plugin_name": "Apache HTTP Server < 2.4.58 Multiple Vulnerabilities",
            "host_name": "webhost-01",
            "host_ip": "10.0.5.20",
            "severity": 4,
            "cvss3_base_score": "9.8",
            "cve": ["CVE-2023-43622"],
            "exploit_available": "true",
            "solution": "Upgrade to Apache HTTP Server 2.4.58 or later.",
            "synopsis": "The remote web server is affected by multiple vulnerabilities.",
            "first_found": "2026-01-15T00:00:00Z",
            "last_found": "2026-04-01T12:00:00Z",
        },
        {
            "plugin_id": "156032",
            "plugin_name": "OpenSSH < 9.6 Multiple Vulnerabilities",
            "host_name": "bastion-01",
            "host_ip": "10.0.5.25",
            "severity": 3,
            "cvss3_base_score": "7.5",
            "cve": ["CVE-2023-48795"],
            "exploit_available": "false",
            "solution": "Upgrade to OpenSSH 9.6 or later.",
            "synopsis": "The SSH server running on the remote host is affected.",
            "first_found": "2026-02-01T00:00:00Z",
            "last_found": "2026-03-30T08:00:00Z",
        },
        {
            "plugin_id": "10287",
            "plugin_name": "Traceroute Information",
            "host_name": "webhost-01",
            "host_ip": "10.0.5.20",
            "severity": 0,
            "cvss3_base_score": "",
            "cve": [],
            "exploit_available": "false",
            "solution": "N/A",
            "synopsis": "It was possible to obtain traceroute information.",
            "first_found": "2026-01-15T00:00:00Z",
            "last_found": "2026-04-01T12:00:00Z",
        },
    ],
    "aws_route53_api": [
        {
            "Name": "api.mycompany.io.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "52.23.180.100"}],
            "HealthCheckId": "hc-abc123",
            "_hosted_zone_id": "Z1D633PJN98FT9",
        },
        {
            "Name": "cdn.mycompany.io.",
            "Type": "CNAME",
            "TTL": 60,
            "ResourceRecords": [{"Value": "d111111abcdef8.cloudfront.net"}],
            "_hosted_zone_id": "Z1D633PJN98FT9",
        },
        {
            "Name": "app.mycompany.io.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": "my-alb-123456.us-east-1.elb.amazonaws.com",
                "HostedZoneId": "Z35SXDOTRQ7X7K",
            },
            "_hosted_zone_id": "Z1D633PJN98FT9",
        },
    ],
    "gcp_clouddns_api": [
        {
            "name": "web.example.dev.",
            "type": "A",
            "ttl": 300,
            "rrdatas": ["34.120.0.10"],
            "_project_id": "my-gcp-project",
            "_zone": "example-dev-zone",
        },
        {
            "name": "svc.example.dev.",
            "type": "CNAME",
            "ttl": 300,
            "rrdatas": ["my-service.run.app."],
            "_project_id": "my-gcp-project",
            "_zone": "example-dev-zone",
        },
    ],

    # ── Wiz ──────────────────────────────────────────────────────
    "wiz_issues": [
        {
            "id": "wiz-issue-001",
            "sourceRule": {"name": "VM exposed to the internet with high severity vulnerabilities"},
            "severity": "CRITICAL",
            "status": "OPEN",
            "entity": {
                "name": "prod-web-vm-01",
                "type": "VIRTUAL_MACHINE",
                "nativeType": "microsoft.compute/virtualmachines",
                "region": "eastus",
                "cloudPlatform": "Azure",
                "cloudAccount": {"id": "sub-abc-123", "name": "Production"},
                "subscription": {"id": "sub-abc-123", "name": "Production"},
            },
            "note": "VM has 5 critical CVEs and is exposed via public IP",
            "createdAt": "2026-02-10T08:00:00Z",
            "updatedAt": "2026-03-28T14:30:00Z",
        },
        {
            "id": "wiz-issue-002",
            "sourceRule": {"name": "S3 bucket allows public read access"},
            "severity": "HIGH",
            "status": "IN_PROGRESS",
            "entity": {
                "name": "data-lake-raw-bucket",
                "type": "CLOUD_RESOURCE",
                "nativeType": "aws.s3.bucket",
                "region": "us-east-1",
                "cloudPlatform": "AWS",
                "cloudAccount": {"id": "123456789012", "name": "DataLake"},
                "subscription": {"id": "123456789012", "name": "DataLake"},
            },
            "note": "Bucket policy allows s3:GetObject for principal *",
            "createdAt": "2026-03-01T12:00:00Z",
            "updatedAt": "2026-04-01T09:00:00Z",
        },
    ],

    # ── Qualys ───────────────────────────────────────────────────
    "qualys_findings": [
        {
            "QID": "38739",
            "TITLE": "OpenSSL Multiple Vulnerabilities (Mar 2024)",
            "IP": "10.20.30.40",
            "DNS": "db-server-01.corp.local",
            "SEVERITY": "5",
            "CVSS_BASE": "9.1",
            "CVE_ID_LIST": {"CVE_ID": ["CVE-2024-0727"]},
            "SOLUTION": "Upgrade OpenSSL to 3.0.13, 3.1.5, or 3.2.1.",
            "FIRST_FOUND_DATETIME": "2026-01-20T00:00:00Z",
            "LAST_FOUND_DATETIME": "2026-04-01T00:00:00Z",
        },
        {
            "QID": "45142",
            "TITLE": "Apache Log4j Remote Code Execution (Log4Shell)",
            "IP": "10.20.30.41",
            "DNS": "app-server-02.corp.local",
            "SEVERITY": "5",
            "CVSS_BASE": "10.0",
            "CVE_ID_LIST": {"CVE_ID": ["CVE-2021-44228"]},
            "SOLUTION": "Upgrade to Log4j 2.17.1 or later.",
            "FIRST_FOUND_DATETIME": "2026-01-05T00:00:00Z",
            "LAST_FOUND_DATETIME": "2026-04-02T00:00:00Z",
        },
    ],

    # ── Tenable.io ───────────────────────────────────────────────
    "tenable_io_findings": [
        {
            "plugin": {
                "id": "97993",
                "name": "Apache HTTP Server < 2.4.58 Multiple Vulnerabilities",
                "cvss3_base_score": "9.8",
                "cve": ["CVE-2023-43622"],
                "exploit_available": "true",
                "solution": "Upgrade to Apache HTTP Server 2.4.58 or later.",
            },
            "asset": {"hostname": "web-01.prod.local", "ipv4": "10.0.1.10"},
            "severity": "critical",
            "first_found": "2026-01-15T00:00:00Z",
            "last_found": "2026-04-01T12:00:00Z",
        },
        {
            "plugin": {
                "id": "156032",
                "name": "OpenSSH < 9.6 Terrapin Attack",
                "cvss3_base_score": "5.9",
                "cve": ["CVE-2023-48795"],
                "exploit_available": "false",
                "solution": "Upgrade to OpenSSH 9.6 or later.",
            },
            "asset": {"hostname": "bastion.prod.local", "ipv4": "10.0.1.20"},
            "severity": "medium",
            "first_found": "2026-02-01T00:00:00Z",
            "last_found": "2026-03-30T08:00:00Z",
        },
    ],

    # ── Tenable Security Center ──────────────────────────────────
    "tenable_sc_findings": [
        {
            "pluginID": "19506",
            "pluginName": "Nessus Scan Information",
            "netbiosName": "FILESERVER01",
            "ip": "10.50.1.100",
            "severity": "0",
            "cve": [],
            "baseScore": "",
            "exploitAvailable": "No",
            "solution": "N/A",
            "firstSeen": 1706745600,
            "lastSeen": 1711929600,
        },
        {
            "pluginID": "160770",
            "pluginName": "OpenSSL 3.x < 3.0.13 Multiple Vulnerabilities",
            "netbiosName": "APPSERVER02",
            "ip": "10.50.1.101",
            "severity": "4",
            "cve": ["CVE-2024-0727"],
            "baseScore": "9.1",
            "exploitAvailable": "Yes",
            "solution": "Upgrade to OpenSSL 3.0.13 or later.",
            "firstSeen": 1709251200,
            "lastSeen": 1711929600,
        },
    ],

    # ── Splunk ───────────────────────────────────────────────────
    "splunk_events": [
        {
            "source": "vuln-scan:critical:10.5.0.50:CVE-2024-3094",
            "search_name": "XZ Utils Backdoor (CVE-2024-3094)",
            "dest": "linux-build-01",
            "dest_ip": "10.5.0.50",
            "severity": "critical",
            "cve": "CVE-2024-3094",
            "signature": "Backdoor detected in XZ Utils 5.6.0/5.6.1 affecting liblzma",
            "vendor_product": "Linux",
            "_time": "2026-03-29T22:15:00Z",
        },
        {
            "source": "vuln-scan:high:10.5.0.51:CVE-2024-21762",
            "search_name": "FortiOS Out-of-Bound Write (CVE-2024-21762)",
            "dest": "fw-edge-01",
            "dest_ip": "10.5.0.51",
            "severity": "high",
            "cve": "CVE-2024-21762",
            "signature": "FortiOS SSL VPN RCE via crafted HTTP requests",
            "vendor_product": "Fortinet FortiGate",
            "_time": "2026-03-30T10:00:00Z",
        },
    ],

    # ── Jira (pull issues) ───────────────────────────────────────
    "jira_issues_pull": [
        {
            "key": "SEC-1042",
            "fields": {
                "summary": "Patch critical OpenSSL vulnerability on production servers",
                "description": {
                    "content": [{"content": [{"text": "Multiple production servers are running OpenSSL 3.0.x < 3.0.13 which is affected by CVE-2024-0727."}]}],
                },
                "status": {"name": "In Progress"},
                "priority": {"name": "Highest"},
                "assignee": {"displayName": "Alex Chen"},
                "issuetype": {"name": "Bug"},
                "labels": ["security", "patching", "critical"],
                "components": [{"name": "prod-web-cluster"}],
                "created": "2026-03-15T09:30:00.000+0000",
                "updated": "2026-04-01T14:22:00.000+0000",
            },
        },
        {
            "key": "SEC-1043",
            "fields": {
                "summary": "Investigate exposed S3 bucket in data-lake account",
                "description": {
                    "content": [{"content": [{"text": "Wiz detected a publicly readable S3 bucket in the data-lake AWS account."}]}],
                },
                "status": {"name": "Open"},
                "priority": {"name": "High"},
                "assignee": {"displayName": "Maria Garcia"},
                "issuetype": {"name": "Task"},
                "labels": ["security", "cloud", "aws"],
                "components": [{"name": "data-lake-infra"}],
                "created": "2026-03-20T11:00:00.000+0000",
                "updated": "2026-03-28T16:45:00.000+0000",
            },
        },
    ],

    # ── CrowdStrike Policies ─────────────────────────────────────
    "crowdstrike_policies": [
        {
            "id": "pol-prev-001",
            "name": "Windows Production - Standard Prevention",
            "prevention_settings": [
                {"id": "AdditionalUserModeData", "value": {"enabled": True, "prevention": "MODERATE"}},
                {"id": "EndUserNotifications", "value": {"enabled": True}},
                {"id": "UnknownDetectionRelatedExecutables", "value": {"enabled": True, "prevention": "AGGRESSIVE"}},
            ],
            "enabled": True,
        },
        {
            "id": "pol-prev-002",
            "name": "Linux Servers - Detect Only",
            "prevention_settings": [
                {"id": "CloudAntiMalware", "value": {"enabled": True, "prevention": "DISABLED"}},
                {"id": "AdwarePUP", "value": {"enabled": False}},
            ],
            "enabled": True,
        },
    ],

    # ── GoDaddy ──────────────────────────────────────────────────
    "godaddy_api": [
        {
            "name": "www",
            "type": "A",
            "data": "198.51.100.50",
            "ttl": 600,
            "_domain": "mycompany.com",
            "_domain_expiry": "2027-06-15T00:00:00Z",
            "_nameservers": ["ns1.godaddy.com", "ns2.godaddy.com"],
            "_registrar_status": "active",
        },
        {
            "name": "mail",
            "type": "CNAME",
            "data": "ghs.google.com",
            "ttl": 3600,
            "_domain": "mycompany.com",
            "_domain_expiry": "2027-06-15T00:00:00Z",
            "_nameservers": ["ns1.godaddy.com", "ns2.godaddy.com"],
            "_registrar_status": "active",
        },
    ],

    # ── Azure DNS ────────────────────────────────────────────────
    "azure_dns_api": [
        {
            "id": "/subscriptions/sub-123/resourceGroups/rg-dns/providers/Microsoft.Network/dnsZones/contoso.com/A/api",
            "name": "api",
            "type": "Microsoft.Network/dnsZones/A",
            "properties": {
                "fqdn": "api.contoso.com.",
                "TTL": 300,
                "ARecords": [{"ipv4Address": "20.42.0.100"}],
            },
            "_zone_name": "contoso.com",
            "_subscription_id": "sub-123",
            "_resource_group": "rg-dns",
        },
        {
            "id": "/subscriptions/sub-123/resourceGroups/rg-dns/providers/Microsoft.Network/dnsZones/contoso.com/CNAME/portal",
            "name": "portal",
            "type": "Microsoft.Network/dnsZones/CNAME",
            "properties": {
                "fqdn": "portal.contoso.com.",
                "TTL": 60,
                "CNAMERecord": {"cname": "contoso-portal.azurewebsites.net"},
            },
            "_zone_name": "contoso.com",
            "_subscription_id": "sub-123",
            "_resource_group": "rg-dns",
        },
    ],
}


# ── MockTransport ───────────────────────────────────────────────────

class MockTransport(BaseTransport):
    """In-memory transport for E2E tests. Yields pre-loaded fixture records."""

    def __init__(self, records: List[dict] = None):
        self.records = records or []
        self.push_calls: List[dict] = []

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        return ConnectResult(success=True, sample_records=self.records[:5])

    async def fetch_all(self, config: dict, credentials: dict, params: dict) -> AsyncIterator:
        for record in self.records:
            yield record

    async def push(self, config: dict, credentials: dict, payload: dict) -> PushResult:
        self.push_calls.append(payload)
        return PushResult(success=True, status_code=200)


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def connector_fixture_data():
    """Return the full CONNECTOR_FIXTURES dict."""
    return CONNECTOR_FIXTURES


@pytest.fixture
def mock_transport_factory():
    """Factory fixture: create a MockTransport pre-loaded with records."""
    def _make(records: List[dict] = None) -> MockTransport:
        return MockTransport(records=records or [])
    return _make


@pytest.fixture
def integration_factory(db_session, test_org, test_scan):
    """Factory fixture: create Integration + IntegrationRun DB records.

    Returns a callable:
        integration, run = integration_factory(
            name="My Integration",
            direction="pull",
            entity="asset",
            transport_type="mock",
            template_id="cloudflare_api",
            field_map=[...],
            dedup_key=[...],
        )
    """
    from models.models import Integration, IntegrationRun

    def _make(
        name: str = "Test Integration",
        direction: str = "pull",
        entity: str = "asset",
        transport_type: str = "mock",
        template_id: str = "test",
        field_map: list = None,
        dedup_key: list = None,
        transport_config: dict = None,
        params: dict = None,
    ):
        integration = Integration(
            id=str(uuid.uuid4()),
            org_id=test_org.id,
            name=name,
            direction=direction,
            entity=entity,
            transport_type=transport_type,
            transport_config=transport_config or {},
            field_map=field_map or [],
            dedup_key=dedup_key or [],
            params=params or {},
            template_id=template_id,
            enabled=True,
        )
        db_session.add(integration)
        db_session.flush()

        run = IntegrationRun(
            id=str(uuid.uuid4()),
            integration_id=integration.id,
            status="running",
            triggered_by="test",
            started_at=datetime.utcnow(),
            records_fetched=0,
            records_inserted=0,
            records_updated=0,
            records_skipped=0,
            errors=[],
            step_log=[],
        )
        db_session.add(run)
        db_session.flush()

        return integration, run

    return _make

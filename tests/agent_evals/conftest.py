"""
Pytest fixtures for agent evaluation test suite.

Provides in-memory database, sample scan data, and mock agent configuration
for deterministic evaluation of agent behavior.
"""
import sys
import os
import json
import pytest
from datetime import datetime, timedelta

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.database import Base
from models.models import Scan, Asset, Finding, Agent, AgentRun


@pytest.fixture
def mock_db():
    """In-memory SQLite session with all models created."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def sample_scan(mock_db):
    """A Scan record with basic metadata."""
    scan = Scan(
        id=1,
        filename="quarterly_scan_2026Q1.nessus",
        scan_name="Q1 2026 Internal Vulnerability Scan",
        scan_date="2026-03-01",
        scan_type="nessus",
        nessus_version="10.7.1",
        policy_used="Advanced Network Scan",
    )
    mock_db.add(scan)
    mock_db.commit()
    mock_db.refresh(scan)
    return scan


@pytest.fixture
def sample_assets(mock_db, sample_scan):
    """5 Asset records with varying criticality and severity counts."""
    assets_data = [
        {
            "id": 1,
            "scan_id": sample_scan.id,
            "ip": "10.0.1.10",
            "hostname": "dc01",
            "fqdn": "dc01.corp.local",
            "os": "Windows Server 2022",
            "criticality": 10,
            "environment_tag": "production",
            "risk_score": 9.2,
            "critical_count": 12,
            "high_count": 8,
            "medium_count": 15,
            "low_count": 5,
            "info_count": 42,
        },
        {
            "id": 2,
            "scan_id": sample_scan.id,
            "ip": "10.0.1.20",
            "hostname": "web-prod-01",
            "fqdn": "web-prod-01.corp.local",
            "os": "Ubuntu 22.04 LTS",
            "criticality": 8,
            "environment_tag": "production",
            "risk_score": 7.8,
            "critical_count": 5,
            "high_count": 12,
            "medium_count": 20,
            "low_count": 8,
            "info_count": 30,
        },
        {
            "id": 3,
            "scan_id": sample_scan.id,
            "ip": "10.0.2.50",
            "hostname": "db-staging",
            "fqdn": "db-staging.corp.local",
            "os": "Windows Server 2019",
            "criticality": 6,
            "environment_tag": "staging",
            "risk_score": 5.5,
            "critical_count": 2,
            "high_count": 6,
            "medium_count": 18,
            "low_count": 12,
            "info_count": 55,
        },
        {
            "id": 4,
            "scan_id": sample_scan.id,
            "ip": "10.0.3.100",
            "hostname": "dev-workstation-04",
            "fqdn": "dev-workstation-04.corp.local",
            "os": "Windows 11 Pro",
            "criticality": 3,
            "environment_tag": "development",
            "risk_score": 3.1,
            "critical_count": 0,
            "high_count": 2,
            "medium_count": 10,
            "low_count": 15,
            "info_count": 60,
        },
        {
            "id": 5,
            "scan_id": sample_scan.id,
            "ip": "10.0.1.5",
            "hostname": "fw-edge-01",
            "fqdn": "fw-edge-01.corp.local",
            "os": "PAN-OS 11.1",
            "criticality": 9,
            "environment_tag": "production",
            "risk_score": 8.4,
            "critical_count": 8,
            "high_count": 4,
            "medium_count": 3,
            "low_count": 1,
            "info_count": 20,
        },
    ]
    assets = []
    for data in assets_data:
        asset = Asset(**data)
        mock_db.add(asset)
        assets.append(asset)
    mock_db.commit()
    for a in assets:
        mock_db.refresh(a)
    return assets


@pytest.fixture
def sample_findings(mock_db, sample_scan, sample_assets):
    """15 Finding records with mix of severities, CVEs, exploit flags, etc."""
    findings_data = [
        # Critical findings with exploits
        {
            "id": 1, "scan_id": sample_scan.id, "asset_id": 1,
            "plugin_id": "156032", "plugin_name": "Windows SMBv3 Remote Code Execution (CVE-2024-38063)",
            "plugin_family": "Windows", "severity": 4, "severity_label": "Critical",
            "cvss3_score": 9.8, "vpr_score": 9.4,
            "cves": json.dumps(["CVE-2024-38063"]),
            "synopsis": "The remote Windows host is affected by a critical RCE vulnerability.",
            "description": "SMBv3 contains an integer overflow that allows unauthenticated remote code execution.",
            "solution": "Apply Microsoft patch KB5041578 or disable SMBv3 compression.",
            "priority_score": 9.5, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": True, "exploit_maturity": "weaponized",
            "is_kev": True, "sla_status": "breached",
        },
        {
            "id": 2, "scan_id": sample_scan.id, "asset_id": 1,
            "plugin_id": "160788", "plugin_name": "Active Directory Certificate Services ESC1 Vulnerability",
            "plugin_family": "Windows", "severity": 4, "severity_label": "Critical",
            "cvss3_score": 9.1, "vpr_score": 8.8,
            "cves": json.dumps([]),
            "synopsis": "ADCS misconfiguration allows privilege escalation to Domain Admin.",
            "description": "Certificate template allows low-privileged users to request certificates for any principal.",
            "solution": "Remove vulnerable certificate template or restrict enrollment permissions.",
            "priority_score": 9.0, "effort_level": "medium", "owner_suggestion": "SecOps",
            "exploit_available": True, "exploit_maturity": "functional",
            "is_kev": False, "sla_status": "at_risk",
        },
        {
            "id": 3, "scan_id": sample_scan.id, "asset_id": 2,
            "plugin_id": "174291", "plugin_name": "Apache Log4j 2.x < 2.17.1 RCE (Log4Shell)",
            "plugin_family": "Web Servers", "severity": 4, "severity_label": "Critical",
            "cvss3_score": 10.0, "vpr_score": 10.0,
            "cves": json.dumps(["CVE-2021-44228", "CVE-2021-45046"]),
            "synopsis": "The remote host has a vulnerable version of Apache Log4j.",
            "description": "Log4j JNDI injection allows unauthenticated remote code execution.",
            "solution": "Upgrade Log4j to 2.17.1 or later. Set log4j2.formatMsgNoLookups=true as mitigation.",
            "priority_score": 10.0, "effort_level": "quick_win", "owner_suggestion": "DevOps",
            "exploit_available": True, "exploit_maturity": "weaponized",
            "is_kev": True, "sla_status": "breached",
        },
        {
            "id": 4, "scan_id": sample_scan.id, "asset_id": 5,
            "plugin_id": "180455", "plugin_name": "PAN-OS Management Interface RCE (CVE-2024-3400)",
            "plugin_family": "Palo Alto Local Security Checks", "severity": 4, "severity_label": "Critical",
            "cvss3_score": 10.0, "vpr_score": 9.9,
            "cves": json.dumps(["CVE-2024-3400"]),
            "synopsis": "The remote Palo Alto firewall is affected by a critical command injection.",
            "description": "GlobalProtect gateway command injection allowing unauthenticated RCE.",
            "solution": "Upgrade PAN-OS to a fixed version. Apply Threat Prevention signature 95187.",
            "priority_score": 9.8, "effort_level": "quick_win", "owner_suggestion": "SecOps",
            "exploit_available": True, "exploit_maturity": "weaponized",
            "is_kev": True, "sla_status": "breached",
        },
        # High findings
        {
            "id": 5, "scan_id": sample_scan.id, "asset_id": 1,
            "plugin_id": "104743", "plugin_name": "Windows Kerberos Unconstrained Delegation",
            "plugin_family": "Windows", "severity": 3, "severity_label": "High",
            "cvss3_score": 7.5, "vpr_score": 7.2,
            "cves": json.dumps([]),
            "synopsis": "A computer account has unconstrained delegation enabled.",
            "description": "Unconstrained delegation allows the host to impersonate any user to any service.",
            "solution": "Switch to constrained delegation or resource-based constrained delegation.",
            "priority_score": 7.0, "effort_level": "medium", "owner_suggestion": "SecOps",
            "exploit_available": False, "sla_status": "on_track",
        },
        {
            "id": 6, "scan_id": sample_scan.id, "asset_id": 2,
            "plugin_id": "112156", "plugin_name": "OpenSSH < 9.8 Remote Code Execution (regreSSHion)",
            "plugin_family": "Misc.", "severity": 3, "severity_label": "High",
            "cvss3_score": 8.1, "vpr_score": 7.8,
            "cves": json.dumps(["CVE-2024-6387"]),
            "synopsis": "The remote SSH server is affected by a signal handler race condition.",
            "description": "OpenSSH sshd race condition that may lead to unauthenticated RCE on glibc-based Linux.",
            "solution": "Upgrade OpenSSH to 9.8p1 or later.",
            "priority_score": 7.5, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": True, "exploit_maturity": "proof-of-concept",
            "is_kev": False, "sla_status": "on_track",
        },
        {
            "id": 7, "scan_id": sample_scan.id, "asset_id": 3,
            "plugin_id": "152180", "plugin_name": "Microsoft SQL Server Elevation of Privilege",
            "plugin_family": "Databases", "severity": 3, "severity_label": "High",
            "cvss3_score": 7.8, "vpr_score": 6.5,
            "cves": json.dumps(["CVE-2024-37340"]),
            "synopsis": "The remote SQL Server installation is affected by an elevation of privilege vulnerability.",
            "description": "SQL Server native scoring allows a low-privileged user to escalate to sysadmin.",
            "solution": "Apply the latest Microsoft cumulative update for SQL Server.",
            "priority_score": 6.5, "effort_level": "medium", "owner_suggestion": "DevOps",
            "exploit_available": False, "sla_status": "on_track",
        },
        {
            "id": 8, "scan_id": sample_scan.id, "asset_id": 5,
            "plugin_id": "178320", "plugin_name": "SSL Certificate Expiry within 30 Days",
            "plugin_family": "General", "severity": 3, "severity_label": "High",
            "cvss3_score": 5.3, "vpr_score": 4.0,
            "cves": json.dumps([]),
            "synopsis": "The SSL certificate on the remote host will expire soon.",
            "description": "The SSL certificate expires in 12 days. Services relying on it will fail.",
            "solution": "Renew the SSL certificate before expiration.",
            "priority_score": 6.0, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "at_risk",
        },
        # Medium findings
        {
            "id": 9, "scan_id": sample_scan.id, "asset_id": 2,
            "plugin_id": "10287", "plugin_name": "Traceroute Information",
            "plugin_family": "Firewalls", "severity": 2, "severity_label": "Medium",
            "cvss3_score": 5.3, "vpr_score": 3.0,
            "cves": json.dumps([]),
            "synopsis": "Network path information is available.",
            "description": "Traceroute reveals internal network topology.",
            "solution": "Filter ICMP and UDP packets at network boundary.",
            "priority_score": 3.0, "effort_level": "medium", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "on_track",
        },
        {
            "id": 10, "scan_id": sample_scan.id, "asset_id": 3,
            "plugin_id": "58453", "plugin_name": "SMB Signing Not Required",
            "plugin_family": "Misc.", "severity": 2, "severity_label": "Medium",
            "cvss3_score": 5.3, "vpr_score": 4.5,
            "cves": json.dumps([]),
            "synopsis": "The remote SMB server does not require signing.",
            "description": "SMB signing is not enforced, enabling potential relay attacks.",
            "solution": "Enable and require SMB signing via Group Policy.",
            "priority_score": 4.5, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "on_track",
        },
        {
            "id": 11, "scan_id": sample_scan.id, "asset_id": 4,
            "plugin_id": "56984", "plugin_name": "SSL / TLS Versions Supported",
            "plugin_family": "General", "severity": 2, "severity_label": "Medium",
            "cvss3_score": 5.0, "vpr_score": 3.5,
            "cves": json.dumps([]),
            "synopsis": "The remote service supports outdated TLS versions.",
            "description": "TLS 1.0 and 1.1 are supported, which have known weaknesses.",
            "solution": "Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and 1.3.",
            "priority_score": 3.5, "effort_level": "medium", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "on_track",
        },
        # Low findings
        {
            "id": 12, "scan_id": sample_scan.id, "asset_id": 1,
            "plugin_id": "10863", "plugin_name": "SSL Certificate Information",
            "plugin_family": "General", "severity": 1, "severity_label": "Low",
            "cvss3_score": 2.0, "vpr_score": 1.5,
            "cves": json.dumps([]),
            "synopsis": "SSL certificate details were collected.",
            "description": "The remote service uses an SSL certificate with the following details.",
            "solution": "No action required. Informational only.",
            "priority_score": 1.5, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "n/a",
        },
        {
            "id": 13, "scan_id": sample_scan.id, "asset_id": 4,
            "plugin_id": "26920", "plugin_name": "Microsoft Windows SMBv1 Enabled",
            "plugin_family": "Windows", "severity": 1, "severity_label": "Low",
            "cvss3_score": 3.1, "vpr_score": 2.0,
            "cves": json.dumps([]),
            "synopsis": "SMBv1 is enabled on the remote Windows host.",
            "description": "SMBv1 is a deprecated protocol with known security issues.",
            "solution": "Disable SMBv1 via PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
            "priority_score": 2.0, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "n/a",
        },
        # Info findings
        {
            "id": 14, "scan_id": sample_scan.id, "asset_id": 1,
            "plugin_id": "19506", "plugin_name": "Nessus Scan Information",
            "plugin_family": "Settings", "severity": 0, "severity_label": "Info",
            "cvss3_score": None, "vpr_score": None,
            "cves": json.dumps([]),
            "synopsis": "Nessus scan configuration details.",
            "description": "This plugin provides information about the Nessus scan.",
            "solution": "N/A",
            "priority_score": 0.0, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "n/a",
        },
        {
            "id": 15, "scan_id": sample_scan.id, "asset_id": 2,
            "plugin_id": "11219", "plugin_name": "Nessus SYN Scanner",
            "plugin_family": "Port scanners", "severity": 0, "severity_label": "Info",
            "cvss3_score": None, "vpr_score": None,
            "cves": json.dumps([]),
            "synopsis": "Port scanning results.",
            "description": "This plugin reports the list of open ports detected.",
            "solution": "N/A",
            "priority_score": 0.0, "effort_level": "quick_win", "owner_suggestion": "IT",
            "exploit_available": False, "sla_status": "n/a",
        },
    ]

    findings = []
    for data in findings_data:
        finding = Finding(**data)
        mock_db.add(finding)
        findings.append(finding)
    mock_db.commit()
    for f in findings:
        mock_db.refresh(f)
    return findings


@pytest.fixture
def mock_agent(mock_db):
    """An Agent model instance with default triage config."""
    agent = Agent(
        id=1,
        name="Daily Triage Agent",
        description="Performs daily vulnerability triage and prioritization.",
        system_prompt=(
            "You are a vulnerability triage agent. Analyze scan results, "
            "prioritize findings by risk, and provide actionable remediation guidance. "
            "Always start by getting a scan summary, then investigate critical findings. "
            "Focus on exploitable vulnerabilities with KEV status first."
        ),
        tools=[
            "get_scan_summary",
            "query_findings",
            "get_sla_status",
            "get_top_risky_assets",
            "get_exploit_findings",
            "get_finding_detail",
            "get_asset_detail",
            "compare_scans",
        ],
        guardrails={
            "max_steps": 10,
            "read_only": True,
            "blocked_tools": ["create_jira_ticket", "send_slack_message"],
        },
        model="claude-sonnet-4-6",
        memory={
            "last_run": "2026-03-10T08:00:00Z",
            "previous_critical_count": 20,
        },
    )
    mock_db.add(agent)
    mock_db.commit()
    mock_db.refresh(agent)
    return agent


@pytest.fixture
def mock_tool_results():
    """Dict mapping tool names to sample return data."""
    return {
        "get_scan_summary": {
            "scan_id": 1,
            "scan_name": "Q1 2026 Internal Vulnerability Scan",
            "scan_date": "2026-03-01",
            "total_assets": 5,
            "total_findings": 15,
            "severity_breakdown": {
                "critical": 4,
                "high": 4,
                "medium": 3,
                "low": 2,
                "info": 2,
            },
            "top_cves": [
                "CVE-2021-44228",
                "CVE-2024-38063",
                "CVE-2024-3400",
                "CVE-2024-6387",
                "CVE-2024-37340",
            ],
            "exploitable_count": 5,
            "kev_count": 3,
            "sla_breached_count": 3,
        },
        "query_findings": {
            "total": 4,
            "findings": [
                {
                    "id": 1, "plugin_id": "156032",
                    "plugin_name": "Windows SMBv3 Remote Code Execution (CVE-2024-38063)",
                    "severity": 4, "cvss3_score": 9.8, "vpr_score": 9.4,
                    "asset_ip": "10.0.1.10", "exploit_available": True,
                    "is_kev": True, "sla_status": "breached",
                },
                {
                    "id": 3, "plugin_id": "174291",
                    "plugin_name": "Apache Log4j 2.x < 2.17.1 RCE (Log4Shell)",
                    "severity": 4, "cvss3_score": 10.0, "vpr_score": 10.0,
                    "asset_ip": "10.0.1.20", "exploit_available": True,
                    "is_kev": True, "sla_status": "breached",
                },
                {
                    "id": 4, "plugin_id": "180455",
                    "plugin_name": "PAN-OS Management Interface RCE (CVE-2024-3400)",
                    "severity": 4, "cvss3_score": 10.0, "vpr_score": 9.9,
                    "asset_ip": "10.0.1.5", "exploit_available": True,
                    "is_kev": True, "sla_status": "breached",
                },
                {
                    "id": 2, "plugin_id": "160788",
                    "plugin_name": "Active Directory Certificate Services ESC1 Vulnerability",
                    "severity": 4, "cvss3_score": 9.1, "vpr_score": 8.8,
                    "asset_ip": "10.0.1.10", "exploit_available": True,
                    "is_kev": False, "sla_status": "at_risk",
                },
            ],
        },
        "get_sla_status": {
            "total_findings": 15,
            "breached": 3,
            "at_risk": 2,
            "on_track": 6,
            "resolved": 0,
            "na": 4,
            "breached_findings": [
                {"id": 1, "plugin_name": "Windows SMBv3 RCE", "severity": 4, "asset_ip": "10.0.1.10", "sla_due_date": "2026-02-15"},
                {"id": 3, "plugin_name": "Log4Shell RCE", "severity": 4, "asset_ip": "10.0.1.20", "sla_due_date": "2026-02-20"},
                {"id": 4, "plugin_name": "PAN-OS RCE", "severity": 4, "asset_ip": "10.0.1.5", "sla_due_date": "2026-02-18"},
            ],
        },
        "get_top_risky_assets": {
            "assets": [
                {"id": 1, "ip": "10.0.1.10", "hostname": "dc01", "risk_score": 9.2, "critical_count": 12, "high_count": 8},
                {"id": 5, "ip": "10.0.1.5", "hostname": "fw-edge-01", "risk_score": 8.4, "critical_count": 8, "high_count": 4},
                {"id": 2, "ip": "10.0.1.20", "hostname": "web-prod-01", "risk_score": 7.8, "critical_count": 5, "high_count": 12},
                {"id": 3, "ip": "10.0.2.50", "hostname": "db-staging", "risk_score": 5.5, "critical_count": 2, "high_count": 6},
                {"id": 4, "ip": "10.0.3.100", "hostname": "dev-workstation-04", "risk_score": 3.1, "critical_count": 0, "high_count": 2},
            ],
        },
        "get_exploit_findings": {
            "total": 5,
            "findings": [
                {"id": 3, "plugin_name": "Log4Shell RCE", "cvss3_score": 10.0, "exploit_maturity": "weaponized", "is_kev": True},
                {"id": 4, "plugin_name": "PAN-OS RCE", "cvss3_score": 10.0, "exploit_maturity": "weaponized", "is_kev": True},
                {"id": 1, "plugin_name": "SMBv3 RCE", "cvss3_score": 9.8, "exploit_maturity": "weaponized", "is_kev": True},
                {"id": 2, "plugin_name": "ADCS ESC1", "cvss3_score": 9.1, "exploit_maturity": "functional", "is_kev": False},
                {"id": 6, "plugin_name": "regreSSHion", "cvss3_score": 8.1, "exploit_maturity": "proof-of-concept", "is_kev": False},
            ],
        },
    }

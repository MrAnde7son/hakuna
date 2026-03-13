"""
Unit tests for backend/parser.py — XML, CSV, and detect_and_parse.
"""
import sys
import os
import textwrap
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from parsers.parser import parse_nessus_xml, parse_nessus_csv, detect_and_parse


# ── XML fixtures ──────────────────────────────────────────────────────────────

MINIMAL_XML = textwrap.dedent("""\
<?xml version="1.0" ?>
<NessusClientData_v2>
  <Policy>
    <policyName>Advanced Network Scan</policyName>
  </Policy>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.10">
      <HostProperties>
        <tag name="host-ip">192.168.1.10</tag>
        <tag name="operating-system">Windows Server 2022</tag>
        <tag name="host-fqdn">dc01.corp.local</tag>
        <tag name="HOST_START">Mon Jan  1 00:00:00 2024</tag>
        <tag name="HOST_END">Mon Jan  1 00:05:00 2024</tag>
      </HostProperties>
      <ReportItem pluginID="19506" pluginName="Nessus Scan Information"
                  pluginFamily="Settings" severity="0" port="0" protocol="tcp">
        <synopsis>Nessus scan information.</synopsis>
        <description>This plugin provides info about the scan.</description>
        <solution>N/A</solution>
      </ReportItem>
      <ReportItem pluginID="156032" pluginName="SMBv3 RCE"
                  pluginFamily="Windows" severity="4" port="445" protocol="tcp">
        <synopsis>Remote code execution via SMBv3.</synopsis>
        <description>SMBv3 integer overflow allows unauthenticated RCE.</description>
        <solution>Apply KB5041578.</solution>
        <cve>CVE-2024-38063</cve>
        <cvss3_base_score>9.8</cvss3_base_score>
        <cvss_base_score>9.3</cvss_base_score>
        <vpr_score>9.4</vpr_score>
        <exploit_available>true</exploit_available>
        <exploited_by_malware>true</exploited_by_malware>
        <risk_factor>Critical</risk_factor>
      </ReportItem>
      <ReportItem pluginID="58651" pluginName="OpenSSH Vulnerability"
                  pluginFamily="Misc." severity="3" port="22" protocol="tcp">
        <synopsis>OpenSSH vulnerability.</synopsis>
        <solution>Upgrade OpenSSH.</solution>
        <cve>CVE-2024-6387</cve>
        <cve>CVE-2024-6387</cve>
        <cvss3_base_score>8.1</cvss3_base_score>
        <risk_factor>High</risk_factor>
        <exploit_framework_metasploit>true</exploit_framework_metasploit>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
        <tag name="operating-system">Ubuntu 22.04</tag>
        <tag name="netbios-name">web-prod</tag>
      </HostProperties>
      <ReportItem pluginID="10287" pluginName="Traceroute Information"
                  pluginFamily="Firewalls" severity="2" port="0" protocol="icmp">
        <synopsis>Network topology revealed.</synopsis>
        <solution>Filter ICMP.</solution>
        <cvss3_base_score>5.3</cvss3_base_score>
        <risk_factor>Medium</risk_factor>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
""")


# ── CSV fixtures ──────────────────────────────────────────────────────────────

CSV_CONTENT = textwrap.dedent("""\
Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output,IP Address,FQDN,OS,Plugin Family,CVSS Base Score,CVSS3 Base Score,VPR
156032,"CVE-2024-38063",Critical,192.168.1.10,tcp,445,SMBv3 RCE,RCE via SMBv3,SMBv3 integer overflow.,Apply KB5041578.,,192.168.1.10,dc01.corp.local,Windows Server 2022,Windows,9.3,9.8,9.4
58651,"CVE-2024-6387",High,192.168.1.10,tcp,22,OpenSSH Vuln,OpenSSH vulnerability.,Upgrade to 9.8p1.,Upgrade OpenSSH.,,,,Linux,Misc.,,,7.8
10287,,Medium,10.0.0.5,icmp,0,Traceroute Info,Network topology.,Reveals routing.,Filter ICMP.,,10.0.0.5,,,Firewalls,,5.3,
19506,,None,192.168.1.10,tcp,0,Nessus Scan Info,Scan info.,Scan details.,N/A,,,,,,,,
""")


# ── XML Parser Tests ──────────────────────────────────────────────────────────

class TestParseNessusXml:
    def test_returns_required_keys(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        assert set(result.keys()) == {"scan", "assets", "findings"}

    def test_scan_metadata(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        scan = result["scan"]
        assert scan["filename"] == "test.nessus"
        assert scan["scan_name"] == "Test Scan"
        assert scan["policy_used"] == "Advanced Network Scan"
        assert scan["scan_type"] == "nessus_xml"

    def test_asset_count(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        assert len(result["assets"]) == 2

    def test_asset_properties(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        dc01 = next(a for a in result["assets"] if a["ip"] == "192.168.1.10")
        assert dc01["os"] == "Windows Server 2022"
        assert dc01["fqdn"] == "dc01.corp.local"
        assert dc01["scan_start"] is not None

    def test_finding_count(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        assert len(result["findings"]) == 4

    def test_critical_finding_properties(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        smb = next(f for f in result["findings"] if f["plugin_id"] == "156032")
        assert smb["severity"] == 4
        assert smb["severity_label"] == "Critical"
        assert smb["cvss3_score"] == 9.8
        assert smb["cvss2_score"] == 9.3
        assert smb["vpr_score"] == 9.4
        assert "CVE-2024-38063" in smb["cves"]
        assert smb["exploit_available"] is True
        assert smb["exploit_maturity"] == "weaponized"
        assert smb["port"] == "445"
        assert smb["protocol"] == "tcp"

    def test_high_finding_metasploit_maturity(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        ssh = next(f for f in result["findings"] if f["plugin_id"] == "58651")
        assert ssh["severity"] == 3
        assert ssh["exploit_maturity"] == "functional"

    def test_cve_deduplication(self):
        """Duplicate CVEs in XML should be deduped."""
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        ssh = next(f for f in result["findings"] if f["plugin_id"] == "58651")
        assert ssh["cves"].count("CVE-2024-6387") == 1

    def test_asset_severity_counts(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        dc01 = next(a for a in result["assets"] if a["ip"] == "192.168.1.10")
        assert dc01["critical_count"] == 1
        assert dc01["high_count"] == 1
        assert dc01["info_count"] == 1

    def test_second_host_medium_finding(self):
        result = parse_nessus_xml(MINIMAL_XML, "test.nessus")
        web = next(a for a in result["assets"] if a["ip"] == "10.0.0.5")
        assert web["medium_count"] == 1
        assert web["netbios_name"] == "web-prod"

    def test_invalid_xml_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid .nessus XML"):
            parse_nessus_xml("not xml at all!!!", "bad.nessus")

    def test_missing_report_element_raises_value_error(self):
        xml = '<?xml version="1.0"?><NessusClientData_v2><Policy/></NessusClientData_v2>'
        with pytest.raises(ValueError, match="No <Report> element"):
            parse_nessus_xml(xml, "missing_report.nessus")

    def test_empty_report_returns_no_assets_or_findings(self):
        xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <NessusClientData_v2>
          <Report name="Empty Scan"/>
        </NessusClientData_v2>
        """)
        result = parse_nessus_xml(xml, "empty.nessus")
        assert result["assets"] == []
        assert result["findings"] == []

    def test_host_name_used_as_ip_fallback(self):
        xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <NessusClientData_v2>
          <Report name="Scan">
            <ReportHost name="172.16.0.1">
              <HostProperties/>
            </ReportHost>
          </Report>
        </NessusClientData_v2>
        """)
        result = parse_nessus_xml(xml, "scan.nessus")
        assert result["assets"][0]["ip"] == "172.16.0.1"


# ── CSV Parser Tests ──────────────────────────────────────────────────────────

class TestParseNessusCsv:
    def test_returns_required_keys(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        assert set(result.keys()) == {"scan", "assets", "findings"}

    def test_scan_metadata(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        assert result["scan"]["filename"] == "test.csv"
        assert result["scan"]["scan_type"] == "nessus_csv"

    def test_asset_count(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        assert len(result["assets"]) == 2

    def test_finding_count(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        assert len(result["findings"]) == 4

    def test_critical_finding(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        smb = next(f for f in result["findings"] if f["plugin_id"] == "156032")
        assert smb["severity"] == 4
        assert smb["severity_label"] == "Critical"
        assert smb["cvss3_score"] == 9.8
        assert smb["cvss2_score"] == 9.3
        assert smb["vpr_score"] == 9.4
        assert "CVE-2024-38063" in smb["cves"]
        assert smb["port"] == "445"

    def test_info_finding_severity(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        nessus_info = next(f for f in result["findings"] if f["plugin_id"] == "19506")
        assert nessus_info["severity"] == 0
        assert nessus_info["severity_label"] == "Info"

    def test_asset_ip_from_ip_address_column(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        dc01 = next(a for a in result["assets"] if a["hostname"] == "192.168.1.10")
        assert dc01["ip"] == "192.168.1.10"

    def test_asset_fqdn_parsed(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        dc01 = next(a for a in result["assets"] if a["hostname"] == "192.168.1.10")
        assert dc01["fqdn"] == "dc01.corp.local"

    def test_asset_severity_counts(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        dc01 = next(a for a in result["assets"] if a["hostname"] == "192.168.1.10")
        assert dc01["critical_count"] == 1
        assert dc01["high_count"] == 1
        assert dc01["info_count"] == 1

    def test_cve_extraction_from_cve_column(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        smb = next(f for f in result["findings"] if f["plugin_id"] == "156032")
        assert "CVE-2024-38063" in smb["cves"]

    def test_no_cvss_returns_none(self):
        result = parse_nessus_csv(CSV_CONTENT, "test.csv")
        nessus_info = next(f for f in result["findings"] if f["plugin_id"] == "19506")
        assert nessus_info["cvss2_score"] is None
        assert nessus_info["cvss3_score"] is None

    def test_empty_csv_returns_empty_results(self):
        header = "Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Output\n"
        result = parse_nessus_csv(header, "empty.csv")
        assert result["assets"] == []
        assert result["findings"] == []

    def test_row_without_host_is_skipped(self):
        csv = "Plugin ID,CVE,Risk,Host,Protocol,Port,Name\n99999,,High,,tcp,80,Test\n"
        result = parse_nessus_csv(csv, "no_host.csv")
        assert len(result["findings"]) == 0


# ── detect_and_parse Tests ────────────────────────────────────────────────────

class TestDetectAndParse:
    def test_nessus_extension_routes_to_xml(self):
        content = MINIMAL_XML.encode("utf-8")
        result = detect_and_parse(content, "scan.nessus")
        assert result["scan"]["scan_type"] == "nessus_xml"

    def test_csv_extension_routes_to_csv(self):
        content = CSV_CONTENT.encode("utf-8")
        result = detect_and_parse(content, "export.csv")
        assert result["scan"]["scan_type"] == "nessus_csv"

    def test_uppercase_extension_handled(self):
        content = CSV_CONTENT.encode("utf-8")
        result = detect_and_parse(content, "export.CSV")
        assert result["scan"]["scan_type"] == "nessus_csv"

    def test_nessus_latin1_encoding(self):
        """XML with latin-1 bytes should be decoded correctly."""
        content = MINIMAL_XML.encode("latin-1")
        result = detect_and_parse(content, "scan.nessus")
        assert len(result["assets"]) == 2

    def test_html_extension_routes_to_html(self):
        minimal_html = textwrap.dedent("""\
        <html><body>
        <div style="font-family: monospace">
        Nessus version : 10.7.1
        Scan name : Test HTML Scan
        Scan Start Date : 2024-01-01
        </div>
        </body></html>
        """)
        content = minimal_html.encode("utf-8")
        result = detect_and_parse(content, "report.html")
        assert "scan" in result
        assert "assets" in result
        assert "findings" in result

    def test_finding_host_name_matches_asset(self):
        """Each finding's host_name should map to an asset."""
        content = MINIMAL_XML.encode("utf-8")
        result = detect_and_parse(content, "scan.nessus")
        asset_hostnames = {a["hostname"] for a in result["assets"]}
        for finding in result["findings"]:
            assert finding["host_name"] in asset_hostnames

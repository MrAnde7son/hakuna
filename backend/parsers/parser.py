"""
Nessus scan parser — supports HTML, XML (.nessus), and CSV export formats.
"""
import re
import csv
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional
from bs4 import BeautifulSoup, Tag

logger = logging.getLogger(__name__)

# CSS severity class -> integer
SEVERITY_CLASS_MAP = {
    "classcell0": 0,  # Info (blue)
    "classcell1": 1,  # Low
    "classcell2": 2,  # Medium
    "classcell3": 3,  # High
    "classcell4": 4,  # Critical
}
SEVERITY_LABEL_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def parse_nessus_html(html_content: str, filename: str) -> dict:
    """
    Parse a Nessus HTML report and return structured data.
    Returns: { scan: {...}, assets: [...], findings: [...] }
    """
    soup = BeautifulSoup(html_content, "lxml")

    # Step 1: Extract scan metadata (from plugin 19506 output)
    scan_info = _extract_scan_info(soup)
    scan_info["filename"] = filename

    # Step 2: Build host map from classsection headers
    host_map = {}  # host_name -> asset dict
    host_sections = soup.find_all("h2", class_="classsection")
    for h2 in host_sections:
        host_name = h2.get_text(strip=True)
        if host_name and host_name not in host_map:
            host_map[host_name] = _build_asset_shell(host_name, h2)

    # Step 3: Build toggle-row index for severity lookup: btag_id -> severity
    btag_severity = {}
    for tr in soup.find_all("tr", onclick=True):
        onclick = tr.get("onclick", "")
        m = re.search(r"toggle\('(btag-[^']+)'\)", onclick)
        if not m:
            continue
        btag_id = m.group(1).strip()
        btag_severity[btag_id] = _severity_from_toggle_tr(tr)

    # Step 4: Build toggle-row index for plugin names: btag_id -> plugin_name
    btag_name = {}
    for tr in soup.find_all("tr", onclick=True):
        onclick = tr.get("onclick", "")
        m = re.search(r"toggle\('(btag-[^']+)'\)", onclick)
        if not m:
            continue
        btag_id = m.group(1).strip()
        for td in tr.find_all("td"):
            text = td.get_text(strip=True)
            nm = re.match(r"^(\d+)\s+-\s+(.+)$", text)
            if nm:
                btag_name[btag_id] = nm.group(2)
                break

    # Step 5: Parse each btag content div into a finding
    findings = []
    for div in soup.find_all("div"):
        if div.attrs is None:
            continue
        div_id = (div.get("id") or "").strip()
        if not div_id.startswith("btag-"):
            continue

        host_name, plugin_id = _parse_btag(div_id)
        if not plugin_id or not plugin_id.isdigit():
            continue

        severity = btag_severity.get(div_id, 0)
        plugin_name = btag_name.get(div_id, f"Plugin {plugin_id}")

        finding = _parse_finding_content(div, plugin_id, plugin_name, severity, host_name)
        findings.append(finding)

    # Step 6: Fill asset summary counts from HTML summary tables
    _fill_asset_counts_from_summary(host_map, host_sections)

    return {
        "scan": scan_info,
        "assets": list(host_map.values()),
        "findings": findings,
    }


def _extract_scan_info(soup: BeautifulSoup) -> dict:
    info = {
        "scan_name": None, "scan_date": None, "scan_type": None,
        "scanner_ip": None, "nessus_version": None, "policy_used": None,
    }
    for div in soup.find_all("div", style=lambda s: s and "font-family: monospace" in s):
        text = div.get_text()
        if "Nessus version" not in text or "Scan name" not in text:
            continue
        for line in text.split("\n"):
            line = line.strip()
            if " : " not in line:
                continue
            k, v = line.split(" : ", 1)
            k, v = k.strip(), v.strip()
            if k == "Nessus version":
                info["nessus_version"] = v
            elif k == "Scan name":
                info["scan_name"] = v
            elif k == "Scanner IP":
                info["scanner_ip"] = v
            elif k == "Scan policy used":
                info["policy_used"] = v
            elif k == "Scan type":
                info["scan_type"] = v
            elif k == "Scan Start Date":
                info["scan_date"] = v
        break
    return info


def _build_asset_shell(host_name: str, h2_tag: Tag) -> dict:
    """Build basic asset dict by scanning siblings for host info tables."""
    asset = {
        "hostname": host_name,
        "ip": None, "fqdn": None, "os": None, "netbios_name": None,
        "mac_address": None, "scan_start": None, "scan_end": None,
        "critical_count": 0, "high_count": 0, "medium_count": 0,
        "low_count": 0, "info_count": 0,
    }
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_name):
        asset["ip"] = host_name

    node = h2_tag.next_sibling
    while node:
        # Stop at next host section
        if hasattr(node, "get"):
            cls = node.get("class") or []
            if isinstance(cls, str):
                cls = cls.split()
            if "classsection" in cls:
                break
            if node.name == "h1" and "classchapter" in cls:
                break

        if hasattr(node, "find_all"):
            for table in ([node] if node.name == "table" else []) + list(node.find_all("table") if node.name != "table" else []):
                for row in table.find_all("tr", recursive=False):
                    cells = row.find_all("td", recursive=False)
                    if len(cells) >= 2:
                        lbl = cells[0].get_text(strip=True).rstrip(":")
                        val = cells[1].get_text(strip=True)
                        if lbl == "OS":
                            asset["os"] = val
                        elif lbl in ("DNS Name", "FQDN"):
                            asset["fqdn"] = val
                        elif lbl == "Netbios Name":
                            asset["netbios_name"] = val
                        elif lbl == "Start time":
                            asset["scan_start"] = val
                        elif lbl == "End time":
                            asset["scan_end"] = val
        node = node.next_sibling
    return asset


def _severity_from_toggle_tr(tr: Tag) -> int:
    """Get severity from color cell class nested in a toggle TR."""
    for td in tr.find_all("td"):
        for inner_td in td.find_all("td"):
            cls = inner_td.get("class") or []
            if isinstance(cls, str):
                cls = cls.split()
            for c in cls:
                if c in SEVERITY_CLASS_MAP:
                    return SEVERITY_CLASS_MAP[c]
        cls = td.get("class") or []
        if isinstance(cls, str):
            cls = cls.split()
        for c in cls:
            if c in SEVERITY_CLASS_MAP:
                return SEVERITY_CLASS_MAP[c]
    return 0


def _parse_btag(btag_id: str):
    """
    Parse btag ID to extract host name and plugin ID.
    Format: btag-HOST-PORT/PROTO-PLUGINID (spaces possible)
    Examples:
      btag-172.26.42.1- / -19506
      btag-dc1-TCP/445-70658
      btag-apadc- / -19506
    """
    rest = btag_id[5:]  # strip "btag-"
    m = re.search(r"[-\s]+(\d+)\s*$", rest)
    if not m:
        return rest, None
    plugin_id = m.group(1)
    host_part = rest[:m.start()].strip()
    # Remove trailing port/protocol segment (e.g., "- / " or "-TCP/445-" or "-445/tcp")
    host_part = re.sub(r"\s*-\s*[\w/.]+\s*$", "", host_part).strip()
    host_part = host_part.rstrip("-").strip()
    return host_part or rest, plugin_id


def _parse_finding_content(div: Tag, plugin_id: str, plugin_name: str, severity: int, host_name: str) -> dict:
    """Parse the content div of a finding."""
    finding = {
        "plugin_id": plugin_id,
        "plugin_name": plugin_name,
        "plugin_family": None,
        "plugin_pub_date": None,
        "plugin_mod_date": None,
        "severity": severity,
        "severity_label": SEVERITY_LABEL_MAP.get(severity, "Info"),
        "risk_factor": None,
        "cvss2_score": None, "cvss2_vector": None,
        "cvss3_score": None, "cvss3_vector": None,
        "vpr_score": None,
        "cves": [], "references": {}, "see_also": [],
        "synopsis": None, "description": None, "solution": None,
        "port": None, "protocol": None,
        "vulnerability_state": None, "plugin_output": None,
        "host_name": host_name,
    }

    current_section = None
    cves = []
    references = {}
    see_also = []

    for element in div.children:
        if not hasattr(element, "name") or not element.name:
            continue

        # Section headers
        if element.name == "h2":
            cls = element.get("class") or []
            if isinstance(cls, str):
                cls = cls.split()

            if "classh1" in cls:
                current_section = element.get_text(strip=True).rstrip(":").strip()
                continue

            if "classh2" in cls:
                text = element.get_text(strip=True)
                pm = re.search(r"\((\w+)/(\w+)\)", text)
                if pm:
                    finding["protocol"] = pm.group(1)
                    finding["port"] = pm.group(2)
                sm = re.search(r"Vulnerability State:\s*(\w+)", text)
                if sm:
                    finding["vulnerability_state"] = sm.group(1)
                continue

        # Content spans
        if element.name == "span":
            cls = element.get("class") or []
            if isinstance(cls, str):
                cls = cls.split()
            if "classtext" not in cls:
                continue

            text = element.get_text(strip=True)
            html_text = _span_to_text(element)

            if current_section == "Synopsis":
                finding["synopsis"] = text
            elif current_section == "Description":
                finding["description"] = html_text
            elif current_section == "Solution":
                finding["solution"] = html_text
            elif current_section == "Risk Factor":
                finding["risk_factor"] = text
                if finding["severity"] == 0 and text in ("Low", "Medium", "High", "Critical"):
                    finding["severity"] = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[text]
                    finding["severity_label"] = text
            elif current_section and "VPR" in current_section:
                try:
                    finding["vpr_score"] = float(text.split()[0])
                except (ValueError, IndexError):
                    pass
            elif current_section and "CVSS v3" in current_section:
                m = re.match(r"([\d.]+)", text)
                if m:
                    finding["cvss3_score"] = float(m.group(1))
                vm = re.search(r"\(([^)]+)\)", text)
                if vm:
                    finding["cvss3_vector"] = vm.group(1)
            elif current_section and "CVSS Base Score" in current_section:
                m = re.match(r"([\d.]+)", text)
                if m:
                    finding["cvss2_score"] = float(m.group(1))
                vm = re.search(r"\(([^)]+)\)", text)
                if vm:
                    finding["cvss2_vector"] = vm.group(1)
            elif current_section and "Plugin Information" in current_section:
                pm = re.search(r"Publication date:\s*([\d/]+)", text)
                mm = re.search(r"Modification date:\s*([\d/]+)", text)
                if pm:
                    finding["plugin_pub_date"] = pm.group(1)
                if mm:
                    finding["plugin_mod_date"] = mm.group(1)
            continue

        # See Also links
        if element.name == "table" and current_section == "See Also":
            for a in element.find_all("a"):
                href = a.get("href", "").strip()
                if href:
                    see_also.append(href)
            continue

        # References table
        if element.name == "table" and current_section == "References":
            for row in element.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    ref_type = cells[0].get_text(strip=True)
                    for a in cells[1].find_all("a"):
                        raw = a.get_text(strip=True)
                        if ref_type == "CVE":
                            cm = re.search(r"CVE-\d{4}-\d+", raw)
                            if cm:
                                cves.append(cm.group(0))
                        elif ref_type:
                            references.setdefault(ref_type, []).append(raw)
            continue

        # Plugin output
        if element.name == "div" and "font-family: monospace" in (element.get("style") or ""):
            finding["plugin_output"] = _div_to_text(element)
            continue

    finding["cves"] = list(dict.fromkeys(cves))
    finding["references"] = references
    finding["see_also"] = see_also
    return finding


def _fill_asset_counts_from_summary(host_map: dict, host_sections):
    """Fill asset severity counts from the HTML summary tables."""
    sev_order = ["critical", "high", "medium", "low", "info"]
    for h2 in host_sections:
        host_name = h2.get_text(strip=True)
        asset = host_map.get(host_name)
        if not asset:
            continue
        node = h2.next_sibling
        while node:
            if hasattr(node, "get"):
                cls = node.get("class") or []
                if "classsection" in cls:
                    break
                if node.name == "h1" and "classchapter" in cls:
                    break
            if hasattr(node, "find"):
                tables = ([node] if hasattr(node, "name") and node.name == "table" else []) + \
                         (list(node.find_all("table")) if hasattr(node, "find_all") and node.name != "table" else [])
                for table in tables:
                    header_row = table.find("tr")
                    if not header_row:
                        continue
                    headers = [td.get_text(strip=True).lower() for td in header_row.find_all("td")]
                    if "critical" in headers and "high" in headers and "info" in headers:
                        rows = table.find_all("tr")
                        if len(rows) >= 2:
                            count_cells = rows[1].find_all("td")
                            for i, sev in enumerate(sev_order):
                                if i < len(count_cells):
                                    try:
                                        asset[f"{sev}_count"] = int(count_cells[i].get_text(strip=True))
                                    except ValueError:
                                        pass
                        break
            node = node.next_sibling


def _span_to_text(span: Tag) -> str:
    text = span.decode_contents()
    text = text.replace("<br/>", "\n").replace("<br>", "\n").replace("<br />", "\n")
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _div_to_text(div: Tag) -> str:
    for d in div.find_all("div", class_="clear"):
        d.decompose()
    text = div.decode_contents()
    text = text.replace("<br/>", "\n").replace("<br>", "\n").replace("<br />", "\n")
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def load_intel_json(intel_path: str) -> dict:
    """Load CVE intel data and return as {cve_id: data} dict."""
    try:
        with open(intel_path) as f:
            data = json.load(f)
        return {entry["id"]: entry for entry in data.get("metadata", []) if "id" in entry}
    except Exception as e:
        logger.warning(f"Could not load intel.json: {e}")
        return {}


# ─────────────────────────────────────────────────────────
# .nessus XML Parser
# ─────────────────────────────────────────────────────────

_XML_SEV_MAP = {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4}
_XML_RISK_MAP = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def parse_nessus_xml(xml_content: str, filename: str) -> dict:
    """Parse a .nessus XML file (NessusClientData_v2 format)."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid .nessus XML: {e}")

    scan_info = {"filename": filename, "scan_name": None, "scan_date": None,
                 "scan_type": "nessus_xml", "scanner_ip": None, "nessus_version": None, "policy_used": None}

    # Extract policy name
    policy = root.find("Policy")
    if policy is not None:
        pname = policy.findtext("policyName")
        if pname:
            scan_info["policy_used"] = pname

    report = root.find("Report")
    if report is None:
        raise ValueError("No <Report> element found in .nessus file")

    scan_info["scan_name"] = report.get("name") or filename

    assets = []
    findings = []
    asset_map = {}  # host_name -> asset dict

    for report_host in report.findall("ReportHost"):
        host_name = report_host.get("name", "unknown")

        # Host properties
        asset = {
            "hostname": host_name, "ip": None, "fqdn": None, "os": None,
            "netbios_name": None, "mac_address": None, "scan_start": None, "scan_end": None,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0,
        }
        props = report_host.find("HostProperties")
        if props is not None:
            for tag in props.findall("tag"):
                n = tag.get("name", "")
                v = (tag.text or "").strip()
                if n == "host-ip":
                    asset["ip"] = v
                elif n == "host-fqdn":
                    asset["fqdn"] = v
                elif n == "operating-system":
                    asset["os"] = v
                elif n == "netbios-name":
                    asset["netbios_name"] = v
                elif n == "mac-address":
                    asset["mac_address"] = v
                elif n == "HOST_START":
                    asset["scan_start"] = v
                elif n == "HOST_END":
                    asset["scan_end"] = v

        if not asset["ip"] and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_name):
            asset["ip"] = host_name

        asset_map[host_name] = asset
        assets.append(asset)

        # Parse ReportItems (findings)
        host_findings = []
        for item in report_host.findall("ReportItem"):
            severity = _XML_SEV_MAP.get(item.get("severity", "0"), 0)
            finding = {
                "plugin_id": item.get("pluginID", ""),
                "plugin_name": item.get("pluginName", ""),
                "plugin_family": item.get("pluginFamily", ""),
                "severity": severity,
                "severity_label": SEVERITY_LABEL_MAP.get(severity, "Info"),
                "port": item.get("port", "0"),
                "protocol": item.get("protocol", ""),
                "host_name": host_name,
                "risk_factor": None,
                "synopsis": None, "description": None, "solution": None,
                "plugin_output": None, "see_also": [],
                "cves": [], "references": {},
                "cvss2_score": None, "cvss2_vector": None,
                "cvss3_score": None, "cvss3_vector": None,
                "vpr_score": None,
                "exploit_available": False, "exploit_maturity": None, "zero_day": False,
                "plugin_pub_date": None, "plugin_mod_date": None,
                "vulnerability_state": "Active",
            }

            for child in item:
                tag = child.tag
                text = (child.text or "").strip()
                if tag == "risk_factor":
                    finding["risk_factor"] = text
                    rf_sev = _XML_RISK_MAP.get(text)
                    if rf_sev is not None and rf_sev > severity:
                        finding["severity"] = rf_sev
                        finding["severity_label"] = SEVERITY_LABEL_MAP[rf_sev]
                elif tag == "synopsis":
                    finding["synopsis"] = text
                elif tag == "description":
                    finding["description"] = text
                elif tag == "solution":
                    finding["solution"] = text
                elif tag == "plugin_output":
                    finding["plugin_output"] = text
                elif tag == "see_also":
                    finding["see_also"] = [u.strip() for u in text.split() if u.strip().startswith("http")]
                elif tag == "cve":
                    finding["cves"].append(text)
                elif tag == "cvss_base_score":
                    try:
                        v = float(text)
                        if v > 0:
                            finding["cvss2_score"] = v
                    except ValueError:
                        pass
                elif tag == "cvss_vector":
                    finding["cvss2_vector"] = text
                elif tag == "cvss3_base_score":
                    try:
                        v = float(text)
                        if v > 0:
                            finding["cvss3_score"] = v
                    except ValueError:
                        pass
                elif tag == "cvss3_vector":
                    finding["cvss3_vector"] = text
                elif tag in ("vpr_score", "vul_priority_rating"):
                    try:
                        finding["vpr_score"] = float(text)
                    except ValueError:
                        pass
                elif tag == "exploit_available":
                    finding["exploit_available"] = text.lower() == "true"
                elif tag == "exploited_by_malware" and text.lower() == "true":
                    finding["exploit_maturity"] = "weaponized"
                elif tag == "exploit_framework_metasploit" and text.lower() == "true":
                    if not finding["exploit_maturity"]:
                        finding["exploit_maturity"] = "functional"
                elif tag == "in_the_news" and text.lower() == "true":
                    if not finding["exploit_maturity"]:
                        finding["exploit_maturity"] = "poc"
                elif tag == "plugin_modification_date":
                    finding["plugin_mod_date"] = text
                elif tag == "plugin_publication_date":
                    finding["plugin_pub_date"] = text
                elif tag == "bid":
                    finding["references"].setdefault("BID", []).append(text)
                elif tag == "xref":
                    finding["references"].setdefault("XREF", []).append(text)

            # Dedup CVEs
            finding["cves"] = list(dict.fromkeys(finding["cves"]))

            sev_key = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}
            asset[sev_key.get(finding["severity"], "info_count")] += 1

            host_findings.append(finding)
        findings.extend(host_findings)

    # Derive scan_date from the earliest HOST_START across all assets
    if not scan_info["scan_date"]:
        host_starts = [a["scan_start"] for a in assets if a.get("scan_start")]
        if host_starts:
            parsed_dates = []
            for ds in host_starts:
                for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                    try:
                        parsed_dates.append(datetime.strptime(ds, fmt))
                        break
                    except ValueError:
                        continue
            if parsed_dates:
                scan_info["scan_date"] = min(parsed_dates).strftime("%Y-%m-%dT%H:%M:%S")

    return {"scan": scan_info, "assets": assets, "findings": findings}


# ─────────────────────────────────────────────────────────
# CSV Parser
# ─────────────────────────────────────────────────────────

_CSV_RISK_MAP = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def parse_nessus_csv(csv_content: str, filename: str) -> dict:
    """Parse a Nessus CSV export."""
    scan_info = {"filename": filename, "scan_name": filename, "scan_date": None,
                 "scan_type": "nessus_csv", "scanner_ip": None, "nessus_version": None, "policy_used": None}

    reader = csv.DictReader(StringIO(csv_content))
    fieldnames = reader.fieldnames or []

    findings = []
    asset_map = {}  # host_key -> asset dict

    for row in reader:
        host_name = row.get("Host", "").strip()
        if not host_name:
            continue

        # Build/update asset entry
        if host_name not in asset_map:
            ip = row.get("IP Address", "").strip() or (host_name if re.match(r"^\d+\.\d+\.\d+\.\d+$", host_name) else None)
            asset_map[host_name] = {
                "hostname": host_name,
                "ip": ip,
                "fqdn": row.get("FQDN", "").strip() or None,
                "os": row.get("OS", "").strip() or None,
                "netbios_name": row.get("NetBios", "").strip() or None,
                "mac_address": row.get("MAC Address", "").strip() or None,
                "scan_start": row.get("Host Start", "").strip() or None,
                "scan_end": row.get("Host End", "").strip() or None,
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0, "info_count": 0,
            }

        # Severity from Risk column
        risk_str = row.get("Risk", "None").strip()
        severity = _CSV_RISK_MAP.get(risk_str, 0)

        # CVSS scores
        cvss2 = None
        try:
            v = float(row.get("CVSS Base Score", "") or row.get("CVSS", "") or 0)
            if v > 0:
                cvss2 = v
        except ValueError:
            pass

        cvss3 = None
        try:
            v = float(row.get("CVSS3 Base Score", "") or 0)
            if v > 0:
                cvss3 = v
        except ValueError:
            pass

        vpr = None
        try:
            vpr_raw = row.get("Vulnerability Priority Rating (VPR)", "") or row.get("VPR", "") or ""
            if vpr_raw.strip():
                vpr = float(vpr_raw.strip())
        except ValueError:
            pass

        # CVEs
        cve_raw = row.get("CVE", "").strip()
        cves = [c.strip() for c in re.findall(r"CVE-\d{4}-\d+", cve_raw)]

        # See also
        see_also_raw = row.get("See Also", "").strip()
        see_also = [u.strip() for u in see_also_raw.split() if u.strip().startswith("http")]

        finding = {
            "plugin_id": row.get("Plugin ID", "").strip(),
            "plugin_name": row.get("Name", "").strip(),
            "plugin_family": row.get("Plugin Family", "").strip() or None,
            "severity": severity,
            "severity_label": SEVERITY_LABEL_MAP.get(severity, "Info"),
            "risk_factor": risk_str,
            "port": row.get("Port", "").strip(),
            "protocol": row.get("Protocol", "").strip(),
            "host_name": host_name,
            "synopsis": row.get("Synopsis", "").strip() or None,
            "description": row.get("Description", "").strip() or None,
            "solution": row.get("Solution", "").strip() or None,
            "plugin_output": row.get("Plugin Output", "").strip() or None,
            "see_also": see_also,
            "cves": cves,
            "references": {},
            "cvss2_score": cvss2,
            "cvss2_vector": row.get("CVSS Vector", "").strip() or None,
            "cvss3_score": cvss3,
            "cvss3_vector": row.get("CVSS3 Vector", "").strip() or None,
            "vpr_score": vpr,
            "exploit_available": False,
            "exploit_maturity": None,
            "zero_day": False,
            "plugin_pub_date": None,
            "plugin_mod_date": None,
            "vulnerability_state": row.get("Vulnerability State", "Active").strip(),
        }

        # Update asset counts
        sev_key = {4: "critical_count", 3: "high_count", 2: "medium_count", 1: "low_count", 0: "info_count"}
        asset_map[host_name][sev_key.get(severity, "info_count")] += 1

        findings.append(finding)

    return {"scan": scan_info, "assets": list(asset_map.values()), "findings": findings}


def detect_and_parse(content: bytes, filename: str) -> dict:
    """Detect file format and parse accordingly."""
    fname = filename.lower()

    if fname.endswith(".nessus"):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        return parse_nessus_xml(text, filename)

    if fname.endswith(".csv"):
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        return parse_nessus_csv(text, filename)

    # Default: HTML
    try:
        text = content.decode("latin-1")
    except Exception:
        text = content.decode("utf-8", errors="replace")
    return parse_nessus_html(text, filename)

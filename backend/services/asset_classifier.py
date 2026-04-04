"""
Heuristic classifier for asset environment_tag and business_context.
Infers values from IP, hostname, FQDN, netbios_name, and OS fields.
All results are best-effort defaults — users can override via the UI.
"""
import re
import ipaddress
from typing import Optional


# ---------------------------------------------------------------------------
# Private / RFC1918 helpers
# ---------------------------------------------------------------------------

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]

def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


def _names(asset_data: dict) -> str:
    """Concatenate all name fields into one lowercase string for pattern matching."""
    parts = [
        asset_data.get("hostname") or "",
        asset_data.get("fqdn") or "",
        asset_data.get("netbios_name") or "",
    ]
    return " ".join(parts).lower()


# ---------------------------------------------------------------------------
# Environment tag inference
# ---------------------------------------------------------------------------

# Ordered list: (pattern, tag).  First match wins.
_ENV_HOSTNAME_RULES = [
    (r"\bdmz\b",                        "dmz"),
    (r"\bprod\b|\bprd\b|\bproduction\b","production"),
    (r"\bdev\b|\bdevel\b|\bdevelopment\b", "development"),
    (r"\btest\b|\btst\b|\btesting\b",   "test"),
    (r"\bstag\b|\bstaging\b|\bstg\b",   "staging"),
    (r"\buat\b",                         "uat"),
    (r"\bqa\b",                          "qa"),
    (r"\bcloud\b|\bec2\b|\bazure\b|\bgcp\b|\baws\b", "cloud"),
    (r"\blab\b|\bsandbox\b",             "lab"),
]


def infer_environment(asset_data: dict) -> str:
    """Return best-guess environment tag string."""
    names = _names(asset_data)

    # Hostname pattern takes priority
    for pattern, tag in _ENV_HOSTNAME_RULES:
        if re.search(pattern, names):
            return tag

    ip = asset_data.get("ip") or ""
    scanner_type = asset_data.get("scanner_type") or ""
    is_ext_scanner = scanner_type in ("cloud", "external")

    # Public IP + external/cloud scanner = confirmed external-facing
    if ip and not _is_private_ip(ip) and is_ext_scanner:
        return "external"

    # Private IP is always internal regardless of scanner
    if ip and _is_private_ip(ip):
        return "internal"

    return "internal"


# ---------------------------------------------------------------------------
# Business context inference
# ---------------------------------------------------------------------------

_ROLE_RULES = [
    # Domain / Identity
    (r"\b(dc|pdc|bdc|addc|domaincontroller|adds|adfs|ldap)\b", "Domain Controller"),
    (r"\b(ad|activedirectory)\b",                               "Active Directory"),
    (r"\b(sso|idp|okta|ping)\b",                               "Identity Provider"),

    # Web / Application tier
    (r"\b(web|www|http|iis|nginx|apache|tomcat|jboss|waf)\b",  "Web Server"),
    (r"\b(app|application|api)\b",                              "Application Server"),

    # Database
    (r"\b(sql|db|database|mysql|mssql|oracle|pg|postgres|mongo|redis|elastic)\b", "Database Server"),

    # Mail
    (r"\b(mail|exch|exchange|smtp|mx|imap|pop3)\b",            "Mail Server"),

    # File / Storage
    (r"\b(file|fs|nas|san|storage|share|nfs|cifs)\b",          "File Server"),

    # Backup
    (r"\b(backup|bkp|veeam|commvault|dpm|tsm)\b",              "Backup Server"),

    # Network devices / security
    (r"\b(fw|firewall|palo|asa|fortigate|checkpoint)\b",        "Firewall"),
    (r"\b(proxy|squid|bluecoat|zscaler)\b",                     "Proxy"),
    (r"\b(vpn|remote.access|ra-)\b",                            "VPN Gateway"),
    (r"\b(router|rtr|switch|sw-|core|dist|access)\b",           "Network Device"),
    (r"\b(lb|loadbalancer|f5|bigip|haproxy|nginx)\b",           "Load Balancer"),

    # Remote Desktop / VDI
    (r"\b(rdp|rds|citrix|ts|vdi|terminal)\b",                  "Terminal Server"),

    # Monitoring / Management
    (r"\b(monitor|sccm|scom|siem|splunk|elastic|logstash|zabbix|nagios|prtg|mgmt|management)\b", "Management Server"),

    # Print
    (r"\b(print|prn|mfp)\b",                                   "Print Server"),

    # CI/CD / Dev tools
    (r"\b(jenkins|gitlab|github|bitbucket|jira|confluence|nexus|artifactory)\b", "DevOps Server"),

    # Workstation (usually Windows 10/11/macOS, or hostname patterns)
    (r"\b(ws|wks|workstation|laptop|desktop|pc)\b",             "Workstation"),
]

# ---------------------------------------------------------------------------
# Default criticality by business context (1-10)
# Applied when no auto-rule or manual override sets criticality.
# ---------------------------------------------------------------------------

CONTEXT_CRITICALITY = {
    "Domain Controller":   9,
    "Active Directory":    9,
    "Identity Provider":   9,
    "Database Server":     8,
    "Mail Server":         8,
    "Web Server":          7,
    "Application Server":  7,
    "VPN Gateway":         7,
    "Firewall":            7,
    "Load Balancer":       7,
    "File Server":         6,
    "Backup Server":       6,
    "Proxy":               6,
    "Management Server":   6,
    "Terminal Server":     5,
    "Network Device":      5,
    "DevOps Server":       5,
    "Print Server":        4,
    "Workstation":         3,
}

def infer_business_context(asset_data: dict) -> Optional[str]:
    """Return best-guess business context string, or None if no confident match."""
    names = _names(asset_data)

    # OS workstation signals are reliable enough to include
    os_str = (asset_data.get("os") or "").lower()
    if re.search(r"windows\s+(10|11)\b|macos|mac os|os x", os_str):
        return "Workstation"

    for pattern, role in _ROLE_RULES:
        if re.search(pattern, names):
            return role

    return None  # unknown — leave blank rather than guess wrong


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Non-host asset type defaults (config-driven, editable via Settings)
# ---------------------------------------------------------------------------

# Curated defaults for well-known asset types.
# Unknown/custom types get safe defaults. Users can add/override via config.
ASSET_TYPE_DEFAULTS: dict[str, dict] = {
    "web_app":          {"environment_tag": "external", "business_context": "Web Application", "context_criticality": 7},
    "cloud_instance":   {"environment_tag": "cloud",    "business_context": "Cloud Instance",  "context_criticality": 5},
    "api_endpoint":     {"environment_tag": "external", "business_context": "API Endpoint",    "context_criticality": 6},
    "identity":         {"environment_tag": "internal", "business_context": "Identity",        "context_criticality": 6},
    "container_image":  {"environment_tag": "cloud",    "business_context": "Container",       "context_criticality": 5},
    "code_repo":        {"environment_tag": "development", "business_context": "Code Repository", "context_criticality": 4},
    "k8s_workload":     {"environment_tag": "cloud",    "business_context": "K8s Workload",    "context_criticality": 5},
}

# Safe fallback for unknown custom asset types
_DEFAULT_NON_HOST = {"environment_tag": "internal", "business_context": None, "context_criticality": 5}


def classify_asset(asset_data: dict) -> dict:
    """
    Returns {"environment_tag": str, "business_context": str|None,
             "context_criticality": int|None}
    to be merged into asset creation kwargs.

    context_criticality is the suggested baseline criticality derived from
    the inferred business context.  Callers should treat it as a default
    that auto-rules and manual overrides can supersede.
    """
    asset_type = asset_data.get("asset_type", "host")
    if asset_type != "host":
        defaults = ASSET_TYPE_DEFAULTS.get(asset_type, _DEFAULT_NON_HOST)
        return dict(defaults)

    biz_ctx = infer_business_context(asset_data)
    return {
        "environment_tag": infer_environment(asset_data),
        "business_context": biz_ctx,
        "context_criticality": CONTEXT_CRITICALITY.get(biz_ctx) if biz_ctx else None,
    }


# ---------------------------------------------------------------------------
# OS / CPE enrichment (plugins 11936, 45590)
# ---------------------------------------------------------------------------

# CPE vendor:product → device_type mapping
_CPE_DEVICE_MAP = [
    # Firewalls
    (r"cisco:(adaptive_security_appliance|asa|firepower)", "firewall"),
    (r"paloaltonetworks:pan-os", "firewall"),
    (r"fortinet:fortios", "firewall"),
    (r"checkpoint:(gaia|splat)", "firewall"),
    (r"sonicwall:", "firewall"),
    (r"watchguard:", "firewall"),
    (r"sophos:(sfos|xg)", "firewall"),
    # Routers
    (r"cisco:ios($|:)", "router"),
    (r"cisco:ios_xe", "router"),
    (r"cisco:nx-os", "switch"),
    (r"juniper:junos", "router"),
    (r"mikrotik:routeros", "router"),
    (r"arista:eos", "switch"),
    # Switches
    (r"cisco:catalyst", "switch"),
    (r"hp:(procurve|comware)", "switch"),
    (r"aruba:arubaos", "switch"),
    # Wireless access points
    (r"cisco:wireless_lan_controller", "wap"),
    (r"aruba:instant", "wap"),
    (r"ubiquiti:unifi", "wap"),
    # Hypervisors
    (r"vmware:esxi", "hypervisor"),
    (r"microsoft:hyper-v", "hypervisor"),
    (r"citrix:xenserver", "hypervisor"),
    (r"linux:linux_kernel.*xen", "hypervisor"),
    # Printers
    (r"(hp|canon|xerox|brother|lexmark|ricoh|kyocera):.*(print|laser|mfp|imagerunner)", "printer"),
    # Storage
    (r"netapp:", "storage"),
    (r"emc:", "storage"),
    (r"synology:diskstation", "storage"),
    (r"qnap:", "storage"),
    # VoIP
    (r"cisco:unified_communications", "voip"),
    (r"avaya:", "voip"),
    (r"polycom:", "voip"),
]

# OS string → device_type fallback (when CPE doesn't match)
_OS_DEVICE_MAP = [
    (r"\bcisco\s+ios\b", "router"),
    (r"\bnx-os\b|\bnexus\b", "switch"),
    (r"\bpan-os\b|\bpalo\s*alto\b", "firewall"),
    (r"\bfortios\b|\bfortigate\b", "firewall"),
    (r"\bjunos\b", "router"),
    (r"\basa\b.*\bcisco\b|\bcisco\b.*\basa\b", "firewall"),
    (r"\besxi\b|\bvmware\b.*\bhypervisor\b", "hypervisor"),
    (r"\bprinter\b|\bjetdirect\b|\bcups\b", "printer"),
    (r"\bwindows\s+(10|11)\b|\bmacos\b|\bmac\s*os\b|\bos\s*x\b", "workstation"),
    (r"\bwindows\s+server\b", "server"),
    (r"\blinux\b|\bubuntu\b|\bdebian\b|\bcentos\b|\bred\s*hat\b|\brhel\b|\bsuse\b", "server"),
    (r"\bfreebsd\b|\bopenbsd\b", "server"),
]


def parse_os_identification(plugin_output: str) -> dict:
    """Parse plugin 11936 (OS Identification) output.

    Returns {"os": str|None, "confidence": int|None, "method": str|None}.
    """
    result = {"os": None, "confidence": None, "method": None}
    if not plugin_output:
        return result

    m = re.search(r"Remote operating system\s*:\s*(.+)", plugin_output)
    if m:
        result["os"] = m.group(1).strip()

    m = re.search(r"Confidence [Ll]evel\s*:\s*(\d+)", plugin_output)
    if m:
        result["confidence"] = int(m.group(1))

    m = re.search(r"Method\s*:\s*(.+)", plugin_output)
    if m:
        result["method"] = m.group(1).strip()

    return result


def parse_cpe(plugin_output: str) -> list[str]:
    """Parse plugin 45590 (CPE) output. Returns list of CPE URIs."""
    if not plugin_output:
        return []
    return re.findall(r"(cpe:/[^\s]+)", plugin_output)


def classify_device_type(cpe_list: list[str], os_string: str = "") -> Optional[str]:
    """Infer device_type from CPE URIs and OS string.

    Returns one of: server, workstation, router, switch, firewall,
    printer, hypervisor, wap, voip, storage, or None.
    """
    # Try CPE-based classification first (more reliable)
    for cpe_uri in cpe_list:
        cpe_lower = cpe_uri.lower()
        # Hardware CPEs are very reliable
        if ":h:" in cpe_lower or cpe_lower.startswith("cpe:/h:"):
            for pattern, dtype in _CPE_DEVICE_MAP:
                if re.search(pattern, cpe_lower):
                    return dtype
        # OS CPEs
        if ":o:" in cpe_lower or cpe_lower.startswith("cpe:/o:"):
            for pattern, dtype in _CPE_DEVICE_MAP:
                if re.search(pattern, cpe_lower):
                    return dtype

    # Fallback to OS string matching
    os_lower = (os_string or "").lower()
    if os_lower:
        for pattern, dtype in _OS_DEVICE_MAP:
            if re.search(pattern, os_lower):
                return dtype

    return None


def enrich_asset_from_os_plugins(
    asset,
    plugin_11936_output: Optional[str] = None,
    plugin_45590_output: Optional[str] = None,
) -> None:
    """Enrich an Asset ORM object in-place with OS identification and CPE data.

    Called during scan upload after findings are created.
    """
    # Parse CPE first (used for device_type)
    cpe_list = []
    if plugin_45590_output:
        cpe_list = parse_cpe(plugin_45590_output)
        if cpe_list:
            asset.cpe = cpe_list

    # Parse OS identification
    if plugin_11936_output:
        os_info = parse_os_identification(plugin_11936_output)
        # Only overwrite OS if higher confidence or if currently empty
        if os_info["os"]:
            current_conf = asset.os_confidence or 0
            new_conf = os_info["confidence"] or 0
            if not asset.os or new_conf >= current_conf:
                asset.os = os_info["os"]
                asset.os_confidence = os_info["confidence"]

    # Classify device type from CPE + OS
    effective_os = asset.os or ""
    device_type = classify_device_type(cpe_list, effective_os)
    if device_type:
        asset.device_type = device_type

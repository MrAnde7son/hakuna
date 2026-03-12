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

    # IP range is a weak signal — some orgs use public IPs internally.
    # Use it only as a last resort and keep the value editable in the UI.
    ip = asset_data.get("ip") or ""
    if ip and _is_private_ip(ip):
        return "internal"

    return "internal"  # safe default — better to under-classify than over-classify


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

def classify_asset(asset_data: dict) -> dict:
    """
    Returns {"environment_tag": str, "business_context": str|None}
    to be merged into asset creation kwargs.
    """
    return {
        "environment_tag": infer_environment(asset_data),
        "business_context": infer_business_context(asset_data),
    }

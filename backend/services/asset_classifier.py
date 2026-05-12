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
    "github_org":       {"environment_tag": "external",    "business_context": "GitHub Organization", "context_criticality": 3},
    "github_user":      {"environment_tag": "external",    "business_context": "GitHub User",     "context_criticality": 2},
    "npm_package":      {"environment_tag": "external",    "business_context": "npm Package",     "context_criticality": 3},
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

# CPE vendor:product → device_type mapping.
# Order matters: first match wins. Place specific (endpoint/model) rules
# before broad vendor catch-alls so e.g. "polycom:vvx" maps to ip_phone
# rather than the generic polycom→voip fallback.
_CPE_DEVICE_MAP = [
    # Firewalls
    (r"cisco:(adaptive_security_appliance|asa|firepower)", "firewall"),
    (r"paloaltonetworks:pan-os", "firewall"),
    (r"fortinet:fortios", "firewall"),
    (r"checkpoint:(gaia|splat)", "firewall"),
    (r"sonicwall:", "firewall"),
    (r"watchguard:", "firewall"),
    (r"sophos:(sfos|xg|utm)", "firewall"),
    (r"barracuda:(cloudgen|ng)?firewall", "firewall"),
    (r"juniper:(srx|netscreen|screenos)", "firewall"),
    # Routers
    (r"cisco:ios($|:)", "router"),
    (r"cisco:ios_xe", "router"),
    (r"cisco:nx-os", "switch"),
    (r"cisco:meraki_mx", "firewall"),
    (r"cisco:meraki_mr", "wap"),
    (r"cisco:meraki_ms", "switch"),
    (r"juniper:junos", "router"),
    (r"mikrotik:routeros", "router"),
    (r"arista:eos", "switch"),
    # Switches
    (r"cisco:catalyst", "switch"),
    (r"hp:(procurve|comware)", "switch"),
    (r"hpe:(aruba_cx|procurve|comware)", "switch"),
    (r"aruba:arubaos", "switch"),
    (r"fortinet:fortiswitch", "switch"),
    (r"dell:(powerswitch|force10|networking)", "switch"),
    (r"extreme(_?networks)?:(exos|xos|voss)", "switch"),
    # Wireless access points
    (r"cisco:wireless_lan_controller", "wap"),
    (r"cisco:aironet", "wap"),
    (r"aruba:instant", "wap"),
    (r"ubiquiti:unifi", "wap"),
    (r"ruckus:(zonedirector|smartzone|unleashed)", "wap"),
    (r"fortinet:fortiap", "wap"),
    (r"mist:", "wap"),
    # Hypervisors
    (r"vmware:esxi", "hypervisor"),
    (r"microsoft:hyper-v", "hypervisor"),
    (r"citrix:xenserver", "hypervisor"),
    (r"linux:linux_kernel.*xen", "hypervisor"),
    (r"proxmox:", "hypervisor"),
    (r"nutanix:ahv", "hypervisor"),
    # IP cameras (place before generic vendor rules)
    (r"axis:.*(network_camera|p\d{4}|m\d{4}|q\d{4})", "ip_camera"),
    (r"axis:network_camera", "ip_camera"),
    (r"hikvision:", "ip_camera"),
    (r"dahua:", "ip_camera"),
    (r"hanwha:(wisenet|techwin)", "ip_camera"),
    (r"samsung:wisenet", "ip_camera"),
    (r"bosch:(dinion|flexidome|autodome|nbn|nbe)", "ip_camera"),
    (r"vivotek:", "ip_camera"),
    (r"reolink:", "ip_camera"),
    (r"pelco:(sarix|spectra)", "ip_camera"),
    (r"mobotix:", "ip_camera"),
    (r"uniview:", "ip_camera"),
    (r"avigilon:", "ip_camera"),
    (r"ring:(doorbell|camera|stick_up_cam|spotlight_cam)", "ip_camera"),
    (r"google:nest_cam", "ip_camera"),
    (r"arlo:", "ip_camera"),
    (r"wyze:(cam|camera)", "ip_camera"),
    # IP phones (place before voip catch-alls)
    (r"polycom:(vvx|trio|soundpoint|soundstation|edge)", "ip_phone"),
    (r"poly:(vvx|trio|edge|ccx)", "ip_phone"),
    (r"yealink:", "ip_phone"),
    (r"grandstream:(gxp|grp|gxv|ht)", "ip_phone"),
    (r"snom:", "ip_phone"),
    (r"mitel:(6\d{3}|5\d{3}|sip_phone)", "ip_phone"),
    (r"avaya:(j1\d{2}|9\d{3}|vantage|sip_phone)", "ip_phone"),
    (r"cisco:(ip_phone|cp-\d|7\d{3}|8\d{3}|9\d{3})", "ip_phone"),
    (r"fanvil:", "ip_phone"),
    (r"alcatel-lucent:(8\d{3}|sip_phone)", "ip_phone"),
    (r"unify:openstage", "ip_phone"),
    # Access control / badge readers
    (r"hid_global:(iclass|prox|signo|edge|vertx)", "access_control"),
    (r"lenel(s2)?:(onguard|netbox|s2_)", "access_control"),
    (r"honeywell:(prowatch|winpak|netaxs|maxpro)", "access_control"),
    (r"genetec:(synergis|security_center)", "access_control"),
    (r"suprema:(biostar|bioentry|biostation)", "access_control"),
    (r"zkteco:", "access_control"),
    (r"axis:.*(door_controller|a1001|a1601|reader)", "access_control"),
    (r"paxton:(net2|paxlock)", "access_control"),
    (r"dormakaba:", "access_control"),
    (r"assa_abloy:(aperio|hi-o)", "access_control"),
    # IoT sensors / building automation / smart-home gateways
    (r"shelly:", "iot_sensor"),
    (r"tp-link:(kasa|tapo)", "iot_sensor"),
    (r"tuya:", "iot_sensor"),
    (r"ecobee:", "iot_sensor"),
    (r"google:nest_(thermostat|protect|hub)", "iot_sensor"),
    (r"honeywell:(t\d|home|lyric)", "iot_sensor"),
    (r"sonos:", "iot_sensor"),
    (r"philips:hue", "iot_sensor"),
    (r"lutron:(caseta|radiora|homeworks)", "iot_sensor"),
    (r"crestron:", "iot_sensor"),
    (r"johnson_controls:(metasys|facility_explorer)", "iot_sensor"),
    (r"siemens:desigo", "iot_sensor"),
    (r"trane:(tracer|sintesis)", "iot_sensor"),
    (r"raspberrypi:", "iot_sensor"),
    # Printers — vendor matches + model-class catch-alls
    (r"(hp|hewlett-packard|hpe):.*(print|laser|jet|officejet|deskjet|jetdirect|mfp)", "printer"),
    (r"canon:.*(print|laser|imageclass|imagerunner|pixma|maxify|mfp)", "printer"),
    (r"xerox:.*(print|workcentre|versalink|altalink|phaser|colorqube|mfp)", "printer"),
    (r"brother:.*(print|laser|mfc|hl-|dcp-|mfp)", "printer"),
    (r"lexmark:", "printer"),
    (r"ricoh:.*(aficio|mp_|sp_|im_|print|mfp)", "printer"),
    (r"kyocera:.*(ecosys|taskalfa|print|mfp)", "printer"),
    (r"sharp:.*(mx-|ar-|aquos_print|mfp)", "printer"),
    (r"konica(_minolta)?:.*(bizhub|magicolor|print|mfp)", "printer"),
    (r"oki:.*(print|mc\d|cx\d|mfp)", "printer"),
    (r"toshiba(_tec)?:.*(estudio|print|mfp)", "printer"),
    (r"epson:.*(workforce|ecotank|laser|print|mfp)", "printer"),
    (r"samsung:.*(xpress|multixpress|proxpress|clx|printer)", "printer"),
    (r"zebra:.*(zt\d|zd\d|zq\d|gk\d|gx\d|print)", "printer"),
    # Storage
    (r"netapp:", "storage"),
    (r"emc:", "storage"),
    (r"dell:(unity|powerstore|powermax|isilon|compellent)", "storage"),
    (r"synology:diskstation", "storage"),
    (r"qnap:", "storage"),
    (r"truenas:", "storage"),
    (r"pure_storage:flasharray", "storage"),
    # VoIP / UC infrastructure (after ip_phone so endpoints win)
    (r"cisco:unified_communications", "voip"),
    (r"cisco:(callmanager|cucm|unity_connection)", "voip"),
    (r"avaya:(aura|communication_manager|session_manager)", "voip"),
    (r"polycom:(hdx|group_series|realpresence)", "voip"),
    (r"poly:(g7500|studio_x|realpresence)", "voip"),
    (r"mitel:(micollab|mivoice|mxone)", "voip"),
    (r"asterisk:", "voip"),
    (r"freepbx:", "voip"),
    (r"3cx:", "voip"),
    # Generic vendor catch-alls (last resort — kept narrow)
    (r"avaya:", "voip"),
    (r"polycom:", "voip"),
]

# OS string → device_type fallback (when CPE doesn't match).
# First match wins — specific patterns (cameras, phones) before generic OS families.
_OS_DEVICE_MAP = [
    # IP cameras
    (r"\b(axis|hikvision|dahua|vivotek|reolink|hanwha|wisenet|mobotix|uniview|avigilon)\b.*\b(camera|cam|dvr|nvr)\b", "ip_camera"),
    (r"\b(network[\s-]?camera|ip[\s-]?camera|onvif)\b", "ip_camera"),
    # IP phones
    (r"\b(yealink|grandstream|snom|fanvil)\b", "ip_phone"),
    (r"\bpolycom\b.*\b(vvx|trio|soundpoint|soundstation)\b", "ip_phone"),
    (r"\bpoly\b.*\b(vvx|trio|ccx|edge)\b", "ip_phone"),
    (r"\bcisco\b.*\bip[\s-]?phone\b", "ip_phone"),
    (r"\bsip[\s-]?phone\b|\bvoip[\s-]?phone\b", "ip_phone"),
    # Access control
    (r"\b(hid|lenel|s2[\s-]?netbox|genetec|suprema|zkteco|paxton)\b.*\b(reader|controller|access|prox)\b", "access_control"),
    (r"\b(badge[\s-]?reader|card[\s-]?reader|door[\s-]?controller)\b", "access_control"),
    # IoT / building automation
    (r"\b(shelly|tuya|ecobee|sonos|crestron|lutron|nest[\s-]?thermostat)\b", "iot_sensor"),
    (r"\bphilips[\s-]?hue\b|\bsmartthings\b|\braspberry[\s-]?pi\b", "iot_sensor"),
    (r"\b(bacnet|modbus|knx|metasys|desigo)\b", "iot_sensor"),
    # Network gear
    (r"\bcisco\s+ios\b", "router"),
    (r"\bnx-os\b|\bnexus\b", "switch"),
    (r"\bpan-os\b|\bpalo\s*alto\b", "firewall"),
    (r"\bfortios\b|\bfortigate\b", "firewall"),
    (r"\bfortiswitch\b", "switch"),
    (r"\bfortiap\b|\bmeraki\s+mr\d", "wap"),
    (r"\bmeraki\s+mx\d", "firewall"),
    (r"\bmeraki\s+ms\d", "switch"),
    (r"\bjunos\b", "router"),
    (r"\basa\b.*\bcisco\b|\bcisco\b.*\basa\b", "firewall"),
    (r"\bsonicwall\b|\bwatchguard\b|\bcheckpoint\s+gaia\b|\bsophos\s+(sfos|xg)\b", "firewall"),
    (r"\baruba(os)?\b|\bprocurve\b|\baruba\s+cx\b", "switch"),
    (r"\bunifi\b|\bubiquiti\b", "wap"),
    # Hypervisors
    (r"\besxi\b|\bvmware\b.*\bhypervisor\b|\bproxmox\b|\bnutanix\s+ahv\b", "hypervisor"),
    # Storage
    (r"\bnetapp\b|\bontap\b|\bisilon\b|\bunity\b|\btruenas\b|\bpure[\s-]?storage\b", "storage"),
    # Printers (broad — page-printer firmwares are recognizable)
    (r"\bprinter\b|\bjetdirect\b|\bcups\b|\bworkcentre\b|\bbizhub\b|\becosys\b|\bimagerunner\b", "printer"),
    # OS families (generic — workstation vs server)
    (r"\bwindows\s+(10|11)\b|\bmacos\b|\bmac\s*os\b|\bos\s*x\b", "workstation"),
    (r"\bwindows\s+server\b", "server"),
    (r"\blinux\b|\bubuntu\b|\bdebian\b|\bcentos\b|\bred\s*hat\b|\brhel\b|\bsuse\b", "server"),
    (r"\bfreebsd\b|\bopenbsd\b", "server"),
]


# ---------------------------------------------------------------------------
# MAC OUI → device_type table (IEEE registry, hand-curated subset).
#
# Used only as a tiebreaker when CPE + OS produce no classification.
# Keys are uppercase 6-hex-digit OUIs (no separators). First match wins.
# Curated for the device classes most often invisible to OS/CPE plugins:
# cameras, IP phones, access control, printers, IoT, network gear.
# ---------------------------------------------------------------------------

_OUI_DEVICE_MAP: dict[str, str] = {
    # --- IP cameras ---
    "00408C": "ip_camera",   # Axis Communications
    "ACCC8E": "ip_camera",   # Axis
    "B8A44F": "ip_camera",   # Axis
    "44A642": "ip_camera",   # Hikvision
    "BCAD28": "ip_camera",   # Hikvision
    "C0560E": "ip_camera",   # Hikvision
    "F84DFC": "ip_camera",   # Hikvision
    "3CE5A6": "ip_camera",   # Hikvision
    "001CF0": "ip_camera",   # Dahua
    "3C0FC1": "ip_camera",   # Dahua
    "90020A": "ip_camera",   # Dahua
    "A0BD1D": "ip_camera",   # Dahua
    "001195": "ip_camera",   # Hanwha / Samsung Techwin
    "0009F0": "ip_camera",   # Hanwha
    "00075F": "ip_camera",   # Vivotek
    "0002D1": "ip_camera",   # Vivotek
    "EC71DB": "ip_camera",   # Reolink (Baichuan)
    "B0C5CA": "ip_camera",   # TP-Link camera division
    "EC1A59": "ip_camera",   # Ring (Belkin/Foxconn shared, but heavily Ring)
    "5CA6E6": "ip_camera",   # Wyze
    "2C5BB8": "ip_camera",   # Wyze
    "001DEC": "ip_camera",   # Pelco
    "003064": "ip_camera",   # Mobotix
    "B0E4D5": "ip_camera",   # Avigilon

    # --- IP phones ---
    "0004F2": "ip_phone",    # Polycom
    "00E0DB": "ip_phone",    # Polycom
    "64167F": "ip_phone",    # Polycom / Poly
    "805EC0": "ip_phone",    # Yealink
    "001565": "ip_phone",    # Yealink
    "249AD8": "ip_phone",    # Yealink
    "44AD2C": "ip_phone",    # Yealink
    "000B82": "ip_phone",    # Grandstream
    "C074AD": "ip_phone",    # Grandstream
    "EC74D7": "ip_phone",    # Grandstream
    "00041326": "ip_phone",  # Snom (legacy)
    "000413": "ip_phone",    # Snom
    "0008A1": "ip_phone",    # Snom (later)
    "08000F": "ip_phone",    # Mitel
    "0003FE": "ip_phone",    # Cisco IP Phone (one of many)
    "001FCA": "ip_phone",    # Cisco SPA / phones
    "F0F755": "ip_phone",    # Cisco phones
    "0015E1": "ip_phone",    # Fanvil
    "0C383E": "ip_phone",    # Fanvil

    # --- Access control / badge readers ---
    "00065B": "access_control",  # HID Global
    "00194D": "access_control",  # HID Global
    "001B55": "access_control",  # HID Global
    "0050F9": "access_control",  # HID Global (legacy)
    "0014E4": "access_control",  # Lenel
    "0050C2": "access_control",  # Lenel (legacy block, partial)
    "00D0A0": "access_control",  # Suprema
    "001F54": "access_control",  # Suprema
    "002662": "access_control",  # ZKTeco
    "B4A2EB": "access_control",  # ZKTeco
    "000760": "access_control",  # Honeywell (security)
    "00A03D": "access_control",  # Honeywell access

    # --- Printers ---
    "00000F": "printer",     # NeXT / printer-era legacy reserved
    "0001E6": "printer",     # HP
    "000F61": "printer",     # HP
    "001F29": "printer",     # HP
    "002655": "printer",     # HP
    "9C8E99": "printer",     # HP
    "001E8F": "printer",     # Canon
    "00BB3A": "printer",     # Canon
    "F4815A": "printer",     # Canon
    "08009F": "printer",     # Xerox
    "00000A": "printer",     # Xerox
    "9C934E": "printer",     # Xerox
    "001BA9": "printer",     # Brother
    "008092": "printer",     # Brother
    "30055C": "printer",     # Brother
    "0021B7": "printer",     # Lexmark
    "0004000F": "printer",   # Lexmark (legacy)
    "000123": "printer",     # Ricoh
    "00267A": "printer",     # Ricoh
    "0017C8": "printer",     # Kyocera
    "00C0EE": "printer",     # Kyocera (legacy)
    "00084E": "printer",     # Konica Minolta
    "002673": "printer",     # Konica Minolta
    "001B77": "printer",     # OKI
    "00808A": "printer",     # OKI (legacy)
    "002219": "printer",     # Sharp
    "0014BF": "printer",     # Toshiba TEC
    "0026AB": "printer",     # Seiko Epson
    "9CAD97": "printer",     # Epson
    "001599": "printer",     # Samsung printer division
    "001632": "printer",     # Samsung printer division
    "0007B6": "printer",     # Zebra Technologies
    "0023A5": "printer",     # Zebra

    # --- IoT / smart-home / building automation ---
    "98F4AB": "iot_sensor",  # Shelly (Allterco Robotics)
    "B4E62D": "iot_sensor",  # Shelly
    "1C90FF": "iot_sensor",  # Shelly
    "5067F0": "iot_sensor",  # Sonos
    "B8E937": "iot_sensor",  # Sonos
    "94946C": "iot_sensor",  # Sonos
    "00178880": "iot_sensor",# Philips Hue (Signify)
    "001788": "iot_sensor",  # Philips Hue
    "ECB5FA": "iot_sensor",  # Philips Hue
    "44650D": "iot_sensor",  # Amazon (Echo / smart hubs)
    "FCA183": "iot_sensor",  # Amazon devices
    "F0F005": "iot_sensor",  # Nest Labs / Google Nest
    "188B45": "iot_sensor",  # Nest
    "00904C": "iot_sensor",  # Lutron
    "00104B": "iot_sensor",  # Crestron
    "0050F9": "iot_sensor",  # Crestron (overlap with HID — left for HID precedence)
    "B827EB": "iot_sensor",  # Raspberry Pi Foundation
    "DCA632": "iot_sensor",  # Raspberry Pi
    "E45F01": "iot_sensor",  # Raspberry Pi

    # --- Network gear (helpful when CPE missing) ---
    "00D0BA": "router",      # Cisco Systems
    "0001C9": "router",      # Cisco
    "0023AB": "router",      # Cisco
    "001F45": "switch",      # Cisco
    "001AE3": "wap",         # Cisco Aironet
    "001B11": "switch",      # Juniper Networks
    "00904B": "router",      # Juniper
    "B4FBE4": "switch",      # Juniper
    "4C5E0C": "wap",         # Ubiquiti
    "24A43C": "wap",         # Ubiquiti
    "E063DA": "wap",         # Ubiquiti
    "9CB6D0": "wap",         # Aruba (HPE)
    "182032": "wap",         # Aruba
    "001F12": "firewall",    # Palo Alto Networks
    "B4001A": "firewall",    # Palo Alto Networks
    "001B17": "firewall",    # Fortinet
    "0009F8": "firewall",    # Fortinet
    "70AAB2": "firewall",    # Fortinet
    "001CE5": "firewall",    # SonicWall
    "C0EAE4": "wap",         # Mist Systems (Juniper)
}


def _normalize_mac(mac: str) -> Optional[str]:
    """Return uppercase 12-hex-digit MAC or None if input is unparseable."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) < 6:
        return None
    return cleaned.upper()


def classify_device_type_from_mac(mac: str) -> Optional[str]:
    """Best-effort device_type from MAC OUI. Returns None if unknown.

    Checks the 8-hex (MA-M, e.g. Lexmark legacy) prefix first, then the
    standard 6-hex OUI. Larger prefixes win to handle vendors that share
    a /24 OUI block but split it across MA-S / MA-M registrations.
    """
    normalized = _normalize_mac(mac)
    if not normalized:
        return None
    if len(normalized) >= 8:
        prefix8 = normalized[:8]
        if prefix8 in _OUI_DEVICE_MAP:
            return _OUI_DEVICE_MAP[prefix8]
    prefix6 = normalized[:6]
    return _OUI_DEVICE_MAP.get(prefix6)


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


def classify_device_type(
    cpe_list: list[str],
    os_string: str = "",
    mac: Optional[str] = None,
) -> Optional[str]:
    """Infer device_type from CPE URIs, OS string, and optionally MAC OUI.

    Resolution order (most reliable first):
      1. Hardware CPE URIs (cpe:/h:vendor:product)
      2. OS CPE URIs (cpe:/o:vendor:product)
      3. OS string regex match
      4. MAC OUI lookup (tiebreaker — only when 1–3 produce nothing)

    Returns one of: server, workstation, router, switch, firewall, printer,
    hypervisor, wap, voip, ip_camera, ip_phone, access_control, iot_sensor,
    storage, or None.
    """
    # 1, 2 & 3: CPE-based classification.
    # Order: hardware (:h:) → OS (:o:) → application (:a:). Hardware is the
    # ground truth, OS is reliable, application is last-resort (a host running
    # vendor management software often functions as that role, e.g. a server
    # running Cisco UC Manager is a VoIP system). Within each tier the first
    # _CPE_DEVICE_MAP rule that matches wins. Match both legacy URI form
    # (cpe:/h:…) and the 2.3 form (cpe:2.3:h:…).
    for kind_token, kind_prefix in ((":h:", "cpe:/h:"), (":o:", "cpe:/o:"), (":a:", "cpe:/a:")):
        for cpe_uri in cpe_list:
            cpe_lower = cpe_uri.lower()
            if not (cpe_lower.startswith(kind_prefix) or kind_token in cpe_lower):
                continue
            for pattern, dtype in _CPE_DEVICE_MAP:
                if re.search(pattern, cpe_lower):
                    return dtype

    # 3: OS string fallback
    os_lower = (os_string or "").lower()
    if os_lower:
        for pattern, dtype in _OS_DEVICE_MAP:
            if re.search(pattern, os_lower):
                return dtype

    # 4: MAC OUI tiebreaker
    if mac:
        return classify_device_type_from_mac(mac)

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

    # Classify device type from CPE + OS, with MAC OUI as tiebreaker
    effective_os = asset.os or ""
    asset_mac = getattr(asset, "mac_address", None)
    device_type = classify_device_type(cpe_list, effective_os, mac=asset_mac)
    if device_type:
        asset.device_type = device_type

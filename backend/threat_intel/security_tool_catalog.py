"""
Security Tool Catalog
---------------------
Maps known security product service names and software patterns to structured
security control metadata.  Used by detect_security_controls_from_inventory()
to enrich InventorySecurityControl records derived from InventoryService and
InventorySoftware rows rather than dedicated Nessus plugins.

Each entry:
    category       – human-readable category (EDR, AV, Firewall, …)
    control_type   – normalised type stored on InventorySecurityControl
    product        – canonical product name
    vendor         – vendor / company name
    service_names  – list of Windows service short-names (case-insensitive)
    software_patterns – substrings to match against InventorySoftware.name
    description    – one-liner
"""

SECURITY_TOOL_CATALOG = [

    # ──────────────────────────────────────────────────────────
    # EDR / XDR
    # ──────────────────────────────────────────────────────────
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "CrowdStrike Falcon",
        "vendor": "CrowdStrike",
        "service_names": [
            "csagent", "csfalconservice", "csfcsc", "crowdstrike",
        ],
        "software_patterns": ["crowdstrike", "falcon sensor"],
        "description": "AI-native endpoint detection and response",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "SentinelOne",
        "vendor": "SentinelOne",
        "service_names": [
            "sentinelagent", "sentinelstaticengine", "sentinelhelper",
            "sentinelmonitor", "sentinelone",
        ],
        "software_patterns": ["sentinelone", "sentinel agent"],
        "description": "Autonomous endpoint protection platform",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "VMware Carbon Black",
        "vendor": "VMware / Broadcom",
        "service_names": [
            "cbdefense", "cbdefenserepux", "carbonblack", "cbagent",
            "cb defense", "carbonblackdefense",
        ],
        "software_patterns": ["carbon black", "vmware carbon black"],
        "description": "Cloud-native endpoint protection",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Microsoft Defender for Endpoint",
        "vendor": "Microsoft",
        "service_names": [
            "sense", "msmpeng", "mssecflt", "diagtrack", "mdefender",
        ],
        "software_patterns": [
            "microsoft defender for endpoint",
            "windows defender advanced threat protection",
        ],
        "description": "Microsoft's enterprise EDR (MDE / Defender ATP)",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Sophos Intercept X",
        "vendor": "Sophos",
        "service_names": [
            "sophosendpointagent", "sophos agent", "sophosav",
            "sophosauthagent", "sophosmanagementservice", "sophoshealth",
        ],
        "software_patterns": ["sophos intercept", "sophos endpoint"],
        "description": "Next-gen endpoint with deep learning",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Cylance PROTECT",
        "vendor": "BlackBerry / Cylance",
        "service_names": ["cylancesvc", "cylance"],
        "software_patterns": ["cylance", "blackberry protect"],
        "description": "AI-based predictive endpoint security",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Cybereason",
        "vendor": "Cybereason",
        "service_names": ["cybereason", "cybereasonactiveprobe"],
        "software_patterns": ["cybereason"],
        "description": "Operation-centric endpoint detection",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Trend Micro Apex One",
        "vendor": "Trend Micro",
        "service_names": [
            "tmlisten", "tmlwfsrv", "tmntsrv", "tmproxy",
            "trend micro endpoint sensor",
        ],
        "software_patterns": ["trend micro apex", "officescan", "apex one"],
        "description": "Trend Micro endpoint protection",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Trellix Endpoint Security",
        "vendor": "Trellix / McAfee",
        "service_names": [
            "mfemms", "mfefire", "mfemactl", "mcafee endpoint",
            "mctray", "mcshield",
        ],
        "software_patterns": ["trellix", "mcafee endpoint security", "ens "],
        "description": "Trellix (McAfee) endpoint security",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Symantec Endpoint Security",
        "vendor": "Broadcom / Symantec",
        "service_names": [
            "sepmasterservice", "smcservice", "symantec endpoint",
            "smc", "sivagent",
        ],
        "software_patterns": [
            "symantec endpoint", "norton 360 for business", "sep ",
        ],
        "description": "Symantec / Broadcom endpoint suite",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Kaspersky Endpoint Security",
        "vendor": "Kaspersky",
        "service_names": ["avp", "avpui", "klnagent", "kavfs"],
        "software_patterns": ["kaspersky endpoint", "kaspersky anti"],
        "description": "Kaspersky endpoint security suite",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "ESET Endpoint Security",
        "vendor": "ESET",
        "service_names": ["ekrn", "eamonm", "esetservice"],
        "software_patterns": ["eset endpoint", "eset nod32", "eset security"],
        "description": "ESET multi-layered endpoint protection",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Bitdefender GravityZone",
        "vendor": "Bitdefender",
        "service_names": [
            "epagent", "epicagentsvc", "bdagent",
            "bitdefender endpoint", "updatesrv",
        ],
        "software_patterns": ["bitdefender gravityzone", "bitdefender endpoint"],
        "description": "Bitdefender enterprise endpoint security",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Malwarebytes EDR",
        "vendor": "Malwarebytes",
        "service_names": ["malwarebytesservice", "mbam", "mbamservice"],
        "software_patterns": ["malwarebytes"],
        "description": "Malwarebytes endpoint remediation & protection",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Palo Alto Cortex XDR",
        "vendor": "Palo Alto Networks",
        "service_names": ["cyvera", "cortexdr", "traps", "cyveraconsole"],
        "software_patterns": ["cortex xdr", "palo alto traps"],
        "description": "Palo Alto XDR agent (formerly Traps)",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "Huntress Agent",
        "vendor": "Huntress",
        "service_names": ["huntressagent", "huntress"],
        "software_patterns": ["huntress"],
        "description": "Managed threat detection for SMB / MSP",
    },
    {
        "category": "EDR",
        "control_type": "edr",
        "product": "WithSecure Elements",
        "vendor": "WithSecure / F-Secure",
        "service_names": ["fsmaagent", "fsma", "fsdevdaemon"],
        "software_patterns": ["f-secure", "withsecure elements"],
        "description": "F-Secure / WithSecure endpoint protection",
    },

    # ──────────────────────────────────────────────────────────
    # AV (standalone / legacy)
    # ──────────────────────────────────────────────────────────
    {
        "category": "AV",
        "control_type": "av",
        "product": "Windows Defender Antivirus",
        "vendor": "Microsoft",
        "service_names": ["windefend", "wdnissvc", "wdnisuserservice"],
        "software_patterns": ["windows defender"],
        "description": "Built-in Windows AV (distinct from MDE Sense service)",
    },
    {
        "category": "AV",
        "control_type": "av",
        "product": "Avast Business",
        "vendor": "Avast / NortonLifeLock",
        "service_names": ["avastsvc", "avastanti", "avastnetwork"],
        "software_patterns": ["avast"],
        "description": "Avast business endpoint AV",
    },
    {
        "category": "AV",
        "control_type": "av",
        "product": "AVG Antivirus",
        "vendor": "AVG / Avast",
        "service_names": ["avgidsagent", "avgwdsvc", "avgemcsvc"],
        "software_patterns": ["avg antivirus", "avg internet security"],
        "description": "AVG consumer / SMB AV",
    },
    {
        "category": "AV",
        "control_type": "av",
        "product": "Avira",
        "vendor": "Avira",
        "service_names": ["avirainfoservice", "aviraupdater", "avshadow"],
        "software_patterns": ["avira"],
        "description": "Avira endpoint security",
    },
    {
        "category": "AV",
        "control_type": "av",
        "product": "Panda Adaptive Defense",
        "vendor": "Panda / WatchGuard",
        "service_names": ["pav_agent", "pandaantivirus"],
        "software_patterns": ["panda security", "watchguard epdr"],
        "description": "WatchGuard / Panda adaptive AV",
    },

    # ──────────────────────────────────────────────────────────
    # Firewall (host-based)
    # ──────────────────────────────────────────────────────────
    {
        "category": "Firewall",
        "control_type": "firewall",
        "product": "Windows Firewall",
        "vendor": "Microsoft",
        "service_names": ["mpssvc", "windefendfw"],
        "software_patterns": [],
        "description": "Windows built-in host firewall",
    },
    {
        "category": "Firewall",
        "control_type": "firewall",
        "product": "Fortinet FortiClient Firewall",
        "vendor": "Fortinet",
        "service_names": [
            "forticlient", "forticlientservice", "fortishield",
        ],
        "software_patterns": ["forticlient", "fortinet endpoint"],
        "description": "FortiClient host-based firewall / ZTNA",
    },
    {
        "category": "Firewall",
        "control_type": "firewall",
        "product": "Check Point Endpoint",
        "vendor": "Check Point",
        "service_names": ["cpd", "fwd", "cpqos", "checkpoint endpoint"],
        "software_patterns": ["check point endpoint", "checkpoint harmony"],
        "description": "Check Point endpoint security blade",
    },
    {
        "category": "Firewall",
        "control_type": "firewall",
        "product": "Symantec Endpoint Firewall",
        "vendor": "Broadcom / Symantec",
        "service_names": ["smcservice"],
        "software_patterns": ["symantec network access"],
        "description": "Symantec host-based firewall",
    },

    # ──────────────────────────────────────────────────────────
    # VPN / Remote Access
    # ──────────────────────────────────────────────────────────
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "Cisco AnyConnect",
        "vendor": "Cisco",
        "service_names": [
            "vpnagent", "csc_vpnagent", "cisco anyconnect", "vpnui",
        ],
        "software_patterns": ["cisco anyconnect", "cisco secure client"],
        "description": "Cisco SSL VPN client",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "Palo Alto GlobalProtect",
        "vendor": "Palo Alto Networks",
        "service_names": ["pangps", "pangpsd", "panhealth", "globalprotect"],
        "software_patterns": ["globalprotect"],
        "description": "PAN GlobalProtect VPN / ZTNA client",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "OpenVPN",
        "vendor": "OpenVPN Inc.",
        "service_names": [
            "openvpnservice", "openvpn", "openvpn-gui",
        ],
        "software_patterns": ["openvpn"],
        "description": "Open-source VPN",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "Ivanti Secure Access",
        "vendor": "Ivanti / Pulse Secure",
        "service_names": [
            "pulsesecureservice", "ivanticlient", "ivantisecure",
        ],
        "software_patterns": ["ivanti secure", "pulse secure", "pulse connect"],
        "description": "Ivanti / Pulse Secure SSL VPN",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "F5 BIG-IP Edge Client",
        "vendor": "F5",
        "service_names": ["f5_svcs", "f5edgeclient", "f5bigip"],
        "software_patterns": ["f5 edge client", "f5 big-ip"],
        "description": "F5 VPN client",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "WireGuard",
        "vendor": "WireGuard LLC",
        "service_names": ["wireguard", "wg_service"],
        "software_patterns": ["wireguard"],
        "description": "Modern, fast VPN tunnel",
    },
    {
        "category": "VPN",
        "control_type": "vpn",
        "product": "SonicWall NetExtender",
        "vendor": "SonicWall",
        "service_names": ["netextender", "sonicwall"],
        "software_patterns": ["netextender", "sonicwall vpn"],
        "description": "SonicWall SSL VPN client",
    },

    # ──────────────────────────────────────────────────────────
    # SASE / ZTNA
    # ──────────────────────────────────────────────────────────
    {
        "category": "SASE",
        "control_type": "sase",
        "product": "Zscaler Client Connector",
        "vendor": "Zscaler",
        "service_names": [
            "zsatray", "zscalerservice", "zscaler tunnel",
            "zscalerclient",
        ],
        "software_patterns": ["zscaler client connector", "zscaler"],
        "description": "Zscaler Internet Access / Private Access agent",
    },
    {
        "category": "SASE",
        "control_type": "sase",
        "product": "Netskope Client",
        "vendor": "Netskope",
        "service_names": ["stagentsvc", "netskope", "stcore"],
        "software_patterns": ["netskope client"],
        "description": "Netskope SASE / CASB agent",
    },
    {
        "category": "SASE",
        "control_type": "sase",
        "product": "Cloudflare WARP",
        "vendor": "Cloudflare",
        "service_names": ["cloudflarewarp", "warp", "cloudflare warp"],
        "software_patterns": ["cloudflare warp", "1.1.1.1 warp"],
        "description": "Cloudflare SASE / Zero Trust client",
    },
    {
        "category": "SASE",
        "control_type": "sase",
        "product": "Prisma Access (GlobalProtect)",
        "vendor": "Palo Alto Networks",
        "service_names": ["pangps"],
        "software_patterns": ["prisma access"],
        "description": "Palo Alto Prisma SASE via GP agent",
    },
    {
        "category": "SASE",
        "control_type": "sase",
        "product": "Cato Client",
        "vendor": "Cato Networks",
        "service_names": ["catoclient", "catoservice"],
        "software_patterns": ["cato client", "cato networks"],
        "description": "Cato SD-WAN / SASE client",
    },

    # ──────────────────────────────────────────────────────────
    # DLP
    # ──────────────────────────────────────────────────────────
    {
        "category": "DLP",
        "control_type": "dlp",
        "product": "Symantec DLP Agent",
        "vendor": "Broadcom / Symantec",
        "service_names": ["edpa", "symantec dlp"],
        "software_patterns": ["symantec data loss prevention", "vontu"],
        "description": "Symantec endpoint DLP agent",
    },
    {
        "category": "DLP",
        "control_type": "dlp",
        "product": "Forcepoint DLP",
        "vendor": "Forcepoint",
        "service_names": ["fpefservice", "forcepoint dlp"],
        "software_patterns": ["forcepoint dlp", "websense endpoint"],
        "description": "Forcepoint endpoint DLP",
    },
    {
        "category": "DLP",
        "control_type": "dlp",
        "product": "Digital Guardian Agent",
        "vendor": "Fortra / Digital Guardian",
        "service_names": ["dgagent", "digitalguardian"],
        "software_patterns": ["digital guardian"],
        "description": "Digital Guardian data-centric endpoint DLP",
    },
    {
        "category": "DLP",
        "control_type": "dlp",
        "product": "McAfee DLP Endpoint",
        "vendor": "Trellix / McAfee",
        "service_names": ["mfedlpe", "mfedlpagent"],
        "software_patterns": ["mcafee data loss prevention", "trellix dlp"],
        "description": "McAfee / Trellix endpoint DLP",
    },
    {
        "category": "DLP",
        "control_type": "dlp",
        "product": "CoSoSys Endpoint Protector",
        "vendor": "CoSoSys",
        "service_names": ["cososysagent", "endpointprotector"],
        "software_patterns": ["endpoint protector", "cososys"],
        "description": "Cross-platform DLP agent",
    },

    # ──────────────────────────────────────────────────────────
    # Identity / PAM / IAM
    # ──────────────────────────────────────────────────────────
    {
        "category": "PAM",
        "control_type": "identity",
        "product": "CyberArk Privileged Access Manager",
        "vendor": "CyberArk",
        "service_names": [
            "privateark", "cyberark vault", "caservicetask",
            "cyberark", "capbimsg",
        ],
        "software_patterns": ["cyberark"],
        "description": "CyberArk PAM / vault agent",
    },
    {
        "category": "PAM",
        "control_type": "identity",
        "product": "BeyondTrust PAM",
        "vendor": "BeyondTrust",
        "service_names": [
            "pbsmd", "beyondtrust", "bomgar",
            "btwebserver", "pbmas",
        ],
        "software_patterns": ["beyondtrust", "bomgar"],
        "description": "BeyondTrust privileged access / remote support",
    },
    {
        "category": "PAM",
        "control_type": "identity",
        "product": "Delinea Secret Server",
        "vendor": "Delinea / Thycotic",
        "service_names": ["thycotic", "delinea", "secretserveragent"],
        "software_patterns": ["thycotic", "delinea", "secret server"],
        "description": "Delinea / Thycotic PAM vault",
    },
    {
        "category": "IAM",
        "control_type": "identity",
        "product": "Azure AD Connect",
        "vendor": "Microsoft",
        "service_names": ["adsync", "microsoftazureadconnect"],
        "software_patterns": ["azure ad connect", "microsoft entra connect"],
        "description": "Hybrid identity sync to Azure AD / Entra ID",
    },
    {
        "category": "IAM",
        "control_type": "identity",
        "product": "Centrify / Delinea Server Suite",
        "vendor": "Delinea / Centrify",
        "service_names": ["centrifydc", "centrify", "adagent"],
        "software_patterns": ["centrify", "delinea server"],
        "description": "Centrify AD-bridging / PAM agent",
    },
    {
        "category": "IAM",
        "control_type": "identity",
        "product": "Duo Device Health App",
        "vendor": "Cisco Duo",
        "service_names": ["duodevicehealth", "duo security"],
        "software_patterns": ["duo device health", "duo security"],
        "description": "Duo MFA / device health agent",
    },
    {
        "category": "IAM",
        "control_type": "identity",
        "product": "Okta Device Trust",
        "vendor": "Okta",
        "service_names": ["okta", "oktadeviceaccessagent"],
        "software_patterns": ["okta device trust", "okta verify"],
        "description": "Okta device trust agent",
    },
    {
        "category": "IAM",
        "control_type": "identity",
        "product": "Active Directory Domain Services",
        "vendor": "Microsoft",
        "service_names": ["ntds", "kdc", "netlogon", "adws", "dns"],
        "software_patterns": [],
        "description": "Active Directory Domain Services (DC presence)",
    },

    # ──────────────────────────────────────────────────────────
    # Vulnerability Management (VM)
    # ──────────────────────────────────────────────────────────
    {
        "category": "VM",
        "control_type": "vulnerability_management",
        "product": "Tenable Nessus Agent",
        "vendor": "Tenable",
        "service_names": ["nessusd", "nessus", "tenableagent"],
        "software_patterns": ["nessus agent", "tenable agent"],
        "description": "Tenable Nessus vulnerability scanner agent",
    },
    {
        "category": "VM",
        "control_type": "vulnerability_management",
        "product": "Qualys Cloud Agent",
        "vendor": "Qualys",
        "service_names": ["qualysagent", "qualyscloudagent", "qagent"],
        "software_patterns": ["qualys cloud agent"],
        "description": "Qualys continuous assessment agent",
    },
    {
        "category": "VM",
        "control_type": "vulnerability_management",
        "product": "Rapid7 Insight Agent",
        "vendor": "Rapid7",
        "service_names": ["ir_agent", "rapid7insightagent", "nexpose"],
        "software_patterns": ["rapid7 insight agent", "rapid7"],
        "description": "Rapid7 InsightVM / InsightIDR agent",
    },
    {
        "category": "VM",
        "control_type": "vulnerability_management",
        "product": "Microsoft Defender Vulnerability Management",
        "vendor": "Microsoft",
        "service_names": ["sense"],   # shared with MDE
        "software_patterns": ["microsoft defender vulnerability management"],
        "description": "MDE built-in vulnerability assessment",
    },

    # ──────────────────────────────────────────────────────────
    # SIEM / Log Forwarding
    # ──────────────────────────────────────────────────────────
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "Splunk Universal Forwarder",
        "vendor": "Splunk / Cisco",
        "service_names": [
            "splunkforwarder", "splunkd", "splunk",
        ],
        "software_patterns": ["splunk universal forwarder", "splunk forwarder"],
        "description": "Splunk log collection agent",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "Elastic Agent / Winlogbeat",
        "vendor": "Elastic",
        "service_names": [
            "elastic-agent", "winlogbeat", "filebeat",
            "metricbeat", "elasticagent",
        ],
        "software_patterns": ["elastic agent", "winlogbeat", "filebeat"],
        "description": "Elastic stack endpoint agent / log shipper",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "LogRhythm System Monitor",
        "vendor": "LogRhythm",
        "service_names": ["lrlogsourcevirtualization", "logrhythm"],
        "software_patterns": ["logrhythm"],
        "description": "LogRhythm SIEM agent",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "IBM QRadar SIEM WinCollect",
        "vendor": "IBM",
        "service_names": ["wincollect", "ibm qradar", "qradar"],
        "software_patterns": ["wincollect", "ibm qradar"],
        "description": "IBM QRadar Windows log collector",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "NXLog",
        "vendor": "NXLog",
        "service_names": ["nxlog"],
        "software_patterns": ["nxlog"],
        "description": "Universal log collection agent",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "Azure Monitor Agent",
        "vendor": "Microsoft",
        "service_names": ["azuremonitoragent", "omscontinuousdiagnostics"],
        "software_patterns": ["azure monitor agent", "log analytics agent"],
        "description": "Microsoft Azure Monitor / Sentinel log agent",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "Microsoft Security Events Collector",
        "vendor": "Microsoft",
        "service_names": [
            "seclogon", "eventsystem", "eventlog",
        ],
        "software_patterns": [],
        "description": "Windows Security Event Log collection",
    },
    {
        "category": "SIEM",
        "control_type": "siem",
        "product": "Graylog Sidecar",
        "vendor": "Graylog",
        "service_names": ["graylog-sidecar", "graylog_sidecar"],
        "software_patterns": ["graylog sidecar"],
        "description": "Graylog log collector sidecar",
    },

    # ──────────────────────────────────────────────────────────
    # MDR / Managed Security
    # ──────────────────────────────────────────────────────────
    {
        "category": "MDR",
        "control_type": "edr",
        "product": "Arctic Wolf Agent",
        "vendor": "Arctic Wolf",
        "service_names": ["arcticwolfagent", "arcticwolf"],
        "software_patterns": ["arctic wolf"],
        "description": "Arctic Wolf managed detection & response agent",
    },
    {
        "category": "MDR",
        "control_type": "edr",
        "product": "Orca Security Agent",
        "vendor": "Orca Security",
        "service_names": ["orcaagent"],
        "software_patterns": ["orca security"],
        "description": "Orca cloud security agent",
    },

    # ──────────────────────────────────────────────────────────
    # Backup / Recovery
    # ──────────────────────────────────────────────────────────
    {
        "category": "Backup",
        "control_type": "backup",
        "product": "Veeam Backup",
        "vendor": "Veeam",
        "service_names": [
            "veeambackupsvc", "veeamcatalogdataservice",
            "veeamdeployservice", "veeamtransportsvc", "veeam",
        ],
        "software_patterns": ["veeam backup", "veeam agent"],
        "description": "Veeam backup and replication agent",
    },
    {
        "category": "Backup",
        "control_type": "backup",
        "product": "Veritas NetBackup",
        "vendor": "Veritas",
        "service_names": ["beagent", "veritas", "bpcd", "nbcd"],
        "software_patterns": ["veritas netbackup", "symantec backup exec"],
        "description": "Veritas enterprise backup agent",
    },
    {
        "category": "Backup",
        "control_type": "backup",
        "product": "Commvault",
        "vendor": "Commvault",
        "service_names": ["gxfwd", "gxclbackup", "commvault", "cvd"],
        "software_patterns": ["commvault"],
        "description": "Commvault data protection agent",
    },
    {
        "category": "Backup",
        "control_type": "backup",
        "product": "Acronis Cyber Protect",
        "vendor": "Acronis",
        "service_names": [
            "acronisvssrequestor", "managedmachineservice", "acronis",
        ],
        "software_patterns": ["acronis cyber protect", "acronis backup"],
        "description": "Acronis backup + AV integration agent",
    },
    {
        "category": "Backup",
        "control_type": "backup",
        "product": "Windows Server Backup",
        "vendor": "Microsoft",
        "service_names": ["wbengine", "swprv"],
        "software_patterns": [],
        "description": "Windows Server built-in backup",
    },

    # ──────────────────────────────────────────────────────────
    # Encryption
    # ──────────────────────────────────────────────────────────
    {
        "category": "Encryption",
        "control_type": "encryption",
        "product": "BitLocker",
        "vendor": "Microsoft",
        "service_names": ["bdesvc"],
        "software_patterns": [],
        "description": "Windows BitLocker drive encryption service",
    },
    {
        "category": "Encryption",
        "control_type": "encryption",
        "product": "Symantec Encryption",
        "vendor": "Broadcom / PGP",
        "service_names": ["pgpopsvc", "symantec encryption"],
        "software_patterns": ["symantec encryption", "pgp desktop"],
        "description": "PGP / Symantec full-disk encryption",
    },
    {
        "category": "Encryption",
        "control_type": "encryption",
        "product": "Sophos SafeGuard",
        "vendor": "Sophos",
        "service_names": ["sgn", "sophossafeguard"],
        "software_patterns": ["sophos safeguard"],
        "description": "Sophos SafeGuard disk encryption",
    },

    # ──────────────────────────────────────────────────────────
    # NAC / Network Access Control
    # ──────────────────────────────────────────────────────────
    {
        "category": "NAC",
        "control_type": "nac",
        "product": "Cisco ISE Posture Agent",
        "vendor": "Cisco",
        "service_names": ["ciscoacagent", "nacagent", "ciscoac"],
        "software_patterns": ["cisco network access control", "cisco nac agent"],
        "description": "Cisco ISE endpoint posture agent",
    },
    {
        "category": "NAC",
        "control_type": "nac",
        "product": "Forescout Agent",
        "vendor": "Forescout",
        "service_names": ["fscoutd", "forescout"],
        "software_patterns": ["forescout"],
        "description": "Forescout device visibility agent",
    },
    {
        "category": "NAC",
        "control_type": "nac",
        "product": "Aruba ClearPass",
        "vendor": "Aruba / HPE",
        "service_names": ["clearpassagent", "arubaclearpass"],
        "software_patterns": ["aruba clearpass", "clearpass onguard"],
        "description": "Aruba ClearPass NAC posture agent",
    },

    # ──────────────────────────────────────────────────────────
    # Patch / Endpoint Management
    # ──────────────────────────────────────────────────────────
    {
        "category": "Patch Management",
        "control_type": "patch_management",
        "product": "Microsoft WSUS / Windows Update",
        "vendor": "Microsoft",
        "service_names": ["wuauserv", "usosvc", "dosvc"],
        "software_patterns": [],
        "description": "Windows Automatic Update / WSUS client",
    },
    {
        "category": "Patch Management",
        "control_type": "patch_management",
        "product": "Microsoft SCCM / Intune Agent",
        "vendor": "Microsoft",
        "service_names": ["ccmexec", "sms_executive", "sccmexec"],
        "software_patterns": ["configuration manager", "sccm client", "intune management"],
        "description": "Microsoft SCCM / ConfigMgr endpoint agent",
    },
    {
        "category": "Patch Management",
        "control_type": "patch_management",
        "product": "Ivanti Patch",
        "vendor": "Ivanti",
        "service_names": [
            "ivantiservicemgr", "ivantiagent", "lenovo_pm",
        ],
        "software_patterns": ["ivanti patch", "shavlik patch"],
        "description": "Ivanti patch management agent",
    },
    {
        "category": "Patch Management",
        "control_type": "patch_management",
        "product": "ManageEngine Patch Manager",
        "vendor": "ManageEngine / Zoho",
        "service_names": ["desktopcentral", "manageengineagent", "uems_agent"],
        "software_patterns": ["manageengine", "patch manager plus"],
        "description": "ManageEngine endpoint patch management",
    },
    {
        "category": "Patch Management",
        "control_type": "patch_management",
        "product": "Automox Agent",
        "vendor": "Automox",
        "service_names": ["automox"],
        "software_patterns": ["automox"],
        "description": "Cloud-native cross-platform patch agent",
    },

    # ──────────────────────────────────────────────────────────
    # NDR / Network Detection
    # ──────────────────────────────────────────────────────────
    {
        "category": "NDR",
        "control_type": "ndr",
        "product": "Darktrace Endpoint Sensor",
        "vendor": "Darktrace",
        "service_names": ["darktrace", "darktraceagent"],
        "software_patterns": ["darktrace"],
        "description": "Darktrace AI network detection agent",
    },
    {
        "category": "NDR",
        "control_type": "ndr",
        "product": "Vectra AI Sensor",
        "vendor": "Vectra AI",
        "service_names": ["vectraagent"],
        "software_patterns": ["vectra ai"],
        "description": "Vectra AI network detection sensor",
    },
    {
        "category": "NDR",
        "control_type": "ndr",
        "product": "ExtraHop Agent",
        "vendor": "ExtraHop / CrowdStrike",
        "service_names": ["extrahop"],
        "software_patterns": ["extrahop"],
        "description": "ExtraHop network analytics agent",
    },
    {
        "category": "NDR",
        "control_type": "ndr",
        "product": "Corelight Sensor",
        "vendor": "Corelight",
        "service_names": ["broscript", "zeek"],
        "software_patterns": ["corelight", "zeek"],
        "description": "Corelight / Zeek network sensor",
    },

    # ──────────────────────────────────────────────────────────
    # Container / Cloud Security
    # ──────────────────────────────────────────────────────────
    {
        "category": "Container Security",
        "control_type": "container_security",
        "product": "Prisma Cloud Defender",
        "vendor": "Palo Alto Networks",
        "service_names": ["twistlock", "prismaclouddefender"],
        "software_patterns": ["prisma cloud", "twistlock"],
        "description": "Palo Alto Prisma Cloud workload defender",
    },
    {
        "category": "Container Security",
        "control_type": "container_security",
        "product": "Aqua Security Agent",
        "vendor": "Aqua Security",
        "service_names": ["aqua-agent", "aquaagent"],
        "software_patterns": ["aqua security", "aqua agent"],
        "description": "Aqua cloud-native security agent",
    },
    {
        "category": "Container Security",
        "control_type": "container_security",
        "product": "Sysdig Agent",
        "vendor": "Sysdig",
        "service_names": ["dragent", "sysdig"],
        "software_patterns": ["sysdig"],
        "description": "Sysdig unified cloud security agent",
    },

    # ──────────────────────────────────────────────────────────
    # Email Security (host agent indicators)
    # ──────────────────────────────────────────────────────────
    {
        "category": "Email Security",
        "control_type": "email_security",
        "product": "Proofpoint Email Protection Agent",
        "vendor": "Proofpoint",
        "service_names": ["proofpointagent", "proofpoint"],
        "software_patterns": ["proofpoint"],
        "description": "Proofpoint e-mail / DLP agent",
    },

    # ──────────────────────────────────────────────────────────
    # Compliance / Integrity Monitoring
    # ──────────────────────────────────────────────────────────
    {
        "category": "Integrity Monitoring",
        "control_type": "integrity_monitoring",
        "product": "Tripwire Enterprise",
        "vendor": "Fortra / Tripwire",
        "service_names": ["tripwire", "twagent"],
        "software_patterns": ["tripwire"],
        "description": "File integrity monitoring agent",
    },
    {
        "category": "Integrity Monitoring",
        "control_type": "integrity_monitoring",
        "product": "OSSEC / Wazuh Agent",
        "vendor": "Wazuh / OSSEC",
        "service_names": ["wazuh-agent", "wazuh", "ossec", "ossec-agent"],
        "software_patterns": ["wazuh", "ossec"],
        "description": "Open-source HIDS / SIEM agent",
    },
    {
        "category": "Integrity Monitoring",
        "control_type": "integrity_monitoring",
        "product": "Qualys FIM",
        "vendor": "Qualys",
        "service_names": ["qualysfim"],
        "software_patterns": ["qualys file integrity monitoring"],
        "description": "Qualys cloud-native FIM agent",
    },

    # ──────────────────────────────────────────────────────────
    # Remote Management / RMM
    # ──────────────────────────────────────────────────────────
    {
        "category": "RMM",
        "control_type": "remote_management",
        "product": "ConnectWise Automate",
        "vendor": "ConnectWise",
        "service_names": ["ltservice", "ltsvc", "labtech"],
        "software_patterns": ["labtech agent", "connectwise automate"],
        "description": "ConnectWise Automate / LabTech RMM agent",
    },
    {
        "category": "RMM",
        "control_type": "remote_management",
        "product": "Kaseya VSA Agent",
        "vendor": "Kaseya",
        "service_names": ["agentmon", "kaseyaagent", "kaseya"],
        "software_patterns": ["kaseya"],
        "description": "Kaseya IT management agent",
    },
    {
        "category": "RMM",
        "control_type": "remote_management",
        "product": "NinjaRMM Agent",
        "vendor": "NinjaRMM",
        "service_names": ["ninjaagent", "ninjarmm"],
        "software_patterns": ["ninjarmm", "ninjarmm agent"],
        "description": "NinjaRMM monitoring and management agent",
    },
    {
        "category": "RMM",
        "control_type": "remote_management",
        "product": "N-able Agent",
        "vendor": "N-able",
        "service_names": ["nable", "mspanywhere"],
        "software_patterns": ["n-able", "solarwinds n-central"],
        "description": "N-able / N-central managed services agent",
    },
    {
        "category": "RMM",
        "control_type": "remote_management",
        "product": "Datto RMM Agent",
        "vendor": "Datto / Kaseya",
        "service_names": ["cagservice", "dattoagent", "datto"],
        "software_patterns": ["datto rmm"],
        "description": "Datto remote monitoring agent",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Pre-computed lookup index: lowercase service name → catalog entry
# ──────────────────────────────────────────────────────────────────────────────

def _build_service_index(catalog: list) -> dict:
    idx = {}
    for entry in catalog:
        for svc in entry["service_names"]:
            key = svc.lower().strip()
            if key and key not in idx:
                idx[key] = entry
    return idx


def _build_software_index(catalog: list) -> list:
    """Returns list of (pattern_lower, catalog_entry) sorted longest-first for greedy matching."""
    pairs = []
    for entry in catalog:
        for pat in entry["software_patterns"]:
            if pat:
                pairs.append((pat.lower().strip(), entry))
    pairs.sort(key=lambda x: -len(x[0]))
    return pairs


SERVICE_INDEX = _build_service_index(SECURITY_TOOL_CATALOG)
SOFTWARE_INDEX = _build_software_index(SECURITY_TOOL_CATALOG)


def match_service(service_name: str, display_name: str = ""):
    """Return catalog entry if the service matches a known security tool, else None."""
    sn = (service_name or "").lower().strip()
    dn = (display_name or "").lower().strip()

    # Exact service-name match
    if sn in SERVICE_INDEX:
        return SERVICE_INDEX[sn]

    # Substring match inside display_name against service_name patterns
    for key, entry in SERVICE_INDEX.items():
        if key and (key in sn or key in dn):
            return entry

    return None


def match_software(software_name: str):
    """Return catalog entry if installed software matches a known security tool, else None."""
    name = (software_name or "").lower().strip()
    for pattern, entry in SOFTWARE_INDEX:
        if pattern in name:
            return entry
    return None

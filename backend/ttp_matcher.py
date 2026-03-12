"""
MITRE ATT&CK TTP Matcher for Nessus findings.

Matches findings to ATT&CK techniques using three signal sources:
  1. Plugin ID → exact technique (highest confidence, from known Nessus plugins)
  2. Keyword match on plugin_name + synopsis (medium-high confidence)
  3. Plugin family → tactic heuristic (fallback, medium confidence)

Output per matched TTP:
  {technique_id, name, tactic, mitre_url, match_reason, confidence}
"""
import re
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def _url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


# ──────────────────────────────────────────────────────────
# 1. Plugin ID → TTP (exact, high confidence)
# ──────────────────────────────────────────────────────────

PLUGIN_ID_MAP: Dict[str, List[dict]] = {
    # AD / domain user enumeration
    "69239": [{"technique_id": "T1087.002", "name": "Account Discovery: Domain Account", "tactic": "discovery"}],
    # Local user SID enumeration
    "10860": [{"technique_id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "discovery"}],
    # Local Administrators group members
    "10902": [{"technique_id": "T1069.001", "name": "Permission Groups Discovery: Local Groups", "tactic": "discovery"}],
    # Last logged-on user
    "38689": [{"technique_id": "T1033",     "name": "System Owner/User Discovery", "tactic": "discovery"}],
    # AD group memberships (full)
    "69238": [{"technique_id": "T1069.002", "name": "Permission Groups Discovery: Domain Groups", "tactic": "discovery"}],
    # LDAP groups (JSON format)
    "167251": [{"technique_id": "T1069.002", "name": "Permission Groups Discovery: Domain Groups", "tactic": "discovery"}],
    # Running services
    "10456": [{"technique_id": "T1007",     "name": "System Service Discovery", "tactic": "discovery"}],
    # Netstat connections (structured)
    "64582": [{"technique_id": "T1049",     "name": "System Network Connections Discovery", "tactic": "discovery"}],
    # Netstat active (raw)
    "58651": [{"technique_id": "T1049",     "name": "System Network Connections Discovery", "tactic": "discovery"}],
    # Scheduled tasks
    "70625": [{"technique_id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "persistence"}],
    # Patch report (missing KBs)
    "66334": [{"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"}],
    # Currently logged-on users
    "161502": [{"technique_id": "T1033",    "name": "System Owner/User Discovery", "tactic": "discovery"}],
    # Windows SMB shares
    "10395": [{"technique_id": "T1135",     "name": "Network Share Discovery", "tactic": "discovery"}],
    # NFS shares
    "11356": [{"technique_id": "T1135",     "name": "Network Share Discovery", "tactic": "discovery"}],
    # Open ports / TCP SYN scan
    "11219": [{"technique_id": "T1046",     "name": "Network Service Discovery", "tactic": "discovery"}],
    # SNMP public community string
    "10264": [{"technique_id": "T1078",     "name": "Valid Accounts", "tactic": "defense-evasion"},
              {"technique_id": "T1040",     "name": "Network Sniffing", "tactic": "credential-access"}],
    # Anonymous FTP
    "10079": [{"technique_id": "T1078.001", "name": "Valid Accounts: Default Accounts", "tactic": "defense-evasion"}],
    # Telnet server
    "10281": [{"technique_id": "T1040",     "name": "Network Sniffing", "tactic": "credential-access"},
              {"technique_id": "T1021",     "name": "Remote Services", "tactic": "lateral-movement"}],
    # RDP enabled
    "18405": [{"technique_id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "lateral-movement"}],
    # MS17-010 (EternalBlue)
    "97833": [{"technique_id": "T1210",     "name": "Exploitation of Remote Services", "tactic": "lateral-movement"},
              {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"}],
    "97737": [{"technique_id": "T1210",     "name": "Exploitation of Remote Services", "tactic": "lateral-movement"}],
    # Heartbleed
    "73412": [{"technique_id": "T1040",     "name": "Network Sniffing", "tactic": "credential-access"},
              {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"}],
    # Shellshock
    "77061": [{"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
              {"technique_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell", "tactic": "execution"}],
    # Log4Shell
    "155999": [{"technique_id": "T1190",    "name": "Exploit Public-Facing Application", "tactic": "initial-access"}],
    "156032": [{"technique_id": "T1190",    "name": "Exploit Public-Facing Application", "tactic": "initial-access"}],
    # Windows DNS cache
    "12218": [{"technique_id": "T1016",     "name": "System Network Configuration Discovery", "tactic": "discovery"}],
    # ARP table
    "10910": [{"technique_id": "T1016",     "name": "System Network Configuration Discovery", "tactic": "discovery"}],
    # Installed software (Windows)
    "20811": [{"technique_id": "T1518",     "name": "Software Discovery", "tactic": "discovery"}],
    # OS version / system info
    "11936": [{"technique_id": "T1082",     "name": "System Information Discovery", "tactic": "discovery"}],
    # Windows firewall status
    "57608": [{"technique_id": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "defense-evasion"}],
    # Windows Defender/AV status
    "42410": [{"technique_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "defense-evasion"}],
    # SAM database accessible
    "26920": [{"technique_id": "T1003.002", "name": "OS Credential Dumping: SAM", "tactic": "credential-access"}],
    # Password policy
    "10394": [{"technique_id": "T1201",     "name": "Password Policy Discovery", "tactic": "discovery"}],
    # Kerberos enumeration
    "23938": [{"technique_id": "T1558",     "name": "Steal or Forge Kerberos Tickets", "tactic": "credential-access"}],
    # SMB signing disabled
    "57608": [{"technique_id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "tactic": "credential-access"}],
    # LSASS memory accessible
    "26917": [{"technique_id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access"}],
}


# ──────────────────────────────────────────────────────────
# 2. Keyword rules — matched against plugin_name + synopsis
# ──────────────────────────────────────────────────────────

# Each rule: (keywords_list, TTP_dict)
# All keywords must be lowercase; matching is case-insensitive substring search.
# First matching keyword triggers the rule.

KEYWORD_RULES: List[tuple] = [
    # ── Credential Access ──────────────────────────────────
    (["lsass", "lsa secrets", "lsa memory dump"],
     {"technique_id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access", "confidence": "high"}),

    (["sam database", "security account manager", "samdump", "hklm\\sam"],
     {"technique_id": "T1003.002", "name": "OS Credential Dumping: Security Account Manager", "tactic": "credential-access", "confidence": "high"}),

    (["ntds.dit", "ntds database", "domain controller credentials"],
     {"technique_id": "T1003.003", "name": "OS Credential Dumping: NTDS", "tactic": "credential-access", "confidence": "high"}),

    (["kerberoast", "service ticket", "rc4-hmac", "spn scan"],
     {"technique_id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "credential-access", "confidence": "high"}),

    (["as-rep roast", "asrep", "as_rep", "pre-authentication not required", "dont_require_preauth"],
     {"technique_id": "T1558.004", "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "credential-access", "confidence": "high"}),

    (["golden ticket", "pass-the-ticket", "pass the ticket", "kerberos ticket"],
     {"technique_id": "T1550.003", "name": "Use Alternate Authentication Material: Pass the Ticket", "tactic": "defense-evasion", "confidence": "high"}),

    (["pass-the-hash", "pass the hash", "pth attack", "ntlm hash relay"],
     {"technique_id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash", "tactic": "defense-evasion", "confidence": "high"}),

    (["credential dump", "mimikatz", "wdigest", "lsadump"],
     {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "credential-access", "confidence": "high"}),

    (["cleartext password", "plaintext password", "password in clear", "password transmitted in clear",
      "unencrypted password", "password in plaintext", "basic auth"],
     {"technique_id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files", "tactic": "credential-access", "confidence": "medium"}),

    (["password policy", "minimum password", "password complexity", "account lockout policy"],
     {"technique_id": "T1201", "name": "Password Policy Discovery", "tactic": "discovery", "confidence": "high"}),

    (["snmp community string", "snmp default", "snmp public", "snmp write"],
     {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "defense-evasion", "confidence": "medium"}),

    (["default credential", "default password", "factory default", "default username"],
     {"technique_id": "T1078.001", "name": "Valid Accounts: Default Accounts", "tactic": "defense-evasion", "confidence": "high"}),

    (["brute force", "brute-force", "brute_force", "password brute", "login attempt"],
     {"technique_id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "credential-access", "confidence": "high"}),

    (["password spray", "password spraying"],
     {"technique_id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "credential-access", "confidence": "high"}),

    (["weak password", "blank password", "empty password", "null password"],
     {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "defense-evasion", "confidence": "medium"}),

    # ── Lateral Movement / Remote Services ────────────────
    (["remote desktop", "rdp", "ms-rdp", "terminal services"],
     {"technique_id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "lateral-movement", "confidence": "medium"}),

    (["smb", "samba", "cifs", "ms-ds-replication", "psexec"],
     {"technique_id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "lateral-movement", "confidence": "medium"}),

    (["wmi ", "wmic ", "windows management instrumentation"],
     {"technique_id": "T1021.003", "name": "Remote Services: Distributed Component Object Model", "tactic": "lateral-movement", "confidence": "medium"}),

    (["ssh brute", "ssh password", "ssh authentication failed", "ssh weak"],
     {"technique_id": "T1021.004", "name": "Remote Services: SSH", "tactic": "lateral-movement", "confidence": "high"}),

    (["vnc", "virtual network computing"],
     {"technique_id": "T1021.005", "name": "Remote Services: VNC", "tactic": "lateral-movement", "confidence": "high"}),

    (["winrm", "windows remote management", "ws-management"],
     {"technique_id": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "lateral-movement", "confidence": "high"}),

    (["telnet"],
     {"technique_id": "T1040", "name": "Network Sniffing", "tactic": "credential-access", "confidence": "medium"}),

    # ── Exploitation ───────────────────────────────────────
    (["ms17-010", "eternalblue", "eternal blue", "smb vulnerability"],
     {"technique_id": "T1210", "name": "Exploitation of Remote Services", "tactic": "lateral-movement", "confidence": "high"}),

    (["heartbleed", "openssl heartbeat"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),

    (["shellshock", "bash code injection", "cgi script"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),

    (["log4j", "log4shell", "jndi injection"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),

    (["remote code execution", "rce", "arbitrary code execution", "code execution"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "medium"}),

    (["privilege escalation", "local privilege", "elevation of privilege"],
     {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation", "confidence": "high"}),

    (["uac bypass", "user account control bypass"],
     {"technique_id": "T1548.002", "name": "Abuse Elevation Control Mechanism: Bypass User Account Control", "tactic": "privilege-escalation", "confidence": "high"}),

    # ── Discovery ──────────────────────────────────────────
    (["domain user", "domain account", "active directory user", "ldap user"],
     {"technique_id": "T1087.002", "name": "Account Discovery: Domain Account", "tactic": "discovery", "confidence": "high"}),

    (["local user", "local account", "windows user account", "sam account"],
     {"technique_id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "discovery", "confidence": "high"}),

    (["domain group", "ad group", "group membership", "group policy"],
     {"technique_id": "T1069.002", "name": "Permission Groups Discovery: Domain Groups", "tactic": "discovery", "confidence": "high"}),

    (["local group", "local administrator", "administrators group"],
     {"technique_id": "T1069.001", "name": "Permission Groups Discovery: Local Groups", "tactic": "discovery", "confidence": "high"}),

    (["network share", "smb share", "nfs share", "file share"],
     {"technique_id": "T1135", "name": "Network Share Discovery", "tactic": "discovery", "confidence": "high"}),

    (["netstat", "network connection", "listening port", "open connection"],
     {"technique_id": "T1049", "name": "System Network Connections Discovery", "tactic": "discovery", "confidence": "medium"}),

    (["dns cache", "dns lookup", "dns query", "dns record"],
     {"technique_id": "T1016", "name": "System Network Configuration Discovery", "tactic": "discovery", "confidence": "medium"}),

    (["arp table", "arp cache", "arp scan"],
     {"technique_id": "T1016", "name": "System Network Configuration Discovery", "tactic": "discovery", "confidence": "medium"}),

    (["installed software", "software inventory", "application list", "program files"],
     {"technique_id": "T1518", "name": "Software Discovery", "tactic": "discovery", "confidence": "high"}),

    (["operating system", "system version", "os detection", "os fingerprint", "system information"],
     {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "discovery", "confidence": "medium"}),

    (["scheduled task", "task scheduler", "at.exe", "schtask"],
     {"technique_id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "persistence", "confidence": "high"}),

    (["running process", "process list", "process enumeration", "tasklist"],
     {"technique_id": "T1057", "name": "Process Discovery", "tactic": "discovery", "confidence": "high"}),

    (["logged on user", "logged-on user", "current user", "whoami"],
     {"technique_id": "T1033", "name": "System Owner/User Discovery", "tactic": "discovery", "confidence": "high"}),

    (["open port", "port scan", "service detection", "port discovery"],
     {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "discovery", "confidence": "medium"}),

    # ── Persistence ────────────────────────────────────────
    (["autorun", "startup folder", "run key", "registry run", "hkcu\\software\\microsoft\\windows\\currentversion\\run"],
     {"technique_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "persistence", "confidence": "high"}),

    (["windows service", "service creation", "service installation", "sc.exe"],
     {"technique_id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactic": "persistence", "confidence": "medium"}),

    (["webshell", "web shell", "php shell", "aspx shell"],
     {"technique_id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "persistence", "confidence": "high"}),

    (["backdoor", "remote access trojan", "rat "],
     {"technique_id": "T1543", "name": "Create or Modify System Process", "tactic": "persistence", "confidence": "high"}),

    # ── Defense Evasion ────────────────────────────────────
    (["dll hijack", "dll search order", "dll side-loading", "dll injection"],
     {"technique_id": "T1574.001", "name": "Hijack Execution Flow: DLL Search Order Hijacking", "tactic": "defense-evasion", "confidence": "high"}),

    (["unquoted service path", "unquoted path"],
     {"technique_id": "T1574.009", "name": "Hijack Execution Flow: Path Interception by Unquoted Path", "tactic": "defense-evasion", "confidence": "high"}),

    (["windows firewall disabled", "firewall disabled", "firewall turned off", "host-based firewall"],
     {"technique_id": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "defense-evasion", "confidence": "high"}),

    (["antivirus disabled", "security software not running", "windows defender disabled", "av not running"],
     {"technique_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "defense-evasion", "confidence": "high"}),

    (["token impersonation", "access token", "impersonation privilege", "seimpersonateprivilege"],
     {"technique_id": "T1134.001", "name": "Access Token Manipulation: Token Impersonation/Theft", "tactic": "defense-evasion", "confidence": "high"}),

    # ── Execution ──────────────────────────────────────────
    (["powershell", "powershell script", "powershell execution"],
     {"technique_id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution", "confidence": "medium"}),

    (["cmd.exe", "command shell", "command interpreter", "batch file"],
     {"technique_id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "execution", "confidence": "medium"}),

    (["wscript", "cscript", "vbscript", "jscript"],
     {"technique_id": "T1059.005", "name": "Command and Scripting Interpreter: Visual Basic", "tactic": "execution", "confidence": "medium"}),

    (["wmi execution", "wmi process", "win32_process"],
     {"technique_id": "T1047", "name": "Windows Management Instrumentation", "tactic": "execution", "confidence": "high"}),

    (["bash ", "sh script", "unix shell", "shell script"],
     {"technique_id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell", "tactic": "execution", "confidence": "medium"}),

    # ── Credential Access (network/crypto) ─────────────────
    (["ssl weak", "ssl medium", "weak cipher", "weak encryption", "null cipher",
      "rc4 cipher", "export cipher", "ssl 3.0", "tls 1.0"],
     {"technique_id": "T1040", "name": "Network Sniffing", "tactic": "credential-access", "confidence": "medium"}),

    (["man-in-the-middle", "mitm", "ssl strip", "ssl interception"],
     {"technique_id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "credential-access", "confidence": "high"}),

    (["arp poison", "arp spoof", "arp cache poison"],
     {"technique_id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Cache Poisoning", "tactic": "credential-access", "confidence": "high"}),

    (["llmnr", "nbt-ns", "nbns poison", "responder"],
     {"technique_id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "credential-access", "confidence": "high"}),

    (["smb signing disabled", "smb signing not required", "smb signing not enforced"],
     {"technique_id": "T1557.001", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "tactic": "credential-access", "confidence": "high"}),

    # ── Collection / Exfil ─────────────────────────────────
    (["sensitive data", "pii", "personally identifiable", "credit card", "ssn"],
     {"technique_id": "T1213", "name": "Data from Information Repositories", "tactic": "collection", "confidence": "medium"}),

    (["ftp", "file transfer"],
     {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration", "confidence": "low"}),

    # ── Initial Access ─────────────────────────────────────
    (["anonymous ftp", "anonymous login", "anonymous access"],
     {"technique_id": "T1078.001", "name": "Valid Accounts: Default Accounts", "tactic": "defense-evasion", "confidence": "high"}),

    (["sql injection", "sqli"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),

    (["xss", "cross-site scripting"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "medium"}),

    (["xml injection", "xxe", "xml external entity"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),

    (["directory traversal", "path traversal", "local file inclusion", "lfi"],
     {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "high"}),
]


# ──────────────────────────────────────────────────────────
# 3. Plugin family fallback map
# ──────────────────────────────────────────────────────────

FAMILY_MAP: Dict[str, List[dict]] = {
    "Brute force attacks": [
        {"technique_id": "T1110",     "name": "Brute Force", "tactic": "credential-access", "confidence": "medium"},
    ],
    "Backdoors": [
        {"technique_id": "T1543",     "name": "Create or Modify System Process", "tactic": "persistence", "confidence": "medium"},
    ],
    "Credentials": [
        {"technique_id": "T1552",     "name": "Unsecured Credentials", "tactic": "credential-access", "confidence": "medium"},
    ],
    "Windows : User Management": [
        {"technique_id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "discovery", "confidence": "medium"},
    ],
    "Service detection": [
        {"technique_id": "T1046",     "name": "Network Service Discovery", "tactic": "discovery", "confidence": "low"},
    ],
    "RPC": [
        {"technique_id": "T1021",     "name": "Remote Services", "tactic": "lateral-movement", "confidence": "low"},
    ],
    "Firewalls": [
        {"technique_id": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall", "tactic": "defense-evasion", "confidence": "low"},
    ],
    "DNS": [
        {"technique_id": "T1016",     "name": "System Network Configuration Discovery", "tactic": "discovery", "confidence": "low"},
    ],
    "Databases": [
        {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "low"},
    ],
    "Web Servers": [
        {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "low"},
    ],
    "CGI abuses": [
        {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "medium"},
    ],
    "CGI abuses : XSS": [
        {"technique_id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "initial-access", "confidence": "medium"},
    ],
}


# ──────────────────────────────────────────────────────────
# Core matching logic
# ──────────────────────────────────────────────────────────

def match_finding(
    plugin_id: str,
    plugin_name: str,
    plugin_family: str,
    synopsis: str,
    description: str,
) -> List[dict]:
    """
    Return a deduplicated list of matched TTP dicts for a single finding.
    Each TTP dict: {technique_id, name, tactic, mitre_url, match_reason, confidence}
    """
    results: List[dict] = []
    seen_ids: set = set()

    def _add(ttp: dict, reason: str):
        tid = ttp["technique_id"]
        if tid not in seen_ids:
            seen_ids.add(tid)
            results.append({
                "technique_id": tid,
                "name": ttp["name"],
                "tactic": ttp["tactic"],
                "mitre_url": _url(tid),
                "match_reason": reason,
                "confidence": ttp.get("confidence", "medium"),
            })

    # 1. Plugin ID exact match (highest confidence)
    if plugin_id and str(plugin_id) in PLUGIN_ID_MAP:
        for ttp in PLUGIN_ID_MAP[str(plugin_id)]:
            _add({**ttp, "confidence": "high"}, "plugin_id")

    # 2. Keyword match on name + synopsis (+ first 300 chars of description)
    search_text = " ".join(filter(None, [
        plugin_name or "",
        synopsis or "",
        (description or "")[:300],
    ])).lower()

    for keywords, ttp in KEYWORD_RULES:
        if any(kw in search_text for kw in keywords):
            _add(ttp, "keyword")

    # 3. Plugin family fallback (only if no matches yet, or always for known families)
    fam = (plugin_family or "").strip()
    if fam in FAMILY_MAP:
        for ttp in FAMILY_MAP[fam]:
            _add(ttp, "plugin_family")

    return results


def match_findings_to_ttps(db, scan_id: int = None) -> dict:
    """
    Run TTP matching on all findings (or a specific scan's findings).
    Updates Finding.matched_ttps in place.
    Returns {"matched": int, "skipped": int}.
    """
    from models import Finding

    fq = db.query(Finding)
    if scan_id is not None:
        fq = fq.filter(Finding.scan_id == scan_id)

    findings = fq.all()
    matched = 0
    skipped = 0

    for f in findings:
        ttps = match_finding(
            plugin_id=f.plugin_id or "",
            plugin_name=f.plugin_name or "",
            plugin_family=f.plugin_family or "",
            synopsis=f.synopsis or "",
            description=f.description or "",
        )
        if ttps:
            f.matched_ttps = ttps
            matched += 1
        else:
            f.matched_ttps = []
            skipped += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("match_findings_to_ttps commit failed: %s", exc)
        db.rollback()

    logger.info("TTP matching: %d findings matched, %d with no match", matched, skipped)
    return {"matched": matched, "skipped": skipped}

"""
Remediation Action Grouping Engine

Vulnerabilities aren't independent — they share root causes.  This engine
fingerprints each finding with an affected component and root-cause type,
then groups them into single remediation actions that collapse N vulnerabilities
into 1 fix.  Cross-asset grouping means "Upgrade Node.js on 5 hosts" is a
single recommendation, not 5 separate ones.

Pipeline:
  1. Fingerprint — extract component + root_cause_type from plugin data
  2. Group — apply rules engine in priority order
  3. Score — rank by efficiency_score
  4. Persist — write AggregatedSolution records
"""

import re
import logging
from collections import defaultdict
from datetime import datetime
from typing import Optional, List, Set

from sqlalchemy.orm import Session

from models.models import Finding, Asset, AggregatedSolution, InventoryPatch
from services.downstream_impact import assess_downstream_impact, VERDICT_MULTIPLIERS

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Step 1: Vulnerability Fingerprinting
# ═══════════════════════════════════════════════════════════════════════

class VulnFingerprint:
    """Structured metadata extracted from a finding."""
    __slots__ = (
        "finding", "component", "root_cause_type",
        "current_version", "target_version", "group_key",
    )

    def __init__(self, finding):
        self.finding = finding
        self.component = None            # e.g. "Node.js", "OpenSSL", "TLS 1.0"
        self.root_cause_type = None      # outdated_version, eol_software, etc.
        self.current_version = None
        self.target_version = None
        self.group_key = None            # (component, root_cause_type) — set after classification


# ── Component extraction patterns ──────────────────────────

# Pattern: "Component X.Y.x < X.Y.Z" — extracts component and target version
_COMPONENT_VERSION_RE = re.compile(
    r"^(.+?)\s+([\d]+\.[\w.x]+)\s*(?:<|/)\s*([\d]+\.[\w.]+)",
    re.I,
)

# Pattern: "Upgrade to Component version X.Y.Z or later" in solution text
_SOLUTION_UPGRADE_RE = re.compile(
    r"[Uu]pgrade\s+to\s+(.+?)\s+(?:version\s+)?([\d]+\.[\w.]+)\s+or\s+later",
)

# Pattern: "Update ... to version X.Y.Z"
_SOLUTION_UPDATE_RE = re.compile(
    r"[Uu]pdate\s+(?:.*?)\s+to\s+version\s+([\d]+\.[\w.]+)",
)

# KB patch: "KBnnnnnnn: Windows ..."
_KB_PATCH_RE = re.compile(r"^(KB\d+):\s*(.+?)(?:\s+Security\s+Update|\s+Cumulative)", re.I)

# Security Updates for component
_SEC_UPDATE_RE = re.compile(r"^Security\s+Updates?\s+for\s+(.+?)(?:\s*\()", re.I)

# SEoL / EOL patterns
_SEOL_RE = re.compile(r"^(.+?)\s+SEoL$", re.I)
_UNSUPPORTED_RE = re.compile(
    r"^(?:Unsupported\s+(?:Version\s+of\s+)?)?(.+?)(?:\s+Unsupported\s+Version|\s+Version\s+Detection)$", re.I)
_EOL_RE = re.compile(r"^(.+?)\s+(?:End\s+of\s+Life|No\s+Longer\s+Supported)", re.I)

# OS names for distinguishing OS EOL from software EOL
_OS_NAMES_RE = re.compile(
    r"(?:Microsoft\s+)?Windows|Linux|Ubuntu|Debian|CentOS|Red\s*Hat|RHEL|macOS|OS\s*X|FreeBSD|Solaris|Unix",
    re.I,
)

# Deprecated protocols
_DEPRECATED_PROTOCOLS = {
    "tls 1.0": "TLS 1.0",
    "tls 1.1": "TLS 1.1",
    "tls version 1.0": "TLS 1.0",
    "tls version 1.1": "TLS 1.1",
    "sslv2": "SSLv2",
    "sslv3": "SSLv3",
    "ssl version 2": "SSLv2",
    "ssl version 3": "SSLv3",
    "smbv1": "SMBv1",
    "smb1": "SMBv1",
    "smb version 1": "SMBv1",
    "telnet": "Telnet",
    "ftp": "FTP (unencrypted)",
}

_DEPRECATED_PROTOCOL_RE = re.compile(
    r"(TLS\s+Version\s+1\.[01]|SSLv[23]|SMBv?1|SMB\s+Version\s+1)\s+"
    r"(?:Protocol\s+)?(?:Detection|Deprecated|Enabled|Supported)",
    re.I,
)

# Vulnerability class taxonomy — used as a scanner-agnostic fingerprint
# fallback for app-layer findings (EASM, agent, DAST) that don't fit the
# Nessus-shaped patterns above. Keyed by CWE; values are display names used
# as the aggregation `component`.
_CWE_TO_VULN_CLASS = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-78": "OS Command Injection",
    "CWE-77": "Command Injection",
    "CWE-94": "Code Injection / RCE",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-611": "XML External Entity",
    "CWE-502": "Insecure Deserialization",
    "CWE-434": "Unrestricted File Upload",
    "CWE-601": "Open Redirect",
    "CWE-798": "Hardcoded Credentials",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Broken Access Control",
    "CWE-200": "Information Disclosure",
    "CWE-269": "Privilege Management",
    "CWE-330": "Weak Randomness",
    "CWE-327": "Weak Cryptography",
    "CWE-319": "Cleartext Transmission",
}

# Heuristic: derive a vuln-class from plugin_name when cwe_ids is empty.
_VULN_CLASS_NAME_RULES = [
    (re.compile(r"\bSQL\s*Injection\b", re.I), "SQL Injection"),
    (re.compile(r"\bCross[-\s]Site\s+Scripting\b|\bXSS\b", re.I), "Cross-Site Scripting"),
    (re.compile(r"\b(?:OS\s+)?Command\s+Injection\b", re.I), "OS Command Injection"),
    (re.compile(r"\bRemote\s+Code\s+Execution\b|\bRCE\b|\bCode\s+Injection\b", re.I), "Code Injection / RCE"),
    (re.compile(r"\bPath\s+Traversal\b|\bDirectory\s+Traversal\b", re.I), "Path Traversal"),
    (re.compile(r"\bSSRF\b|\bServer[-\s]Side\s+Request\s+Forgery\b", re.I), "Server-Side Request Forgery"),
    (re.compile(r"\bCSRF\b|\bCross[-\s]Site\s+Request\s+Forgery\b", re.I), "Cross-Site Request Forgery"),
    (re.compile(r"\bXXE\b|\bXML\s+External\s+Entity\b", re.I), "XML External Entity"),
    (re.compile(r"\b(?:Insecure|Unsafe)\s+Deserialization\b", re.I), "Insecure Deserialization"),
    (re.compile(r"\bUnrestricted\s+File\s+Upload\b|\bArbitrary\s+File\s+Upload\b", re.I), "Unrestricted File Upload"),
    (re.compile(r"\bOpen\s+Redirect\b", re.I), "Open Redirect"),
    (re.compile(r"\bHardcoded\s+(?:Credential|Password|Secret)\b", re.I), "Hardcoded Credentials"),
    (re.compile(r"\bMissing\s+Authentication\b", re.I), "Missing Authentication"),
    (re.compile(r"\bBroken\s+Access\s+Control\b|\bIDOR\b|\bInsecure\s+Direct\s+Object\b", re.I), "Broken Access Control"),
    (re.compile(r"\bInformation\s+Disclosure\b", re.I), "Information Disclosure"),
]


# Class-specific remediation guidance. Surfaced in the aggregated solution
# description; mirrors the per-finding CWE guidance in prioritizer.py but
# framed as a cross-asset code-fix action.
_VULN_CLASS_GUIDANCE = {
    "SQL Injection":
        "1. Replace string-concatenated SQL with parameterized queries / prepared statements\n"
        "2. Apply allow-list input validation at the boundary\n"
        "3. Reduce DB credentials to least privilege so a successful injection can't pivot\n"
        "4. Add a WAF rule for the affected endpoint as short-term mitigation",
    "Cross-Site Scripting":
        "1. Apply context-aware output encoding (HTML, JS, URL, attribute) at render time\n"
        "2. Set a strict Content-Security-Policy (`default-src 'self'`, no `unsafe-inline`)\n"
        "3. Sanitize stored content via a vetted library (DOMPurify, OWASP Java Encoder)",
    "OS Command Injection":
        "1. Replace shell invocations with direct OS API calls\n"
        "2. If a shell call is unavoidable, pass arguments as an array (never a concatenated string)\n"
        "3. Validate inputs against an allow-list and drop privileges before invocation",
    "Command Injection":
        "1. Replace string-concatenated commands with structured APIs\n"
        "2. Validate inputs against an allow-list; quote/escape any remaining user-controlled values",
    "Code Injection / RCE":
        "1. Eliminate dynamic code evaluation (`eval`, `exec`, `Function()`)\n"
        "2. Replace with a fixed allow-list of handlers keyed by a sanitized identifier\n"
        "3. Patch the affected library/runtime if the RCE path is in a dependency",
    "Path Traversal":
        "1. Resolve user-supplied paths against a fixed base directory\n"
        "2. Reject any resolved path that escapes the base (`realpath` + `startswith` check)\n"
        "3. Map filenames to opaque server-side IDs instead of trusting input",
    "Server-Side Request Forgery":
        "1. Validate outbound URLs against an allow-list of hosts\n"
        "2. Resolve DNS once and reuse the resolved IP for the request\n"
        "3. Block requests to RFC1918, link-local (incl. 169.254.169.254 metadata), and loopback ranges",
    "Cross-Site Request Forgery":
        "1. Require an unguessable per-session anti-CSRF token on every state-changing request\n"
        "2. Use `SameSite=Lax` (or `Strict`) cookies\n"
        "3. Verify the `Origin`/`Referer` header on sensitive endpoints",
    "XML External Entity":
        "1. Disable external entity resolution in the XML parser\n"
        "2. Prefer a parser configured for XXE-safety by default (defusedxml, etc.)",
    "Insecure Deserialization":
        "1. Do not deserialize untrusted input with native deserializers (`pickle`, Java `ObjectInputStream`)\n"
        "2. Switch to a data-only format (JSON) with strict schema validation",
    "Unrestricted File Upload":
        "1. Validate uploads by content type and magic bytes, not extension\n"
        "2. Store outside the web root; generate a server-side filename\n"
        "3. Serve via a download handler that sets `Content-Disposition: attachment`",
    "Open Redirect":
        "1. Validate redirect targets against an allow-list of internal paths\n"
        "2. Never echo a user-supplied URL into a `Location` header without verification",
    "Hardcoded Credentials":
        "1. Remove the hardcoded credential from source\n"
        "2. Rotate the secret immediately (assume compromise)\n"
        "3. Load it from a secret manager (Vault, AWS/GCP Secrets Manager) at runtime",
    "Improper Authentication":
        "1. Enforce authentication at the framework/middleware layer, not per-handler\n"
        "2. Add automated tests for unauthenticated access on each protected endpoint\n"
        "3. Audit recent access logs for exploitation",
    "Missing Authentication":
        "1. Add the standard auth middleware/guard to the affected route(s)\n"
        "2. Verify the route is no longer reachable anonymously",
    "Missing Authorization":
        "1. Add explicit authorization checks for each protected resource\n"
        "2. Verify the principal has the required role/permission before returning data",
    "Broken Access Control":
        "1. Re-check object ownership/tenant scoping server-side\n"
        "2. Do not rely on client-supplied IDs or hidden form fields",
    "Information Disclosure":
        "1. Audit responses for sensitive fields (stack traces, internal IDs, tokens, PII) and strip them\n"
        "2. Disable verbose error pages in production",
}


def _classify_vuln_class(finding):
    """Return a vuln-class display name, or None."""
    for raw in (getattr(finding, "cwe_ids", None) or []):
        if not isinstance(raw, str):
            continue
        cls = _CWE_TO_VULN_CLASS.get(raw.upper().strip())
        if cls:
            return cls
    name = getattr(finding, "plugin_name", None) or ""
    for pattern, cls in _VULN_CLASS_NAME_RULES:
        if pattern.search(name):
            return cls
    return None


# ── Agent CVE Hunt support (audit families) ───────────────────────────────

# Per-protocol upgrade bucket used only when a CVE-bearing audit finding's
# title is too generic to extract a real component. Misconfiguration audit
# findings without CVEs are intentionally NOT bucketed — each one has its own
# specific config fix in finding.solution and should surface individually.
_AUDIT_FAMILY_BUCKETS = {
    "audit: windows":         "Windows Software",
    "audit: ssh":             "Linux Packages",
    "audit: smb":             "Windows Software",
    "audit: kerberos":        "Active Directory",
    "audit: winrm":           "Windows Software",
    "audit: snmp":            "Network Devices",
    "audit: active directory": "Active Directory",
    "audit: ldap":            "Active Directory",
    "audit: cloud (aws)":     "AWS Resources",
    "audit: cloud (azure)":   "Azure Resources",
    "audit: cloud (gcp)":     "GCP Resources",
}

_AUDIT_TITLE_PREFIX_RE = re.compile(
    r"^\s*(?:Outdated|Vulnerable|Unpatched|Missing\s+patch\s+for|"
    r"End[-\s]of[-\s]life|EOL)\s+",
    re.I,
)
_AUDIT_TITLE_CVE_TAIL_RE = re.compile(r"\s+CVE-\d{4}-\d+.*$", re.I)
_AUDIT_TITLE_VERSION_TAIL_RE = re.compile(r"\s+v?\d+(?:[.\w]+)*\s*$")


def _extract_audit_component(name):
    """Best-effort component extraction from a free-form agent title.

    The CVE Hunt mission emits titles like 'Outdated Google Chrome 119 — RCE
    (CVE-2024-1234)'. Strip the noise and return 'Google Chrome'. Return
    None if the result is too short to be a useful aggregation key.
    """
    if not name:
        return None
    cleaned = _AUDIT_TITLE_PREFIX_RE.sub("", name.strip())
    # Cut at the first separator: em/en-dash, colon, parenthesis
    cleaned = re.split(r"\s*[—–:(]\s*", cleaned, maxsplit=1)[0]
    # Cut at " - " (with spaces) to avoid splitting hyphenated names
    cleaned = re.split(r"\s+-\s+", cleaned, maxsplit=1)[0]
    cleaned = _AUDIT_TITLE_CVE_TAIL_RE.sub("", cleaned)
    cleaned = _AUDIT_TITLE_VERSION_TAIL_RE.sub("", cleaned)
    cleaned = cleaned.strip(" ,;.")
    if not cleaned or len(cleaned) < 3:
        return None
    if re.match(r"^CVE-\d", cleaned, re.I):
        return None
    return _normalize_component(cleaned)

# Misconfiguration keywords. Covers Nessus-shaped finding names and the
# audit-profile output (SMB / WMI / SNMP / LDAP) used by host-credentialed scans.
_MISCONFIG_PATTERNS = [
    # TLS / certificates
    (re.compile(r"SSL\s+(?:Medium|Weak)\s+Strength\s+Cipher", re.I), "SSL/TLS Cipher Config"),
    (re.compile(r"SSL\s+Certificate\s+(?:Cannot\s+Be\s+Trusted|Expir|Self.Signed|Chain)", re.I), "SSL Certificate"),
    (re.compile(r"SSL\s+(?:RC4|CBC|NULL|Anonymous|Export)\s+Cipher", re.I), "SSL/TLS Cipher Config"),
    # SMB hardening (audit profile)
    (re.compile(r"SMB\s+Signing\s+(?:not\s+required|disabled|not\s+enabled)", re.I), "SMB Signing"),
    (re.compile(r"SMB\s+(?:Null\s+Session|Anonymous(?:\s+(?:Access|Enumeration))?|Guest\s+Access)", re.I), "SMB Hardening"),
    (re.compile(r"SMB\s+(?:Encryption\s+(?:Disabled|Not\s+Required)|Use\s+Host\s+SIDs)", re.I), "SMB Hardening"),
    # WMI hardening
    (re.compile(r"WMI\s+(?:Anonymous|Remote|Hardening|DCOM|Authentication)", re.I), "WMI Hardening"),
    (re.compile(r"DCOM\s+(?:Hardening|Authentication|Remote\s+Activation)", re.I), "WMI Hardening"),
    # SNMP hardening (audit profile)
    (re.compile(r"SNMP(?:v?[12c]?)?\s+(?:Default\s+Community|Public\s+Community|Private\s+Community|Weak\s+Community|Community\s+String|Enabled|Detection\s+w?/?\s*default)", re.I), "SNMP Hardening"),
    (re.compile(r"SNMPv[12c]?\s+(?:Supported|Enabled)", re.I), "SNMP Hardening"),
    # LDAP / AD hardening (audit profile)
    (re.compile(r"LDAP\s+(?:Anonymous\s+Bind|Signing(?:\s+Not\s+Required)?|Channel\s+Binding|Null\s+Bind)", re.I), "LDAP Hardening"),
    (re.compile(r"LDAPS?\s+(?:Not\s+Enforced|Disabled|Not\s+Configured)", re.I), "LDAP Hardening"),
    (re.compile(r"Active\s+Directory\s+(?:Anonymous|Signing|Hardening|Pre.Windows\s+2000)", re.I), "Active Directory Hardening"),
    # SSH hardening
    (re.compile(r"(?:SSH|SSHD).*(?:Weak|CBC|Deprecated|Enabled|Algorithm|Cipher|MAC)", re.I), "SSH Config"),
    # Credentials / accounts
    (re.compile(r"(?:Default|Weak|Blank)\s+(?:Credential|Password|Account)", re.I), "Default Credentials"),
    (re.compile(r"Password\s+Policy\s+(?:Weak|Misconfigured|Insufficient)", re.I), "Password Policy"),
    # Kerberos
    (re.compile(r"Kerberos\s+.*(?:Pre.authentication|Weak\s+Encryption|RC4|DES)", re.I), "Kerberos Config"),
    # NFS / RPC / NTP / DNS open services
    (re.compile(r"(?:NFS|RPC|NTP|DNS)\s+.*(?:Open|Anonymous|Recursive|Amplification|Cache\s+Snooping)", re.I), "Service Hardening"),
    # Windows config
    (re.compile(r"(?:AutoAdmin|Autologon)\s+Enabled", re.I), "Windows Autologon"),
    (re.compile(r"Speculative\s+Execution", re.I), "Speculative Execution Mitigations"),
    (re.compile(r"Insecure\s+Windows\s+Service\s+Permissions", re.I), "Windows Service Permissions"),
    (re.compile(r"UAC\s+(?:Disabled|Misconfigured|Bypass)", re.I), "Windows UAC"),
    (re.compile(r"Windows\s+Firewall\s+(?:Disabled|Misconfigured)", re.I), "Windows Firewall"),
    # Compliance / audit-profile generic catchers (CIS / DISA STIG / Nessus audit policies)
    (re.compile(r"(?:CIS|DISA\s+STIG|Nessus\s+Audit)\b.*(?:Failed|Non[-\s]Compliant|Violation)", re.I), "Compliance Baseline"),
]


def _normalize_component(name):
    """Normalize component name for grouping."""
    if not name:
        return None
    name = name.strip()
    # Normalize .NET variants
    name = re.sub(r"Microsoft\s+\.NET\s+(?:Core|Framework)", ".NET", name)
    name = re.sub(r"ASP\.NET\s+Core", "ASP.NET Core", name)
    name = re.sub(r"Security\s+Updates?\s+for\s+", "", name)
    # Remove trailing date/version noise
    name = re.sub(r"\s*\(.*$", "", name)
    name = re.sub(
        r"\s*(?:Multiple\s+)?(?:Vulnerabilities|Detection|Deprecated|Protocol).*$",
        "", name, flags=re.I)
    return name.strip() or None


def _extract_target_version(solution):
    """Extract target version from solution text."""
    if not solution:
        return None
    m = _SOLUTION_UPGRADE_RE.search(solution)
    if m:
        return m.group(2)
    m = _SOLUTION_UPDATE_RE.search(solution)
    if m:
        return m.group(1)
    return None


def fingerprint_finding(finding):
    """
    Classify a single finding into component + root_cause_type.
    Returns a VulnFingerprint or None if the finding can't be classified.
    """
    fp = VulnFingerprint(finding)
    name = finding.plugin_name or ""
    family = finding.plugin_family or ""
    solution = finding.solution or ""
    severity = finding.severity or 0

    # Skip info-level findings (severity 0)
    if severity < 1:
        return None

    # ── Rule 1: EOL / SEoL Software ────────────────────────
    m = _SEOL_RE.match(name)
    if m:
        component = m.group(1).strip()
        fp.component = _normalize_component(component)
        fp.root_cause_type = "eol_software"
        fp.target_version = _extract_target_version(solution)
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    m = _UNSUPPORTED_RE.match(name)
    if m and ("unsupported" in name.lower() or "detection" in name.lower()):
        fp.component = _normalize_component(m.group(1))
        fp.root_cause_type = "eol_software"
        fp.target_version = _extract_target_version(solution)
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    m = _EOL_RE.match(name)
    if m:
        fp.component = _normalize_component(m.group(1))
        fp.root_cause_type = "eol_software"
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    # ── Rule 2: Deprecated Protocol ───────────────────────
    m = _DEPRECATED_PROTOCOL_RE.search(name)
    if m:
        proto_raw = m.group(1).strip().lower()
        for key, canonical in _DEPRECATED_PROTOCOLS.items():
            if key in proto_raw:
                fp.component = canonical
                break
        else:
            fp.component = m.group(1).strip()
        fp.root_cause_type = "deprecated_protocol"
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    # ── Rule 3: Misconfiguration Cluster ──────────────────
    for pattern, config_component in _MISCONFIG_PATTERNS:
        if pattern.search(name):
            fp.component = config_component
            fp.root_cause_type = "misconfiguration"
            fp.group_key = (fp.component, fp.root_cause_type)
            return fp

    # ── Rule 4: KB Patch Bundle (Windows) ─────────────────
    m = _KB_PATCH_RE.match(name)
    if m:
        os_hint = m.group(2).strip()
        os_match = re.match(
            r"(Windows\s+(?:10|11|Server\s+\d{4}(?:\s+R2)?)(?:\s+[Vv]ersion\s+\S+)?)", os_hint)
        if os_match:
            fp.component = os_match.group(1).strip()
        else:
            fp.component = os_hint.split(" Security")[0].split(" Cumulative")[0].strip()
        fp.root_cause_type = "missing_patch"
        fp.target_version = _extract_target_version(solution)
        # Patches stay per-asset — prefix to distinguish from cross-asset groups
        fp.group_key = ("__patch__" + fp.component, fp.root_cause_type)
        return fp

    # ── Rule 5: Security Updates for Component (monthly) ──
    m = _SEC_UPDATE_RE.match(name)
    if m:
        fp.component = _normalize_component(m.group(1))
        fp.root_cause_type = "outdated_version"
        fp.target_version = _extract_target_version(solution)
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    # ── Rule 6: Component Version Upgrade ─────────────────
    m = _COMPONENT_VERSION_RE.match(name)
    if m:
        fp.component = _normalize_component(m.group(1))
        fp.current_version = m.group(2)
        fp.target_version = m.group(3)
        fp.root_cause_type = "outdated_version"
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    # ── Rule 7: Generic upgrade from solution text ────────
    if "upgrade" in solution.lower() or "update" in solution.lower():
        sol_m = _SOLUTION_UPGRADE_RE.search(solution)
        if sol_m:
            fp.component = _normalize_component(sol_m.group(1))
            fp.target_version = sol_m.group(2)
            fp.root_cause_type = "outdated_version"
            fp.group_key = (fp.component, fp.root_cause_type)
            return fp

    # ── Rule 8: Linux package updates ─────────────────────
    if "Local Security Checks" in family:
        os_fam = family.split(" Local")[0].strip()
        fp.component = os_fam + " Packages"
        fp.root_cause_type = "missing_patch"
        fp.group_key = ("__patch__" + fp.component, fp.root_cause_type)
        return fp

    family_lower = family.lower()

    # ── Rule 8.5: Agent CVE Hunt — audit family + CVEs → outdated_version ──
    # WMI/SSH/SMB/SNMP/LDAP CVE Hunt missions emit findings with an
    # `Audit: <protocol>` family and a CVE list. Group them as
    # outdated_version so multiple CVEs against the same component on
    # multiple hosts collapse into one "Update X" remediation. Runs before
    # the misconfig fallback below so an "Audit: SMB" finding *with* CVEs
    # isn't mis-routed to SMB Hardening.
    if family_lower.startswith("audit:") and (finding.cves or []):
        component = _extract_audit_component(name)
        if component is None:
            component = _AUDIT_FAMILY_BUCKETS.get(family_lower)
        if component:
            fp.component = component
            fp.target_version = _extract_target_version(solution)
            fp.root_cause_type = "outdated_version"
            fp.group_key = (fp.component, fp.root_cause_type)
            return fp

    # Audit-family misconfiguration findings without a specific match in
    # Rule 3 (_MISCONFIG_PATTERNS) are left un-aggregated. Each one carries
    # its own concrete remediation in finding.solution (disable cipher X,
    # set MaxAuthTries=N, etc.), so collapsing them behind a generic
    # "Fix SSH Audit" / "SMB Hardening" / "Compliance Baseline" card hides
    # the actual work. They surface individually in the findings list.

    # ── Rule 9: CWE / vuln-class fallback ─────────────────
    # Catches app-layer findings (EASM, agent, DAST) where the rules above
    # — built around Nessus-shaped plugin metadata — don't match. Groups by
    # vulnerability class so e.g. all SQL injections aggregate into one
    # remediation action.
    vuln_class = _classify_vuln_class(finding)
    if vuln_class:
        fp.component = vuln_class
        fp.root_cause_type = "vuln_class"
        fp.group_key = (fp.component, fp.root_cause_type)
        return fp

    return None


# ═══════════════════════════════════════════════════════════════════════
# Step 2: Grouping Rules Engine
# ═══════════════════════════════════════════════════════════════════════

def _determine_action_type(root_cause_type):
    """Map root cause to recommended action type."""
    return {
        "eol_software": "migrate_to_supported",
        "deprecated_protocol": "disable_protocol",
        "outdated_version": "upgrade_component",
        "misconfiguration": "remediate_config",
        "missing_patch": "apply_patch",
        "vuln_class": "fix_code_defect",
    }.get(root_cause_type, "upgrade_component")


def _determine_effort(root_cause_type, finding_count, asset_count):
    """Estimate effort level."""
    if root_cause_type == "eol_software":
        return "complex"
    if root_cause_type == "misconfiguration" and asset_count <= 3:
        return "quick_win"
    if root_cause_type == "deprecated_protocol" and asset_count <= 5:
        return "quick_win"
    if root_cause_type == "missing_patch" and finding_count > 20:
        return "complex"
    if root_cause_type == "missing_patch" and asset_count <= 5:
        return "quick_win"
    if root_cause_type == "outdated_version" and asset_count <= 5:
        return "quick_win"
    if root_cause_type == "vuln_class":
        # Code-level fixes need dev cycles; scale with finding count
        if finding_count > 10:
            return "complex"
        return "medium"
    if asset_count > 10:
        return "complex"
    return "medium"


def _determine_owner(root_cause_type, component):
    """Suggest responsible team."""
    if root_cause_type == "misconfiguration":
        comp_lower = (component or "").lower()
        if "ssl" in comp_lower or "tls" in comp_lower or "certificate" in comp_lower:
            return "DevOps"
        if "kerberos" in comp_lower or "credential" in comp_lower:
            return "SecOps"
        return "IT"
    if root_cause_type == "vuln_class":
        return "AppSec"
    if root_cause_type in ("eol_software", "deprecated_protocol", "missing_patch"):
        return "IT"
    return "IT"


# ═══════════════════════════════════════════════════════════════════════
# Step 3: Recommendation Builder
# ═══════════════════════════════════════════════════════════════════════

def _build_title(action_type, component, target_version, asset_count, finding_count):
    """Generate concise human-readable title."""
    comp = component or "Unknown"

    if action_type == "migrate_to_supported":
        if asset_count > 1:
            return "Migrate from %s across %d hosts" % (comp, asset_count)
        return "Migrate from %s to supported version" % comp

    if action_type == "disable_protocol":
        if asset_count > 1:
            return "Disable %s across %d hosts" % (comp, asset_count)
        return "Disable %s" % comp

    if action_type == "upgrade_component":
        ver_str = " to %s" % target_version if target_version else ""
        if asset_count > 1:
            return "Upgrade %s%s across %d hosts" % (comp, ver_str, asset_count)
        return "Upgrade %s%s" % (comp, ver_str)

    if action_type == "apply_patch":
        return "Apply %d pending patches for %s" % (finding_count, comp)

    if action_type == "remediate_config":
        if asset_count > 1:
            return "Fix %s across %d hosts" % (comp, asset_count)
        return "Fix %s" % comp

    if action_type == "fix_code_defect":
        if finding_count > 1:
            return "Fix %d %s findings" % (finding_count, comp)
        return "Fix %s" % comp

    return "Remediate %s (%d findings)" % (comp, finding_count)


def _build_description(root_cause_type, action_type, component, fingerprints,
                       target_version, asset_hostnames):
    """Generate detailed remediation description."""
    n = len(fingerprints)
    hosts = ", ".join(asset_hostnames[:5])
    if len(asset_hostnames) > 5:
        hosts += " +%d more" % (len(asset_hostnames) - 5)

    parts = []

    if action_type == "migrate_to_supported":
        parts.append(
            "**%s** is end-of-life and no longer receives security patches. "
            "%d vulnerability findings stem from this unsupported software." % (component, n))
        parts.append("\n**Affected hosts:** %s" % hosts)
        parts.append(
            "\n**Recommended action:** Migrate to a supported version.\n"
            "1. Identify the latest supported release from vendor documentation\n"
            "2. Test migration in a staging environment\n"
            "3. Plan maintenance window for production migration\n"
            "4. If immediate migration is blocked, isolate affected systems "
            "and document as technical debt")

    elif action_type == "disable_protocol":
        parts.append(
            "**%s** is a deprecated protocol with known security vulnerabilities. "
            "%d findings across %d hosts relate to this protocol." % (
                component, n, len(asset_hostnames)))
        parts.append("\n**Affected hosts:** %s" % hosts)
        parts.append(
            "\n**Recommended action:** Disable %s and migrate to the modern alternative." % component)
        if "TLS" in (component or ""):
            parts.append(
                "\n1. Enable TLS 1.2 and TLS 1.3 only\n"
                "2. Update client compatibility if needed\n"
                "3. Test with `nmap --script ssl-enum-ciphers` or SSL Labs")
        elif "SMB" in (component or ""):
            parts.append(
                "\n1. `Set-SmbServerConfiguration -EnableSMB1Protocol $false`\n"
                "2. Enforce SMBv2/v3 with signing\n"
                "3. Restrict SMB access to necessary subnets")

    elif action_type == "upgrade_component":
        ver = " to **%s**" % target_version if target_version else ""
        parts.append(
            "**%s** has %d known vulnerabilities. "
            "Upgrading%s resolves all of them in a single action." % (component, n, ver))
        parts.append("\n**Affected hosts:** %s" % hosts)
        parts.append(
            "\n**Recommended action:** Upgrade %s%s.\n"
            "1. Test the upgrade in staging first\n"
            "2. Schedule a maintenance window\n"
            "3. Verify with a follow-up scan" % (component, ver))

    elif action_type == "apply_patch":
        parts.append(
            "%d pending patches can be applied in a single maintenance window." % n)
        parts.append("\n**Affected hosts:** %s" % hosts)
        parts.append(
            "\n**Recommended action:**\n"
            "1. Deploy all outstanding patches via WSUS/SCCM/Intune (Windows) "
            "or package manager (Linux)\n"
            "2. Test in staging before production\n"
            "3. Schedule maintenance window with reboot if required\n"
            "4. Verify with follow-up scan")

    elif action_type == "remediate_config":
        parts.append(
            "%d findings relate to **%s** misconfiguration across %d hosts." % (
                n, component, len(asset_hostnames)))
        parts.append("\n**Affected hosts:** %s" % hosts)
        parts.append(
            "\n**Recommended action:** Apply a consistent configuration fix "
            "across all affected hosts.")
        if "SSL" in (component or "") or "TLS" in (component or "") or "Cipher" in (component or ""):
            parts.append(
                "\n1. Disable weak cipher suites (RC4, DES, 3DES, NULL, export)\n"
                "2. Renew or replace expired/self-signed certificates\n"
                "3. Enable HSTS and configure proper certificate chains")
        elif "Credential" in (component or ""):
            parts.append(
                "\n1. Change all default credentials immediately\n"
                "2. Use strong, unique passwords (16+ chars)\n"
                "3. Disable unused accounts")

    elif action_type == "fix_code_defect":
        parts.append(
            "**%s** — %d findings across %d %s share the same vulnerability "
            "class. Fix the underlying defect at the code/library layer rather "
            "than per-finding." % (
                component, n, len(asset_hostnames),
                "host" if len(asset_hostnames) == 1 else "hosts"))
        parts.append("\n**Affected hosts:** %s" % hosts)
        guidance = _VULN_CLASS_GUIDANCE.get(component)
        if guidance:
            parts.append("\n**Recommended action:**\n" + guidance)
        else:
            parts.append(
                "\n**Recommended action:** Identify the shared input-handling or "
                "auth/authorization code path and apply a class-appropriate fix "
                "(input validation, output encoding, parameterization, or access "
                "checks) at that single location.")

    else:
        parts.append("%d findings can be resolved by addressing **%s**." % (n, component))

    # Append CVE summary
    all_cves = set()
    for fp in fingerprints:
        if fp.finding.cves:
            all_cves.update(fp.finding.cves)
    if all_cves and len(all_cves) <= 15:
        parts.append("\n\n**CVEs resolved:** " + ", ".join(sorted(all_cves)))
    elif all_cves:
        parts.append("\n\n**CVEs resolved:** %d unique CVEs" % len(all_cves))

    return "\n".join(parts)


def _build_vs_alternative(finding_count, asset_count):
    """Explain what this replaces."""
    if asset_count > 1:
        return ("Replaces %d individual remediation actions across %d hosts "
                "with 1 coordinated action" % (finding_count, asset_count))
    if finding_count > 2:
        return "Collapses %d separate findings into 1 remediation action" % finding_count
    return None


# ═══════════════════════════════════════════════════════════════════════
# Step 4: Scoring
# ═══════════════════════════════════════════════════════════════════════

def _compute_efficiency_score(finding_count, asset_count, severity_max,
                              priority_max, total_scan_risk):
    """
    efficiency = (vulns_resolved / actions_required) x risk_weight x asset_breadth

    Higher = more impactful.  A single action that fixes 20 CVEs on 5 hosts
    scores much higher than fixing 1 CVE on 1 host.
    """
    risk_weight = {4: 1.0, 3: 0.8, 2: 0.5, 1: 0.3, 0: 0.1}.get(severity_max, 0.5)
    breadth = min(asset_count, 20) / 5.0  # 5 assets = 1.0, cap at 4.0
    score = (finding_count / 1.0) * risk_weight * max(breadth, 0.5)
    return round(score, 2)


def _compute_risk_reduction(priority_sum, total_scan_risk):
    """Percentage of total scan risk resolved by this single action."""
    if total_scan_risk <= 0:
        return 0.0
    return round((priority_sum / total_scan_risk) * 100, 1)


# ═══════════════════════════════════════════════════════════════════════
# Step 5: Patch Catalog Enrichment
# ═══════════════════════════════════════════════════════════════════════

# Extract KB IDs from finding plugin names
_KB_EXTRACT_RE = re.compile(r"(KB\d{6,})", re.I)


# Extract USN/DSA/RHSA advisory IDs from plugin names
_ADVISORY_RE = re.compile(r"\((USN-[\w.-]+|DSA-[\w.-]+|RHSA-[\w:.-]+|ALAS-[\w.-]+)\)", re.I)


def _build_finding_based_breakdown(fingerprints, cve_ids):
    """
    Build patch breakdown directly from finding metadata (Linux packages).
    Each finding = one package update to apply, with its own CVE list.
    """
    patch_list = []
    all_cves_covered = set()

    for fp in fingerprints:
        f = fp.finding
        name = f.plugin_name or ""

        # Try to extract advisory ID (USN-XXXX, DSA-XXXX, etc.)
        adv_match = _ADVISORY_RE.search(name)
        advisory_id = adv_match.group(1) if adv_match else None

        # Extract CVEs from this finding
        finding_cves = list(f.cves) if f.cves else []
        all_cves_covered.update(finding_cves)

        # Clean up the display title — strip the long Ubuntu version prefix
        title = name
        # "UBUNTU 14.04 ... 24.04 : Foo Vulnerability (USN-1234)" → "Foo Vulnerability"
        colon_idx = name.find(" : ")
        if colon_idx > 0:
            title = name[colon_idx + 3:].strip()
        # Strip redundant advisory ID from title if already captured
        if advisory_id and title.endswith("(%s)" % advisory_id):
            title = title[:-(len(advisory_id) + 3)].strip()

        entry = {
            "advisory_id": advisory_id or f"plugin-{f.plugin_id}" if f.plugin_id else name[:60],
            "source": _guess_source_from_family(f.plugin_family),
            "title": title,
            "severity": {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(f.severity),
            "release_date": None,
            "url": None,
            "cves_fixed": finding_cves[:20],
            "cve_count": len(finding_cves),
            "restart_required": None,
        }
        patch_list.append(entry)

    uncovered = set(cve_ids or []) - all_cves_covered

    return {
        "patches": patch_list,
        "patch_count": len(patch_list),
        "original_finding_count": len(fingerprints),
        "superseded_count": 0,
        "effective_patch_count": len(patch_list),
        "cves_covered": len(all_cves_covered),
        "cves_uncovered": sorted(uncovered) if uncovered else [],
        "warnings": [],
        "has_recalled": False,
        "has_known_issues": False,
    }


def _guess_source_from_family(family):
    """Map plugin family to patch source."""
    if not family:
        return "linux"
    fl = family.lower()
    if "ubuntu" in fl: return "ubuntu"
    if "debian" in fl: return "debian"
    if "red hat" in fl or "rhel" in fl or "centos" in fl: return "rhel"
    if "amazon" in fl: return "amazon"
    if "suse" in fl: return "suse"
    if "fedora" in fl: return "fedora"
    return "linux"


def _enrich_patch_group(db, fingerprints, asset_id, cve_ids):
    """
    Build an actionable patch breakdown from finding data + patch catalog.

    Strategy: always start from finding data (CVEs, plugin names) as the
    baseline, then layer catalog data (supersedence, reliability) on top.
    This ensures CVE counts are always correct even when the catalog has
    no data for a given KB or advisory.

    Returns a dict with patch_breakdown, or None if no data.
    """
    # ── 1. Build baseline from findings (always works) ───────────────
    # Each finding → one patch entry with its own CVEs.
    kb_to_finding_cves = defaultdict(set)  # kb_or_id → CVEs from findings
    kb_to_entry = {}                        # kb_or_id → patch entry dict
    kb_order = []                           # preserve order

    for fp in fingerprints:
        f = fp.finding
        name = f.plugin_name or ""
        finding_cves = list(f.cves) if f.cves else []

        # Try to extract KB ID
        kb_match = _KB_EXTRACT_RE.search(name)
        # Try to extract advisory (USN, DSA, RHSA, etc.)
        adv_match = _ADVISORY_RE.search(name)

        if kb_match:
            patch_id = kb_match.group(1).upper()
        elif adv_match:
            patch_id = adv_match.group(1)
        else:
            patch_id = "plugin-%s" % (f.plugin_id or f.id)

        kb_to_finding_cves[patch_id].update(finding_cves)

        if patch_id not in kb_to_entry:
            # Clean title
            title = name
            colon_idx = name.find(" : ")
            if colon_idx > 0:
                title = name[colon_idx + 3:].strip()
            if adv_match and title.endswith("(%s)" % adv_match.group(1)):
                title = title[:-(len(adv_match.group(1)) + 3)].strip()

            kb_to_entry[patch_id] = {
                "advisory_id": patch_id,
                "source": "microsoft" if kb_match else _guess_source_from_family(f.plugin_family),
                "title": title,
                "severity": {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(f.severity),
                "release_date": None,
                "url": None,
                "restart_required": None,
            }
            kb_order.append(patch_id)

    all_patch_ids = set(kb_order)
    all_kbs = {pid for pid in all_patch_ids if pid.startswith("KB")}

    # ── 2. Enrich from patch catalog (when available) ────────────────
    superseded_by = {}
    warnings = []

    try:
        from threat_intel.patch_catalog import get_patches_for_cve
        from models.threat_intel_models import MSRCPatch
        has_catalog = True
    except ImportError:
        has_catalog = False

    if has_catalog and all_kbs:
        # Query MSRC for metadata + supersedence on KBs we have
        msrc_records = (
            db.query(MSRCPatch)
            .filter(MSRCPatch.kb_id.in_(all_kbs))
            .all()
        )
        for r in msrc_records:
            kb = (r.kb_id or "").upper()
            entry = kb_to_entry.get(kb)
            if entry:
                entry["title"] = f"{r.kb_id} — {r.product_name}" if r.product_name else entry["title"]
                entry["severity"] = r.severity or entry["severity"]
                entry["release_date"] = r.release_date
                entry["url"] = r.article_url
                entry["restart_required"] = r.restart_required
                # Add catalog CVEs on top of finding CVEs
                kb_to_finding_cves[kb].add(r.cve_id)

        # Check supersedence: newer KBs that replace ours
        superseding = (
            db.query(MSRCPatch)
            .filter(MSRCPatch.supercedence.in_(all_kbs))
            .all()
        )
        for r in superseding:
            old_kb = (r.supercedence or "").upper()
            new_kb = (r.kb_id or "").upper()
            if old_kb in all_kbs and new_kb != old_kb:
                superseded_by[old_kb] = new_kb
                # New KB inherits old KB's CVEs
                kb_to_finding_cves[new_kb].update(kb_to_finding_cves.get(old_kb, set()))
                if new_kb not in kb_to_entry:
                    kb_to_entry[new_kb] = {
                        "advisory_id": r.kb_id,
                        "source": "microsoft",
                        "title": f"{r.kb_id} — {r.product_name}" if r.product_name else r.kb_id,
                        "severity": r.severity,
                        "release_date": r.release_date,
                        "url": r.article_url,
                        "restart_required": r.restart_required,
                    }

        # Attach reliability data
        try:
            from services import patch_reliability as reliability_svc
            pairs = [
                ("msrc" if pid.startswith("KB") else kb_to_entry[pid].get("source", ""), pid)
                for pid in all_patch_ids
            ]
            rel_map = reliability_svc.get_reliability_map(db, pairs)
            for pid in all_patch_ids:
                key = (
                    ("msrc" if pid.startswith("KB") else kb_to_entry[pid].get("source", "")).strip().lower(),
                    pid.strip(),
                )
                rel = rel_map.get(key)
                if rel:
                    rel_dict = reliability_svc.reliability_to_dict(rel)
                    kb_to_entry[pid]["reliability"] = rel_dict
                    status = rel_dict.get("status", "unknown")
                    if status == "recalled":
                        warnings.append({
                            "advisory_id": pid,
                            "warning": "recalled",
                            "message": f"{pid} has been recalled by the vendor — skip or check for a replacement",
                        })
                    elif status == "known_issues":
                        warnings.append({
                            "advisory_id": pid,
                            "warning": "known_issues",
                            "message": f"{pid} has known issues — test in staging before deploying",
                            "score": rel_dict.get("score"),
                        })
        except Exception:
            pass  # reliability is best-effort

    # ── 3. Build final patch list with supersedence applied ──────────
    superseded_set = set(superseded_by.keys())
    effective_ids = [pid for pid in kb_order if pid not in superseded_set]
    # Add replacement KBs that aren't already in the list
    for new_kb in superseded_by.values():
        if new_kb not in effective_ids:
            effective_ids.append(new_kb)

    patch_list = []
    all_cves_covered = set()

    for pid in effective_ids:
        entry = dict(kb_to_entry.get(pid, {"advisory_id": pid}))
        cves = sorted(kb_to_finding_cves.get(pid, set()))
        entry["cves_fixed"] = cves[:20]
        entry["cve_count"] = len(cves)
        all_cves_covered.update(cves)

        replaces = [old for old, new in superseded_by.items() if new == pid]
        if replaces:
            entry["supersedes"] = sorted(replaces)
            entry["supersedes_count"] = len(replaces)

        patch_list.append(entry)

    uncovered = set(cve_ids or []) - all_cves_covered

    return {
        "patches": patch_list,
        "patch_count": len(patch_list),
        "original_finding_count": len(fingerprints),
        "superseded_count": len(superseded_set),
        "effective_patch_count": len(effective_ids),
        "cves_covered": len(all_cves_covered),
        "cves_uncovered": sorted(uncovered) if uncovered else [],
        "warnings": warnings,
        "has_recalled": any(w["warning"] == "recalled" for w in warnings),
        "has_known_issues": any(w["warning"] == "known_issues" for w in warnings),
    }


def _build_patch_title(patch_breakdown, hostname, finding_count):
    """Build an actionable title using patch catalog data."""
    pb = patch_breakdown
    effective = pb["effective_patch_count"]
    superseded = pb["superseded_count"]

    if effective == 0:
        return "Apply %d pending patches — %s" % (finding_count, hostname)

    if superseded > 0:
        return "Install %d update%s (%d findings, %d superseded) — %s" % (
            effective, "s" if effective != 1 else "",
            finding_count, superseded, hostname)

    return "Install %d patch%s (%d CVEs) — %s" % (
        effective, "es" if effective != 1 else "",
        pb["cves_covered"], hostname)


def _build_patch_description(patch_breakdown, hostname):
    """Build an actionable description listing actual patches to install."""
    pb = patch_breakdown
    parts = []

    # Summary line
    if pb["superseded_count"] > 0:
        parts.append(
            "**%d findings** collapse into **%d effective patches** "
            "(%d older patches are superseded by cumulative updates)." % (
                pb["original_finding_count"], pb["effective_patch_count"],
                pb["superseded_count"]))
    else:
        parts.append(
            "**%d patches** to install, covering **%d CVEs**." % (
                pb["effective_patch_count"], pb["cves_covered"]))

    # Warnings
    for w in pb.get("warnings", []):
        if w["warning"] == "recalled":
            parts.append("\n> **Warning:** %s" % w["message"])
        elif w["warning"] == "known_issues":
            parts.append("\n> **Caution:** %s" % w["message"])

    # Patch table
    patches = pb.get("patches", [])
    if patches:
        parts.append("\n**Patches to install:**")
        for p in patches[:15]:  # cap display
            line = "- **%s**" % p["advisory_id"]
            if p.get("title") and p["title"] != p["advisory_id"]:
                line += " — %s" % p["title"]
            if p.get("cve_count"):
                line += " (%d CVEs)" % p["cve_count"]
            if p.get("severity"):
                line += " [%s]" % p["severity"]
            if p.get("restart_required") and p["restart_required"].lower() not in ("no", ""):
                line += " ⟳ restart required"
            if p.get("supersedes"):
                line += " (supersedes %s)" % ", ".join(p["supersedes"][:3])
                if len(p["supersedes"]) > 3:
                    line += " +%d more" % (len(p["supersedes"]) - 3)
            # Reliability status
            rel = p.get("reliability") or {}
            status = rel.get("status")
            if status == "recalled":
                line += " **RECALLED**"
            elif status == "known_issues":
                line += " ⚠ known issues (score: %.1f)" % (rel.get("score", 0))
            parts.append(line)
        if len(patches) > 15:
            parts.append("- ... +%d more patches" % (len(patches) - 15))

    # Uncovered CVEs
    uncovered = pb.get("cves_uncovered", [])
    if uncovered:
        parts.append("\n**CVEs with no known patch:** %s" % ", ".join(uncovered[:10]))
        if len(uncovered) > 10:
            parts[-1] += " +%d more" % (len(uncovered) - 10)

    parts.append("\n**Affected host:** %s" % hostname)

    parts.append(
        "\n**Recommended action:**\n"
        "1. Deploy the patches listed above via WSUS/SCCM/Intune (Windows) "
        "or package manager (Linux)\n"
        "2. Test in staging before production\n"
        "3. Schedule maintenance window with reboot if required\n"
        "4. Verify with follow-up scan")

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# Main Pipeline
# ═══════════════════════════════════════════════════════════════════════

def aggregate_solutions(db, scan_id):
    """
    Run the full remediation grouping pipeline on a scan.

    Returns: {"created": int, "findings_linked": int}
    """
    # Clear previous aggregations for this scan
    # Nullify FK references — must cover ALL findings pointing at these solutions,
    # not just same-scan findings, because dedup can link cross-scan findings.
    old_solution_ids = [
        r[0] for r in db.query(AggregatedSolution.id)
        .filter(AggregatedSolution.scan_id == scan_id).all()
    ]
    if old_solution_ids:
        db.query(Finding).filter(
            Finding.aggregated_solution_id.in_(old_solution_ids),
        ).update({"aggregated_solution_id": None}, synchronize_session=False)
        db.flush()
        db.query(AggregatedSolution).filter(AggregatedSolution.id.in_(old_solution_ids)).delete(synchronize_session=False)
        db.flush()

    # Load all findings
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    if not findings:
        return {"created": 0, "findings_linked": 0}

    # Total scan risk for risk_reduction calculation
    total_scan_risk = sum(f.priority_score or 0 for f in findings)

    # Load assets
    asset_ids_set = {f.asset_id for f in findings}
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids_set)).all()}

    # ── Step 1: Fingerprint every finding ──────────────────
    fingerprints = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp:
            fingerprints.append(fp)

    if not fingerprints:
        return {"created": 0, "findings_linked": 0}

    # ── Step 2: Group ──────────────────────────────────────
    # For missing_patch, group per-asset (you apply patches per machine).
    # Everything else groups cross-asset.
    cross_asset_groups = defaultdict(list)
    per_asset_groups = defaultdict(list)

    for fp in fingerprints:
        if fp.root_cause_type == "missing_patch":
            per_asset_groups[(fp.finding.asset_id, fp.group_key)].append(fp)
        else:
            cross_asset_groups[fp.group_key].append(fp)

    created = 0
    linked = 0

    # ── Process cross-asset groups ─────────────────────────
    for group_key, fps in cross_asset_groups.items():
        if len(fps) < 2:
            continue

        component = fps[0].component
        root_cause = fps[0].root_cause_type
        action_type = _determine_action_type(root_cause)

        finding_ids = [fp.finding.id for fp in fps]
        affected_asset_ids = list({fp.finding.asset_id for fp in fps})
        asset_count = len(affected_asset_ids)
        hostnames = []
        for aid in affected_asset_ids:
            a = assets.get(aid)
            if a:
                hostnames.append(a.hostname or a.ip or str(aid))

        all_cves = set()
        for fp in fps:
            if fp.finding.cves:
                all_cves.update(fp.finding.cves)

        sev_max = max((fp.finding.severity or 0) for fp in fps)
        pri_max = max((fp.finding.priority_score or 0) for fp in fps)
        pri_sum = sum((fp.finding.priority_score or 0) for fp in fps)

        # Pick best target version
        target_version = None
        current_version = None
        for fp in fps:
            if fp.target_version:
                target_version = fp.target_version
            if fp.current_version:
                current_version = fp.current_version

        finding_count = len(fps)
        effort = _determine_effort(root_cause, finding_count, asset_count)
        owner = _determine_owner(root_cause, component)

        agg = AggregatedSolution(
            scan_id=scan_id,
            affected_component=component,
            current_version=current_version,
            target_version=target_version,
            root_cause_type=root_cause,
            action_type=action_type,
            title=_build_title(action_type, component, target_version,
                               asset_count, finding_count),
            description=_build_description(root_cause, action_type, component, fps,
                                           target_version, hostnames),
            action_details={
                "from_version": current_version,
                "to_version": target_version,
                "affected_hosts": hostnames,
            },
            vs_alternative=_build_vs_alternative(finding_count, asset_count),
            asset_ids=affected_asset_ids,
            asset_count=asset_count,
            finding_count=finding_count,
            finding_ids=finding_ids,
            cve_ids=sorted(all_cves) if all_cves else [],
            severity_max=sev_max,
            priority_score=round(pri_max, 2),
            risk_reduction=_compute_risk_reduction(pri_sum, total_scan_risk),
            efficiency_score=_compute_efficiency_score(
                finding_count, asset_count, sev_max, pri_max, total_scan_risk),
            effort_level=effort,
            owner_suggestion=owner,
            created_at=datetime.utcnow(),
        )
        db.add(agg)
        db.flush()

        for fp in fps:
            fp.finding.aggregated_solution_id = agg.id
        linked += finding_count
        created += 1

    # ── Process per-asset patch groups ─────────────────────
    for (asset_id, group_key), fps in per_asset_groups.items():
        if len(fps) < 2:
            continue

        component = fps[0].component
        root_cause = fps[0].root_cause_type
        asset = assets.get(asset_id)
        hostname = asset.hostname or asset.ip if asset else str(asset_id)

        finding_ids = [fp.finding.id for fp in fps]
        all_cves = set()
        for fp in fps:
            if fp.finding.cves:
                all_cves.update(fp.finding.cves)

        sev_max = max((fp.finding.severity or 0) for fp in fps)
        pri_max = max((fp.finding.priority_score or 0) for fp in fps)
        pri_sum = sum((fp.finding.priority_score or 0) for fp in fps)

        target_version = None
        for fp in fps:
            if fp.target_version:
                target_version = fp.target_version

        finding_count = len(fps)
        effort = _determine_effort(root_cause, finding_count, 1)

        # Clean component name
        clean_component = (component or "").replace("__patch__", "")

        # ── Enrich with patch catalog data ────────────────
        patch_breakdown = _enrich_patch_group(
            db, fps, asset_id, sorted(all_cves) if all_cves else [])

        if patch_breakdown and patch_breakdown["effective_patch_count"] > 0:
            title = _build_patch_title(patch_breakdown, hostname, finding_count)
            description = _build_patch_description(patch_breakdown, hostname)
            action_details = {
                "patch_count": finding_count,
                "effective_patch_count": patch_breakdown["effective_patch_count"],
                "superseded_count": patch_breakdown["superseded_count"],
                "host": hostname,
                "cve_count": len(all_cves),
                "cves_covered": patch_breakdown["cves_covered"],
                "cves_uncovered": patch_breakdown["cves_uncovered"],
                "has_recalled": patch_breakdown["has_recalled"],
                "has_known_issues": patch_breakdown["has_known_issues"],
                "patch_breakdown": patch_breakdown["patches"],
                "warnings": patch_breakdown["warnings"],
            }
            if patch_breakdown["superseded_count"] > 0:
                vs_alt = (
                    "Collapses %d individual patches into %d effective updates "
                    "(%d superseded by cumulative patches)" % (
                        finding_count, patch_breakdown["effective_patch_count"],
                        patch_breakdown["superseded_count"]))
            else:
                vs_alt = "Collapses %d separate patch actions into 1 maintenance window" % finding_count
        else:
            title = "Apply %d pending patches — %s" % (finding_count, hostname)
            description = _build_description(
                root_cause, "apply_patch", clean_component,
                fps, target_version, [hostname])
            action_details = {
                "patch_count": finding_count,
                "host": hostname,
                "cve_count": len(all_cves),
            }
            vs_alt = "Collapses %d separate patch actions into 1 maintenance window" % finding_count

        agg = AggregatedSolution(
            scan_id=scan_id,
            affected_component=clean_component,
            current_version=None,
            target_version=target_version,
            root_cause_type=root_cause,
            action_type="apply_patch",
            title=title,
            description=description,
            action_details=action_details,
            vs_alternative=vs_alt,
            asset_ids=[asset_id],
            asset_id=asset_id,
            asset_count=1,
            finding_count=finding_count,
            finding_ids=finding_ids,
            cve_ids=sorted(all_cves) if all_cves else [],
            severity_max=sev_max,
            priority_score=round(pri_max, 2),
            risk_reduction=_compute_risk_reduction(pri_sum, total_scan_risk),
            efficiency_score=_compute_efficiency_score(
                finding_count, 1, sev_max, pri_max, total_scan_risk),
            effort_level=effort,
            owner_suggestion="IT",
            created_at=datetime.utcnow(),
        )
        db.add(agg)
        db.flush()

        for fp in fps:
            fp.finding.aggregated_solution_id = agg.id
        linked += finding_count
        created += 1

    # ── Downstream impact assessment ─────────────────────
    _run_downstream_impact_on_all(db, scan_id)

    db.flush()
    logger.info("Remediation engine: %d recommendations, %d findings linked", created, linked)
    return {"created": created, "findings_linked": linked}


def _enrich_with_lifecycle(db, component, target_version):
    """
    Look up ProductLifecycle data for a component and return the actual
    latest version from endoflife.date if it's newer than the scan's target.
    """
    try:
        from threat_intel.threat_intel_sync import _resolve_slug
        from models.threat_intel_models import ProductLifecycle
    except ImportError:
        return None

    slug = _resolve_slug(component)
    if not slug:
        return None

    cycles = (
        db.query(ProductLifecycle)
        .filter(ProductLifecycle.slug == slug)
        .order_by(ProductLifecycle.is_eol, ProductLifecycle.cycle.desc())
        .all()
    )
    if not cycles:
        return None

    # Find the cycle matching the target version (prefix match)
    matched_cycle = None
    for c in cycles:
        if target_version and target_version.startswith(c.cycle):
            matched_cycle = c
            break

    if matched_cycle and matched_cycle.latest_version:
        # If the target version is already the latest, or cycle is EOL → find best
        from services.downstream_impact import _parse_version_tuple
        try:
            target_t = _parse_version_tuple(target_version)
            latest_t = _parse_version_tuple(matched_cycle.latest_version)
        except Exception:
            target_t = latest_t = None

        result = {
            "slug": slug,
            "cycle": matched_cycle.cycle,
            "is_eol": matched_cycle.is_eol,
            "eol_date": matched_cycle.eol if matched_cycle.is_eol else None,
            "lts": matched_cycle.lts,
        }

        if matched_cycle.is_eol:
            # Find the newest non-EOL cycle
            for c in cycles:
                if not c.is_eol and c.latest_version:
                    result["latest_version"] = c.latest_version
                    result["recommended_cycle"] = c.cycle
                    return result
            # All cycles EOL — still suggest the newest cycle's latest
            result["latest_version"] = cycles[0].latest_version if cycles else None
            result["recommended_cycle"] = cycles[0].cycle if cycles else None
            return result

        if target_t and latest_t and target_t < latest_t:
            result["latest_version"] = matched_cycle.latest_version
            return result

    return None


def _pick_best_version(impact, current_version):
    """
    Given a downstream impact result, check if any alternative version is
    strictly better than the current target (fewer remaining CVEs and/or
    better verdict).  Returns the best alternative dict or None.
    """
    alternatives = impact.get("alternative_versions") or []
    if not alternatives:
        return None

    current_verdict = impact.get("verdict", "safe")
    current_remaining = len(impact.get("introduced_cves") or [])

    # Verdict ranking: safe > needs_review > high_risk
    _verdict_rank = {"safe": 0, "needs_review": 1, "high_risk": 2}
    current_rank = _verdict_rank.get(current_verdict, 1)

    best = None
    for alt in alternatives:
        alt_rank = _verdict_rank.get(alt.get("verdict", "needs_review"), 1)
        alt_remaining = alt.get("introduced_cve_count", 999)

        # Must be strictly better: fewer remaining CVEs or better verdict
        if alt_remaining < current_remaining or alt_rank < current_rank:
            if best is None:
                best = alt
            else:
                best_rank = _verdict_rank.get(best.get("verdict", "needs_review"), 1)
                best_remaining = best.get("introduced_cve_count", 999)
                # Prefer fewer remaining CVEs, then better verdict
                if (alt_remaining, alt_rank) < (best_remaining, best_rank):
                    best = alt

    return best


def _run_downstream_impact_on_all(db, scan_id):
    """Run downstream impact assessment on upgrade/migrate recommendations."""
    eligible = (
        db.query(AggregatedSolution)
        .filter(
            AggregatedSolution.scan_id == scan_id,
            AggregatedSolution.action_type.in_(["upgrade_component", "migrate_to_supported"]),
        )
        .all()
    )

    # Build a map of all target versions and their resolved CVEs/findings
    # across sibling recommendations so we can suggest better versions
    sibling_data = _collect_sibling_data(eligible)

    for agg in eligible:
        to_version = None
        if agg.action_details and isinstance(agg.action_details, dict):
            to_version = agg.action_details.get("to_version")
        if not to_version and agg.target_version:
            to_version = agg.target_version
        if not to_version:
            continue

        # Find alternative target versions from sibling recommendations
        comp_lower = (agg.affected_component or "").lower()
        siblings = sibling_data.get(comp_lower, [])
        # Only suggest versions higher than current target
        to_clean = to_version.rstrip(".")
        candidates = []
        for s in siblings:
            if s["version"] == to_clean:
                continue
            candidates.append(s)

        impact = assess_downstream_impact(
            db,
            scan_id=scan_id,
            component=agg.affected_component,
            to_version=to_version,
            resolved_finding_ids=agg.finding_ids or [],
            resolved_cve_ids=agg.cve_ids or [],
            candidate_versions=candidates,
        )
        if impact is not None:
            # If a better version exists, upgrade the recommendation to use it
            best_alt = _pick_best_version(impact, to_version)
            if best_alt:
                old_version = to_version
                new_version = best_alt["version"]
                agg.target_version = new_version
                if agg.action_details and isinstance(agg.action_details, dict):
                    agg.action_details = {**agg.action_details, "to_version": new_version}
                agg.title = _build_title(
                    agg.action_type, agg.affected_component,
                    new_version, agg.asset_count, agg.finding_count,
                )
                # Update impact to reflect the better version
                impact["original_version"] = old_version
                impact["upgraded_to"] = new_version
                impact["verdict"] = best_alt["verdict"]
                impact["introduced_cves"] = []  # will be recomputed below
                impact["net_cve_delta"] = best_alt.get("net_cve_delta", impact["net_cve_delta"])
                # Recompute for the new version
                recomputed = assess_downstream_impact(
                    db,
                    scan_id=scan_id,
                    component=agg.affected_component,
                    to_version=new_version,
                    resolved_finding_ids=list(
                        set(agg.finding_ids or []) | set(best_alt.get("_combined_finding_ids", []))
                    ),
                    resolved_cve_ids=list(
                        set(agg.cve_ids or []) | set(best_alt.get("_combined_cve_ids", []))
                    ),
                    candidate_versions=[],
                )
                if recomputed:
                    recomputed["original_version"] = old_version
                    recomputed["upgraded_to"] = new_version
                    impact = recomputed

            # Enrich with product lifecycle data (endoflife.date)
            lifecycle = _enrich_with_lifecycle(db, agg.affected_component, agg.target_version or to_version)
            if lifecycle:
                impact["lifecycle"] = lifecycle
                lc_ver = lifecycle.get("latest_version")
                current_target = agg.target_version or to_version
                if lc_ver and lc_ver != current_target:
                    agg.target_version = lc_ver
                    if agg.action_details and isinstance(agg.action_details, dict):
                        agg.action_details = {**agg.action_details, "to_version": lc_ver}
                    agg.title = _build_title(
                        agg.action_type, agg.affected_component,
                        lc_ver, agg.asset_count, agg.finding_count,
                    )
                    if not impact.get("original_version"):
                        impact["original_version"] = to_version
                    impact["upgraded_to"] = lc_ver

            agg.downstream_impact = impact
            # Apply verdict multiplier to efficiency_score
            verdict = impact.get("verdict", "safe")
            multiplier = VERDICT_MULTIPLIERS.get(verdict, 1.0)
            agg.efficiency_score = round((agg.efficiency_score or 0) * multiplier, 2)
    db.flush()


def _collect_sibling_data(eligible):
    """
    Build a map of component_name → [{"version", "finding_ids", "cve_ids"}]
    across sibling recommendations (same component family, different versions).

    Groups variants like ".NET", "Microsoft .NET core", "Microsoft ASP.NET Core"
    under a common family so they can suggest each other's versions.
    Each entry carries the finding_ids and cve_ids it resolves, so the
    alternative assessment can compute what upgrading to that version fixes.
    """
    import re

    def _component_family(name):
        """Normalize component name to a family key."""
        n = (name or "").lower().strip()
        n = re.sub(r'^(microsoft|security updates? for)\s+', '', n)
        n = re.sub(r'(\.net|dotnet)\s*(framework|core|)\s*\d*', '.net', n)
        n = re.sub(r'asp\.net\s*core?', '.net', n)
        n = re.sub(r'\s+', ' ', n).strip()
        return n

    # Collect per-family version data
    family_data = {}  # family → [{"version", "finding_ids", "cve_ids"}]
    for agg in eligible:
        version = agg.target_version
        if not version:
            if agg.action_details and isinstance(agg.action_details, dict):
                version = agg.action_details.get("to_version")
        if not version:
            continue
        version = version.rstrip(".")
        family = _component_family(agg.affected_component)
        if family not in family_data:
            family_data[family] = []
        family_data[family].append({
            "version": version,
            "finding_ids": agg.finding_ids or [],
            "cve_ids": agg.cve_ids or [],
        })

    # Index by raw component name so lookup works
    result = {}
    for agg in eligible:
        comp_lower = (agg.affected_component or "").lower()
        family = _component_family(agg.affected_component)
        result[comp_lower] = family_data.get(family, [])

    return result

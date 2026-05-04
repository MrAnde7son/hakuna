"""
Prioritization engine for vulnerability findings.

Priority score (0-10) factoring:
  - CVSS score (v4 > v3 > v2, configurable)
  - VPR score (Tenable risk rating, when available)
  - EPSS probability
  - Exploit availability & maturity
  - Asset criticality (user-defined 1-10)
  - Plugin family / finding-type context signals
  - Informational plugin signals (attack surface indicators)
  - Internet-facing exposure (maxes reachability for external/dmz/public-IP assets)

Supports findings from any scanner source (Nessus, Nuclei, Qualys, etc.).
Plugin family weights and attack surface plugin IDs are Nessus-originated but
applied generically — findings without a matching family get a neutral weight.
"""

import re


PLUGIN_FAMILY_WEIGHTS = {
    # High-value families — direct exploitation paths
    "Windows": 1.3,
    "Windows : Microsoft Bulletins": 1.4,
    "Windows : User management": 1.2,
    "Gain a shell remotely": 1.5,
    "RPC": 1.2,
    "Backdoors": 1.5,
    "Denial of Service": 1.1,
    # Credential / auth issues
    "Credentials": 1.3,
    "Default Unix Accounts": 1.3,
    # Web app
    "CGI abuses": 1.2,
    "CGI abuses : XSS": 1.1,
    # Network config issues
    "Firewalls": 1.1,
    "Misc.": 1.0,
    "General": 1.0,
    # Lower priority info families
    "Service detection": 0.7,
    "Settings": 0.5,
    "Policy Compliance": 0.8,
    # Internet-facing remote-access appliances. Heavily weighted because the
    # exploit chain is "scan → public PoC → ransomware" with days, not months,
    # of patch latency. CISA KEV is dominated by this surface.
    "VPN Appliance": 1.5,
}

EXPLOIT_MATURITY_MULTIPLIERS = {
    "weaponized": 2.0,
    "functional": 1.7,
    "poc": 1.4,
    "unproven": 1.1,
    None: 1.0,
}

# Families where remediation is always a package/patch apply (no reboot caveat applies to workstations)
PATCH_FAMILIES = {
    "Windows : Microsoft Bulletins",
    "Patch Management",
    "Ubuntu Local Security Checks",
    "Red Hat Local Security Checks",
    "CentOS Local Security Checks",
    "Debian Local Security Checks",
    "Fedora Local Security Checks",
    "Amazon Linux Local Security Checks",
    "SuSE Local Security Checks",
    "Oracle Linux Local Security Checks",
    "Scientific Linux Local Security Checks",
    "Alma Linux Local Security Checks",
    "Rocky Linux Local Security Checks",
}

COMPLEX_FAMILIES = {
    "Gain a shell remotely",
    "Backdoors",
    "Credentials",
    "Firewalls",
    "SCADA",
}

# Solution text keywords that indicate a reboot is likely needed
_REBOOT_KEYWORDS = {"reboot", "restart the system", "restart windows", "kernel update", "restart your computer"}

# Solution text keywords that indicate patch/update (lower effort)
_PATCH_KEYWORDS = {"apply patch", "apply the patch", "upgrade to", "update to", "install the update",
                   "apply update", "apply the update", "apply the fix", "install kb", "apply kb"}

# Solution text keywords that indicate complex architectural change
_COMPLEX_KEYWORDS = {"redesign", "implement", "replace the", "reconfigure", "segment", "migrate",
                     "rewrite", "architect", "end of life", "no longer supported",
                     "upgrade to a supported", "no longer maintains"}

# Plugin name patterns that indicate an OS/product end-of-life (always complex)
_EOL_PLUGIN_KEYWORDS = {"seol", "end of life", "eol", "unsupported", "out of support"}

# OS strings that indicate a server (vs workstation)
_SERVER_OS_KEYWORDS = {
    "server", "linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
    "suse", "oracle linux", "amazon linux", "alma", "rocky", "esxi", "vmware",
    "freebsd", "solaris", "aix", "hp-ux",
}
_WORKSTATION_OS_KEYWORDS = {"windows 10", "windows 11", "macos", "mac os x", "darwin"}

OWNER_MAP = {
    # IT — OS patching, endpoint/workstation hygiene
    "Windows": "IT",
    "Windows : Microsoft Bulletins": "IT",
    "Windows : User management": "IT",
    "Linux": "IT",
    "Patch Management": "IT",
    "MacOS X Local Security Checks": "IT",
    "Red Hat Local Security Checks": "IT",
    "Ubuntu Local Security Checks": "IT",
    "SuSE Local Security Checks": "IT",
    "Debian Local Security Checks": "IT",
    # AppSec — web application & code-level findings
    "CGI abuses": "AppSec",
    "CGI abuses : XSS": "AppSec",
    "Web Servers": "AppSec",
    # DBA — database hardening owned by the database team
    "Databases": "DBA",
    # Networking — network devices & perimeter infra
    "Firewalls": "Networking",
    "CISCO": "Networking",
    "Junos Local Security Checks": "Networking",
    "Palo Alto Local Security Checks": "Networking",
    # IAM — identity, credentials, stale accounts
    "Credentials": "IAM",
    "Default Unix Accounts": "IAM",
    # SOC — active compromise indicators, IR-driven response
    "Gain a shell remotely": "SOC",
    "Backdoors": "SOC",
    "Malware": "SOC",
    # GRC — compliance framework findings
    "Policy Compliance": "GRC",
    # VM — vulnerability management team owns findings from the VM scanners they operate
    "Nuclei": "VM",
    # Networking owns perimeter remote-access appliances
    "VPN Appliance": "Networking",
    # SecOps — residual hardening / misc security controls
    "RPC": "SecOps",
    "General": "SecOps",
    "Misc.": "SecOps",
}

# Informational plugins that indicate meaningful attack surface
ATTACK_SURFACE_PLUGIN_IDS = {
    "10287",   # Traceroute Information
    "11219",   # Nessus SYN scanner (open ports)
    "34220",   # Netstat portscanner (SSH)
    "50686",   # IP Forwarding Enabled
    "10114",   # ICMP Timestamp
    "22964",   # Service Detection
    "25220",   # TCP/IP Timestamps
}


_DEFAULT_FINDING_WEIGHTS = {
    "severity":       0.25,
    "exploitability": 0.25,
    "intel":          0.20,
    "criticality":    0.10,
    "family":         0.10,
    "controls":       0.05,
    "reachability":   0.05,
}


def compute_priority_score(
    finding: dict,
    asset_criticality: int = 5,
    intel: dict = None,
    risk_cfg: dict = None,
    asset_inventory: dict = None,
) -> dict:
    """
    Compute a priority score and remediation metadata for a finding.

    Args:
        finding:           finding dict (plugin_id/source_vuln_id, severity, cvss*, vpr_score, …)
        asset_criticality: 1-10 asset criticality
        intel:             CVE enrichment dict from intel.json
        risk_cfg:          loaded risk config — when provided, uses finding_formula_weights
        asset_inventory:   {has_av, has_firewall, established_connections} for this asset
    Returns dict with: priority_score, effort_level, owner_suggestion, remediation_steps
    """
    intel = intel or {}

    # --- Severity source (configurable via risk config) ---
    sev_source = (risk_cfg or {}).get("severity_source", "cvss_best")
    if sev_source == "cvss2":
        sev_raw = finding.get("cvss2_score") or 0.0
        sev_norm = sev_raw / 10.0
    elif sev_source == "cvss3":
        sev_raw = finding.get("cvss3_score") or 0.0
        sev_norm = sev_raw / 10.0
    elif sev_source == "cvss4":
        sev_raw = finding.get("cvss4_score") or 0.0
        sev_norm = sev_raw / 10.0
    elif sev_source == "vpr":
        sev_raw = finding.get("vpr_score") or 0.0
        sev_norm = sev_raw / 10.0
    elif sev_source == "epss":
        sev_raw = finding.get("epss_score") or 0.0
        sev_norm = min(sev_raw, 1.0)  # EPSS is already 0-1
    else:  # cvss_best — prefer v4 > v3 > v2
        sev_raw = finding.get("cvss4_score") or finding.get("cvss3_score") or finding.get("cvss2_score") or 0.0
        sev_norm = sev_raw / 10.0

    # Keep cvss for downstream use (effort calculation, intel fallback)
    cvss = finding.get("cvss4_score") or finding.get("cvss3_score") or finding.get("cvss2_score") or 0.0
    cvss_norm = cvss / 10.0  # 0-1

    # --- VPR score ---
    vpr = finding.get("vpr_score") or 0.0
    vpr_norm = vpr / 10.0

    # --- Exploit availability ---
    exploit_bonus = 0.0
    exploit_maturity = finding.get("exploit_maturity")
    if finding.get("zero_day"):
        exploit_bonus = 1.0
    elif exploit_maturity:
        maturity_scores = {
            "weaponized": 0.9,
            "functional": 0.7,
            "poc": 0.5,
            "unproven": 0.2,
        }
        exploit_bonus = maturity_scores.get(exploit_maturity.lower(), 0.2)
    elif finding.get("exploit_available"):
        exploit_bonus = 0.5

    # Check intel.json for CVE enrichment
    cves = finding.get("cves", [])
    for cve_id in cves:
        cve_data = intel.get(cve_id, {})
        if cve_data.get("zero_day"):
            exploit_bonus = max(exploit_bonus, 1.0)
        maturity = cve_data.get("exploit_maturity", "")
        if maturity:
            maturity_scores = {"weaponized": 0.9, "functional": 0.7, "poc": 0.5, "unproven": 0.2}
            exploit_bonus = max(exploit_bonus, maturity_scores.get(maturity.lower(), 0.0))
            finding["exploit_maturity"] = maturity
        # Use intel CVSS if we don't have one
        if not finding.get("cvss3_score") and cve_data.get("cvss3", {}).get("base_score"):
            cvss = cve_data["cvss3"]["base_score"]
            cvss_norm = cvss / 10.0

    # --- Threat intel component (real-world threat signals) ---
    # Separate from exploitability: this measures "is it being exploited / is it
    # relevant right now" rather than "can it theoretically be exploited".
    intel_signals = []
    # KEV: CISA known-exploited vulnerabilities
    if finding.get("is_kev"):
        intel_signals.append(0.9)
    # EPSS: probability of exploitation in next 30 days (0-1 scale)
    epss = finding.get("epss_score")
    if epss is not None and epss > 0:
        intel_signals.append(min(epss * 1.5, 1.0))
    # Ransomware-linked CVEs
    if finding.get("ransomware_linked"):
        intel_signals.append(1.0)
    # Trending in news
    if finding.get("trending_in_news"):
        intel_signals.append(0.6)
    # VPR as a baseline intel signal (Tenable's own threat rating)
    if vpr > 0:
        intel_signals.append(vpr_norm)
    intel_factor = max(intel_signals) if intel_signals else 0.0

    # --- Asset criticality (1-10) normalized to 0-1 ---
    criticality_norm = (asset_criticality - 1) / 9.0

    # --- Plugin family weight ---
    family = finding.get("plugin_family", "")
    family_weight = PLUGIN_FAMILY_WEIGHTS.get(family, 1.0)
    family_bonus = min((family_weight - 0.5) / 1.0, 1.0)  # 0-1

    # --- Severity override for info plugins with attack surface signals ---
    plugin_id = finding.get("plugin_id", "")
    if plugin_id in ATTACK_SURFACE_PLUGIN_IDS and finding.get("severity", 0) == 0:
        # Bump attack surface indicators slightly
        family_bonus = max(family_bonus, 0.2)

    # --- Controls & reachability (from asset inventory when available) ---
    inv = asset_inventory or {}
    has_av       = inv.get("has_av")
    has_firewall = inv.get("has_firewall")
    if has_av is True or has_firewall is True:
        controls_factor = 0.0    # compensating controls present → no penalty
    elif has_av is False and has_firewall is False:
        controls_factor = 1.0    # neither present → full penalty
    else:
        controls_factor = 0.5    # unknown → neutral

    # Internet-facing assets: any attacker on the internet can reach all ports,
    # so all findings are fully reachable regardless of local netstat data.
    if inv.get("is_internet_facing"):
        reachability_factor = 1.0
    else:
        # Port-aware reachability: check if the finding's specific port is
        # listening or has established connections on the asset.
        finding_port = finding.get("port")
        listening_ports = inv.get("listening_ports") or set()
        established_ports = inv.get("established_ports") or set()
        if finding_port and str(finding_port).isdigit():
            port_int = int(finding_port)
            if port_int in established_ports:
                reachability_factor = 1.0    # actively connected on this port
            elif port_int in listening_ports:
                reachability_factor = 0.7    # port is open/listening
            else:
                reachability_factor = 0.0    # port not reachable
        else:
            # No port on finding (e.g. local check) — fall back to general connectivity
            conns = int(inv.get("established_connections", 0))
            reachability_factor = min(conns / 20.0, 1.0)

    # --- Weighted score ---
    if risk_cfg is not None:
        w = risk_cfg.get("finding_formula_weights", _DEFAULT_FINDING_WEIGHTS)
    else:
        # Legacy fallback — keeps backward-compatible behaviour
        w = {
            "severity":       0.30,
            "exploitability": 0.20,
            "intel":          0.30,
            "criticality":    0.10,
            "family":         0.10,
            "controls":       0.0,
            "reachability":   0.0,
        }

    base_score = (
        w.get("severity",       0.25) * sev_norm +
        w.get("intel",          0.25) * intel_factor +
        w.get("exploitability", 0.20) * exploit_bonus +
        w.get("criticality",    0.10) * criticality_norm +
        w.get("family",         0.10) * family_bonus +
        w.get("controls",       0.05) * controls_factor +
        w.get("reachability",   0.05) * reachability_factor
    ) * 10.0  # Scale to 0-10

    # Apply severity floor (critical findings always score >= 7)
    severity = finding.get("severity", 0)
    if severity == 4:
        base_score = max(base_score, 7.0)
    elif severity == 3:
        base_score = max(base_score, 5.0)
    elif severity == 2:
        base_score = max(base_score, 3.0)
    elif severity == 0:
        base_score = min(base_score, 2.5)  # Info findings capped

    priority_score = round(min(base_score, 10.0), 2)

    # --- Effort level ---
    # Effort is about remediation complexity, NOT risk severity.
    # Key signals: remediation type (patch vs config vs architectural),
    #              whether a reboot is needed, and whether it's a server or workstation.

    solution_lower = (finding.get("solution") or "").lower()
    plugin_name_lower = (finding.get("plugin_name") or "").lower()
    asset_os = (finding.get("asset_os") or "").lower()

    is_patch_family = family in PATCH_FAMILIES
    is_complex_family = family in COMPLEX_FAMILIES

    solution_is_patch = any(kw in solution_lower for kw in _PATCH_KEYWORDS)
    solution_is_complex = any(kw in solution_lower for kw in _COMPLEX_KEYWORDS)
    likely_needs_reboot = any(kw in solution_lower or kw in plugin_name_lower for kw in _REBOOT_KEYWORDS)
    # Windows KB patches almost always need a reboot
    if is_patch_family and "windows" in family.lower():
        likely_needs_reboot = True

    # Determine if this is a server asset or workstation
    is_workstation = any(kw in asset_os for kw in _WORKSTATION_OS_KEYWORDS)
    is_server = not is_workstation and any(kw in asset_os for kw in _SERVER_OS_KEYWORDS)
    # Fallback: use asset criticality as proxy (high criticality = likely server)
    if not asset_os:
        is_server = asset_criticality >= 7
        is_workstation = asset_criticality <= 4

    # --- Decision tree ---
    is_eol = any(kw in plugin_name_lower for kw in _EOL_PLUGIN_KEYWORDS)
    if is_eol:
        # OS/product end-of-life requires full migration — never a quick win
        effort_level = "complex"
    elif is_complex_family or solution_is_complex:
        effort_level = "complex"
    elif is_patch_family or solution_is_patch:
        # Patch-based remediation: effort depends on reboot + asset type
        if likely_needs_reboot and is_server:
            # Server reboot = change management, maintenance window, coordination
            effort_level = "medium" if asset_criticality < 9 else "complex"
        else:
            # Workstation patch/reboot or server patch without reboot → straightforward
            effort_level = "quick_win"
    else:
        # Config change or unknown — use severity + exploitability as tiebreaker
        if severity <= 1:
            effort_level = "quick_win"
        elif severity == 4 and exploit_bonus >= 0.7:
            # Critical + actively exploited → likely needs emergency process = complex
            effort_level = "complex"
        else:
            effort_level = "medium"

    # --- Owner suggestion ---
    owner = OWNER_MAP.get(family, "SecOps")

    # --- Remediation steps ---
    remediation_steps = _generate_remediation_steps(finding)

    return {
        "priority_score": priority_score,
        "effort_level": effort_level,
        "owner_suggestion": owner,
        "remediation_steps": remediation_steps,
    }


# CWE → concrete remediation guidance. Scanner-agnostic; preferred over
# plugin_name/family keyword matching because CWE is normalized at ingest.
_CWE_GUIDANCE = {
    "CWE-89": "Use parameterized queries / prepared statements with bound variables. Reject input via allow-list validation, never blocklist. Apply least-privilege DB credentials so a successful injection can't read other tables. Add a WAF rule for the affected endpoint as a short-term mitigation.",
    "CWE-79": "Context-aware output encoding (HTML, JS, URL, attribute) on every untrusted value at render time. Set a strict Content-Security-Policy with `default-src 'self'` and no `unsafe-inline`. Sanitize stored content via a vetted library (DOMPurify, OWASP Java Encoder).",
    "CWE-78": "Avoid shelling out — call the OS API directly. If a shell call is unavoidable, pass arguments as an array (never a concatenated string) and validate against an allow-list. Drop privileges before invocation.",
    "CWE-77": "Replace string-concatenated commands with structured APIs. Validate inputs against an allow-list and quote/escape any remaining user-controlled values.",
    "CWE-94": "Eliminate dynamic code evaluation (`eval`, `exec`, `Function()`, deserialization-driven code paths). If dynamic dispatch is required, use a fixed allow-list of handlers keyed by a sanitized identifier.",
    "CWE-22": "Resolve user-supplied paths against a fixed base directory and reject any result that escapes it (`os.path.realpath` + `startswith` check). Never trust filename input directly — map to opaque IDs.",
    "CWE-918": "Validate outbound URLs against an allow-list of hosts. Resolve DNS once and reuse the resolved IP for the request. Block requests to RFC1918, link-local (169.254/16, including 169.254.169.254 metadata), and loopback ranges.",
    "CWE-352": "Require an unguessable per-session anti-CSRF token on every state-changing request. Use `SameSite=Lax` (or `Strict`) cookies and verify the `Origin`/`Referer` header on sensitive endpoints.",
    "CWE-287": "Enforce authentication on every protected route at the framework/middleware layer, not per-handler. Centralize the check, add automated tests for unauthenticated access on each endpoint, and audit recent access logs for exploitation.",
    "CWE-306": "This endpoint is missing authentication entirely. Add the auth middleware/guard used by the rest of the application and verify the route is no longer reachable anonymously.",
    "CWE-862": "Add explicit authorization checks for this resource. Verify the authenticated principal has the required role/permission before returning data or performing the action.",
    "CWE-863": "Authorization is enforced incorrectly. Re-check object ownership/tenant scoping on the server side — do not rely on client-supplied IDs or hidden form fields.",
    "CWE-798": "Remove the hardcoded credential from source. Rotate the secret immediately (assume compromise) and load it from a secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) at runtime.",
    "CWE-611": "Disable external entity resolution in the XML parser (`disallow-doctype-decl` / `XMLConstants.FEATURE_SECURE_PROCESSING`). Prefer a parser configured for XXE-safety by default (defusedxml, etc.).",
    "CWE-502": "Do not deserialize untrusted input with native deserializers (`pickle`, Java `ObjectInputStream`, `unserialize`). Switch to a data-only format (JSON) with strict schema validation.",
    "CWE-434": "Validate uploaded files by content type and magic bytes, not extension. Store outside the web root, generate a server-side filename, and serve via a download handler that sets `Content-Disposition: attachment`.",
    "CWE-601": "Validate redirect targets against an allow-list of known internal paths. Never echo a user-supplied URL into a `Location` header without verification.",
    "CWE-200": "Audit the response for sensitive fields (stack traces, internal IDs, tokens, PII) and strip them. Disable verbose error pages in production.",
    "CWE-269": "Apply least privilege — review the role/capability granted and reduce to the minimum required. Audit recent uses of the elevated permission for misuse.",
    "CWE-330": "Replace the weak randomness source with a CSPRNG (`secrets` in Python, `crypto.randomBytes` in Node, `SecureRandom` in Java). Rotate any tokens generated with the weak source.",
    "CWE-327": "Migrate to a current algorithm (AES-GCM, ChaCha20-Poly1305 for encryption; SHA-256+ for hashing; Argon2/bcrypt for passwords). Re-encrypt or re-hash existing data during the next user touch.",
    "CWE-319": "Enforce TLS for this channel. Redirect HTTP→HTTPS, set HSTS with `includeSubDomains`, and disable plaintext fallback in clients.",
}

# Heuristic name match when cwe_ids is empty — covers EASM/agent findings
# whose plugin_name describes the vuln class directly.
_VULN_NAME_TO_CWE = [
    (re.compile(r"\bSQL\s*Injection\b", re.I), "CWE-89"),
    (re.compile(r"\bCross[-\s]Site\s+Scripting\b|\bXSS\b", re.I), "CWE-79"),
    (re.compile(r"\b(?:OS\s+)?Command\s+Injection\b", re.I), "CWE-78"),
    (re.compile(r"\bCode\s+Injection\b|\bRemote\s+Code\s+Execution\b|\bRCE\b", re.I), "CWE-94"),
    (re.compile(r"\bPath\s+Traversal\b|\bDirectory\s+Traversal\b", re.I), "CWE-22"),
    (re.compile(r"\bSSRF\b|\bServer[-\s]Side\s+Request\s+Forgery\b", re.I), "CWE-918"),
    (re.compile(r"\bCSRF\b|\bCross[-\s]Site\s+Request\s+Forgery\b", re.I), "CWE-352"),
    (re.compile(r"\bXXE\b|\bXML\s+External\s+Entity\b", re.I), "CWE-611"),
    (re.compile(r"\b(?:Insecure|Unsafe)\s+Deserialization\b", re.I), "CWE-502"),
    (re.compile(r"\bUnrestricted\s+File\s+Upload\b|\bArbitrary\s+File\s+Upload\b", re.I), "CWE-434"),
    (re.compile(r"\bOpen\s+Redirect\b", re.I), "CWE-601"),
    (re.compile(r"\bHardcoded\s+(?:Credential|Password|Secret)\b", re.I), "CWE-798"),
    (re.compile(r"\bMissing\s+Authentication\b", re.I), "CWE-306"),
    (re.compile(r"\bBroken\s+Access\s+Control\b|\bIDOR\b|\bInsecure\s+Direct\s+Object\b", re.I), "CWE-863"),
]


def _cwe_guidance(cwe_ids, plugin_name):
    """Return CWE-driven guidance for the first matching CWE, or None."""
    for raw in cwe_ids or []:
        if not isinstance(raw, str):
            continue
        cwe = raw.upper().strip()
        if cwe in _CWE_GUIDANCE:
            return _CWE_GUIDANCE[cwe]
    name = plugin_name or ""
    for pattern, cwe in _VULN_NAME_TO_CWE:
        if pattern.search(name):
            return _CWE_GUIDANCE.get(cwe)
    return None


def _generate_remediation_steps(finding: dict) -> str:
    """Generate plain-English remediation steps based on finding context."""
    solution = finding.get("solution", "")
    plugin_name = finding.get("plugin_name", "")
    family = finding.get("plugin_family", "")
    severity = finding.get("severity", 0)
    cves = finding.get("cves", [])
    cwe_ids = finding.get("cwe_ids", []) or []

    steps = []

    # Step 1: Assessment
    if severity >= 3:
        steps.append(f"**IMMEDIATE ACTION REQUIRED** — This is a {'Critical' if severity == 4 else 'High'} severity finding.")
    if cves:
        cve_list = ", ".join(cves[:3])
        steps.append(f"Review the following CVE(s): {cve_list}")

    # Step 2: Specific remediation from the scanner's solution field, if present
    if solution and solution.strip() not in ("N/A", "n/a", ""):
        steps.append(f"**Recommended fix:** {solution.strip()}")

    # Step 3: Vuln-class guidance — prefer CWE (taxonomy is scanner-agnostic),
    # fall back to plugin_family / plugin_name keyword heuristics.
    cwe_step = _cwe_guidance(cwe_ids, plugin_name)
    if cwe_step:
        steps.append(cwe_step)
    else:
        family_lower = family.lower() if family else ""
        plugin_lower = plugin_name.lower() if plugin_name else ""
        if "windows" in family_lower or "microsoft" in family_lower:
            steps.append("Apply the latest Windows Update or the specific KB article referenced. Test in staging before production rollout.")
        elif "ssl" in plugin_lower or "tls" in plugin_lower:
            steps.append("Disable weak cipher suites and protocols. Enable TLS 1.2/1.3 only. Renew or replace the certificate if expired.")
        elif "ssh" in plugin_lower:
            steps.append("Review SSH configuration (/etc/ssh/sshd_config). Disable root login, weak algorithms, and unused authentication methods.")
        elif "smb" in plugin_lower:
            steps.append("Disable SMBv1 via PowerShell: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`. Ensure SMB signing is enforced.")
        elif "rdp" in plugin_lower:
            steps.append("Enable Network Level Authentication (NLA). Restrict RDP access via firewall to trusted IP ranges only.")
        elif "ip forwarding" in plugin_lower:
            steps.append("Disable IP forwarding unless this host is a router: Linux: `echo 0 > /proc/sys/net/ipv4/ip_forward`. Windows: Set IPEnableRouter=0 in registry.")
        elif "default" in plugin_lower and "account" in plugin_lower:
            steps.append("Change all default credentials immediately. Disable accounts that are not needed.")
        elif "icmp" in plugin_lower:
            steps.append("Configure firewall rules to block ICMP timestamp requests (type 13) and replies (type 14).")

    # Step 4: Verification — scanner-agnostic
    steps.append("Verify the fix by re-running a scan against the affected host after remediation.")

    return "\n\n".join(steps)


def compute_asset_risk_score(findings: list) -> float:
    """Compute an overall risk score for an asset based on its findings."""
    if not findings:
        return 0.0

    # Weighted sum: critical=10, high=7, medium=4, low=1, info=0
    SEVERITY_WEIGHTS = {4: 10, 3: 7, 2: 4, 1: 1, 0: 0}
    total = sum(SEVERITY_WEIGHTS.get(f.get("severity", 0), 0) for f in findings)
    # Normalize: assume 5 critical findings = max score
    normalized = min(total / 50.0, 1.0) * 10.0
    return round(normalized, 2)

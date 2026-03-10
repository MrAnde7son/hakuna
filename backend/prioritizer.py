"""
Prioritization engine for Nessus findings.

Priority score (0-10) factoring:
  - CVSS score (v3 preferred, v2 fallback)
  - VPR score (Nessus's own risk rating)
  - Exploit availability & maturity
  - Asset criticality (user-defined 1-5)
  - Plugin family context signals
  - Informational plugin signals (attack surface indicators)
"""

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
}

EXPLOIT_MATURITY_MULTIPLIERS = {
    "weaponized": 2.0,
    "functional": 1.7,
    "poc": 1.4,
    "unproven": 1.1,
    None: 1.0,
}

EFFORT_THRESHOLDS = {
    # Plugin IDs or families known to be quick wins
    "quick_win_families": {"Windows : Microsoft Bulletins", "Patch Management"},
    "complex_families": {"Gain a shell remotely", "Backdoors", "Credentials"},
}

OWNER_MAP = {
    "Windows": "IT",
    "Windows : Microsoft Bulletins": "IT",
    "Windows : User management": "IT",
    "Linux": "IT",
    "Patch Management": "IT",
    "CGI abuses": "AppSec",
    "CGI abuses : XSS": "AppSec",
    "Databases": "AppSec",
    "Web Servers": "DevOps",
    "Firewalls": "SecOps",
    "Gain a shell remotely": "SecOps",
    "Backdoors": "SecOps",
    "Credentials": "SecOps",
    "Default Unix Accounts": "SecOps",
    "RPC": "SecOps",
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
    "intel":          0.25,
    "exploitability": 0.20,
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
        finding:           finding dict (plugin_id, severity, cvss*, vpr_score, …)
        asset_criticality: 1-10 asset criticality
        intel:             CVE enrichment dict from intel.json
        risk_cfg:          loaded risk config — when provided, uses finding_formula_weights
        asset_inventory:   {has_av, has_firewall, established_connections} for this asset
    Returns dict with: priority_score, effort_level, owner_suggestion, remediation_steps
    """
    intel = intel or {}

    # --- Base score: best available CVSS ---
    cvss = finding.get("cvss3_score") or finding.get("cvss2_score") or 0.0
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

    conns = int(inv.get("established_connections", 0))
    reachability_factor = min(conns / 20.0, 1.0)

    # --- Weighted score ---
    if risk_cfg is not None:
        w = risk_cfg.get("finding_formula_weights", _DEFAULT_FINDING_WEIGHTS)
    else:
        # Legacy fallback — keeps backward-compatible behaviour
        w = {
            "severity":       0.30,
            "intel":          0.30,
            "exploitability": 0.20,
            "criticality":    0.10,
            "family":         0.10,
            "controls":       0.0,
            "reachability":   0.0,
        }

    base_score = (
        w.get("severity",       0.25) * cvss_norm +
        w.get("intel",          0.25) * vpr_norm +
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
    if severity <= 1 or (cvss <= 4.0 and not exploit_bonus):
        effort_level = "quick_win"
    elif severity == 4 or exploit_bonus >= 0.7:
        effort_level = "complex"
    else:
        effort_level = "medium"

    # Quick win override for well-known patch families
    if family in EFFORT_THRESHOLDS["quick_win_families"]:
        effort_level = "quick_win"
    if family in EFFORT_THRESHOLDS["complex_families"]:
        effort_level = "complex"

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


def _generate_remediation_steps(finding: dict) -> str:
    """Generate plain-English remediation steps based on finding context."""
    solution = finding.get("solution", "")
    plugin_name = finding.get("plugin_name", "")
    family = finding.get("plugin_family", "")
    severity = finding.get("severity", 0)
    cves = finding.get("cves", [])
    cvss = finding.get("cvss3_score") or finding.get("cvss2_score") or 0

    steps = []

    # Step 1: Assessment
    if severity >= 3:
        steps.append(f"**IMMEDIATE ACTION REQUIRED** — This is a {'Critical' if severity == 4 else 'High'} severity finding.")
    if cves:
        cve_list = ", ".join(cves[:3])
        steps.append(f"Review the following CVE(s): {cve_list}")

    # Step 2: Specific remediation
    if solution and solution.strip() not in ("N/A", "n/a", ""):
        steps.append(f"**Recommended fix:** {solution.strip()}")

    # Step 3: Family-specific guidance
    family_lower = family.lower() if family else ""
    if "windows" in family_lower or "microsoft" in family_lower:
        steps.append("Apply the latest Windows Update or the specific KB article referenced. Test in staging before production rollout.")
    elif "ssl" in plugin_name.lower() or "tls" in plugin_name.lower():
        steps.append("Disable weak cipher suites and protocols. Enable TLS 1.2/1.3 only. Renew or replace the certificate if expired.")
    elif "ssh" in plugin_name.lower():
        steps.append("Review SSH configuration (/etc/ssh/sshd_config). Disable root login, weak algorithms, and unused authentication methods.")
    elif "smb" in plugin_name.lower():
        steps.append("Disable SMBv1 via PowerShell: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`. Ensure SMB signing is enforced.")
    elif "rdp" in plugin_name.lower():
        steps.append("Enable Network Level Authentication (NLA). Restrict RDP access via firewall to trusted IP ranges only.")
    elif "ip forwarding" in plugin_name.lower():
        steps.append("Disable IP forwarding unless this host is a router: Linux: `echo 0 > /proc/sys/net/ipv4/ip_forward`. Windows: Set IPEnableRouter=0 in registry.")
    elif "default" in plugin_name.lower() and "account" in plugin_name.lower():
        steps.append("Change all default credentials immediately. Disable accounts that are not needed.")
    elif "icmp" in plugin_name.lower():
        steps.append("Configure firewall rules to block ICMP timestamp requests (type 13) and replies (type 14).")

    # Step 4: Verification
    steps.append("Verify the fix by re-running the Nessus scan against the affected host after remediation.")

    # Step 5: Compensating controls
    if severity >= 3 and not cves:
        steps.append("If immediate patching is not possible, implement compensating controls: network segmentation, access restrictions, or additional monitoring.")

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

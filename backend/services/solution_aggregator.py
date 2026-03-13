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

from models.models import Finding, Asset, AggregatedSolution

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

# Misconfiguration keywords
_MISCONFIG_PATTERNS = [
    (re.compile(r"SSL\s+(?:Medium|Weak)\s+Strength\s+Cipher", re.I), "SSL/TLS Cipher Config"),
    (re.compile(r"SSL\s+Certificate\s+(?:Cannot\s+Be\s+Trusted|Expir|Self.Signed|Chain)", re.I), "SSL Certificate"),
    (re.compile(r"SSL\s+(?:RC4|CBC|NULL|Anonymous|Export)\s+Cipher", re.I), "SSL/TLS Cipher Config"),
    (re.compile(r"SMB\s+Signing\s+(?:not\s+required|disabled)", re.I), "SMB Signing"),
    (re.compile(r"(?:SSH|SSHD).*(?:Weak|CBC|Deprecated|Enabled)", re.I), "SSH Config"),
    (re.compile(r"(?:Default|Weak)\s+(?:Credential|Password|Account)", re.I), "Default Credentials"),
    (re.compile(r"Kerberos\s+.*(?:Pre.authentication|Weak\s+Encryption)", re.I), "Kerberos Config"),
    (re.compile(r"(?:NFS|RPC|SNMP).*(?:Enabled|Open|Public|Community)", re.I), "Service Hardening"),
    (re.compile(r"(?:AutoAdmin|Autologon)\s+Enabled", re.I), "Windows Autologon"),
    (re.compile(r"Speculative\s+Execution", re.I), "Speculative Execution Mitigations"),
    (re.compile(r"Insecure\s+Windows\s+Service\s+Permissions", re.I), "Windows Service Permissions"),
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
# Main Pipeline
# ═══════════════════════════════════════════════════════════════════════

def aggregate_solutions(db, scan_id):
    """
    Run the full remediation grouping pipeline on a scan.

    Returns: {"created": int, "findings_linked": int}
    """
    # Clear previous aggregations for this scan
    db.query(AggregatedSolution).filter(AggregatedSolution.scan_id == scan_id).delete()
    db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.aggregated_solution_id.isnot(None),
    ).update({"aggregated_solution_id": None}, synchronize_session=False)
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

        agg = AggregatedSolution(
            scan_id=scan_id,
            affected_component=clean_component,
            current_version=None,
            target_version=target_version,
            root_cause_type=root_cause,
            action_type="apply_patch",
            title="Apply %d pending patches — %s" % (finding_count, hostname),
            description=_build_description(root_cause, "apply_patch", clean_component,
                                           fps, target_version, [hostname]),
            action_details={
                "patch_count": finding_count,
                "host": hostname,
                "cve_count": len(all_cves),
            },
            vs_alternative="Collapses %d separate patch actions into 1 maintenance window" % finding_count,
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

    db.flush()
    logger.info("Remediation engine: %d recommendations, %d findings linked", created, linked)
    return {"created": created, "findings_linked": linked}

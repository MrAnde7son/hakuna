"""
SBOM pipeline — correlates InventorySoftware, InventoryProcess, Findings,
and ProductLifecycle data to produce SBOMComponent + SBOMVulnerability records.

Called automatically at the end of scan upload, after inventory extraction.
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from models.models import (
    SBOMComponent, SBOMVulnerability,
    InventorySoftware, InventoryProcess, Finding, Asset,
)
from models.threat_intel_models import ProductLifecycle, ThreatCVE

logger = logging.getLogger(__name__)

# ── Category → component_type heuristics ─────────────────

_CATEGORY_TYPE_MAP = {
    "Security":        "application",
    "Dev Tools":       "library",
    "Collaboration":   "application",
    "Productivity":    "application",
    "Browser":         "application",
    "Remote Access":   "application",
    "Virtualization":  "application",
    "Cloud & Storage": "application",
    "Database":        "application",
    "Media":           "application",
    "Utilities":       "application",
    "Networking":      "application",
}

_RUNTIME_KEYWORDS = {"python", "node", "nodejs", "java", "jre", "jdk", "dotnet",
                     ".net", "ruby", "php", "perl", "go", "rust"}

_OS_KEYWORDS = {"windows", "linux", "macos", "ubuntu", "debian", "centos",
                "red hat", "rhel", "suse", "fedora", "freebsd"}

# ── Known product → endoflife.date slug mapping ──────────

_PRODUCT_SLUG_MAP = {
    "python":               "python",
    "node.js":              "nodejs",
    "nodejs":               "nodejs",
    "java":                 "java-se",
    "jre":                  "java-se",
    "jdk":                  "java-se",
    "openjdk":              "java-se",
    ".net framework":       "dotnet-framework",
    ".net":                 "dotnet",
    "dotnet":               "dotnet",
    "ruby":                 "ruby",
    "php":                  "php",
    "apache http server":   "apache",
    "apache httpd":         "apache",
    "nginx":                "nginx",
    "openssl":              "openssl",
    "postgresql":           "postgresql",
    "mysql":                "mysql",
    "mariadb":              "mariadb",
    "mongodb":              "mongodb",
    "redis":                "redis",
    "elasticsearch":        "elasticsearch",
    "tomcat":               "tomcat",
    "docker":               "docker-engine",
    "kubernetes":           "kubernetes",
    "windows server":       "windows-server",
    "windows 10":           "windows",
    "windows 11":           "windows",
    "ubuntu":               "ubuntu",
    "debian":               "debian",
    "centos":               "centos",
    "red hat enterprise":   "rhel",
    "rhel":                 "rhel",
    "suse":                 "sles",
    "amazon linux":         "amazon-linux",
    "oracle linux":         "oracle-linux",
    "log4j":                "log4j",
    "spring framework":     "spring-framework",
    "spring boot":          "spring-boot",
    "angular":              "angular",
    "react":                "react",
    "vue":                  "vue",
    "jquery":               "jquery",
    "wordpress":            "wordpress",
    "drupal":               "drupal",
    "iis":                  "iis",
    "adobe acrobat":        "adobe-acrobat",
    "adobe reader":         "adobe-acrobat",
}


def _classify_component_type(sw):
    """Determine component_type from software metadata."""
    name_lower = (sw.name or "").lower()
    cat = sw.category or ""

    # OS detection
    for kw in _OS_KEYWORDS:
        if kw in name_lower:
            return "os"

    # Runtime detection
    for kw in _RUNTIME_KEYWORDS:
        if kw in name_lower.split() or name_lower.startswith(kw):
            return "runtime"

    return _CATEGORY_TYPE_MAP.get(cat, "application")


def _normalize_name(name):
    """Normalize software name for matching."""
    if not name:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()


def _build_cpe(vendor, name, version):
    """Generate a CPE 2.3 URI from vendor/name/version."""
    if not name:
        return None
    v = (vendor or "").lower().replace(" ", "_")
    n = name.lower().replace(" ", "_")
    ver = (version or "*").replace(" ", "_")
    return f"cpe:2.3:a:{v or '*'}:{n}:{ver}:*:*:*:*:*:*:*"


def _match_process_name(sw_name, process_names_lower):
    """Check if a software name matches any running process."""
    if not sw_name:
        return False
    name_lower = sw_name.lower()
    # Direct match
    if name_lower in process_names_lower:
        return True
    # Match without common suffixes
    base = re.sub(r"\.(exe|dll|sys|service|daemon)$", "", name_lower)
    if base in process_names_lower:
        return True
    # First word match (e.g. "Apache HTTP Server" → "apache" or "httpd")
    words = name_lower.split()
    if words and words[0] in process_names_lower:
        return True
    return False


def _find_lifecycle_match(db, sw_name, sw_version):
    """Find a ProductLifecycle match for a software component."""
    name_lower = _normalize_name(sw_name)

    # Try known slug mapping
    matched_slug = None
    for product_key, slug in _PRODUCT_SLUG_MAP.items():
        if product_key in name_lower:
            matched_slug = slug
            break

    if not matched_slug:
        return None

    # Extract major.minor cycle from version
    if not sw_version:
        return None
    ver_match = re.match(r"(\d+(?:\.\d+)?)", sw_version)
    if not ver_match:
        return None
    cycle = ver_match.group(1)

    lifecycle = db.query(ProductLifecycle).filter(
        ProductLifecycle.slug == matched_slug,
        ProductLifecycle.cycle == cycle,
    ).first()

    return lifecycle


def _compute_eol_status(lifecycle):
    """Compute eol_status from a ProductLifecycle record."""
    if not lifecycle:
        return "unknown", None
    if lifecycle.is_eol:
        return "eol", lifecycle.eol
    # Check if approaching EOL (within 90 days)
    if lifecycle.eol and lifecycle.eol not in ("true", "false"):
        try:
            eol_date = datetime.strptime(lifecycle.eol, "%Y-%m-%d")
            if eol_date - datetime.utcnow() < timedelta(days=90):
                return "approaching_eol", lifecycle.eol
        except ValueError:
            pass
    return "active", lifecycle.eol


def _compute_vuln_priority(severity, is_running, is_eol, in_kev):
    """Compute P1-P5 priority tier for a vulnerability."""
    if is_running and severity >= 4 and is_eol:
        return "P1"
    if is_running and severity >= 4:
        return "P2"
    if in_kev:
        return "P2"
    if is_running and severity >= 3:
        return "P3"
    if not is_running and severity >= 4:
        return "P4"
    if is_eol and severity >= 3:
        return "P3"
    if severity >= 3:
        return "P4"
    return "P5"


def _compute_component_priority(cve_count, max_severity, is_running, eol_status):
    """Compute P1-P5 priority tier for a component."""
    is_eol = eol_status == "eol"
    if is_running and max_severity >= 4 and is_eol:
        return "P1"
    if is_running and max_severity >= 4:
        return "P2"
    if is_running and max_severity >= 3:
        return "P3"
    if not is_running and max_severity >= 4:
        return "P4"
    if is_eol and cve_count == 0:
        return "P5"
    if is_eol:
        return "P4"
    if cve_count > 0:
        return "P5"
    return None


def _generate_remediation_note(sw_name, sw_version, cve_id, eol_status, lifecycle):
    """Generate a human-readable remediation note."""
    if eol_status == "eol":
        if lifecycle and lifecycle.latest_version:
            return f"Replace — {sw_name} {sw_version} is EOL, upgrade to latest supported cycle or replace"
        return f"Replace — {sw_name} {sw_version} is EOL, no patch available"
    if lifecycle and lifecycle.latest_version:
        return f"Patch {sw_name} to {lifecycle.latest_version}+"
    return f"Update {sw_name} to latest patched version"


def build_sbom_from_inventory(db: Session, scan_id: int):
    """
    Build SBOM records by correlating inventory software, processes,
    findings, and product lifecycle data.

    Returns summary stats dict.
    """
    # ── 1. Load source data ──────────────────────────────
    software_rows = db.query(InventorySoftware).filter(
        InventorySoftware.scan_id == scan_id
    ).all()

    if not software_rows:
        return {"components": 0, "vulnerabilities": 0}

    # Need org_id to write `cve_on_asset` edges tagged `source_system='sbom'`.
    # Without it the chain coordinator's `sbom_unpatched` pattern can never fire.
    from models.models import Scan
    scan_row = db.query(Scan.org_id).filter(Scan.id == scan_id).first()
    org_id = scan_row[0] if scan_row else None

    process_rows = db.query(InventoryProcess).filter(
        InventoryProcess.scan_id == scan_id
    ).all()

    # Build per-asset process name sets
    asset_processes = defaultdict(set)
    for p in process_rows:
        if p.process_name:
            asset_processes[p.asset_id].add(p.process_name.lower().rstrip(".exe"))

    # Load findings with CVEs for this scan, grouped by asset
    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id,
        Finding.cves.isnot(None),
    ).all()

    asset_findings = defaultdict(list)
    for f in findings:
        if f.cves:
            asset_findings[f.asset_id].append(f)

    # Build CVE → ThreatCVE lookup (for enrichment)
    all_cves = set()
    for f in findings:
        if f.cves:
            all_cves.update(f.cves)
    threat_cve_map = {}
    if all_cves:
        threat_cves = db.query(ThreatCVE).filter(ThreatCVE.cve_id.in_(list(all_cves))).all()
        threat_cve_map = {tc.cve_id: tc for tc in threat_cves}

    # ── 2. Clear existing SBOM data for this scan ────────
    existing_comp_ids = [c[0] for c in db.query(SBOMComponent.id).filter(
        SBOMComponent.scan_id == scan_id
    ).all()]
    if existing_comp_ids:
        db.query(SBOMVulnerability).filter(
            SBOMVulnerability.component_id.in_(existing_comp_ids)
        ).delete(synchronize_session=False)
        db.query(SBOMComponent).filter(
            SBOMComponent.scan_id == scan_id
        ).delete(synchronize_session=False)
        db.flush()

    # ── 3. Create SBOMComponent records ──────────────────
    components = []
    comp_by_asset = defaultdict(list)
    seen = set()

    for sw in software_rows:
        key = (sw.scan_id, sw.asset_id, (sw.name or "").lower(), sw.version or "")
        if key in seen:
            continue
        seen.add(key)

        comp_type = _classify_component_type(sw)
        is_running = _match_process_name(sw.name, asset_processes.get(sw.asset_id, set()))

        # EOL check
        lifecycle = _find_lifecycle_match(db, sw.name, sw.version)
        eol_status, eol_date = _compute_eol_status(lifecycle)

        comp = SBOMComponent(
            scan_id=sw.scan_id,
            asset_id=sw.asset_id,
            software_id=sw.id,
            name=sw.name,
            version=sw.version,
            vendor=sw.vendor,
            cpe=_build_cpe(sw.vendor, sw.name, sw.version),
            component_type=comp_type,
            is_running=is_running,
            eol_date=eol_date,
            eol_status=eol_status,
            source_plugin=sw.source_plugin,
        )
        db.add(comp)
        components.append(comp)
        comp_by_asset[sw.asset_id].append((comp, sw, lifecycle))

    db.flush()  # get IDs

    # ── 4. Build component hierarchy ─────────────────────
    for asset_id, comps in comp_by_asset.items():
        # Find runtimes on this asset
        runtimes = {c.id: c for c, _, _ in comps if c.component_type == "runtime"}
        if not runtimes:
            continue
        # Simple heuristic: libraries on same asset with matching vendor → child of runtime
        for comp, sw, _ in comps:
            if comp.component_type == "library" and comp.id not in runtimes:
                for rt_id, rt in runtimes.items():
                    rt_name = _normalize_name(rt.name)
                    comp_name = _normalize_name(comp.name)
                    if rt_name and (rt_name in comp_name or
                                   (rt.vendor and comp.vendor and
                                    rt.vendor.lower() == comp.vendor.lower())):
                        comp.parent_component_id = rt_id
                        break

    # ── 5. Match components against findings (CVEs) ──────
    vuln_count = 0

    for asset_id, comps in comp_by_asset.items():
        asset_finding_list = asset_findings.get(asset_id, [])
        if not asset_finding_list:
            continue

        for comp, sw, lifecycle in comps:
            comp_name_norm = _normalize_name(comp.name)
            matched_cves = {}  # cve_id → (finding, severity, cvss)

            for finding in asset_finding_list:
                # Match by name in plugin_name or solution
                finding_name_norm = _normalize_name(finding.plugin_name)
                finding_solution_norm = _normalize_name(finding.solution or "")

                name_match = (
                    comp_name_norm and len(comp_name_norm) > 2 and
                    (comp_name_norm in finding_name_norm or
                     comp_name_norm in finding_solution_norm)
                )

                if not name_match:
                    continue

                for cve_id in (finding.cves or []):
                    if cve_id not in matched_cves:
                        matched_cves[cve_id] = finding

            # Create SBOMVulnerability records
            max_sev = 0
            max_cvss_val = 0.0

            for cve_id, finding in matched_cves.items():
                tc = threat_cve_map.get(cve_id)
                sev = finding.severity or 0
                cvss = finding.cvss3_score or finding.cvss2_score or 0.0
                if tc:
                    cvss = tc.cvss3_score or cvss

                is_eol = comp.eol_status == "eol"
                ptier = _compute_vuln_priority(sev, comp.is_running, is_eol, tc.in_kev if tc else False)

                vuln = SBOMVulnerability(
                    component_id=comp.id,
                    finding_id=finding.id,
                    cve_id=cve_id,
                    severity=sev,
                    cvss_score=cvss,
                    epss_score=tc.epss_score if tc else None,
                    in_kev=tc.in_kev if tc else False,
                    remediation_note=_generate_remediation_note(
                        comp.name, comp.version, cve_id, comp.eol_status, lifecycle
                    ),
                    priority_tier=ptier,
                )
                db.add(vuln)
                vuln_count += 1

                if org_id and tc and tc.in_kev and asset_id:
                    from services.asset_edges import write_sbom_kev_edge
                    write_sbom_kev_edge(
                        db,
                        org_id=org_id,
                        asset_id=asset_id,
                        cve_id=cve_id,
                        finding_id=finding.id,
                        component_name=comp.name,
                        component_version=comp.version,
                    )

                max_sev = max(max_sev, sev)
                max_cvss_val = max(max_cvss_val, cvss or 0)

            # Update denormalized fields on component
            comp.cve_count = len(matched_cves)
            comp.max_severity = max_sev
            comp.max_cvss = max_cvss_val if max_cvss_val > 0 else None
            comp.priority_tier = _compute_component_priority(
                len(matched_cves), max_sev, comp.is_running, comp.eol_status
            )

    db.commit()

    # Summary stats
    p_counts = defaultdict(int)
    for c in components:
        if c.priority_tier:
            p_counts[c.priority_tier] += 1

    return {
        "components": len(components),
        "vulnerabilities": vuln_count,
        **{f"{k}_count": v for k, v in sorted(p_counts.items())},
    }

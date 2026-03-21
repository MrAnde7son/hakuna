"""
OS & Software auto-tagging — automatically creates and assigns tags based on
asset operating systems and installed software detected during scans.

Tags are created under two categories:
  - os:<family>        e.g. os:Windows, os:Linux, os:macOS
  - software:<name>    e.g. software:Apache, software:MySQL, software:OpenSSH

Called from the post-ingest pipeline after every scan upload.
"""

import logging
import re
from typing import Optional

from sqlalchemy.orm import Session

from models.models import Asset, Tag, TagAssignment, InventorySoftware, Scan

logger = logging.getLogger(__name__)

# ─── OS family classification patterns ─────────────────────────────────────────

_OS_FAMILY_PATTERNS = [
    (r"\bwindows\s+server\b", "Windows Server"),
    (r"\bwindows\s+(10|11)\b", "Windows Desktop"),
    (r"\bwindows\b", "Windows"),
    (r"\bubuntu\b", "Ubuntu"),
    (r"\bdebian\b", "Debian"),
    (r"\bcentos\b", "CentOS"),
    (r"\bred\s*hat\b|\brhel\b", "Red Hat"),
    (r"\bsuse\b|\bsles\b", "SUSE"),
    (r"\bfedora\b", "Fedora"),
    (r"\bamazon\s+linux\b", "Amazon Linux"),
    (r"\boracle\s+linux\b", "Oracle Linux"),
    (r"\barch\s*linux\b", "Arch Linux"),
    (r"\balpine\b", "Alpine Linux"),
    (r"\blinux\b", "Linux"),
    (r"\bmacos\b|\bmac\s*os\b|\bos\s*x\b|\bdarwin\b", "macOS"),
    (r"\bfreebsd\b", "FreeBSD"),
    (r"\bopenbsd\b", "OpenBSD"),
    (r"\besxi\b|\bvmware\b", "VMware ESXi"),
    (r"\bcisco\s+ios\b|\bnx-os\b", "Cisco IOS"),
    (r"\bjunos\b", "Juniper JunOS"),
    (r"\bfortios\b|\bfortigate\b", "FortiOS"),
    (r"\bpan-os\b|\bpalo\s*alto\b", "PAN-OS"),
    (r"\baix\b", "AIX"),
    (r"\bsolaris\b|\bsunos\b", "Solaris"),
    (r"\bhp-ux\b", "HP-UX"),
]

# Compiled for performance
_OS_FAMILY_COMPILED = [(re.compile(pat, re.IGNORECASE), family) for pat, family in _OS_FAMILY_PATTERNS]

# ─── Common software normalization ─────────────────────────────────────────────

_SOFTWARE_NORMALIZE = [
    (r"\bapache\s+(http\s*server|httpd)\b", "Apache HTTP Server"),
    (r"\bnginx\b", "Nginx"),
    (r"\biis\b|\binternet\s+information\s+services\b", "Microsoft IIS"),
    (r"\bmysql\b", "MySQL"),
    (r"\bpostgresql\b|\bpostgres\b", "PostgreSQL"),
    (r"\bmicrosoft\s+sql\s+server\b|\bmssql\b", "Microsoft SQL Server"),
    (r"\boracle\s+database\b|\boracle\s+db\b", "Oracle Database"),
    (r"\bmongodb\b", "MongoDB"),
    (r"\bredis\b", "Redis"),
    (r"\bopenssh\b", "OpenSSH"),
    (r"\bopenssl\b", "OpenSSL"),
    (r"\bapache\s+tomcat\b|\btomcat\b", "Apache Tomcat"),
    (r"\bjava\b.*\bjdk\b|\bjdk\b|\bjava\s+se\b", "Java JDK"),
    (r"\bpython\b", "Python"),
    (r"\bnode\.?js\b", "Node.js"),
    (r"\b\.net\s+framework\b|\bdotnet\b", ".NET Framework"),
    (r"\bphp\b", "PHP"),
    (r"\bdocker\b", "Docker"),
    (r"\bkubernetes\b|\bk8s\b", "Kubernetes"),
    (r"\bjenkins\b", "Jenkins"),
    (r"\bgit\b(?!\s*hub)", "Git"),
    (r"\bwordpress\b", "WordPress"),
    (r"\bsamba\b", "Samba"),
    (r"\bbind\b.*\bdns\b|\bnamed\b|\bbind9\b", "BIND DNS"),
    (r"\bpostfix\b", "Postfix"),
    (r"\bsendmail\b", "Sendmail"),
    (r"\belasticsearch\b", "Elasticsearch"),
    (r"\bkafka\b", "Apache Kafka"),
    (r"\brabbitmq\b", "RabbitMQ"),
    (r"\bvmware\s+tools\b", "VMware Tools"),
    (r"\bcrowdstrike\b|\bfalcon\b", "CrowdStrike Falcon"),
    (r"\bsymantec\b.*\bendpoint\b|\bsep\b", "Symantec Endpoint Protection"),
    (r"\bmcafee\b|\btrellix\b", "McAfee/Trellix"),
    (r"\bwindows\s+defender\b", "Windows Defender"),
]

_SOFTWARE_COMPILED = [(re.compile(pat, re.IGNORECASE), name) for pat, name in _SOFTWARE_NORMALIZE]


def classify_os_family(os_string: str) -> Optional[str]:
    """Classify an OS string into a normalized OS family name."""
    if not os_string:
        return None
    for pattern, family in _OS_FAMILY_COMPILED:
        if pattern.search(os_string):
            return family
    return None


def normalize_software_name(name: str) -> Optional[str]:
    """Normalize a software name to a canonical form, or return None if not recognized."""
    if not name:
        return None
    for pattern, canonical in _SOFTWARE_COMPILED:
        if pattern.search(name):
            return canonical
    return None


def _get_or_create_tag(category: str, value: str, color: str, db: Session) -> Tag:
    """Find or create a tag by category + value."""
    tag = db.query(Tag).filter(Tag.category == category, Tag.value == value).first()
    if not tag:
        tag = Tag(category=category, value=value, color=color)
        db.add(tag)
        db.flush()
    return tag


def _assign_tag_to_asset(tag: Tag, asset_id: int, db: Session) -> bool:
    """Assign a tag to an asset if not already assigned. Returns True if new."""
    existing = db.query(TagAssignment).filter(
        TagAssignment.tag_id == tag.id,
        TagAssignment.asset_id == asset_id,
    ).first()
    if existing:
        return False
    db.add(TagAssignment(
        tag_id=tag.id,
        asset_id=asset_id,
        assigned_by="system:os_software",
    ))
    return True


# ─── OS tag colors ─────────────────────────────────────────────────────────────

_OS_COLORS = {
    "Windows Server": "#0078d4",
    "Windows Desktop": "#00a4ef",
    "Windows": "#0078d4",
    "Ubuntu": "#e95420",
    "Debian": "#a80030",
    "CentOS": "#932279",
    "Red Hat": "#ee0000",
    "SUSE": "#73ba25",
    "Fedora": "#51a2da",
    "Amazon Linux": "#ff9900",
    "Oracle Linux": "#f80000",
    "Linux": "#fcc624",
    "macOS": "#a2aaad",
    "FreeBSD": "#ab2b28",
    "VMware ESXi": "#696566",
    "Cisco IOS": "#049fd9",
    "FortiOS": "#ee3124",
}


def run_os_auto_tags(db: Session, scan_id: int) -> dict:
    """Create os:<family> tags for all assets in a scan. Returns stats."""
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    tagged = 0
    families_seen = set()

    for asset in assets:
        family = classify_os_family(asset.os)
        if not family:
            continue
        families_seen.add(family)
        color = _OS_COLORS.get(family, "#6366f1")
        tag = _get_or_create_tag("os", family, color, db)
        if _assign_tag_to_asset(tag, asset.id, db):
            tagged += 1

    if tagged:
        db.flush()
    return {"os_tags_assigned": tagged, "os_families": list(families_seen)}


def run_software_auto_tags(db: Session, scan_id: int, top_n: int = 50) -> dict:
    """Create software:<name> tags for assets based on InventorySoftware.

    Only tags the top N most common software products to avoid tag explosion.
    """
    software_rows = (
        db.query(InventorySoftware)
        .filter(InventorySoftware.scan_id == scan_id)
        .all()
    )

    if not software_rows:
        return {"software_tags_assigned": 0, "software_products": []}

    # Count occurrences of each normalized software name across assets
    # Key: canonical name -> set of asset_ids
    product_assets: dict[str, set[int]] = {}
    for sw in software_rows:
        canonical = normalize_software_name(sw.name)
        if not canonical:
            continue
        product_assets.setdefault(canonical, set()).add(sw.asset_id)

    # Sort by number of assets (most common first), take top N
    ranked = sorted(product_assets.items(), key=lambda x: len(x[1]), reverse=True)[:top_n]

    tagged = 0
    products_seen = []
    for canonical, asset_ids in ranked:
        tag = _get_or_create_tag("software", canonical, "#14b8a6", db)
        products_seen.append(canonical)
        for asset_id in asset_ids:
            if _assign_tag_to_asset(tag, asset_id, db):
                tagged += 1

    if tagged:
        db.flush()
    return {"software_tags_assigned": tagged, "software_products": products_seen}


def run_os_software_auto_tags(db: Session, scan_id: int) -> dict:
    """Run both OS and software auto-tagging. Called from post-ingest pipeline."""
    os_result = run_os_auto_tags(db, scan_id)
    sw_result = run_software_auto_tags(db, scan_id)
    db.commit()

    total = os_result["os_tags_assigned"] + sw_result["software_tags_assigned"]
    if total:
        logger.info(
            "OS/Software auto-tags: %d OS tags (%d families), %d software tags (%d products)",
            os_result["os_tags_assigned"], len(os_result["os_families"]),
            sw_result["software_tags_assigned"], len(sw_result["software_products"]),
        )
    return {**os_result, **sw_result}

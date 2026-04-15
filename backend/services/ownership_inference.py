"""
Ownership Inference Engine
─────────────────────────
Auto-derives asset ownership from inventory data:
  - Primary user from InventoryLoggedOn
  - Admin contacts from InventoryUser (is_local_admin)
  - Responsible team from InventoryService fingerprints
"""
from __future__ import annotations

import logging
from typing import Optional
from sqlalchemy.orm import Session

from models.models import (
    Asset, InventoryUser, InventoryLoggedOn, InventoryService,
    AssetOwnership,
)

log = logging.getLogger(__name__)

# ── Service-to-team mapping ──────────────────────────────────────────
# Keys are substrings matched against service_name (lowercased).
# Order matters — first match wins.
SERVICE_TEAM_RULES = [
    # Database services → DBA
    (["mssql", "sqlserver", "mysql", "postgres", "oracle", "mongodb", "mariadb", "redis",
      "cassandra", "elasticsearch", "dynamodb"], "DBA"),
    # Identity / directory services → IAM (catch before generic IT mail/directory bucket)
    (["ntds", "kdc", "adws", "netlogon", "ldap", "kerberos", "okta", "pingfederate",
      "adfs", "shibboleth", "keycloak", "radius", "tacacs"], "IAM"),
    # Security monitoring / SIEM / EDR / IR tooling → SOC
    (["splunk", "sentinel", "qradar", "sumologic", "datadog_security", "rapid7_insight",
      "crowdstrike", "carbonblack", "defender", "cylance", "sophos", "symantec",
      "mcafee", "trellix"], "SOC"),
    # Vuln scanners / security configuration tooling → SecOps
    (["qualys", "nessus", "tenable", "openvas", "wazuh"], "SecOps"),
    # Cloud security tooling / CSPM → CloudSec
    (["prisma", "wiz", "lacework", "orca", "cloudguard", "aqua", "twistlock",
      "scoutsuite", "cloudsploit"], "CloudSec"),
    # Web / app servers → AppSec (application layer hardening)
    (["iis", "w3svc", "apache", "httpd", "nginx", "tomcat", "nodejs", "kestrel",
      "express", "gunicorn", "uwsgi", "weblogic", "websphere", "jboss", "glassfish"], "AppSec"),
    # Containers / orchestration / runtime → Platform
    (["docker", "containerd", "kubelet", "kube-proxy", "etcd", "consul", "nomad"], "Platform"),
    # CI/CD and configuration management → DevOps
    (["jenkins", "gitlab", "bamboo", "teamcity", "github_actions", "argo", "circleci",
      "ansible", "puppet", "chef", "salt", "terraform"], "DevOps"),
    # Mail / messaging → IT
    (["exchange", "smtp", "imap", "pop3", "postfix", "sendmail"], "IT"),
    # Generic directory / name services → IT
    (["dns", "dhcp", "bind", "unbound"], "IT"),
    # Network infra services → Networking
    (["snmp", "bgp", "ospf", "vrrp", "hsrp", "ipsec", "strongswan", "openvpn"], "Networking"),
]


def _team_from_services(service_names: set[str]) -> str | None:
    """Determine responsible team from the set of running service names."""
    scores: dict[str, int] = {}
    for svc in service_names:
        svc_lower = svc.lower()
        for keywords, team in SERVICE_TEAM_RULES:
            if any(kw in svc_lower for kw in keywords):
                scores[team] = scores.get(team, 0) + 1
                break  # first-match per service

    if not scores:
        return None
    # Return team with highest match count
    return max(scores, key=scores.get)


# Service accounts / machine accounts to exclude from "primary user"
_EXCLUDED_SUFFIXES = ("$",)
_EXCLUDED_NAMES = {
    "system", "local service", "network service", "nt authority\\system",
    "nt authority\\local service", "nt authority\\network service",
    "defaultaccount", "guest", "wdagutilityaccount",
}


def _is_real_user(username: str, domain: str | None) -> bool:
    """Filter out service/machine accounts from logged-on users."""
    if not username:
        return False
    lower = username.lower().strip()
    if lower in _EXCLUDED_NAMES:
        return False
    if any(lower.endswith(s) for s in _EXCLUDED_SUFFIXES):
        return False
    full = f"{domain}\\{lower}" if domain else lower
    if full.lower() in _EXCLUDED_NAMES:
        return False
    return True


def infer_asset_ownership(db: Session, scan_id: int) -> dict:
    """
    Compute inferred ownership for all assets in a scan.
    Returns summary: {updated: int, high: int, medium: int, low: int}
    """
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    stats = {"updated": 0, "high": 0, "medium": 0, "low": 0}

    for asset in assets:
        # Skip assets that already have a manual ownership override
        manual = db.query(AssetOwnership).filter(
            AssetOwnership.asset_id == asset.id
        ).first()
        if manual and manual.owner_name:
            continue

        # ── 1. Primary user from logged-on sessions ──
        logged_on = db.query(InventoryLoggedOn).filter_by(
            scan_id=scan_id, asset_id=asset.id
        ).all()
        real_users = []
        seen = set()
        for lo in logged_on:
            if _is_real_user(lo.username, lo.domain):
                key = (lo.username.lower(), (lo.domain or "").lower())
                if key not in seen:
                    seen.add(key)
                    real_users.append(lo)

        if len(real_users) == 1:
            u = real_users[0]
            primary = f"{u.domain}\\{u.username}" if u.domain else u.username
            confidence = "high"
        elif len(real_users) > 1:
            # Multiple users — pick the first but lower confidence
            u = real_users[0]
            primary = f"{u.domain}\\{u.username}" if u.domain else u.username
            confidence = "medium"
        else:
            primary = None
            confidence = "low"

        # ── 2. Local admin contacts ──
        admins = db.query(InventoryUser).filter_by(
            scan_id=scan_id, asset_id=asset.id, is_local_admin=True
        ).all()
        admin_contacts = []
        admin_seen = set()
        for a in admins:
            if a.username and a.username.lower() not in admin_seen:
                admin_seen.add(a.username.lower())
                label = f"{a.domain}\\{a.username}" if a.domain else a.username
                admin_contacts.append(label)

        # ── 3. Team inference from services ──
        services = db.query(InventoryService).filter_by(
            scan_id=scan_id, asset_id=asset.id
        ).all()
        service_names = {s.service_name for s in services if s.service_name}
        inferred_team = _team_from_services(service_names)

        # ── Write back ──
        changed = False
        if primary != asset.inferred_primary_user:
            asset.inferred_primary_user = primary
            changed = True
        if admin_contacts != (asset.inferred_admin_contacts or []):
            asset.inferred_admin_contacts = admin_contacts
            changed = True
        if inferred_team != asset.inferred_team:
            asset.inferred_team = inferred_team
            changed = True
        if confidence != asset.owner_confidence:
            asset.owner_confidence = confidence
            changed = True

        if changed:
            stats["updated"] += 1
            stats[confidence] += 1

    db.commit()
    log.info("Ownership inference for scan %d: %s", scan_id, stats)
    return stats


def resolve_finding_owner(finding, asset, db: Session) -> dict:
    """
    Resolve the effective owner for a finding using the full resolution chain:
      1. FindingOwnership (manual per-finding)
      2. AssetOwnership (manual per-asset, inherited)
      3. Asset.inferred_team (auto from inventory services)
      4. Asset.inferred_primary_user (auto from logged-on data)
      5. Finding.owner_suggestion (static plugin family map — fallback)
    Returns: {owner_name, owner_role, owner_team, source}
    """
    # 1. Manual finding-level ownership
    if finding.ownership:
        own = finding.ownership[0]
        if own.owner_name or own.owner_role:
            return {
                "owner_name": own.owner_name,
                "owner_email": own.owner_email,
                "owner_role": own.owner_role,
                "owner_team": own.team,
                "notes": own.notes,
                "source": "manual_finding",
            }

    # 2. Manual asset-level ownership
    if asset and asset.ownership:
        own = asset.ownership[0]
        if own.owner_name or own.owner_role:
            return {
                "owner_name": own.owner_name,
                "owner_email": own.owner_email,
                "owner_role": own.owner_role,
                "owner_team": own.team,
                "notes": own.notes,
                "source": "manual_asset",
            }

    # 3. Inferred team from services
    if asset and asset.inferred_team:
        return {
            "owner_name": asset.inferred_primary_user,
            "owner_role": asset.inferred_team,
            "owner_team": asset.inferred_team,
            "source": "inferred_service",
        }

    # 4. Inferred primary user (no team, but we know the person)
    if asset and asset.inferred_primary_user:
        return {
            "owner_name": asset.inferred_primary_user,
            "owner_role": finding.owner_suggestion,
            "owner_team": None,
            "source": "inferred_user",
        }

    # 5. Static plugin family map (fallback)
    return {
        "owner_name": None,
        "owner_role": finding.owner_suggestion,
        "owner_team": None,
        "source": "plugin_family",
    }

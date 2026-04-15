"""
Built-in team roles — one RBAC role per ownership team.

Each org is automatically seeded with a read/write role per team (IT, DevOps, SOC,
VM, IAM, GRC, etc.). Org admins assign these to users and the scope filter on
`/api/findings` and `/api/assets` restricts what the user sees to resources owned
by their team(s).

A user with an unscoped role (org_admin, or a scoped role alongside an unscoped
CustomRole) has no scope restriction — scope only kicks in when ALL of a user's
access to findings/assets comes through scoped roles.
"""
from __future__ import annotations

from typing import Iterable, Optional

from sqlalchemy.orm import Session

from core.ownership_teams import OWNERSHIP_ROLES
from models.models import AutoTagRule, CustomRole, Tag, TagPermission


# Permissions every built-in team role grants. Scoped by owner_role at query time.
_TEAM_BASE_PERMISSIONS = {
    # Read across the core working surface
    "read_scans": True,
    "read_assets": True,
    "read_findings": True,
    "view_reports": True,
    # Let team members triage + close out their own work
    "write_findings": True,
    "write_assets": True,
    "manage_campaigns": True,
    "manage_exceptions": True,
    "manage_tags": True,
    "export_report": True,
    # Pages needed to actually do the above
    "page_dashboard": True,
    "page_assets": True,
    "page_findings": True,
    "page_reports": True,
    "page_inventory": True,
    "page_campaigns": True,
    "page_remediation": True,
    "page_tags": True,
    "page_threat_intel": True,
    "page_settings": True,
}


# Short human-readable descriptions per team. Drives the `description` field on
# seeded roles so org admins see what each one does in the Settings UI.
_TEAM_DESCRIPTIONS: dict[str, str] = {
    "IT":          "Endpoint patching, workstations, and general IT ops. Scoped to findings/assets owned by IT.",
    "HelpDesk":    "User-facing support and endpoint remediation. Scoped to findings/assets owned by Help Desk.",
    "DevOps":      "CI/CD pipelines, deployment, and container platforms. Scoped to findings/assets owned by DevOps.",
    "SRE":         "Site reliability, availability, and platform incident response. Scoped to SRE-owned resources.",
    "Platform":    "Platform engineering, infra-as-code, shared tooling. Scoped to Platform-owned resources.",
    "Networking":  "Network engineering — switches, routers, firewalls. Scoped to Networking-owned resources.",
    "CloudOps":    "Cloud infrastructure operations (AWS/Azure/GCP). Scoped to CloudOps-owned resources.",
    "DBA":         "Database administration. Scoped to findings/assets owned by the DBA team.",
    "VM":          "Vulnerability management — owns the VM scanners (Nessus/Qualys/Nuclei) and triage of their output.",
    "SecOps":      "Operational security, hardening, and configuration. Scoped to SecOps-owned resources.",
    "SOC":         "Security operations center — monitoring, alert triage, IR. Scoped to SOC-owned resources.",
    "AppSec":      "Application security — code-level and web findings. Scoped to AppSec-owned resources.",
    "CloudSec":    "Cloud security posture. Scoped to CloudSec-owned resources.",
    "IAM":         "Identity & access — credentials, MFA, stale accounts. Scoped to IAM-owned resources.",
    "GRC":         "Governance, risk & compliance — audit, policy, frameworks. Scoped to GRC-owned resources.",
    "Engineering": "General software engineering — code owners for AppSec-flagged findings.",
    "Mobile":      "Mobile engineering and MDM. Scoped to Mobile-owned resources.",
    "Data":        "Data engineering, data platform, analytics pipelines. Scoped to Data-owned resources.",
}


# Tag colors per team — grouped by category for visual distinction in the UI.
_TEAM_TAG_COLORS: dict[str, str] = {
    # Infrastructure & Ops — blues/teals
    "IT":          "#3b82f6",
    "HelpDesk":    "#60a5fa",
    "DevOps":      "#06b6d4",
    "SRE":         "#0891b2",
    "Platform":    "#0d9488",
    "Networking":  "#14b8a6",
    "CloudOps":    "#22d3ee",
    "DBA":         "#2dd4bf",
    # Security — reds/oranges/ambers
    "VM":          "#f59e0b",
    "SecOps":      "#ef4444",
    "SOC":         "#dc2626",
    "AppSec":      "#f97316",
    "CloudSec":    "#fb923c",
    "IAM":         "#eab308",
    "GRC":         "#d97706",
    # Engineering — purples/pinks
    "Engineering": "#8b5cf6",
    "Mobile":      "#a78bfa",
    "Data":        "#7c3aed",
}


def _role_name(team: str) -> str:
    """Canonical display name for a built-in team role."""
    return team


def builtin_team_role_specs() -> list[dict]:
    """Return the seed spec for every built-in team role.

    One dict per team, suitable for handing to CustomRole(**spec). Excludes
    "Custom" since that's the user-defined escape hatch, not a team.
    """
    specs = []
    for team in OWNERSHIP_ROLES:
        if team == "Custom":
            continue
        specs.append({
            "name": _role_name(team),
            "description": _TEAM_DESCRIPTIONS.get(team, f"Team-scoped role for {team}."),
            "base_permissions": dict(_TEAM_BASE_PERMISSIONS),
            "deny_permissions": {},
            "is_active": True,
            "is_builtin": True,
            "scope_owner_role": team,
        })
    return specs


def _get_or_create_team_tag(db: Session, org_id: int, team: str) -> Tag:
    """Return the ``team:<team>`` tag, creating it if it doesn't exist."""
    tag = db.query(Tag).filter(Tag.category == "team", Tag.value == team).first()
    if tag is None:
        tag = Tag(
            org_id=org_id,
            category="team",
            value=team,
            color=_TEAM_TAG_COLORS.get(team, "#6366f1"),
            description=f"Built-in team tag for {team}",
        )
        db.add(tag)
        db.flush()
    return tag


def _ensure_tag_permission(db: Session, role_id: int, tag_id: int, permission: str) -> None:
    """Add a tag permission if it doesn't already exist."""
    exists = db.query(TagPermission).filter(
        TagPermission.role_id == role_id,
        TagPermission.target_type == "tag",
        TagPermission.target_id == tag_id,
        TagPermission.permission == permission,
        TagPermission.effect == "allow",
    ).first()
    if not exists:
        db.add(TagPermission(
            role_id=role_id,
            target_type="tag",
            target_id=tag_id,
            permission=permission,
            effect="allow",
        ))


_ASSET_AUTOTAG_RULE_NAME = "map:inferred_team→tag:team*"
_FINDING_AUTOTAG_RULE_NAME = "map:owner_suggestion→tag:team*"

# Legacy names — used to detect and rename rules created before the naming change.
_LEGACY_RULE_NAMES = {
    "Auto-tag assets by team (ownership)": _ASSET_AUTOTAG_RULE_NAME,
    "Auto-tag findings by team (ownership)": _FINDING_AUTOTAG_RULE_NAME,
}


def _ensure_team_autotag_rules(db: Session, org_id: int) -> None:
    """Create passthrough auto-tag rules that map ownership → team tags.

    Two rules per org (idempotent):
      - Assets: ``inferred_team`` → ``team:<value>``
      - Findings: ``owner_suggestion`` → ``team:<value>``

    Names follow the ``map:`` convention so the frontend Tag Mappings tab
    picks them up automatically.
    """
    # Rename any legacy-named rules so they appear in Tag Mappings.
    for old_name, new_name in _LEGACY_RULE_NAMES.items():
        legacy = db.query(AutoTagRule).filter(
            AutoTagRule.org_id == org_id,
            AutoTagRule.name == old_name,
        ).first()
        if legacy:
            legacy.name = new_name

    for rule_name, target_type, field in (
        (_ASSET_AUTOTAG_RULE_NAME, "asset", "inferred_team"),
        (_FINDING_AUTOTAG_RULE_NAME, "finding", "owner_suggestion"),
    ):
        exists = db.query(AutoTagRule).filter(
            AutoTagRule.org_id == org_id,
            AutoTagRule.name == rule_name,
        ).first()
        if not exists:
            db.add(AutoTagRule(
                org_id=org_id,
                name=rule_name,
                description=f"Automatically applies team:* tags to {target_type}s based on ownership attribution.",
                tag_id=None,  # passthrough creates tags dynamically
                target_type=target_type,
                conditions=[{"field": field, "op": "passthrough", "value": "team"}],
                condition_logic="AND",
                is_enabled=True,
            ))


def seed_builtin_team_roles(db: Session, org_id: int) -> int:
    """Create any missing built-in team roles for a given org. Idempotent.

    Also creates a ``team:<name>`` tag per team, grants read+write
    tag permissions on it to the corresponding role, and sets up
    passthrough auto-tag rules that apply ``team:*`` tags to assets
    and findings based on ownership attribution.

    Returns the number of roles inserted.
    """
    existing_names = {
        name for (name,) in db.query(CustomRole.name)
        .filter(CustomRole.org_id == org_id, CustomRole.is_builtin == True)  # noqa: E712
        .all()
    }
    created = 0
    for spec in builtin_team_role_specs():
        team = spec["scope_owner_role"]
        if spec["name"] in existing_names:
            # Role exists — still ensure tag + permissions are in place.
            role = db.query(CustomRole).filter(
                CustomRole.org_id == org_id,
                CustomRole.name == spec["name"],
                CustomRole.is_builtin == True,  # noqa: E712
            ).first()
        else:
            role = CustomRole(org_id=org_id, **spec)
            db.add(role)
            db.flush()
            created += 1

        # Ensure the team tag exists and the role has read+write on it.
        tag = _get_or_create_team_tag(db, org_id, team)
        _ensure_tag_permission(db, role.id, tag.id, "read")
        _ensure_tag_permission(db, role.id, tag.id, "write")

    # Ensure passthrough auto-tag rules that map ownership → team tags.
    _ensure_team_autotag_rules(db, org_id)

    if created:
        db.flush()
    return created


def seed_builtin_team_roles_for_all_orgs(db: Session) -> dict[int, int]:
    """Used by the migration — seed every existing org. Returns {org_id: rows_inserted}."""
    from models.models import Organization
    results: dict[int, int] = {}
    for (org_id,) in db.query(Organization.id).all():
        results[org_id] = seed_builtin_team_roles(db, org_id)
    db.commit()
    return results


def user_owner_scopes(db: Session, user_id: int) -> Optional[set[str]]:
    """Compute the set of `owner_role` values a user can access, or None for unrestricted.

    Rules:
      - If the user has any active CustomRole with scope_owner_role = NULL that grants
        read_findings, they are unrestricted → return None.
      - Otherwise, union the scope_owner_role values from all active CustomRoles.
      - If the user has zero CustomRoles, return None (built-in role defaults apply
        and are not team-scoped).
    """
    from models.models import UserCustomRole

    assignments = (
        db.query(UserCustomRole)
        .filter(UserCustomRole.user_id == user_id)
        .all()
    )
    if not assignments:
        return None

    scopes: set[str] = set()
    has_scoped_role = False
    for ucr in assignments:
        role = ucr.role
        if not role or not role.is_active:
            continue
        # An unscoped role that grants read_findings means the user isn't restricted.
        base_perms = role.base_permissions or {}
        if not role.scope_owner_role:
            if base_perms.get("read_findings") or base_perms.get("read_assets"):
                return None
            continue
        has_scoped_role = True
        scopes.add(role.scope_owner_role)

    if not has_scoped_role:
        return None
    return scopes


def apply_owner_scope_to_findings(query, scopes: Optional[Iterable[str]]):
    """Narrow a Finding query by the user's owner-role scope.

    Matches on owner_suggestion (the scanner-inferred role) OR an explicit
    FindingOwnership/AssetOwnership row that overrides it. This mirrors the
    resolution chain in services.ownership_inference.resolve_finding_owner.
    """
    if scopes is None:
        return query
    scope_list = list(scopes)
    if not scope_list:
        # User has scoped roles but no accessible teams → see nothing.
        from models.models import Finding
        return query.filter(Finding.id == -1)

    from sqlalchemy import or_
    from models.models import Finding, FindingOwnership, AssetOwnership, Asset

    return query.filter(or_(
        Finding.owner_suggestion.in_(scope_list),
        Finding.ownership.any(FindingOwnership.owner_role.in_(scope_list)),
        Finding.asset.has(Asset.ownership.any(AssetOwnership.owner_role.in_(scope_list))),
    ))


def apply_owner_scope_to_assets(query, scopes: Optional[Iterable[str]]):
    """Narrow an Asset query by the user's owner-role scope.

    Matches on Asset.inferred_team OR AssetOwnership.owner_role.
    """
    if scopes is None:
        return query
    scope_list = list(scopes)
    if not scope_list:
        from models.models import Asset
        return query.filter(Asset.id == -1)

    from sqlalchemy import or_
    from models.models import Asset, AssetOwnership

    return query.filter(or_(
        Asset.inferred_team.in_(scope_list),
        Asset.ownership.any(AssetOwnership.owner_role.in_(scope_list)),
    ))

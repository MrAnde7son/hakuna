"""Credential→asset binding resolver.

Given an asset and an audit protocol, returns the credential the audit
should run with — looked up from the per-org ``credential_binding_rules``
table.

Rule evaluation:
  1. Fetch all enabled rules for the org, sorted by priority asc
     (lower priority number = higher precedence, like firewall rules).
  2. For each rule, check every non-null condition matches the asset.
     NULL conditions are wildcards.
  3. Return the credential_id of the first matching rule. None if no
     rule matches — the caller decides whether to fall back to an
     explicit credential_id, run anonymously (for anon-capable audits),
     or error.

Conditions:
  - ``audit_protocol``    — must equal the audit's protocol if set
  - ``asset_type``        — must equal Asset.asset_type
  - ``device_type``       — must equal Asset.device_type
  - ``cidr``              — Asset.ip must fall within the network
  - ``hostname_pattern``  — regex matches Asset.hostname / fqdn / netbios_name
  - ``tag``               — Asset has this tag (via tag_assignments)

Multiple conditions on one rule are AND-ed. To express OR, create
multiple rules with the same credential.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from models.models import (
    Asset,
    CredentialBindingRule,
    IntegrationCredential,
    Tag,
    TagAssignment,
)

logger = logging.getLogger(__name__)


# ── Public API ───────────────────────────────────────────────────────


def resolve_credential_for_asset(
    db: Session,
    asset: Asset,
    *,
    protocol: str,
    org_id: int,
) -> Optional[str]:
    """Return the credential_id the audit should use, or None if no rule matches.

    The credential's own ``org_id`` is verified — rules from another org
    are never honored even if a stale rule references one (defense in
    depth; the schema's CASCADE delete normally prevents this).
    """
    rules = (
        db.query(CredentialBindingRule)
        .filter(
            CredentialBindingRule.org_id == org_id,
            CredentialBindingRule.enabled.is_(True),
        )
        .order_by(CredentialBindingRule.priority.asc(),
                  CredentialBindingRule.id.asc())
        .all()
    )

    # Skip the join entirely when no enabled rule constrains by tag — the
    # vast majority of rules don't, so this saves a query per asset.
    asset_tags = _asset_tag_names(db, asset) if any(r.tag for r in rules) else set()
    for rule in rules:
        if not _rule_matches(rule, asset, protocol=protocol, asset_tags=asset_tags):
            continue
        # Verify the credential still exists and belongs to the same org.
        cred = (
            db.query(IntegrationCredential)
            .filter(IntegrationCredential.id == rule.credential_id)
            .first()
        )
        if not cred:
            logger.warning(
                "credential_binding rule %s references missing credential %s",
                rule.id, rule.credential_id,
            )
            continue
        if cred.org_id is not None and cred.org_id != org_id:
            logger.warning(
                "credential_binding rule %s references cross-org credential %s",
                rule.id, rule.credential_id,
            )
            continue
        return rule.credential_id

    return None


def explain_rule_match(
    rule: CredentialBindingRule,
    asset: Asset,
    *,
    protocol: str,
    asset_tags: Optional[Iterable[str]] = None,
    db: Optional[Session] = None,
) -> dict:
    """Return a per-condition breakdown of why a rule matched / didn't.

    Useful for the API ``/resolve`` endpoint when an operator wants to
    debug "why did this audit pick credential X?" without grepping logs.
    """
    if asset_tags is None:
        # Caller didn't pre-resolve tags. Fetch them only if this rule's
        # tag condition is set and a db session is available; otherwise
        # treat as empty (the wildcard branch in _check_tag short-circuits).
        if rule.tag and db is not None:
            asset_tags = _asset_tag_names(db, asset)
        else:
            asset_tags = set()
    checks = {
        "audit_protocol": _check_protocol(rule, protocol),
        "asset_type":     _check_eq(rule.asset_type, asset.asset_type),
        "device_type":    _check_eq(rule.device_type, asset.device_type),
        "cidr":           _check_cidr(rule.cidr, asset.ip),
        "hostname_pattern": _check_hostname(rule.hostname_pattern, asset),
        "tag":            _check_tag(rule.tag, asset_tags),
    }
    return {
        "rule_id": rule.id,
        "matched": all(v["matched"] for v in checks.values()),
        "checks": checks,
    }


# ── Matching primitives ──────────────────────────────────────────────


def _rule_matches(
    rule: CredentialBindingRule,
    asset: Asset,
    *,
    protocol: str,
    asset_tags: Iterable[str],
) -> bool:
    if not _check_protocol(rule, protocol)["matched"]:
        return False
    if not _check_eq(rule.asset_type, asset.asset_type)["matched"]:
        return False
    if not _check_eq(rule.device_type, asset.device_type)["matched"]:
        return False
    if not _check_cidr(rule.cidr, asset.ip)["matched"]:
        return False
    if not _check_hostname(rule.hostname_pattern, asset)["matched"]:
        return False
    if not _check_tag(rule.tag, asset_tags)["matched"]:
        return False
    return True


def _check_protocol(rule: CredentialBindingRule, protocol: str) -> dict:
    if not rule.audit_protocol:
        return {"matched": True, "reason": "wildcard"}
    if rule.audit_protocol == protocol:
        return {"matched": True, "reason": f"protocol={protocol}"}
    return {"matched": False, "reason": f"want {rule.audit_protocol}, got {protocol}"}


def _check_eq(want: Optional[str], have: Optional[str]) -> dict:
    if not want:
        return {"matched": True, "reason": "wildcard"}
    if have == want:
        return {"matched": True, "reason": f"=={want!r}"}
    return {"matched": False, "reason": f"want {want!r}, got {have!r}"}


def _check_cidr(cidr: Optional[str], ip: Optional[str]) -> dict:
    if not cidr:
        return {"matched": True, "reason": "wildcard"}
    if not ip:
        return {"matched": False, "reason": "asset has no IP"}
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError) as e:
        return {"matched": False, "reason": f"invalid CIDR or IP: {e}"}
    if addr in network:
        return {"matched": True, "reason": f"{ip} in {cidr}"}
    return {"matched": False, "reason": f"{ip} not in {cidr}"}


def _check_hostname(pattern: Optional[str], asset: Asset) -> dict:
    if not pattern:
        return {"matched": True, "reason": "wildcard"}
    candidates = [c for c in (asset.hostname, asset.fqdn, getattr(asset, "netbios_name", None))
                  if c]
    if not candidates:
        return {"matched": False, "reason": "asset has no hostname/fqdn/netbios"}
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return {"matched": False, "reason": f"invalid regex: {e}"}
    for c in candidates:
        if rx.search(c):
            return {"matched": True, "reason": f"{c!r} matches /{pattern}/"}
    return {"matched": False, "reason": f"no candidate matches /{pattern}/"}


def _check_tag(tag: Optional[str], asset_tags: Iterable[str]) -> dict:
    if not tag:
        return {"matched": True, "reason": "wildcard"}
    tag_set = set(asset_tags or [])
    if tag in tag_set:
        return {"matched": True, "reason": f"tag {tag!r} present"}
    return {"matched": False, "reason": f"asset tags {sorted(tag_set)!r} miss {tag!r}"}


def _asset_tag_names(db: Session, asset: Asset) -> set[str]:
    """Return the asset's tag names in ``category:value`` form.

    Joined explicitly through ``tag_assignments`` because Asset doesn't
    declare a tags relationship — the join is the only path to a tag from
    an asset_id. We return ``"category:value"`` strings to match the
    canonical tag form used elsewhere in the UI / NLP search.
    """
    if asset is None or asset.id is None:
        return set()
    rows = (
        db.query(Tag.category, Tag.value)
        .join(TagAssignment, TagAssignment.tag_id == Tag.id)
        .filter(TagAssignment.asset_id == asset.id)
        .all()
    )
    return {f"{cat}:{val}" for cat, val in rows if cat and val}

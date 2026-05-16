"""CRUD + resolve routes for credential→asset binding rules.

Prefix: /api/credential-bindings

Endpoints:
  GET    /            — list rules for the active org
  POST   /            — create a rule
  GET    /{rule_id}   — read a single rule
  PUT    /{rule_id}   — update
  DELETE /{rule_id}   — delete
  POST   /resolve     — given asset_id + protocol, return matched rule +
                        per-condition explanation. Useful for the UI to
                        show "which credential will run when this asset
                        is audited?".
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from core.auth import get_current_user, get_accessible_org_ids
from core.database import get_db
from models.models import (
    Asset,
    CredentialBindingRule,
    IntegrationCredential,
    User,
)
from services.credential_binding import (
    explain_rule_match,
    resolve_credential_for_asset,
)


router = APIRouter(prefix="/api/credential-bindings", tags=["credential-bindings"])


# ── Schemas ──────────────────────────────────────────────────────────


class _ConditionMixin(BaseModel):
    audit_protocol: Optional[str] = None
    asset_type: Optional[str] = None
    device_type: Optional[str] = None
    cidr: Optional[str] = None
    hostname_pattern: Optional[str] = None
    tag: Optional[str] = None

    @model_validator(mode="after")
    def _validate_conditions(self):
        if self.cidr:
            try:
                ipaddress.ip_network(self.cidr, strict=False)
            except (ValueError, TypeError) as e:
                raise ValueError(f"invalid CIDR {self.cidr!r}: {e}")
        if self.hostname_pattern:
            try:
                re.compile(self.hostname_pattern)
            except re.error as e:
                raise ValueError(f"invalid hostname regex: {e}")
        return self


class BindingRuleCreate(_ConditionMixin):
    credential_id: str
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    priority: int = 100
    enabled: bool = True

    @model_validator(mode="after")
    def _require_at_least_one_condition(self):
        if not any([self.audit_protocol, self.asset_type, self.device_type,
                    self.cidr, self.hostname_pattern, self.tag]):
            # A rule with zero conditions is a wildcard that catches every
            # asset for every protocol. That's almost never intentional —
            # require operators to pick at least one dimension.
            raise ValueError(
                "a binding rule must constrain at least one of: audit_protocol, "
                "asset_type, device_type, cidr, hostname_pattern, tag"
            )
        return self


class BindingRuleUpdate(_ConditionMixin):
    credential_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None


class BindingRuleOut(BaseModel):
    id: int
    org_id: int
    credential_id: str
    name: str
    description: Optional[str]
    priority: int
    enabled: bool
    audit_protocol: Optional[str]
    asset_type: Optional[str]
    device_type: Optional[str]
    cidr: Optional[str]
    hostname_pattern: Optional[str]
    tag: Optional[str]

    @classmethod
    def from_orm_(cls, rule: CredentialBindingRule) -> "BindingRuleOut":
        return cls(
            id=rule.id, org_id=rule.org_id, credential_id=rule.credential_id,
            name=rule.name, description=rule.description,
            priority=rule.priority, enabled=rule.enabled,
            audit_protocol=rule.audit_protocol, asset_type=rule.asset_type,
            device_type=rule.device_type, cidr=rule.cidr,
            hostname_pattern=rule.hostname_pattern, tag=rule.tag,
        )


class ResolveRequest(BaseModel):
    asset_id: int
    protocol: str


class ResolveResponse(BaseModel):
    credential_id: Optional[str]
    matched_rule_id: Optional[int]
    evaluated_rules: list


# ── Helpers ──────────────────────────────────────────────────────────


def _active_org_id(org_ids: list[int]) -> int:
    if not org_ids:
        raise HTTPException(403, "no accessible org")
    return org_ids[0]


def _verify_credential(db: Session, credential_id: str, org_id: int) -> None:
    cred = (
        db.query(IntegrationCredential)
        .filter(IntegrationCredential.id == credential_id)
        .first()
    )
    if not cred:
        raise HTTPException(404, f"credential {credential_id} not found")
    # Org-scoped credentials must match the active org. Shared credentials
    # (org_id NULL) are allowed.
    if cred.org_id is not None and cred.org_id != org_id:
        raise HTTPException(403, f"credential {credential_id} belongs to another org")


def _get_rule(db: Session, rule_id: int, org_id: int) -> CredentialBindingRule:
    rule = (
        db.query(CredentialBindingRule)
        .filter(
            CredentialBindingRule.id == rule_id,
            CredentialBindingRule.org_id == org_id,
        )
        .first()
    )
    if not rule:
        raise HTTPException(404, f"binding rule {rule_id} not found")
    return rule


# ── List / create ────────────────────────────────────────────────────


@router.get("/", response_model=List[BindingRuleOut])
def list_rules(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    org_id = _active_org_id(org_ids)
    rules = (
        db.query(CredentialBindingRule)
        .filter(CredentialBindingRule.org_id == org_id)
        .order_by(CredentialBindingRule.priority.asc(),
                  CredentialBindingRule.id.asc())
        .all()
    )
    return [BindingRuleOut.from_orm_(r) for r in rules]


@router.post("/", response_model=BindingRuleOut, status_code=201)
def create_rule(
    body: BindingRuleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    org_id = _active_org_id(org_ids)
    _verify_credential(db, body.credential_id, org_id)

    rule = CredentialBindingRule(
        org_id=org_id,
        credential_id=body.credential_id,
        name=body.name,
        description=body.description,
        priority=body.priority,
        enabled=body.enabled,
        audit_protocol=body.audit_protocol,
        asset_type=body.asset_type,
        device_type=body.device_type,
        cidr=body.cidr,
        hostname_pattern=body.hostname_pattern,
        tag=body.tag,
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return BindingRuleOut.from_orm_(rule)


# ── Read / update / delete ───────────────────────────────────────────


@router.get("/{rule_id}", response_model=BindingRuleOut)
def read_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    org_id = _active_org_id(org_ids)
    return BindingRuleOut.from_orm_(_get_rule(db, rule_id, org_id))


@router.put("/{rule_id}", response_model=BindingRuleOut)
def update_rule(
    rule_id: int,
    body: BindingRuleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    org_id = _active_org_id(org_ids)
    rule = _get_rule(db, rule_id, org_id)

    if body.credential_id is not None and body.credential_id != rule.credential_id:
        _verify_credential(db, body.credential_id, org_id)
        rule.credential_id = body.credential_id

    for field in ("name", "description", "priority", "enabled",
                  "audit_protocol", "asset_type", "device_type",
                  "cidr", "hostname_pattern", "tag"):
        value = getattr(body, field)
        if value is not None:
            setattr(rule, field, value)

    db.commit()
    db.refresh(rule)
    return BindingRuleOut.from_orm_(rule)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    org_id = _active_org_id(org_ids)
    rule = _get_rule(db, rule_id, org_id)
    db.delete(rule)
    db.commit()


# ── Resolve (debug / preview) ────────────────────────────────────────


@router.post("/resolve", response_model=ResolveResponse)
def resolve_for_asset(
    body: ResolveRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    org_ids: list[int] = Depends(get_accessible_org_ids),
):
    """Given an asset + protocol, return which rule would match and why.

    Returns the resolved credential_id (if any) plus a per-rule breakdown
    so operators can debug "why did this audit pick credential X?" — same
    information the audit_runner uses, exposed for UI preview.
    """
    org_id = _active_org_id(org_ids)
    asset = (
        db.query(Asset)
        .filter(Asset.id == body.asset_id, Asset.org_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(404, f"asset {body.asset_id} not found in this org")

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
    explanations = [
        explain_rule_match(r, asset, protocol=body.protocol, db=db)
        for r in rules
    ]

    matched_id = next((e["rule_id"] for e in explanations if e["matched"]), None)
    credential_id = resolve_credential_for_asset(
        db, asset, protocol=body.protocol, org_id=org_id,
    )
    return ResolveResponse(
        credential_id=credential_id,
        matched_rule_id=matched_id,
        evaluated_rules=explanations,
    )

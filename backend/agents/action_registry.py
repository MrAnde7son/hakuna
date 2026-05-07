"""Unified action registry for HITL approval gating.

Single source of truth replacing the four hardcoded sets that used to live
in ``agent_engine`` (CONFIRMATION_REQUIRED_TOOLS, HITL_TOOLS,
LOW_RISK_WRITE_TOOLS, EXTERNAL_TOOLS): each agent tool — and each external
MCP action — declares its risk tier via the ``@action`` decorator, and the
autonomy mapping decides whether a given call needs human approval.

Used by the agent engine (internal LLM-driven calls) and the MCP routes
(external callers) so both flow through the same gate.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class RiskTier(enum.Enum):
    """Risk classification for an action.

    READ          — pure read; never gated.
    SOFT_WRITE    — low-impact write (tagging, status flips, local reports).
    HARD_WRITE    — durable state change with org-visible impact (campaigns,
                    exceptions, agent provisioning).
    EXTERNAL      — touches a third-party system (Jira, ServiceNow, Slack,
                    Teams, email, generic webhooks, integration push/fetch).
    DESTRUCTIVE   — irreversible or hard-to-reverse (deletes, force-pushes).
    """
    READ = "read"
    SOFT_WRITE = "soft_write"
    HARD_WRITE = "hard_write"
    EXTERNAL = "external"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class ActionSpec:
    name: str
    risk_tier: RiskTier
    scopes: list[str] = field(default_factory=list)
    description: str = ""
    # Legacy: tool body refuses to run unless caller passes ``confirmed=true``.
    # Distinct from approval gating — this is a per-call sanity guard the LLM
    # has to acknowledge. Defaults to True for HARD_WRITE / EXTERNAL /
    # DESTRUCTIVE; pass explicitly to opt SOFT_WRITE tools in or out.
    confirmation_required: bool = False


ACTIONS: dict[str, ActionSpec] = {}


def action(
    name: str,
    risk_tier: RiskTier,
    scopes: Optional[list[str]] = None,
    description: str = "",
    confirmation_required: Optional[bool] = None,
):
    """Register an action's risk classification. Stack alongside ``@agent_tool``.

    The decorator returns the function unchanged — registration is a side
    effect that populates the module-level ``ACTIONS`` dict at import time.
    """
    if confirmation_required is None:
        confirmation_required = risk_tier in (
            RiskTier.HARD_WRITE,
            RiskTier.EXTERNAL,
            RiskTier.DESTRUCTIVE,
        )
    spec = ActionSpec(
        name=name,
        risk_tier=risk_tier,
        scopes=list(scopes or []),
        description=description,
        confirmation_required=confirmation_required,
    )
    ACTIONS[name] = spec

    def decorator(fn):
        return fn
    return decorator


def register_action(
    name: str,
    risk_tier: RiskTier,
    scopes: Optional[list[str]] = None,
    description: str = "",
    confirmation_required: Optional[bool] = None,
) -> ActionSpec:
    """Imperative form of ``@action`` for actions without a Python function
    (e.g. external MCP tools whose handler lives in a route)."""
    action(name, risk_tier, scopes, description, confirmation_required)
    return ACTIONS[name]


def get_action(name: str) -> Optional[ActionSpec]:
    return ACTIONS.get(name)


def list_actions(risk_tier: Optional[RiskTier] = None) -> list[ActionSpec]:
    if risk_tier is None:
        return list(ACTIONS.values())
    return [a for a in ACTIONS.values() if a.risk_tier == risk_tier]


# Autonomy → tiers that require approval.
#  conservative: any non-READ requires approval
#  standard:     HARD_WRITE, EXTERNAL, DESTRUCTIVE require approval
#  autonomous:   EXTERNAL, DESTRUCTIVE require approval
_APPROVAL_TIERS: dict[str, set[RiskTier]] = {
    "conservative": {
        RiskTier.SOFT_WRITE,
        RiskTier.HARD_WRITE,
        RiskTier.EXTERNAL,
        RiskTier.DESTRUCTIVE,
    },
    "standard": {
        RiskTier.HARD_WRITE,
        RiskTier.EXTERNAL,
        RiskTier.DESTRUCTIVE,
    },
    "autonomous": {
        RiskTier.EXTERNAL,
        RiskTier.DESTRUCTIVE,
    },
}


def requires_approval(
    action_name: str,
    autonomy_level: str,
    org_policy: Optional[dict] = None,
) -> bool:
    """True if this action needs HITL approval at this autonomy level.

    Unregistered actions default to False (not gated). ``org_policy`` is an
    optional per-org override map shaped like
    ``{"force_approve": [names], "auto_approve": [names]}`` — used by the
    MCP path to let an org pin specific tools regardless of tier.
    """
    if org_policy:
        if action_name in (org_policy.get("force_approve") or ()):
            return True
        if action_name in (org_policy.get("auto_approve") or ()):
            return False

    spec = ACTIONS.get(action_name)
    if spec is None:
        return False
    tiers = _APPROVAL_TIERS.get(autonomy_level, _APPROVAL_TIERS["conservative"])
    return spec.risk_tier in tiers


def hitl_tools_for_autonomy(autonomy_level: str) -> set[str]:
    """Return the set of registered actions that need HITL approval at the
    given autonomy level. Replaces the legacy
    ``agent_engine.get_hitl_tools_for_autonomy``."""
    return {
        name for name in ACTIONS
        if requires_approval(name, autonomy_level)
    }

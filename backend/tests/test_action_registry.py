"""Behavior-parity tests for the action registry refactor.

The registry replaces four hardcoded sets that used to live in
``agent_engine`` (CONFIRMATION_REQUIRED_TOOLS, HITL_TOOLS,
LOW_RISK_WRITE_TOOLS, EXTERNAL_TOOLS) and the
``get_hitl_tools_for_autonomy`` function. These tests pin the *old* sets
as a snapshot and prove the new registry produces the same approval
decision for every (tool, autonomy) pair.
"""
from __future__ import annotations

import pytest

# Import the agent tool module so registry decorators run.
import agents.agent_tools  # noqa: F401  (side-effect: register actions)
import agents.tools.org_memory_tools  # noqa: F401

from agents import action_registry
from agents.action_registry import RiskTier, requires_approval
from agents import agent_engine


# ── Snapshot of pre-refactor sets ─────────────────────────────────────
# Frozen copy of the original literals so the parity test isn't tautological.

OLD_CONFIRMATION_REQUIRED_TOOLS = {
    "create_jira_ticket", "create_servicenow_ticket",
    "send_slack_message", "send_teams_message", "send_email_alert",
    "create_campaign", "send_webhook",
    "update_finding_status", "create_exception",
    "call_integration_fetch", "call_integration_push",
    "build_report", "create_agent", "create_agent_schedule",
}

OLD_HITL_TOOLS = OLD_CONFIRMATION_REQUIRED_TOOLS | {
    "tag_assets", "bulk_tag_findings", "create_tag",
    "create_auto_tag_rule", "run_auto_tag_rules",
}

OLD_LOW_RISK_WRITE_TOOLS = {
    "tag_assets", "bulk_tag_findings", "create_tag", "create_auto_tag_rule",
    "run_auto_tag_rules", "update_finding_status", "build_report",
    "remember_org_memory",
}

OLD_EXTERNAL_TOOLS = {
    "create_jira_ticket", "create_servicenow_ticket",
    "send_slack_message", "send_teams_message", "send_email_alert",
    "send_webhook", "call_integration_fetch", "call_integration_push",
}


def _old_get_hitl_tools_for_autonomy(autonomy_level: str) -> set:
    """Verbatim copy of the pre-refactor function for parity comparison."""
    if autonomy_level == "autonomous":
        return OLD_EXTERNAL_TOOLS
    elif autonomy_level == "standard":
        return OLD_HITL_TOOLS - OLD_LOW_RISK_WRITE_TOOLS
    return OLD_HITL_TOOLS


# ── Decorator semantics ──────────────────────────────────────────────


def test_registry_populated_from_agent_tools():
    """Importing agent_tools should populate the registry with the
    19 tools we migrated."""
    expected = OLD_HITL_TOOLS  # all 19 gated tools
    for name in expected:
        spec = action_registry.get_action(name)
        assert spec is not None, f"{name} missing from registry"
        assert spec.risk_tier != RiskTier.READ


def test_list_actions_filters_by_tier():
    external = action_registry.list_actions(RiskTier.EXTERNAL)
    names = {a.name for a in external}
    assert names == OLD_EXTERNAL_TOOLS


def test_get_action_returns_none_for_unknown():
    assert action_registry.get_action("nonexistent_tool") is None


# ── Approval rules per autonomy ──────────────────────────────────────


@pytest.mark.parametrize("name", sorted(OLD_CONFIRMATION_REQUIRED_TOOLS))
def test_confirmation_required_tools_gated_at_conservative(name):
    """Every tool in the OLD CONFIRMATION_REQUIRED_TOOLS set still requires
    approval at conservative autonomy."""
    assert requires_approval(name, "conservative") is True


@pytest.mark.parametrize("name", sorted(OLD_LOW_RISK_WRITE_TOOLS))
def test_low_risk_write_tools_auto_approve_at_standard(name):
    """LOW_RISK_WRITE_TOOLS auto-approve at standard autonomy.

    ``remember_org_memory`` is in the old set but isn't registered (it was
    never in HITL_TOOLS, so it was effectively a no-op). It still
    auto-approves: an unregistered action is never gated.
    """
    assert requires_approval(name, "standard") is False


@pytest.mark.parametrize("name", sorted(OLD_EXTERNAL_TOOLS))
def test_external_tools_require_approval_at_autonomous(name):
    """EXTERNAL_TOOLS still need approval even at the loosest autonomy."""
    assert requires_approval(name, "autonomous") is True


# ── Full parity sweep ────────────────────────────────────────────────


@pytest.mark.parametrize("autonomy", ["conservative", "standard", "autonomous"])
def test_parity_with_old_get_hitl_tools_for_autonomy(autonomy):
    """For every (tool, autonomy) pair the registry produces the same
    answer the old function did."""
    universe = OLD_HITL_TOOLS | OLD_LOW_RISK_WRITE_TOOLS | OLD_EXTERNAL_TOOLS
    old_set = _old_get_hitl_tools_for_autonomy(autonomy)
    for name in sorted(universe):
        old = name in old_set
        new = requires_approval(name, autonomy)
        assert new == old, (
            f"parity drift: {name} @ {autonomy} — old={old}, new={new}"
        )


def test_engine_shim_get_hitl_tools_for_autonomy_matches_old():
    """The deprecated ``agent_engine.get_hitl_tools_for_autonomy`` shim
    returns the same membership the old function did, for tools we
    migrated. (It now also covers any *new* gated actions registered
    afterwards, so we test ⊇ on the legacy universe rather than ==.)"""
    for autonomy in ("conservative", "standard", "autonomous"):
        old = _old_get_hitl_tools_for_autonomy(autonomy)
        new = agent_engine.get_hitl_tools_for_autonomy(autonomy)
        assert old.issubset(new), (
            f"shim missing legacy entries at {autonomy}: {old - new}"
        )
        # And nothing outside the legacy universe sneaks in for legacy names.
        legacy_names = OLD_HITL_TOOLS
        assert (new & legacy_names) == old, (
            f"shim added/dropped legacy names at {autonomy}: "
            f"added={new & legacy_names - old}, dropped={old - (new & legacy_names)}"
        )


def test_deprecated_shim_views_match_old_sets():
    """The legacy module-level names still expose the right membership
    so existing imports keep working."""
    # Set equality is enough for existing call-sites (`tool in HITL_TOOLS`).
    # remember_org_memory is intentionally absent from the new
    # LOW_RISK_WRITE_TOOLS view (it's not in HITL_TOOLS so the old
    # behavior of `HITL_TOOLS - LOW_RISK_WRITE_TOOLS` is preserved).
    assert set(agent_engine.HITL_TOOLS) == OLD_HITL_TOOLS
    assert set(agent_engine.EXTERNAL_TOOLS) == OLD_EXTERNAL_TOOLS
    assert set(agent_engine.CONFIRMATION_REQUIRED_TOOLS) == OLD_CONFIRMATION_REQUIRED_TOOLS
    # The shim - deprecated set difference still works:
    assert (
        set(agent_engine.HITL_TOOLS) - set(agent_engine.LOW_RISK_WRITE_TOOLS)
        == OLD_HITL_TOOLS - OLD_LOW_RISK_WRITE_TOOLS
    )


# ── Org policy override hook ─────────────────────────────────────────


def test_org_policy_force_approve():
    policy = {"force_approve": ["query_findings"]}
    # Read-only tool — normally never gated.
    assert requires_approval("query_findings", "autonomous", org_policy=policy) is True


def test_org_policy_auto_approve():
    policy = {"auto_approve": ["create_jira_ticket"]}
    # Normally gated at every autonomy level.
    assert requires_approval("create_jira_ticket", "conservative", org_policy=policy) is False


def test_unregistered_action_default_not_gated():
    assert requires_approval("never_registered", "conservative") is False

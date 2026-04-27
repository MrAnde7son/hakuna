"""Tests for the Managed-AI (SaaS) Governance Audit (Phase 3.5, slice 0).

Covers:
  - audit registration shape (missions, compliance tags, credential connectors)
  - multi-prefix support in cloud_tools (managed_ai_saas spans openai_* and
    anthropic_* connector ids; aws/azure/gcp keep single-prefix behavior)
  - cloud_list_operations filtering by audit prefix set
  - cloud_invoke refuses cross-vendor calls (e.g. aws_iam_users when running
    under managed_ai_saas)
  - prompt files resolve and inline the preamble at import time
  - the eight admin-API connector JSON files are well-formed (bearer/api-key
    auth, cursor pagination, ``audit_only`` entity, ``data`` records_path)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

# Side-effect import — populates AUDITS + ENHANCED_PROMPTS + connector cache.
import agents.agent_tools  # noqa: F401
from agents.tools import cloud_tools  # noqa: F401  (registers managed_ai_saas)


CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

OPENAI_CONNECTORS = [
    "openai_admin_projects",
    "openai_admin_api_keys",
    "openai_admin_users",
    "openai_admin_audit_logs",
]
ANTHROPIC_CONNECTORS = [
    "anthropic_admin_workspaces",
    "anthropic_admin_api_keys",
    "anthropic_admin_users",
    "anthropic_admin_workspace_members",
]
ALL_SAAS_CONNECTORS = OPENAI_CONNECTORS + ANTHROPIC_CONNECTORS


# ── Audit registration ───────────────────────────────────────────────


def test_managed_ai_saas_audit_registered():
    from agents.audit_registry import get_audit, list_audits

    assert "managed_ai_saas" in list_audits()
    audit = get_audit("managed_ai_saas")
    assert audit.label == "Managed AI (SaaS) Governance Audit"
    assert audit.safety_class == "credentialed"
    assert audit.is_anonymous_capable() is False
    assert audit.requires_per_asset_consent() is False
    assert audit.relay_method == "none"
    assert audit.supported_os == ["cloud"]
    assert {m.key for m in audit.missions} == {"keys_hygiene", "identity", "explore"}
    assert audit.compliance_tags == ("nist_ai_rmf", "iso_42001")
    # Credential picker should accept both vendors so the kickoff UI can list
    # any saved admin credential under either prefix.
    assert set(audit.credential_connector_ids) == set(ALL_SAAS_CONNECTORS)


def test_managed_ai_saas_mission_prompt_keys_resolve():
    """All three mission prompt_keys must exist in ENHANCED_PROMPTS with the
    preamble inlined (no literal ``{preamble}`` marker remaining)."""
    from agents.agent_prompts import ENHANCED_PROMPTS
    from agents.audit_registry import get_audit

    audit = get_audit("managed_ai_saas")
    for mission in audit.missions:
        prompt = ENHANCED_PROMPTS.get(mission.prompt_key)
        assert prompt, f"prompt {mission.prompt_key!r} missing"
        assert "{preamble}" not in prompt, (
            f"{mission.prompt_key} did not have its preamble substituted"
        )
        assert "managed-AI governance auditor" in prompt
        assert f'mission="{mission.key}"' in prompt
        assert 'protocol="managed_ai_saas"' in prompt


def test_managed_ai_saas_preamble_warns_on_admin_scope():
    """The preamble must call out the no-inference and no-cross-tenant
    safety rules — these are the load-bearing guardrails for an admin key."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    preamble = ENHANCED_PROMPTS.get("_managed_ai_saas_audit_preamble", "")
    assert preamble
    assert "READ-ONLY" in preamble
    # Inference endpoints must be explicitly off-limits.
    assert "/chat/completions" in preamble
    assert "/messages" in preamble
    assert "cross-tenant" in preamble.lower() or "cross-tenant pivoting" in preamble.lower()


# ── Multi-prefix logic ───────────────────────────────────────────────


def test_provider_prefixes_managed_ai_saas_spans_two_vendors():
    prefixes = cloud_tools._provider_prefixes("managed_ai_saas")
    assert prefixes == ("openai_", "anthropic_")


@pytest.mark.parametrize("protocol,expected", [
    ("aws", ("aws_",)),
    ("azure", ("azure_",)),
    ("gcp", ("gcp_",)),
    ("AWS", ("aws_",)),  # case-insensitive
])
def test_provider_prefixes_single_prefix_unchanged(protocol, expected):
    """The aws/azure/gcp audits must keep their single-prefix behavior so
    the change is invisible to existing cloud audits."""
    assert cloud_tools._provider_prefixes(protocol) == expected


def test_is_cloud_audit_connector_accepts_in_prefix_pull_only():
    fake = {"id": "openai_admin_projects", "direction": "pull"}
    assert cloud_tools._is_cloud_audit_connector(fake, ("openai_", "anthropic_"))


def test_is_cloud_audit_connector_rejects_push_direction():
    """A push connector under the same prefix must still be rejected — the
    cloud audit palette is read-only by construction."""
    fake = {"id": "openai_admin_projects", "direction": "push"}
    assert not cloud_tools._is_cloud_audit_connector(fake, ("openai_", "anthropic_"))


def test_is_cloud_audit_connector_rejects_outside_prefix_set():
    """aws_iam_users must not be reachable from a managed_ai_saas run even
    if the agent guesses the id."""
    fake = {"id": "aws_iam_users", "direction": "pull"}
    assert not cloud_tools._is_cloud_audit_connector(fake, ("openai_", "anthropic_"))


# ── cloud_list_operations filtering ──────────────────────────────────


def test_cloud_list_operations_returns_only_saas_llm_connectors():
    """Calling cloud_list_operations under the managed_ai_saas audit must
    surface only openai_* and anthropic_* connectors — never aws/azure/gcp,
    never push connectors, never inference-plane endpoints."""
    result = cloud_tools.cloud_list_operations_tool(db=None, params={
        "_protocol": "managed_ai_saas",
    })
    assert result["provider"] == "managed_ai_saas"
    ids = {op["id"] for op in result["operations"]}
    # Every saas connector authored in this slice must be present.
    assert set(ALL_SAAS_CONNECTORS).issubset(ids)
    # No cloud-provider leakage.
    for cid in ids:
        assert cid.startswith("openai_") or cid.startswith("anthropic_"), cid


def test_cloud_list_operations_aws_unaffected():
    """The aws audit must not see openai_/anthropic_ connectors leak in."""
    result = cloud_tools.cloud_list_operations_tool(db=None, params={
        "_protocol": "aws",
    })
    ids = {op["id"] for op in result["operations"]}
    assert all(cid.startswith("aws_") for cid in ids)
    assert "openai_admin_projects" not in ids
    assert "anthropic_admin_workspaces" not in ids


# ── cloud_invoke prefix enforcement ──────────────────────────────────


def test_cloud_invoke_refuses_aws_connector_under_managed_ai_saas():
    """The agent cannot smuggle an AWS call through a SaaS LLM audit run —
    even if it has a valid AWS credential bound, the prefix check rejects."""
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "managed_ai_saas",
        "_credential_id": "fake-cred-id",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "aws_iam_users",
    })
    assert "error" in result
    assert "managed_ai_saas operation" in result["error"]


def test_cloud_invoke_refuses_unknown_connector():
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "managed_ai_saas",
        "_credential_id": "fake-cred-id",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "openai_does_not_exist",
    })
    assert "error" in result


def test_cloud_invoke_accepts_in_prefix_connector():
    """For an in-prefix connector the prefix check passes and we reach the
    credential/dispatch path. We mock the connector invocation so we don't
    actually call api.openai.com — but the call shape proves the prefix
    gate let it through."""
    fake_records = [{"id": "proj_abc", "name": "default", "status": "active"}]

    async def fake_invoke(db, org_id, credential_id, connector_id, call_params):
        assert connector_id == "openai_admin_projects"
        return fake_records

    with patch.object(cloud_tools, "_invoke_connector", side_effect=fake_invoke):
        result = cloud_tools.cloud_invoke_tool(db=None, params={
            "_protocol": "managed_ai_saas",
            "_credential_id": "fake-cred-id",
            "_org_id": 1,
            "_agent_id": 9999,
            "connector_id": "openai_admin_projects",
        })
    assert result.get("connector_id") == "openai_admin_projects"
    assert result.get("total") == 1
    assert "error" not in result


# ── Connector JSON shape ─────────────────────────────────────────────


def _load_connector_json(cid: str) -> dict:
    return json.loads((CONNECTORS_DIR / f"{cid}.json").read_text())


@pytest.mark.parametrize("cid", ALL_SAAS_CONNECTORS)
def test_saas_llm_connector_files_well_formed(cid):
    c = _load_connector_json(cid)
    assert c["id"] == cid
    assert c["direction"] == "pull"
    assert c["entity"] == "audit_only", "saas LLM connectors are audit-only, not asset/finding ingestion"
    assert c["transport_type"] == "api"
    assert c["records_path"] == "data"
    assert c["category"] == "AI Governance"
    pagination = c["transport_config"]["pagination"]
    assert pagination["strategy"] == "cursor"
    assert pagination["cursor_field"] == "last_id"


@pytest.mark.parametrize("cid", OPENAI_CONNECTORS)
def test_openai_connector_uses_bearer_admin_key(cid):
    c = _load_connector_json(cid)
    headers = c["transport_config"]["headers"]
    assert headers.get("Authorization") == "Bearer {{credentials.admin_api_key}}"
    assert c["transport_config"]["base_url"] == "https://api.openai.com/v1"
    assert c["transport_config"]["pagination"]["cursor_param"] == "after"


@pytest.mark.parametrize("cid", ANTHROPIC_CONNECTORS)
def test_anthropic_connector_uses_x_api_key_with_version(cid):
    c = _load_connector_json(cid)
    headers = c["transport_config"]["headers"]
    assert headers.get("x-api-key") == "{{credentials.admin_api_key}}"
    # Without the version header Anthropic rejects the request — load-bearing.
    assert headers.get("anthropic-version") == "2023-06-01"
    assert c["transport_config"]["base_url"] == "https://api.anthropic.com/v1"
    assert c["transport_config"]["pagination"]["cursor_param"] == "after_id"


def test_primary_connectors_gate_on_admin_scope_acknowledgement():
    """The primary connector for each vendor (the one that owns the credential
    acquisition flow) must include the explicit 'I understand this key has
    org-wide visibility' checkbox. Shared-credential connectors don't repeat
    the flow — they reference the primary."""
    for primary in ("openai_admin_projects", "anthropic_admin_workspaces"):
        c = _load_connector_json(primary)
        steps = c["credential_acquisition"]["steps"]
        ack_steps = [s for s in steps if s.get("capture", {}).get("field") == "_acknowledge_admin_scope"]
        assert len(ack_steps) == 1, f"{primary} missing the admin-scope acknowledgement step"
        assert ack_steps[0]["capture"]["type"] == "checkbox"
        assert ack_steps[0]["capture"].get("required") is True


def test_secondary_connectors_share_primary_credential():
    """Each non-primary saas connector must declare a shared_credential
    pattern referencing its vendor's primary. This keeps the kickoff UI
    from prompting for the same admin key 4 times per vendor."""
    primaries = {"openai_admin_projects", "anthropic_admin_workspaces"}
    expected_primary = {
        "openai_admin_api_keys": "openai_admin_projects",
        "openai_admin_users": "openai_admin_projects",
        "openai_admin_audit_logs": "openai_admin_projects",
        "anthropic_admin_api_keys": "anthropic_admin_workspaces",
        "anthropic_admin_users": "anthropic_admin_workspaces",
        "anthropic_admin_workspace_members": "anthropic_admin_workspaces",
    }
    for cid, primary in expected_primary.items():
        assert cid not in primaries
        c = _load_connector_json(cid)
        acq = c["credential_acquisition"]
        assert acq["pattern"] == "shared_credential"
        assert acq["shared_with"] == primary

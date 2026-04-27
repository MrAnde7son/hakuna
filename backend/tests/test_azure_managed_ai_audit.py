"""Tests for the Azure managed_ai mission (Phase 3.5, slice 2).

Adds Azure OpenAI + Cognitive Services governance to the existing `azure`
cloud audit. Two new connectors (account list + per-account deployments);
RBAC analysis reuses the existing `azure_role_assignments` connector.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import agents.agent_tools  # noqa: F401  — populates AUDITS + ENHANCED_PROMPTS
from agents.tools import cloud_tools


CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

NEW_AZURE_CONNECTORS = [
    "azure_cognitive_services_accounts",
    "azure_openai_deployments",
]


def _load(cid: str) -> dict:
    return json.loads((CONNECTORS_DIR / f"{cid}.json").read_text())


# ── Audit shape ──────────────────────────────────────────────────────


def test_azure_audit_has_managed_ai_mission():
    """Azure now exposes 4 missions (exposure / identity / explore /
    managed_ai). The original three must keep their keys + prompt_keys."""
    from agents.audit_registry import get_audit

    azure = get_audit("azure")
    keys = {m.key for m in azure.missions}
    assert keys == {"exposure", "identity", "explore", "managed_ai"}
    managed_ai = next(m for m in azure.missions if m.key == "managed_ai")
    assert managed_ai.prompt_key == "azure_audit_managed_ai"
    assert "Azure OpenAI" in managed_ai.label
    assert "Cognitive Services" in managed_ai.label


def test_azure_managed_ai_prompt_resolves_with_preamble():
    """The prompt must inline the Azure preamble at import time and
    self-identify so emit_finding gets the right (protocol, mission)."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("azure_audit_managed_ai")
    assert prompt
    assert "{preamble}" not in prompt
    assert "Azure cloud auditor" in prompt
    assert 'protocol="azure"' in prompt
    assert 'mission="managed_ai"' in prompt
    # The risk vocabulary that makes managed_ai different from generic
    # exposure/identity must be present so the LLM doesn't drift.
    assert "disableLocalAuth" in prompt
    assert "publicNetworkAccess" in prompt
    assert "privateEndpointConnections" in prompt
    # The Cognitive Services User builtin role guid is load-bearing
    # (RBAC walk reuses the generic role_assignments connector — without
    # the role guids in the prompt the LLM has no filter to apply).
    assert "a97b65f3-24c7-4388-baec-2e87135dc908" in prompt


def test_azure_credential_connectors_include_new_managed_ai_connectors():
    from agents.audit_registry import get_audit

    cids = set(get_audit("azure").credential_connector_ids)
    for new in NEW_AZURE_CONNECTORS:
        assert new in cids, f"{new} missing from azure credential_connector_ids"


# ── Connector JSON shape ─────────────────────────────────────────────


@pytest.mark.parametrize("cid", NEW_AZURE_CONNECTORS)
def test_azure_managed_ai_connector_files_well_formed(cid):
    c = _load(cid)
    assert c["id"] == cid
    assert c["direction"] == "pull"
    assert c["entity"] == "audit_only"
    assert c["category"] == "AI Governance"
    tc = c["transport_config"]
    assert tc["base_url"] == "https://management.azure.com"
    assert tc["query_params"]["api-version"] == "2023-05-01"
    # Subscription is parameterized — Cognitive Services is subscription-scoped.
    assert "{{params.subscription_id}}" in tc["path"]
    # Pagination via Azure's nextLink convention.
    assert tc["pagination"]["cursor_field"] == "nextLink"


def test_cognitive_services_accounts_lists_all_accounts():
    """The primary connector must hit the subscription-wide list path so
    one call returns every CS/AOAI account in the subscription. Drilling
    into a specific account (via deployments) is a separate connector."""
    c = _load("azure_cognitive_services_accounts")
    path = c["transport_config"]["path"]
    # Ends at /accounts (no trailing /{name}) — proves it's the LIST path.
    assert path.endswith("/Microsoft.CognitiveServices/accounts")
    assert c["records_path"] == "value"


def test_openai_deployments_requires_account_scope_params():
    """Deployments are listed per-account, so the connector requires both
    resource_group and account_name in its params_schema. The LLM extracts
    these from the account `id` field returned by the LIST connector."""
    c = _load("azure_openai_deployments")
    schema = c["params_schema"]
    assert schema["subscription_id"]["required"] is True
    assert schema["resource_group"]["required"] is True
    assert schema["account_name"]["required"] is True


def test_azure_managed_ai_connectors_use_client_credentials():
    """Azure SP auth — not bearer/api_key. Confirms the credential shape
    the integration vault stores is the same client_id/secret/tenant tuple
    used by every other azure_* connector."""
    for cid in NEW_AZURE_CONNECTORS:
        c = _load(cid)
        acq = c["credential_acquisition"]
        assert acq["pattern"] == "client_credentials"
        assert "https://management.azure.com/.default" in acq["scopes"]


# ── Audit dispatch (cross-audit prefix isolation) ────────────────────


def test_azure_cloud_list_operations_includes_managed_ai_connectors():
    result = cloud_tools.cloud_list_operations_tool(db=None, params={
        "_protocol": "azure",
    })
    ids = {op["id"] for op in result["operations"]}
    for new in NEW_AZURE_CONNECTORS:
        assert new in ids, f"{new} not surfaced to azure cloud_list_operations"


def test_managed_ai_saas_cannot_reach_azure_cs_account():
    """SaaS LLM audit's prefix gate must reject `azure_*` ids — different
    credential shape (client_credentials vs admin api key)."""
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "managed_ai_saas",
        "_credential_id": "fake",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "azure_cognitive_services_accounts",
    })
    assert "error" in result
    assert "managed_ai_saas operation" in result["error"]


def test_aws_cannot_reach_azure_cs_account():
    """The AWS audit (with SigV4 creds) must not be able to invoke an
    Azure ARM endpoint even if the agent guesses the id — the prefix gate
    prevents credential mismatch from ever reaching the dispatch layer."""
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "aws",
        "_credential_id": "fake",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "azure_cognitive_services_accounts",
    })
    assert "error" in result
    assert "aws operation" in result["error"]


def test_azure_cloud_invoke_accepts_cs_accounts_connector():
    """Under the azure audit, the prefix gate passes and we reach the
    credential dispatch path (mocked)."""
    fake_records = [
        {
            "id": "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.CognitiveServices/accounts/aoai-prod",
            "name": "aoai-prod",
            "kind": "OpenAI",
            "properties": {
                "disableLocalAuth": False,
                "publicNetworkAccess": "Enabled",
                "privateEndpointConnections": [],
            },
        },
    ]

    async def fake_invoke(db, org_id, credential_id, connector_id, call_params):
        assert connector_id == "azure_cognitive_services_accounts"
        assert call_params.get("subscription_id") == "abc"
        return fake_records

    with patch.object(cloud_tools, "_invoke_connector", side_effect=fake_invoke):
        result = cloud_tools.cloud_invoke_tool(db=None, params={
            "_protocol": "azure",
            "_credential_id": "fake",
            "_org_id": 1,
            "_agent_id": 9999,
            "connector_id": "azure_cognitive_services_accounts",
            "params": {"subscription_id": "abc"},
        })
    assert result.get("connector_id") == "azure_cognitive_services_accounts"
    assert result.get("total") == 1
    assert "error" not in result

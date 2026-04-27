"""Tests for the AWS managed_ai mission (Phase 3.5, slice 1).

Adds Bedrock + SageMaker governance to the existing `aws` cloud audit:
no new ProtocolAudit registration, just a 4th mission and 5 new
SigV4-signed connector JSON files. Tests cover:

  - the AWS audit grew a fourth mission (`managed_ai`) without disturbing
    the original three
  - the managed_ai prompt resolves with the AWS preamble inlined
  - the 5 new connectors (3 Bedrock + 2 SageMaker) load, sign with SigV4,
    target the right service, and stay read-only (`pull`, `audit_only`)
  - cloud_invoke under `aws` reaches them; cloud_invoke under
    `managed_ai_saas` does NOT (prefix isolation across audits)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import agents.agent_tools  # noqa: F401  — populates AUDITS + ENHANCED_PROMPTS
from agents.tools import cloud_tools


CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

BEDROCK_CONNECTORS = [
    "aws_bedrock_invocation_logging",
    "aws_bedrock_foundation_models",
    "aws_bedrock_guardrails",
]
SAGEMAKER_CONNECTORS = [
    "aws_sagemaker_endpoints",
    "aws_sagemaker_endpoint_configs",
]
ALL_NEW_CONNECTORS = BEDROCK_CONNECTORS + SAGEMAKER_CONNECTORS


def _load(cid: str) -> dict:
    return json.loads((CONNECTORS_DIR / f"{cid}.json").read_text())


# ── AWS audit shape ──────────────────────────────────────────────────


def test_aws_audit_has_managed_ai_mission():
    """The aws audit must now expose 4 missions; the original 3 plus
    `managed_ai`. Existing missions must not have been renamed or dropped."""
    from agents.audit_registry import get_audit

    aws = get_audit("aws")
    keys = {m.key for m in aws.missions}
    assert keys == {"exposure", "identity", "explore", "managed_ai"}
    managed_ai = next(m for m in aws.missions if m.key == "managed_ai")
    assert managed_ai.prompt_key == "aws_audit_managed_ai"
    assert "Bedrock" in managed_ai.label
    assert "SageMaker" in managed_ai.label


def test_aws_managed_ai_prompt_resolves_with_preamble():
    """The managed_ai prompt must inline the AWS preamble at import time
    and self-identify so an emit_finding has correct (protocol, mission)."""
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("aws_audit_managed_ai")
    assert prompt
    assert "{preamble}" not in prompt
    assert "AWS cloud auditor" in prompt
    assert 'protocol="aws"' in prompt
    assert 'mission="managed_ai"' in prompt
    # Risk vocabulary must be there — the prompt is what makes this mission
    # different from generic exposure/identity.
    assert "bedrock:InvokeModel" in prompt
    assert "sagemaker:InvokeEndpoint" in prompt
    assert "VpcConfig" in prompt or "VPC isolation" in prompt


def test_aws_credential_connectors_include_new_managed_ai_connectors():
    """The kickoff UI lists saved AWS credentials by connector_id. The new
    Bedrock/SageMaker connectors must be in the credential picker so a
    customer who saved their AWS key under bedrock can still use it."""
    from agents.audit_registry import get_audit

    cids = set(get_audit("aws").credential_connector_ids)
    for new in ALL_NEW_CONNECTORS:
        assert new in cids, f"{new} not in aws credential_connector_ids"


# ── Connector JSON shape ─────────────────────────────────────────────


@pytest.mark.parametrize("cid", ALL_NEW_CONNECTORS)
def test_managed_ai_connector_files_well_formed(cid):
    c = _load(cid)
    assert c["id"] == cid
    assert c["direction"] == "pull"
    assert c["entity"] == "audit_only", "managed AI connectors are audit-only"
    assert c["category"] == "AI Governance"
    tc = c["transport_config"]
    assert tc["auth_strategy"] == "aws_sigv4"
    # Region is parameterized — Bedrock/SageMaker are regional services.
    assert "{{credentials.region}}" in tc["base_url"]


@pytest.mark.parametrize("cid", BEDROCK_CONNECTORS)
def test_bedrock_connectors_target_bedrock_service(cid):
    c = _load(cid)
    tc = c["transport_config"]
    assert tc["aws_service"] == "bedrock"
    assert tc["base_url"].startswith("https://bedrock.")
    assert tc["method"] == "GET"


@pytest.mark.parametrize("cid", SAGEMAKER_CONNECTORS)
def test_sagemaker_connectors_use_jsonrpc_with_x_amz_target(cid):
    """SageMaker control plane is JSON-RPC (POST `/` with X-Amz-Target).
    Without that header SigV4 still signs but AWS returns 400. Lock it in."""
    c = _load(cid)
    tc = c["transport_config"]
    assert tc["aws_service"] == "sagemaker"
    assert tc["method"] == "POST"
    assert tc["headers"].get("Content-Type") == "application/x-amz-json-1.1"
    target = tc["headers"].get("X-Amz-Target", "")
    assert target.startswith("SageMaker."), f"{cid} missing X-Amz-Target action"


def test_bedrock_invocation_logging_uses_singleton_response():
    """GetModelInvocationLoggingConfiguration returns a single object,
    not a list. records_path must be empty so the LLM sees the wrapper —
    a null/empty config is itself the finding (logging not configured)."""
    c = _load("aws_bedrock_invocation_logging")
    assert c["records_path"] == ""
    assert c["transport_config"]["pagination"]["strategy"] == "none"


# ── Audit dispatch (cross-audit prefix isolation) ────────────────────


def test_aws_cloud_list_operations_includes_managed_ai_connectors():
    result = cloud_tools.cloud_list_operations_tool(db=None, params={
        "_protocol": "aws",
    })
    ids = {op["id"] for op in result["operations"]}
    for new in ALL_NEW_CONNECTORS:
        assert new in ids, f"{new} not surfaced to aws cloud_list_operations"


def test_managed_ai_saas_cannot_reach_aws_bedrock():
    """The SaaS LLM audit must not be able to invoke aws_bedrock_* even if
    the agent guesses the id — Bedrock auth is SigV4 with an AWS key, not
    an OpenAI/Anthropic admin key, so a successful call would mean either
    the prefix gate failed or credentials got mixed up. Lock the gate."""
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "managed_ai_saas",
        "_credential_id": "fake-cred-id",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "aws_bedrock_invocation_logging",
    })
    assert "error" in result
    assert "managed_ai_saas operation" in result["error"]


def test_aws_cloud_invoke_accepts_bedrock_connector():
    """Under the aws audit, the bedrock prefix gate passes and we reach
    the credential dispatch path (mocked — we don't call AWS here)."""
    fake_records = [{"loggingConfig": {"s3Config": {"bucketName": "logs"}}}]

    async def fake_invoke(db, org_id, credential_id, connector_id, call_params):
        assert connector_id == "aws_bedrock_invocation_logging"
        return fake_records

    with patch.object(cloud_tools, "_invoke_connector", side_effect=fake_invoke):
        result = cloud_tools.cloud_invoke_tool(db=None, params={
            "_protocol": "aws",
            "_credential_id": "fake-cred-id",
            "_org_id": 1,
            "_agent_id": 9999,
            "connector_id": "aws_bedrock_invocation_logging",
            "params": {"region": "us-east-1"},
        })
    assert result.get("connector_id") == "aws_bedrock_invocation_logging"
    assert result.get("total") == 1
    assert "error" not in result

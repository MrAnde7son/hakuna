"""Tests for the GCP managed_ai mission (Phase 3.5, slice 3).

Adds Vertex AI governance to the existing `gcp` cloud audit. Three new
connectors (endpoint list + model list + per-endpoint IAM); project-level
IAM analysis reuses the existing `gcp_project_iam_bindings` connector.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import agents.agent_tools  # noqa: F401  — populates AUDITS + ENHANCED_PROMPTS
from agents.tools import cloud_tools


CONNECTORS_DIR = Path(__file__).parent.parent / "integrations" / "connectors"

NEW_GCP_CONNECTORS = [
    "gcp_vertex_endpoints",
    "gcp_vertex_models",
    "gcp_vertex_endpoint_iam",
]


def _load(cid: str) -> dict:
    return json.loads((CONNECTORS_DIR / f"{cid}.json").read_text())


# ── Audit shape ──────────────────────────────────────────────────────


def test_gcp_audit_has_managed_ai_mission():
    """GCP now exposes 4 missions. Original three keys + prompt_keys must
    be untouched."""
    from agents.audit_registry import get_audit

    gcp = get_audit("gcp")
    keys = {m.key for m in gcp.missions}
    assert keys == {"exposure", "identity", "explore", "managed_ai"}
    managed_ai = next(m for m in gcp.missions if m.key == "managed_ai")
    assert managed_ai.prompt_key == "gcp_audit_managed_ai"
    assert "Vertex AI" in managed_ai.label


def test_all_three_clouds_now_have_managed_ai():
    """At end of slice 3, AWS / Azure / GCP all have a managed_ai mission
    with provider-specific prompts. Lock the staging."""
    from agents.audit_registry import get_audit

    for proto, expected_label_word in [("aws", "Bedrock"), ("azure", "Azure OpenAI"), ("gcp", "Vertex")]:
        audit = get_audit(proto)
        managed_ai = [m for m in audit.missions if m.key == "managed_ai"]
        assert len(managed_ai) == 1, f"{proto} missing managed_ai mission"
        assert expected_label_word in managed_ai[0].label
        assert managed_ai[0].prompt_key == f"{proto}_audit_managed_ai"


def test_gcp_managed_ai_prompt_resolves_with_preamble():
    from agents.agent_prompts import ENHANCED_PROMPTS

    prompt = ENHANCED_PROMPTS.get("gcp_audit_managed_ai")
    assert prompt
    assert "{preamble}" not in prompt
    assert "GCP cloud auditor" in prompt
    assert 'protocol="gcp"' in prompt
    assert 'mission="managed_ai"' in prompt
    # Risk vocabulary specific to Vertex IAM model.
    assert "allUsers" in prompt
    assert "allAuthenticatedUsers" in prompt
    assert "aiplatform.endpoints.predict" in prompt


def test_gcp_credential_connectors_include_new_vertex_connectors():
    from agents.audit_registry import get_audit

    cids = set(get_audit("gcp").credential_connector_ids)
    for new in NEW_GCP_CONNECTORS:
        assert new in cids, f"{new} missing from gcp credential_connector_ids"


# ── Connector JSON shape ─────────────────────────────────────────────


@pytest.mark.parametrize("cid", NEW_GCP_CONNECTORS)
def test_vertex_connector_files_well_formed(cid):
    c = _load(cid)
    assert c["id"] == cid
    assert c["direction"] == "pull"
    assert c["entity"] == "audit_only"
    assert c["category"] == "AI Governance"
    tc = c["transport_config"]
    assert tc["auth_strategy"] == "gcp_service_account"
    # Vertex base URL is regional — locked into the params.location substitution.
    assert "{{params.location}}-aiplatform.googleapis.com" in tc["base_url"]


def test_vertex_endpoints_uses_get_with_cursor_pagination():
    c = _load("gcp_vertex_endpoints")
    tc = c["transport_config"]
    assert tc["method"] == "GET"
    assert c["records_path"] == "endpoints"
    assert tc["pagination"]["cursor_field"] == "nextPageToken"


def test_vertex_endpoint_iam_uses_post_with_get_iam_policy():
    """getIamPolicy is a POST on Google APIs (not GET) — without that the
    server returns 400. Lock the method + path suffix."""
    c = _load("gcp_vertex_endpoint_iam")
    tc = c["transport_config"]
    assert tc["method"] == "POST"
    assert tc["path"].endswith(":getIamPolicy")
    # A getIamPolicy call requires a JSON body even if empty — the GCP API
    # returns 411 (Length Required) for POST without Content-Length when body
    # is missing. The connector defines an empty dict body for that reason.
    assert tc.get("body") == {}
    assert c["records_path"] == "bindings"


def test_vertex_endpoint_iam_requires_endpoint_id_param():
    c = _load("gcp_vertex_endpoint_iam")
    schema = c["params_schema"]
    assert schema["project_id"]["required"] is True
    assert schema["location"]["required"] is True
    assert schema["endpoint_id"]["required"] is True


# ── Audit dispatch (cross-audit prefix isolation) ────────────────────


def test_gcp_cloud_list_operations_includes_vertex_connectors():
    result = cloud_tools.cloud_list_operations_tool(db=None, params={
        "_protocol": "gcp",
    })
    ids = {op["id"] for op in result["operations"]}
    for new in NEW_GCP_CONNECTORS:
        assert new in ids, f"{new} not surfaced to gcp cloud_list_operations"


def test_managed_ai_saas_cannot_reach_gcp_vertex():
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "managed_ai_saas",
        "_credential_id": "fake",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "gcp_vertex_endpoints",
    })
    assert "error" in result
    assert "managed_ai_saas operation" in result["error"]


def test_aws_cannot_reach_gcp_vertex():
    result = cloud_tools.cloud_invoke_tool(db=None, params={
        "_protocol": "aws",
        "_credential_id": "fake",
        "_org_id": 1,
        "_agent_id": 1,
        "connector_id": "gcp_vertex_endpoint_iam",
    })
    assert "error" in result


def test_gcp_cloud_invoke_accepts_vertex_endpoints():
    fake_records = [
        {
            "name": "projects/my-proj/locations/us-central1/endpoints/12345",
            "displayName": "production-llama",
            "deployedModels": [{"serviceAccount": "default@developer.gserviceaccount.com"}],
        },
    ]

    async def fake_invoke(db, org_id, credential_id, connector_id, call_params):
        assert connector_id == "gcp_vertex_endpoints"
        assert call_params.get("location") == "us-central1"
        return fake_records

    with patch.object(cloud_tools, "_invoke_connector", side_effect=fake_invoke):
        result = cloud_tools.cloud_invoke_tool(db=None, params={
            "_protocol": "gcp",
            "_credential_id": "fake",
            "_org_id": 1,
            "_agent_id": 9999,
            "connector_id": "gcp_vertex_endpoints",
            "params": {"project_id": "my-proj", "location": "us-central1"},
        })
    assert result.get("connector_id") == "gcp_vertex_endpoints"
    assert result.get("total") == 1
    assert "error" not in result

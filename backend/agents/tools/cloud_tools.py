"""Cloud audit tool palette — live, read-only reasoning over cloud APIs.

Unlike the network-protocol audits (wmi/ldap/smb/...), cloud audits don't run
through a relay. The backend already holds the cloud credential (via the
integration credential vault) and speaks the cloud control plane directly
using the existing integration-builder transport + connector templates.

Design choices:

  - **Tools are API-agnostic.** A single `cloud_invoke` executes any connector
    from the JSON catalog. The LLM picks the connector by id. This sidesteps
    the "N auto-generated tools per provider" explosion — the palette stays
    four tools regardless of how many cloud ops exist.
  - **Nothing lands in the Asset table.** Responses are projected/summarized
    in-context so the agent reasons over live state, and only `emit_finding`
    persists anything. The user's requirement: "reason on the data without
    necessarily storing it".
  - **Per-run cache.** The most recent `cloud_invoke` response per
    `(agent_id, connector_id, params_hash)` is kept in-process so
    `cloud_inspect` can pull full records without a second API call.
    Cache dies with the worker process — same scope as the agent run.
  - **Read-only by construction.** The tool builder refuses any connector
    whose `direction != "pull"`. Push connectors (Jira create, Automox patch)
    are not reachable from this palette.

The protocol key is `aws` for the MVP; azure/gcp register in the same shape.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
from typing import Any

from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from integrations.connector_loader import get_connector, get_all_connectors_unpaginated
from services.credential_manager import load_credentials
from services.transports.api_transport import ApiTransport

logger = logging.getLogger(__name__)


_CLOUD_CALL_TIMEOUT_S = 60
_MAX_RECORDS_RETURNED = 200  # cap per cloud_invoke response

# Per-run invocation cache: {(agent_id, cache_key): [records...]}
# Keeps `cloud_inspect` cheap when the agent drills into a specific record
# after a slim projection. Evicted lazily when the process restarts.
_RUN_CACHE: dict[tuple[int, str], list[dict]] = {}


# ── Async dispatch helper (same pattern as smb_tools._run_async) ──────


def _run_async(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_CLOUD_CALL_TIMEOUT_S + 15)
    return asyncio.run(coro)


# ── Connector / credential helpers ────────────────────────────────────


# A protocol key normally maps 1:1 to a connector-id prefix
# (`aws` → `aws_*`). The `managed_ai_saas` audit is the exception — it spans
# multiple SaaS LLM vendors (OpenAI, Anthropic, …) and each vendor's
# connector ids are prefixed by the vendor name, not by the audit name. The
# table below gives the audit a list of allowed prefixes; everything else
# stays single-prefix.
_PROTOCOL_CONNECTOR_PREFIXES: dict[str, tuple[str, ...]] = {
    "managed_ai_saas": ("openai_", "anthropic_"),
}


def _provider_prefixes(protocol: str) -> tuple[str, ...]:
    """Return the connector-id prefixes the audit is allowed to invoke.
    Falls back to the protocol name itself for the simple aws/azure/gcp
    case so we don't have to enumerate them in the table above."""
    p = (protocol or "").lower()
    if p in _PROTOCOL_CONNECTOR_PREFIXES:
        return _PROTOCOL_CONNECTOR_PREFIXES[p]
    return (f"{p}_",)


def _provider_prefix(protocol: str) -> str:
    """Single-prefix back-compat shim used in error strings. Still returns
    the protocol name lowercased; multi-prefix audits should use
    `_provider_prefixes` for membership checks."""
    return (protocol or "").lower()


def _is_cloud_audit_connector(connector: dict, prefixes: tuple[str, ...]) -> bool:
    """Only expose read-only pull connectors whose id starts with one of
    the audit's allowed prefixes. Push connectors (create/delete/patch
    actions) and connectors outside the prefix set are filtered out
    defensively — the agent cannot reach them even if it guesses the id."""
    if connector.get("direction") != "pull":
        return False
    cid = connector.get("id", "")
    return any(cid.startswith(p) for p in prefixes)


def _cache_key(connector_id: str, call_params: dict) -> str:
    """Stable hash of (connector_id, params) so repeat calls in a run hit
    the cache rather than re-calling the cloud API."""
    payload = json.dumps({"cid": connector_id, "params": call_params or {}}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


async def _invoke_connector(
    db, org_id: int, credential_id: str, connector_id: str, call_params: dict
) -> list[dict]:
    """Run one connector via ApiTransport and return the flattened records.

    Reuses:
      - connector template from the JSON catalog (base_url, auth, paging)
      - credential from the vault (SigV4 keys, bearer token, etc.)
      - ApiTransport.fetch_all (pagination, XML→JSON, records_path resolution)
    """
    connector = get_connector(connector_id)
    if not connector:
        raise ValueError(f"unknown connector_id {connector_id!r}")
    if connector.get("direction") != "pull":
        raise ValueError(f"connector {connector_id!r} is not a read-only pull connector")

    credentials = await load_credentials(db, credential_id, org_id)
    if not credentials:
        raise ValueError(f"credential {credential_id} not found for org {org_id}")

    transport = ApiTransport()
    records: list[dict] = []
    async for rec in transport.fetch_all(
        connector["transport_config"],
        credentials,
        params=call_params or {},
    ):
        records.append(rec)
        if len(records) >= _MAX_RECORDS_RETURNED:
            break
    return records


def _project(records: list[dict], fields: list[str] | None) -> list[dict]:
    """Project each record to the requested top-level fields. When `fields`
    is None, return the first-level scalar keys only — keeps the LLM's
    context cheap. The raw record is always retrievable via `cloud_inspect`.
    """
    if not records:
        return []
    if fields:
        return [{f: r.get(f) for f in fields if f in r} for r in records]
    # Default: top-level scalars (skip nested dicts/lists to keep it small).
    projected = []
    for r in records:
        if not isinstance(r, dict):
            projected.append({"_value": r})
            continue
        projected.append({
            k: v for k, v in r.items()
            if isinstance(v, (str, int, float, bool)) or v is None
        })
    return projected


# ── Tools ─────────────────────────────────────────────────────────────


@agent_tool(
    "cloud_list_operations",
    "List the cloud operations available for this audit's provider. Returns "
    "[{id, name, description, params_schema}]. Use this before cloud_invoke "
    "to discover which connectors exist (e.g. aws_iam_users, aws_s3_buckets, "
    "aws_iam_policies). Filtered to the provider your audit is bound to and "
    "to read-only pull connectors only.",
    {
        "search": {
            "type": "string",
            "description": "Optional substring filter on connector name/description (case-insensitive).",
        },
    },
)
def cloud_list_operations_tool(db, params: dict) -> dict:
    protocol = _provider_prefix(params.get("_protocol") or "aws")
    prefixes = _provider_prefixes(protocol)
    search = (params.get("search") or "").strip().lower()
    ops = []
    for summary in get_all_connectors_unpaginated():
        cid = summary["id"]
        if not any(cid.startswith(p) for p in prefixes):
            continue
        if summary.get("direction") != "pull":
            continue
        if search and search not in summary["name"].lower() and search not in summary.get("description", "").lower():
            continue
        connector = get_connector(cid)
        ops.append({
            "id": cid,
            "name": summary["name"],
            "description": summary.get("description", ""),
            "params_schema": (connector or {}).get("params_schema", {}),
        })
    return {"provider": protocol, "total": len(ops), "operations": ops}


@agent_tool(
    "cloud_invoke",
    "Call one cloud connector live and return its records. Nothing is "
    "persisted — records live in the agent run's scratch cache. Use `fields` "
    "to project large responses (e.g. fields=['UserName','CreateDate'] on "
    "aws_iam_users); omit to get all top-level scalar fields. Use `limit` to "
    "cap how many projected records come back. To fetch the full nested JSON "
    "for one record, call cloud_inspect with the same connector_id.",
    {
        "connector_id": {
            "type": "string",
            "description": "Connector id (from cloud_list_operations). E.g. 'aws_iam_users'.",
        },
        "params": {
            "type": "object",
            "description": "Connector-specific params (matches params_schema on the op).",
        },
        "fields": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Top-level field names to keep. Omit for all scalars.",
        },
        "limit": {
            "type": "integer",
            "description": "Max records returned (caps at 50 by default; hard ceiling 200).",
        },
    },
)
def cloud_invoke_tool(db, params: dict) -> dict:
    connector_id = (params.get("connector_id") or "").strip()
    if not connector_id:
        return {"error": "connector_id is required"}
    protocol = _provider_prefix(params.get("_protocol") or "aws")
    prefixes = _provider_prefixes(protocol)
    if not any(connector_id.startswith(p) for p in prefixes):
        return {"error": f"connector {connector_id!r} is not a {protocol} operation"}

    connector = get_connector(connector_id)
    if not connector or not _is_cloud_audit_connector(connector, prefixes):
        return {"error": f"connector {connector_id!r} is not available to cloud audits (not a pull connector, or wrong provider)"}

    org_id = params.get("_org_id")
    credential_id = params.get("_credential_id")
    if not credential_id:
        return {"error": "no credential bound to this audit run"}

    call_params = params.get("params") or {}
    fields = params.get("fields")
    limit = params.get("limit") or 50
    try:
        limit = max(1, min(int(limit), _MAX_RECORDS_RETURNED))
    except (TypeError, ValueError):
        limit = 50

    try:
        records = _run_async(_invoke_connector(db, org_id, credential_id, connector_id, call_params))
    except Exception as e:
        logger.info("cloud_invoke failed connector=%s err=%s", connector_id, e)
        return {"connector_id": connector_id, "error": str(e)}

    # Cache full records for cloud_inspect to drill into.
    agent_id = params.get("_agent_id")
    if agent_id is not None:
        _RUN_CACHE[(agent_id, _cache_key(connector_id, call_params))] = records

    projected = _project(records, fields)
    return {
        "connector_id": connector_id,
        "total": len(records),
        "returned": min(len(projected), limit),
        "truncated": len(projected) > limit,
        "records": projected[:limit],
        "hint": (
            "Use cloud_inspect with the same connector_id + params to get the full JSON "
            "for a specific record_index."
        ),
    }


@agent_tool(
    "cloud_inspect",
    "Return the full (un-projected) JSON for one record from the most recent "
    "cloud_invoke call against this (connector_id, params) pair. Uses the "
    "per-run cache — no second API call unless the cache has been evicted.",
    {
        "connector_id": {"type": "string"},
        "params": {
            "type": "object",
            "description": "Same params used in the cloud_invoke call (for cache lookup).",
        },
        "record_index": {
            "type": "integer",
            "description": "Zero-based index into the cached record list.",
        },
    },
)
def cloud_inspect_tool(db, params: dict) -> dict:
    connector_id = (params.get("connector_id") or "").strip()
    if not connector_id:
        return {"error": "connector_id is required"}
    call_params = params.get("params") or {}
    idx = params.get("record_index")
    if not isinstance(idx, int) or idx < 0:
        return {"error": "record_index (non-negative int) is required"}

    agent_id = params.get("_agent_id")
    key = (agent_id, _cache_key(connector_id, call_params))
    records = _RUN_CACHE.get(key)
    cache_hit = records is not None

    if records is None:
        # Fallback — re-invoke. Rare path; the LLM should call cloud_invoke first.
        org_id = params.get("_org_id")
        credential_id = params.get("_credential_id")
        if not credential_id:
            return {"error": "no credential bound to this audit run"}
        try:
            records = _run_async(_invoke_connector(db, org_id, credential_id, connector_id, call_params))
        except Exception as e:
            return {"connector_id": connector_id, "error": str(e)}
        if agent_id is not None:
            _RUN_CACHE[key] = records

    if idx >= len(records):
        return {
            "error": f"record_index {idx} out of range (cached {len(records)} records)",
            "cache_hit": cache_hit,
        }
    return {
        "connector_id": connector_id,
        "record_index": idx,
        "cache_hit": cache_hit,
        "record": records[idx],
    }


# ── Registration ──────────────────────────────────────────────────────


_CLOUD_TOOL_NAMES = [
    "cloud_list_operations",
    "cloud_invoke",
    "cloud_inspect",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


# Per-provider credential connector lists — these are connector ids whose
# credential shape the audit accepts. Mirrors the pattern used by the protocol
# audits (windows_host / linux_host / etc.). Any pull connector under the
# provider prefix can in principle vend the credential; we enumerate a few
# representative ones so the kickoff UI can filter saved credentials sensibly.
_AWS_CREDENTIAL_CONNECTORS = [
    "aws_iam_users", "aws_iam_roles", "aws_iam_policies",
    "aws_s3_buckets", "aws_ec2_instances", "aws_lambda_functions",
    "aws_security_hub_findings",
    # Phase 3.5 — managed AI (Bedrock + SageMaker). Same SigV4 credential
    # shape as the rest of AWS, but listed here so the kickoff UI surfaces
    # AWS credentials saved against any of these connector ids.
    "aws_bedrock_invocation_logging", "aws_bedrock_foundation_models",
    "aws_bedrock_guardrails",
    "aws_sagemaker_endpoints", "aws_sagemaker_endpoint_configs",
]

_AZURE_CREDENTIAL_CONNECTORS = [
    "azure_ad_identities", "azure_role_assignments", "azure_role_definitions",
    "azure_storage_accounts", "azure_virtual_machines", "azure_function_apps",
    "azure_defender_findings",
    "azure_cognitive_services_accounts", "azure_openai_deployments",
]

_GCP_CREDENTIAL_CONNECTORS = [
    "gcp_iam_service_accounts", "gcp_project_iam_bindings",
    "gcp_storage_buckets", "gcp_compute_instances", "gcp_cloud_functions",
    "gcp_scc_findings",
    "gcp_vertex_endpoints", "gcp_vertex_models", "gcp_vertex_endpoint_iam",
]

_MANAGED_AI_SAAS_CREDENTIAL_CONNECTORS = [
    "openai_admin_projects", "openai_admin_api_keys",
    "openai_admin_users", "openai_admin_audit_logs",
    "anthropic_admin_workspaces", "anthropic_admin_api_keys",
    "anthropic_admin_users", "anthropic_admin_workspace_members",
]


def _cloud_missions(provider: str) -> list[MissionTemplate]:
    """Three-mission base shared across providers (exposure / identity /
    explore). AWS gets a fourth mission appended for Bedrock + SageMaker
    governance — see `_aws_managed_ai_mission`."""
    base = [
        MissionTemplate(
            key="exposure",
            label="Public Exposure",
            description="Public storage, open firewall/security-group rules, publicly-reachable serverless endpoints, unauthenticated resources.",
            prompt_key=f"{provider}_audit_exposure",
            suggested_budget=25,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="identity",
            label="Identity & Access",
            description="Privilege-escalation paths, over-permissive policies/roles, stale keys, unexpected external trust.",
            prompt_key=f"{provider}_audit_identity",
            suggested_budget=30,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about control-plane exposure.",
            prompt_key=f"{provider}_audit_explore",
            suggested_budget=25,
            cost_hint="medium",
        ),
    ]
    if provider == "aws":
        base.append(MissionTemplate(
            key="managed_ai",
            label="Managed AI (Bedrock + SageMaker)",
            description="Model-invocation logging gaps, missing guardrails, IAM principals with bedrock:InvokeModel / sagemaker:InvokeEndpoint at wildcard scope, SageMaker endpoints without VPC isolation.",
            prompt_key="aws_audit_managed_ai",
            suggested_budget=25,
            cost_hint="medium",
        ))
    elif provider == "azure":
        base.append(MissionTemplate(
            key="managed_ai",
            label="Managed AI (Azure OpenAI + Cognitive Services)",
            description="Local key auth still enabled, public network access without IP allowlist, missing private endpoints, Cognitive Services RBAC granted at subscription scope.",
            prompt_key="azure_audit_managed_ai",
            suggested_budget=25,
            cost_hint="medium",
        ))
    elif provider == "gcp":
        base.append(MissionTemplate(
            key="managed_ai",
            label="Managed AI (Vertex AI)",
            description="Vertex endpoints with allUsers / allAuthenticatedUsers IAM bindings, aiplatform.endpoints.predict granted at project scope, default Compute SA used by Vertex inference.",
            prompt_key="gcp_audit_managed_ai",
            suggested_budget=25,
            cost_hint="medium",
        ))
    return base


register_audit(ProtocolAudit(
    protocol="aws",
    label="AWS Cloud Audit",
    description=(
        "Credentialed AWS audit that reasons over IAM, S3, EC2, Lambda, and "
        "other control-plane APIs live — without persisting intermediate state. "
        "Reuses integration-builder connectors as the tool catalog."
    ),
    supported_os=["cloud"],
    auth_modes=["aws_sigv4"],
    relay_method="none",
    credential_connector_ids=_AWS_CREDENTIAL_CONNECTORS,
    tool_names=_CLOUD_TOOL_NAMES,
    required_ports=(),
    default_wallclock_s=900,
    missions=_cloud_missions("aws"),
))


register_audit(ProtocolAudit(
    protocol="azure",
    label="Azure Cloud Audit",
    description=(
        "Credentialed Azure audit that reasons over Entra ID, RBAC, Storage "
        "Accounts, Virtual Machines, and other control-plane APIs live. "
        "Reuses integration-builder connectors as the tool catalog."
    ),
    supported_os=["cloud"],
    auth_modes=["oauth2"],
    relay_method="none",
    credential_connector_ids=_AZURE_CREDENTIAL_CONNECTORS,
    tool_names=_CLOUD_TOOL_NAMES,
    required_ports=(),
    default_wallclock_s=900,
    missions=_cloud_missions("azure"),
))


register_audit(ProtocolAudit(
    protocol="gcp",
    label="GCP Cloud Audit",
    description=(
        "Credentialed GCP audit that reasons over project IAM bindings, "
        "service accounts, GCS buckets, Compute, and Cloud Functions live. "
        "Reuses integration-builder connectors as the tool catalog."
    ),
    supported_os=["cloud"],
    auth_modes=["gcp_service_account"],
    relay_method="none",
    credential_connector_ids=_GCP_CREDENTIAL_CONNECTORS,
    tool_names=_CLOUD_TOOL_NAMES,
    required_ports=(),
    default_wallclock_s=900,
    missions=_cloud_missions("gcp"),
))


def _managed_ai_saas_missions() -> list[MissionTemplate]:
    """Three missions specific to SaaS LLM admin-plane governance.
    Distinct from `_cloud_missions` because the risk vocabulary is different
    (no S3/IAM/SG; instead admin keys, workspace boundaries, audit logs)."""
    return [
        MissionTemplate(
            key="keys_hygiene",
            label="API Keys Hygiene",
            description="Stale active keys, no-rotation, broad-scope keys, orphaned keys whose creator left the org.",
            prompt_key="managed_ai_saas_audit_keys_hygiene",
            suggested_budget=20,
            cost_hint="low",
        ),
        MissionTemplate(
            key="identity",
            label="Identity & Access",
            description="Owner-role sprawl, external-domain members, inactive privileged users, workspace boundary leaks, audit-log gaps.",
            prompt_key="managed_ai_saas_audit_identity",
            suggested_budget=25,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about admin-plane governance.",
            prompt_key="managed_ai_saas_audit_explore",
            suggested_budget=20,
            cost_hint="medium",
        ),
    ]


register_audit(ProtocolAudit(
    protocol="managed_ai_saas",
    label="Managed AI (SaaS) Governance Audit",
    description=(
        "Credentialed audit over a SaaS LLM provider's admin API "
        "(OpenAI or Anthropic). Reasons about API keys, members, workspaces, "
        "and audit logs to surface governance and credential-hygiene risks. "
        "The admin key has org-wide visibility — onboarding gates behind an "
        "explicit acknowledgement of that scope."
    ),
    supported_os=["cloud"],
    auth_modes=["bearer", "api_key"],
    relay_method="none",
    credential_connector_ids=_MANAGED_AI_SAAS_CREDENTIAL_CONNECTORS,
    tool_names=_CLOUD_TOOL_NAMES,
    required_ports=(),
    default_wallclock_s=600,
    missions=_managed_ai_saas_missions(),
    compliance_tags=("nist_ai_rmf", "iso_42001"),
))

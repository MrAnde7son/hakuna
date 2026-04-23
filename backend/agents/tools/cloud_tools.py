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


def _provider_prefix(protocol: str) -> str:
    """Map a protocol key to its connector-id prefix. Cloud audits are
    registered under short provider names (aws/azure/gcp) which also happen
    to be the connector-id prefix."""
    return protocol.lower()


def _is_cloud_audit_connector(connector: dict, provider: str) -> bool:
    """Only expose read-only pull connectors for the given provider to the
    cloud audit agent. Push connectors (create/delete/patch actions) and
    connectors for other providers are filtered out defensively — the agent
    cannot reach them even if it guesses the id."""
    if connector.get("direction") != "pull":
        return False
    cid = connector.get("id", "")
    return cid.startswith(f"{provider}_")


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
    provider = _provider_prefix(params.get("_protocol") or "aws")
    search = (params.get("search") or "").strip().lower()
    ops = []
    for summary in get_all_connectors_unpaginated():
        cid = summary["id"]
        if not cid.startswith(f"{provider}_"):
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
    return {"provider": provider, "total": len(ops), "operations": ops}


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
    provider = _provider_prefix(params.get("_protocol") or "aws")
    if not connector_id.startswith(f"{provider}_"):
        return {"error": f"connector {connector_id!r} is not a {provider} operation"}

    connector = get_connector(connector_id)
    if not connector or not _is_cloud_audit_connector(connector, provider):
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


# Connector ids that vend an AWS SigV4 credential shape — any of these is a
# valid credential source for an AWS audit. Mirrors the credential_connector_ids
# pattern used by the protocol audits (windows_host / linux_host / etc.).
_AWS_CREDENTIAL_CONNECTORS = [
    "aws_iam_users",
    "aws_iam_roles",
    "aws_iam_policies",
    "aws_s3_buckets",
    "aws_ec2_instances",
    "aws_lambda_functions",
    "aws_security_hub_findings",
]


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
    missions=[
        MissionTemplate(
            key="exposure",
            label="Public Exposure",
            description="Public S3 buckets, open security groups, publicly-reachable Lambda URLs, unauthenticated endpoints.",
            prompt_key="aws_audit_exposure",
            suggested_budget=25,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="identity",
            label="Identity & Access",
            description="IAM privilege-escalation paths, over-permissive policies, unused access keys, cross-account trust risk.",
            prompt_key="aws_audit_identity",
            suggested_budget=30,
            cost_hint="medium",
        ),
        MissionTemplate(
            key="explore",
            label="Explore (creative)",
            description="No fixed checklist — agent reasons freely about AWS control-plane exposure.",
            prompt_key="aws_audit_explore",
            suggested_budget=25,
            cost_hint="medium",
        ),
    ],
))

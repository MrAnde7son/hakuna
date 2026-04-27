"""Exposed-AI-Service tool palette for the Exposed-AI-Service Audit ReAct agent.

Phase 3 of the protocol audit roadmap (Family B). The scanner already emits
``ai_exposure_*`` Findings for the eight services it probes natively
(Ollama, vLLM, Qdrant, Milvus, Chroma, MCP, LiteLLM, LangServe) — see
``hakuna-scanner/app/ingest/ai_exposure_probe.py``. This audit's tool palette
is **gap-fill only**: services the scanner does not currently cover, plus a
small set of consent-gated capability probes (``prompt_injection_probe``
mission only) that go deeper than a banner check.

## Coverage split

  - **Triage mission** (``safety_class="anon_ai_exposure"``):
      Jupyter (8888), Ray Dashboard (8265), MLflow (5000), TensorBoard (6006),
      HuggingFace TGI (8080/3000 OpenAI-compat), LM Studio (1234), OpenWebUI
      (3000/8080), Langfuse (3000). Anonymous metadata-only HTTP probes.
  - **Prompt-injection-probe mission** (still ``anon_ai_exposure``, but the
      mission requires explicit per-asset consent — never auto-triggered):
      benign canary inference against Ollama (11434) and vLLM (8000), plus
      MCP tool enumeration. The scanner already flags these as exposed; the
      audit adds capability evidence (e.g. "this Ollama instance accepts
      arbitrary completions and has model X loaded") for the finding.

## Coexistence with the scanner

Scanner finding types are ``ai_exposure_<service>``; audit finding types use
the ``exposed_ai_<service>`` prefix. Different namespaces → no dedup logic
needed. The triage prompt instructs the agent to read ``Asset.findings`` and
skip any service that already has an ``ai_exposure_*`` finding so the LLM
loop doesn't burn budget re-probing what the scanner just classified.

## Safety stance

Every probe is read-only and metadata-only:
  - No model invocation in triage. Inference happens only inside the
    consent-gated ``prompt_injection_probe`` mission, with hardcoded benign
    canary prompts at the relay layer (the LLM cannot supply prompt text).
  - Per-call timeout enforced at the relay (8s default).
  - Anonymous by spec — ``credentials={}`` always.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Optional

from models.models import Asset
from agents.agent_tools import agent_tool
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target, split_host_port
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_PROBE_TIMEOUT_S = 8


def _run_async(coro):
    """Bridge sync agent_tool to async relay broker. Same shape as
    ``exposed_datastore_tools._run_async``."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_PROBE_TIMEOUT_S + 15)
    return asyncio.run(coro)


def _ctx(params: dict) -> tuple[Optional[str], Optional[str]]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


async def _dispatch_probe(
    db,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: Optional[str],
    default_port: int,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    raw_target = asset.ip or asset.fqdn or asset.hostname
    if not raw_target:
        raise ValueError(f"asset {asset_id} has no ip or hostname")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")

    target, target_port = split_host_port(raw_target)
    if target_port is None:
        _, target_port = resolve_asset_target(asset)
    port = target_port or default_port

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ai_service_probe",
        config={"target": target, "port": port},
        credentials={},  # anonymous by spec for this audit family
        params={"op": op, "op_params": op_params, "timeout_s": _PROBE_TIMEOUT_S},
    )
    return asset, (result or {})


# ── Triage tools (gap-fill: services scanner doesn't cover) ─────────


@agent_tool(
    "jupyter_check_auth",
    "Probe a Jupyter / JupyterLab server (default 8888) for unauthenticated "
    "access. Hits `GET /api/status` — if it returns 200 with a JSON status "
    "body, the server has `--NotebookApp.token=''` (no token) and is "
    "completely open: anyone can spawn a notebook and execute Python with the "
    "host user's privileges. NEVER opens a kernel or runs code. Returns: "
    "`{auth_required: bool, version: str, scheme: str, kernels_endpoint_open: "
    "bool, _errors?: dict}`. `auth_required: false` is a critical finding.",
    {"asset_id": {"type": "integer"}},
)
def jupyter_check_auth_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "jupyter", {}, relay, 8888))
    return result


@agent_tool(
    "ray_dashboard_info",
    "Probe a Ray Dashboard (default 8265) for unauthenticated access. Hits "
    "`GET /api/version` (cluster info) and `GET /api/jobs/` (lists submitted "
    "jobs). Ray's job submission API takes arbitrary Python entrypoints — an "
    "unauthenticated dashboard is full RCE on every node in the cluster. "
    "NEVER submits a job. Returns: `{reachable: bool, version: str, "
    "ray_version: str, jobs_visible: bool, job_count: int, _errors?: dict}`. "
    "`jobs_visible: true` is a critical finding.",
    {"asset_id": {"type": "integer"}},
)
def ray_dashboard_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "ray", {}, relay, 8265))
    return result


@agent_tool(
    "mlflow_list_experiments",
    "Probe an MLflow tracking server (default 5000) for unauthenticated "
    "access. Hits `GET /api/2.0/mlflow/experiments/search` with no token. If "
    "the response includes an experiments list, the server is open: artifact "
    "URIs in MLflow runs frequently include S3 bucket names + paths and "
    "occasionally cloud creds in env vars. NEVER reads artifacts. Returns: "
    "`{auth_required: bool, version: str, experiments_count: int, sample_"
    "experiment_names: [str] (capped at 5), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def mlflow_list_experiments_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "mlflow", {}, relay, 5000))
    return result


@agent_tool(
    "tensorboard_list_runs",
    "Probe a TensorBoard server (default 6006) for unauthenticated access. "
    "Hits `GET /data/runs` — if it returns 200 with a JSON list, anyone can "
    "view the training runs (loss curves, hyperparameters, sometimes raw "
    "training data summaries). TensorBoard has no auth model: reachability "
    "*is* the finding when on a public network. Returns: `{reachable: bool, "
    "runs_count: int, sample_run_names: [str] (capped at 5), _errors?: "
    "dict}`.",
    {"asset_id": {"type": "integer"}},
)
def tensorboard_list_runs_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "tensorboard", {}, relay, 6006))
    return result


@agent_tool(
    "tgi_info",
    "Probe a HuggingFace Text Generation Inference (TGI) server (default "
    "8080) via its OpenAI-compat `/v1/models` endpoint. If models are listed "
    "without auth, the inference endpoint accepts unauthenticated completions "
    "— a quota/cost exposure plus prompt-injection-of-downstream-systems "
    "vector. NEVER calls `/v1/completions`. Returns: `{auth_required: bool, "
    "models: [str] (capped at 10), framework: str, _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def tgi_info_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "tgi", {}, relay, 8080))
    return result


@agent_tool(
    "lmstudio_models",
    "Probe an LM Studio server (default 1234) via OpenAI-compat `/v1/models`. "
    "LM Studio has no auth in any version — a publicly-reachable LM Studio "
    "instance is an unauthenticated GPU/inference endpoint. NEVER calls "
    "`/v1/chat/completions`. Returns: `{reachable: bool, models: [str] "
    "(capped at 10), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def lmstudio_models_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "lmstudio", {}, relay, 1234))
    return result


@agent_tool(
    "openwebui_status",
    "Probe an OpenWebUI / Open WebUI deployment (default 3000) for "
    "unauthenticated signup. Hits `GET /api/config` to read the auth state "
    "and signup-enabled flag. OpenWebUI's first signup becomes admin; if "
    "signup is open and admin doesn't exist yet, an attacker takes the chair. "
    "NEVER signs up. Returns: `{auth_required: bool, signup_enabled: bool, "
    "version: str, default_models: [str], _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def openwebui_status_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "openwebui", {}, relay, 3000))
    return result


@agent_tool(
    "langfuse_status",
    "Probe a Langfuse self-hosted instance (default 3000) for unauthenticated "
    "access. Hits `GET /api/public/health` (always anonymous) and "
    "`GET /api/public/projects` (auth-required when configured). If projects "
    "list anonymously, anyone can read LLM trace logs — frequently containing "
    "prompts, completions, and PII. Returns: `{reachable: bool, version: "
    "str, auth_required: bool, projects_visible: bool, project_count: int, "
    "_errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def langfuse_status_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "langfuse", {}, relay, 3000))
    return result


# ── Prompt-injection-probe tools (consent-gated mission only) ───────


@agent_tool(
    "ollama_capability_probe",
    "Send one benign hardcoded canary prompt to an Ollama instance (default "
    "11434) and report whether inference completes without auth. Used in the "
    "`prompt_injection_probe` mission ONLY (consent-gated). The prompt text "
    "is fixed at the relay (`Reply with the exact two-word phrase: hakuna "
    "matata.`); the LLM cannot supply prompt text via this tool. Returns: "
    "`{inference_open: bool, models_loaded: [str], canary_response_match: "
    "bool, response_truncated: str (first 200 chars), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def ollama_capability_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "ollama_canary", {}, relay, 11434))
    return result


@agent_tool(
    "vllm_capability_probe",
    "Send one benign hardcoded canary prompt to a vLLM server (default 8000) "
    "via `/v1/completions`. Used in the `prompt_injection_probe` mission ONLY "
    "(consent-gated). The prompt text is fixed at the relay; the LLM cannot "
    "supply prompt text. Same pattern as `ollama_capability_probe`. Returns: "
    "`{inference_open: bool, models: [str], canary_response_match: bool, "
    "response_truncated: str (first 200 chars), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}},
)
def vllm_capability_probe_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    _, result = _run_async(_dispatch_probe(db, asset_id, "vllm_canary", {}, relay, 8000))
    return result


@agent_tool(
    "mcp_enumerate_tools",
    "Enumerate the tool palette exposed by an MCP (Model Context Protocol) "
    "server. Hits `GET /tools` or sends a single `tools/list` JSON-RPC frame. "
    "An exposed MCP server is an inference-side RCE primitive: every tool in "
    "the palette is something an attacker could trigger via prompt injection "
    "of any LLM that connects to it. Used in the `prompt_injection_probe` "
    "mission ONLY (consent-gated). NEVER invokes a tool. Returns: "
    "`{reachable: bool, transport: str, tools: [{name, description}] (capped "
    "at 25), _errors?: dict}`.",
    {"asset_id": {"type": "integer"}, "port": {"type": "integer"}},
)
def mcp_enumerate_tools_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    relay, _cred = _ctx(params)
    # MCP has no canonical port — the agent supplies one from the asset's
    # open_ports (typically 3001/3010/8765). Fall back to 3000 only as a
    # last resort.
    port = params.get("port")
    try:
        default_port = int(port) if port is not None else 3000
    except (TypeError, ValueError):
        default_port = 3000
    _, result = _run_async(_dispatch_probe(db, asset_id, "mcp", {}, relay, default_port))
    return result


# ── Registry ─────────────────────────────────────────────────────────


_EXPOSED_AI_TRIAGE_TOOLS = [
    "jupyter_check_auth",
    "ray_dashboard_info",
    "mlflow_list_experiments",
    "tensorboard_list_runs",
    "tgi_info",
    "lmstudio_models",
    "openwebui_status",
    "langfuse_status",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]

# Prompt-injection-probe mission gets the triage palette PLUS the canary +
# MCP tools. The mission's prompt forbids running canaries against services
# the scanner already classified as authenticated; the consent-gating is
# at the auto-trigger layer.
_EXPOSED_AI_PROMPT_INJECTION_TOOLS = _EXPOSED_AI_TRIAGE_TOOLS + [
    "ollama_capability_probe",
    "vllm_capability_probe",
    "mcp_enumerate_tools",
]


register_audit(ProtocolAudit(
    protocol="exposed_ai_service",
    label="Exposed AI Service Audit",
    description=(
        "Anonymous-probe audit for self-hosted AI/ML services that ship "
        "auth-disabled by default and are not already covered by the EASM "
        "scanner's ai_exposure stage (Jupyter, Ray, MLflow, TensorBoard, "
        "TGI, LM Studio, OpenWebUI, Langfuse). The triage mission confirms "
        "exposure and emits a sized finding; the consent-gated "
        "prompt_injection_probe mission additionally runs benign canary "
        "inference against Ollama/vLLM and enumerates MCP tool palettes "
        "for evidence depth. Read-only — never invokes inference outside "
        "the canary path."
    ),
    supported_os=["linux", "windows", "container"],
    auth_modes=["anonymous"],
    relay_method="ai_service_probe",
    credential_connector_ids=[],
    tool_names=_EXPOSED_AI_PROMPT_INJECTION_TOOLS,  # superset; mission picks subset via prompt
    required_ports=(
        # Triage ports
        8888, 8265, 5000, 6006, 8080, 1234, 3000,
        # Prompt-injection-probe ports (kept reachable for predicate matching)
        11434, 8000,
    ),
    safety_class="anon_ai_exposure",
    auto_trigger_policy="auto_org_opt_in",
    cooldown_hours=24,
    compliance_tags=("nist_ai_rmf", "iso_42001"),
    missions=[
        MissionTemplate(
            key="triage",
            label="AI Service Exposure Triage",
            description=(
                "Confirm whether the exposed AI service accepts unauthenticated "
                "queries and emit a single sized finding. Skips services the "
                "EASM scanner has already classified (ai_exposure_*) to avoid "
                "double-emitting."
            ),
            prompt_key="exposed_ai_service_audit_triage",
            suggested_budget=10,
            cost_hint="low",
        ),
        MissionTemplate(
            key="prompt_injection_probe",
            label="AI Capability Probe (consent-gated)",
            description=(
                "Send one benign hardcoded canary prompt to confirm the "
                "service accepts arbitrary inference, plus enumerate MCP tool "
                "palettes when reachable. Requires explicit per-asset consent "
                "— never auto-triggered."
            ),
            prompt_key="exposed_ai_service_audit_prompt_injection_probe",
            suggested_budget=12,
            cost_hint="medium",
        ),
    ],
))

"""Exposed AI service probe executor for the Hakuna relay agent.

Phase 3 of the protocol audit roadmap. Single relay method (``ai_service_probe``)
covering the Family B gap-fill set:

  Triage ops (anonymous metadata-only):
    - op="jupyter"      Jupyter / JupyterLab    (default 8888)
    - op="ray"          Ray Dashboard           (default 8265)
    - op="mlflow"       MLflow Tracking         (default 5000)
    - op="tensorboard"  TensorBoard             (default 6006)
    - op="tgi"          HuggingFace TGI         (default 8080)
    - op="lmstudio"     LM Studio (OpenAI-compat) (default 1234)
    - op="openwebui"    OpenWebUI               (default 3000)
    - op="langfuse"     Langfuse                (default 3000)

  Prompt-injection-probe ops (consent-gated at the backend; mission-only):
    - op="ollama_canary"  Ollama benign-canary completion (default 11434)
    - op="vllm_canary"    vLLM benign-canary completion   (default 8000)
    - op="mcp"            MCP tool-palette enumeration

## Design notes

* All probes are anonymous by spec. ``credentials`` is ignored.
* Canary prompts are hardcoded **here** — the backend tool can't supply
  prompt text. This is a deliberate defense layer: even a prompt-injected
  audit agent can't pivot into "send arbitrary prompt to remote LLM."
* Per-op timeout enforced at the handler. Failures return ``_errors``
  rather than raising so the agent can reason over the error string.
* httpx is the single HTTP client; lazy-imported so a missing optional
  dependency only fails the specific op.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_S = 8

# Hardcoded benign canary. Two-word phrase + a deterministic check so the
# handler can decide ``canary_response_match`` without an LLM. Picked to be
# obviously non-malicious (no jailbreak verbiage) and short enough that any
# small model can answer in one token-pair.
_CANARY_PROMPT = "Reply with the exact two-word phrase: hakuna matata."
_CANARY_EXPECTED_SUBSTRING = "hakuna matata"


class AIServiceProbeError(Exception):
    """Any AI-service probe failure surfaced back to the backend."""


@register_method("ai_service_probe")
async def ai_service_probe_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch one AI-service probe based on ``params.op``.

    Mirrors ``datastore_probe_handler``: relay-side allowlist is the keys of
    ``_OP_HANDLERS``. Unknown ops are rejected before any network code runs.
    """
    target = (transport_config or {}).get("target")
    if not target:
        raise AIServiceProbeError("transport_config.target is required")
    port = int((transport_config or {}).get("port") or 0)
    op = (params or {}).get("op") or ""
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or _DEFAULT_TIMEOUT_S)

    handler = _OP_HANDLERS.get(op)
    if handler is None:
        raise AIServiceProbeError(
            f"unknown ai_service_probe op {op!r}; allowed: {sorted(_OP_HANDLERS.keys())}"
        )

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(handler, target, port, op_params, timeout_s),
            timeout=timeout_s + 2,
        )
    except asyncio.TimeoutError:
        return {"_errors": {op: f"probe timed out after {timeout_s}s for {target}:{port}"}}


# ── Jupyter ──────────────────────────────────────────────────────────


def _probe_jupyter(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/status on Jupyter / JupyterLab.

    A 200 with a JSON status body means token auth is disabled (or token
    missing). A 401/403 with a redirect to ``/login`` means it's secured.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"jupyter": "httpx not installed on relay"}}

    port = port or 8888
    out: dict[str, Any] = {"auth_required": None}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False, follow_redirects=False) as client:
                resp = client.get(f"{base}/api/status")
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except Exception:
                        last_err = f"{scheme} non-json status"
                        continue
                    out["auth_required"] = False
                    out["scheme"] = scheme
                    out["version"] = body.get("version") or body.get("started")
                    # /api/kernels is the smoking gun: if it's open too, an
                    # attacker can spawn a kernel and exec Python. Just check
                    # the status code — never list kernel ids.
                    try:
                        kr = client.get(f"{base}/api/kernels")
                        out["kernels_endpoint_open"] = kr.status_code == 200
                    except httpx.RequestError:
                        out["kernels_endpoint_open"] = None
                    return out
                if resp.status_code in (401, 403):
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                # Some Jupyter installs redirect / -> /login when token is
                # required without ever returning 401. Treat 302->/login as
                # auth-required.
                if resp.status_code in (302, 303) and "/login" in resp.headers.get("location", ""):
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                last_err = f"{scheme} GET /api/status -> HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"jupyter": last_err or "unreachable"}}


# ── Ray Dashboard ────────────────────────────────────────────────────


def _probe_ray(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/version + /api/jobs/ on the Ray Dashboard.

    /api/version is informational; /api/jobs/ lists submitted jobs and is
    the same endpoint that accepts POST to submit a Python entrypoint. A
    200 there with a job list = unauthenticated cluster RCE primitive.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"ray": "httpx not installed on relay"}}

    port = port or 8265
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"reachable": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            ver = client.get(f"{base}/api/version")
            if ver.status_code != 200:
                return {"_errors": {"ray": f"GET /api/version HTTP {ver.status_code}"}}
            try:
                v = ver.json()
            except Exception:
                return {"_errors": {"ray": "GET /api/version non-json — probably not Ray"}}
            out["reachable"] = True
            out["version"] = v.get("version")
            out["ray_version"] = v.get("ray_version") or v.get("version")
            out["python_version"] = v.get("python_version")

            jobs = client.get(f"{base}/api/jobs/")
            if jobs.status_code == 200:
                try:
                    body = jobs.json()
                except Exception:
                    body = None
                if isinstance(body, list):
                    out["jobs_visible"] = True
                    out["job_count"] = len(body)
                elif isinstance(body, dict) and isinstance(body.get("jobs"), list):
                    out["jobs_visible"] = True
                    out["job_count"] = len(body["jobs"])
                else:
                    out["jobs_visible"] = True
                    out["job_count"] = 0
            elif jobs.status_code in (401, 403):
                out["jobs_visible"] = False
            else:
                out["_errors"] = {"jobs": f"HTTP {jobs.status_code}"}
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"ray": f"{type(e).__name__}: {e}"}}
    return out


# ── MLflow ───────────────────────────────────────────────────────────


def _probe_mlflow(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/2.0/mlflow/experiments/search on the MLflow tracking server.

    No JSON body required — MLflow accepts an empty GET. If experiments are
    listed without auth, the server is open. Returns a small sample of
    experiment names so the finding evidence has substance, not just a count.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"mlflow": "httpx not installed on relay"}}

    port = port or 5000
    out: dict[str, Any] = {"auth_required": None}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                # /version was added in 2.x; tolerate either presence/absence.
                try:
                    ver = client.get(f"{base}/version")
                    if ver.status_code == 200:
                        out["version"] = ver.text.strip()[:64]
                except httpx.RequestError:
                    pass

                resp = client.get(f"{base}/api/2.0/mlflow/experiments/search")
                if resp.status_code == 401:
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                if resp.status_code != 200:
                    last_err = f"{scheme} experiments/search HTTP {resp.status_code}"
                    continue
                try:
                    body = resp.json() or {}
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                experiments = body.get("experiments") or []
                if not isinstance(experiments, list):
                    experiments = []
                out["auth_required"] = False
                out["scheme"] = scheme
                out["experiments_count"] = len(experiments)
                out["sample_experiment_names"] = [
                    str(e.get("name") or e.get("experiment_id") or "")[:80]
                    for e in experiments[:5]
                    if isinstance(e, dict)
                ]
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"mlflow": last_err or "unreachable"}}


# ── TensorBoard ──────────────────────────────────────────────────────


def _probe_tensorboard(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /data/runs on TensorBoard.

    TensorBoard has no auth; reachability with a runs payload is itself the
    finding. We return run names (first 5) so the finding evidence shows the
    asset owner is actually serving training-run data publicly.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"tensorboard": "httpx not installed on relay"}}

    port = port or 6006
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"reachable": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.get(f"{base}/data/runs")
            if resp.status_code != 200:
                return {"_errors": {"tensorboard": f"GET /data/runs HTTP {resp.status_code}"}}
            try:
                body = resp.json()
            except Exception:
                return {"_errors": {"tensorboard": "GET /data/runs non-json — probably not TB"}}
            if not isinstance(body, list):
                return {"_errors": {"tensorboard": "unexpected response shape"}}
            out["reachable"] = True
            out["runs_count"] = len(body)
            out["sample_run_names"] = [str(r)[:80] for r in body[:5]]
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"tensorboard": f"{type(e).__name__}: {e}"}}
    return out


# ── HuggingFace TGI ──────────────────────────────────────────────────


def _probe_tgi(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /v1/models on TGI's OpenAI-compat surface.

    Standard OpenAI shape: ``{data: [{id: ..., object: "model"}]}``. If
    auth is required, returns 401 with WWW-Authenticate.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"tgi": "httpx not installed on relay"}}

    port = port or 8080
    out: dict[str, Any] = {"auth_required": None, "framework": "tgi"}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                resp = client.get(f"{base}/v1/models")
                if resp.status_code == 401:
                    out["auth_required"] = True
                    out["scheme"] = scheme
                    return out
                if resp.status_code != 200:
                    last_err = f"{scheme} GET /v1/models HTTP {resp.status_code}"
                    continue
                try:
                    body = resp.json() or {}
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                data = body.get("data") or []
                if not isinstance(data, list):
                    data = []
                out["auth_required"] = False
                out["scheme"] = scheme
                out["models"] = [
                    str(m.get("id") or "")[:120]
                    for m in data[:10]
                    if isinstance(m, dict)
                ]
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"tgi": last_err or "unreachable"}}


# ── LM Studio ────────────────────────────────────────────────────────


def _probe_lmstudio(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /v1/models on LM Studio.

    LM Studio has no auth model — reachability *is* the finding when the
    instance is publicly exposed. Same OpenAI-compat shape as TGI.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"lmstudio": "httpx not installed on relay"}}

    port = port or 1234
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"reachable": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.get(f"{base}/v1/models")
            if resp.status_code != 200:
                return {"_errors": {"lmstudio": f"GET /v1/models HTTP {resp.status_code}"}}
            try:
                body = resp.json() or {}
            except Exception:
                return {"_errors": {"lmstudio": "non-json — probably not LM Studio"}}
            data = body.get("data") or []
            if not isinstance(data, list):
                data = []
            out["reachable"] = True
            out["models"] = [
                str(m.get("id") or "")[:120]
                for m in data[:10]
                if isinstance(m, dict)
            ]
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"lmstudio": f"{type(e).__name__}: {e}"}}
    return out


# ── OpenWebUI ────────────────────────────────────────────────────────


def _probe_openwebui(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/config on OpenWebUI.

    ``features.enable_signup`` controls whether a stranger can claim the
    first-admin chair. ``oauth.providers`` and ``auth`` shape vary across
    versions; we surface the raw values for the agent to reason over.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"openwebui": "httpx not installed on relay"}}

    port = port or 3000
    out: dict[str, Any] = {"reachable": False}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                resp = client.get(f"{base}/api/config")
                if resp.status_code != 200:
                    last_err = f"{scheme} GET /api/config HTTP {resp.status_code}"
                    continue
                try:
                    body = resp.json() or {}
                except Exception:
                    last_err = f"{scheme} non-json"
                    continue
                out["reachable"] = True
                out["scheme"] = scheme
                out["version"] = body.get("version")
                features = body.get("features") or {}
                # Various OpenWebUI versions use different keys; try them all.
                signup = (
                    features.get("enable_signup")
                    if isinstance(features, dict)
                    else None
                )
                if signup is None and isinstance(features, dict):
                    signup = features.get("auth") is False
                out["signup_enabled"] = bool(signup) if signup is not None else None
                # Auth required if signup is closed AND there's no anonymous flag.
                if isinstance(features, dict) and "auth" in features:
                    out["auth_required"] = bool(features.get("auth"))
                else:
                    out["auth_required"] = None
                default_models = body.get("default_models") or []
                if isinstance(default_models, str):
                    default_models = [default_models]
                out["default_models"] = [str(m)[:80] for m in default_models[:5]]
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"openwebui": last_err or "unreachable"}}


# ── Langfuse ─────────────────────────────────────────────────────────


def _probe_langfuse(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """GET /api/public/health + /api/public/projects on Langfuse.

    Health endpoint is always anonymous (it's how the load balancer probes).
    Projects is the auth-gated one — if it returns 200 with a project list
    anonymously, the deployment is misconfigured.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"langfuse": "httpx not installed on relay"}}

    port = port or 3000
    out: dict[str, Any] = {"reachable": False}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                health = client.get(f"{base}/api/public/health")
                if health.status_code not in (200, 204):
                    last_err = f"{scheme} health HTTP {health.status_code}"
                    continue
                out["reachable"] = True
                out["scheme"] = scheme
                try:
                    out["version"] = (health.json() or {}).get("version")
                except Exception:
                    pass

                projects = client.get(f"{base}/api/public/projects")
                if projects.status_code == 401:
                    out["auth_required"] = True
                    out["projects_visible"] = False
                    return out
                if projects.status_code == 200:
                    try:
                        body = projects.json() or {}
                    except Exception:
                        body = {}
                    data = body.get("data") if isinstance(body, dict) else None
                    if not isinstance(data, list):
                        data = body if isinstance(body, list) else []
                    out["auth_required"] = False
                    out["projects_visible"] = True
                    out["project_count"] = len(data)
                else:
                    out["auth_required"] = None
                    out["_errors"] = {"projects": f"HTTP {projects.status_code}"}
                return out
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"langfuse": last_err or "unreachable"}}


# ── Ollama canary ────────────────────────────────────────────────────


def _probe_ollama_canary(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send the hardcoded canary prompt to Ollama's /api/generate.

    Ollama has no auth in any released version. We confirm anonymous
    inference by sending the canary and checking the response substring.
    Streaming is disabled so we get a single JSON envelope.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"ollama": "httpx not installed on relay"}}

    port = port or 11434
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"inference_open": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            tags = client.get(f"{base}/api/tags")
            models: list[str] = []
            if tags.status_code == 200:
                try:
                    body = tags.json() or {}
                    for m in (body.get("models") or [])[:10]:
                        if isinstance(m, dict) and m.get("name"):
                            models.append(str(m["name"])[:120])
                except Exception:
                    pass
            out["models_loaded"] = models

            if not models:
                # No models loaded → can't run a canary even though the API
                # is reachable. Still surface that the API is open.
                out["inference_open"] = None
                out["_errors"] = {"canary": "no models loaded; cannot test inference"}
                return out

            req_body = {
                "model": models[0],
                "prompt": _CANARY_PROMPT,
                "stream": False,
            }
            gen = client.post(f"{base}/api/generate", json=req_body)
            if gen.status_code != 200:
                out["_errors"] = {"canary": f"HTTP {gen.status_code}"}
                return out
            try:
                gen_body = gen.json() or {}
            except Exception:
                out["_errors"] = {"canary": "non-json response"}
                return out
            response_text = str(gen_body.get("response") or "")
            out["inference_open"] = True
            out["canary_response_match"] = (
                _CANARY_EXPECTED_SUBSTRING in response_text.lower()
            )
            out["response_truncated"] = response_text[:200]
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"ollama": f"{type(e).__name__}: {e}"}}
    return out


# ── vLLM canary ──────────────────────────────────────────────────────


def _probe_vllm_canary(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Send the hardcoded canary prompt to vLLM's OpenAI-compat /v1/completions.

    Tolerates both /v1/completions (text) and /v1/chat/completions (chat)
    by trying the simpler completions endpoint first.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"vllm": "httpx not installed on relay"}}

    port = port or 8000
    base = f"http://{target}:{port}"
    out: dict[str, Any] = {"inference_open": False}
    try:
        with httpx.Client(timeout=timeout_s) as client:
            mods = client.get(f"{base}/v1/models")
            models: list[str] = []
            if mods.status_code == 200:
                try:
                    body = mods.json() or {}
                    for m in (body.get("data") or [])[:5]:
                        if isinstance(m, dict) and m.get("id"):
                            models.append(str(m["id"])[:120])
                except Exception:
                    pass
            elif mods.status_code in (401, 403):
                out["inference_open"] = False
                out["_errors"] = {"models": f"auth required (HTTP {mods.status_code})"}
                return out
            out["models"] = models

            if not models:
                out["inference_open"] = None
                out["_errors"] = {"canary": "no models advertised; cannot test inference"}
                return out

            req_body = {
                "model": models[0],
                "prompt": _CANARY_PROMPT,
                "max_tokens": 16,
                "temperature": 0,
                "stream": False,
            }
            gen = client.post(f"{base}/v1/completions", json=req_body)
            if gen.status_code in (401, 403):
                out["inference_open"] = False
                return out
            if gen.status_code != 200:
                out["_errors"] = {"canary": f"HTTP {gen.status_code}"}
                return out
            try:
                gen_body = gen.json() or {}
            except Exception:
                out["_errors"] = {"canary": "non-json response"}
                return out
            choices = gen_body.get("choices") or []
            response_text = ""
            if choices and isinstance(choices, list) and isinstance(choices[0], dict):
                response_text = str(choices[0].get("text") or "")
            out["inference_open"] = True
            out["canary_response_match"] = (
                _CANARY_EXPECTED_SUBSTRING in response_text.lower()
            )
            out["response_truncated"] = response_text[:200]
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
        return {"_errors": {"vllm": f"{type(e).__name__}: {e}"}}
    return out


# ── MCP tool enumeration ─────────────────────────────────────────────


def _probe_mcp(target: str, port: int, op_params: dict, timeout_s: int) -> dict:
    """Enumerate the tool palette of an exposed MCP server.

    MCP supports multiple transports. We try, in order:
      1. HTTP+SSE: ``GET /tools`` (some custom servers expose this)
      2. JSON-RPC over HTTP: ``POST /`` with a ``tools/list`` request

    Either way, we never call ``tools/call``. The point is to enumerate the
    palette as evidence that the MCP server is exposed and dangerous.
    """
    try:
        import httpx  # type: ignore
    except ImportError:
        return {"_errors": {"mcp": "httpx not installed on relay"}}

    port = port or 3000
    out: dict[str, Any] = {"reachable": False}
    last_err: str | None = None
    for scheme in ("http", "https"):
        base = f"{scheme}://{target}:{port}"
        try:
            with httpx.Client(timeout=timeout_s, verify=False) as client:
                # 1. Plain /tools (some custom servers + early MCP shims)
                try:
                    r = client.get(f"{base}/tools")
                    if r.status_code == 200:
                        try:
                            body = r.json() or {}
                        except Exception:
                            body = None
                        tools = _extract_mcp_tools(body)
                        if tools is not None:
                            out["reachable"] = True
                            out["scheme"] = scheme
                            out["transport"] = "http_get_tools"
                            out["tools"] = tools[:25]
                            return out
                except httpx.RequestError:
                    pass

                # 2. JSON-RPC tools/list
                req = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
                r = client.post(f"{base}/", json=req)
                if r.status_code == 200:
                    try:
                        body = r.json() or {}
                    except Exception:
                        body = None
                    result = (body or {}).get("result") if isinstance(body, dict) else None
                    tools = _extract_mcp_tools(result)
                    if tools is not None:
                        out["reachable"] = True
                        out["scheme"] = scheme
                        out["transport"] = "jsonrpc_http"
                        out["tools"] = tools[:25]
                        return out
                last_err = f"{scheme} no MCP transport answered (last status {r.status_code})"
        except (httpx.TimeoutException, httpx.ConnectError, OSError) as e:
            last_err = f"{scheme} {type(e).__name__}: {e}"
            continue
    return {"_errors": {"mcp": last_err or "unreachable"}}


def _extract_mcp_tools(body: Any) -> list[dict] | None:
    """Pull a ``[{name, description}]`` list out of the various MCP shapes.

    Returns None if the body isn't recognizable as an MCP tools list — the
    caller falls through to the next transport.
    """
    if body is None:
        return None
    if isinstance(body, list):
        items = body
    elif isinstance(body, dict):
        items = body.get("tools")
        if not isinstance(items, list):
            return None
    else:
        return None
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        out.append({
            "name": str(name)[:120],
            "description": str(item.get("description") or "")[:200],
        })
    return out


# ── Relay-side allowlist ─────────────────────────────────────────────


_OP_HANDLERS: dict[str, Any] = {
    # Triage (gap-fill)
    "jupyter": _probe_jupyter,
    "ray": _probe_ray,
    "mlflow": _probe_mlflow,
    "tensorboard": _probe_tensorboard,
    "tgi": _probe_tgi,
    "lmstudio": _probe_lmstudio,
    "openwebui": _probe_openwebui,
    "langfuse": _probe_langfuse,
    # Prompt-injection-probe (consent-gated at the backend)
    "ollama_canary": _probe_ollama_canary,
    "vllm_canary": _probe_vllm_canary,
    "mcp": _probe_mcp,
}

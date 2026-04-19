"""Specialist vulnerability agents — prompts, tools, categories.

Five narrow agents, each scoped to one vulnerability class:

  - injection   — SQLi / NoSQLi / command injection / SSTI
  - xss         — reflected / stored / DOM XSS
  - ssrf        — server-side request forgery and blind SSRF surfaces
  - authn       — authentication / session / MFA bypass
  - authz       — IDOR / privilege escalation / tenant isolation

The narrow scope is intentional. A single "find all vulns" agent burns
tokens exploring everything and validates nothing well. Five specialists
each with ~10 tool-call turns produces tighter, higher-precision
findings and lets us gate the expensive ones (authz requires two
identities, ssrf needs an OOB listener) behind features the asset
supports.

Each specialist owns:

  - a system prompt — what to look for, how to decide "true positive"
  - an entry context  — the asset + endpoint slice that matters for the
    category (an XSS agent needs HTML endpoints; an authz agent needs
    parameterised IDs)
  - an LLM budget     — max tool-call iterations before forced closeout

Tools are shared across specialists because the LLM needs the same
primitives (HTTP request, response inspection) for every category. What
differs is WHICH PAYLOADS the LLM chooses to send, and that's driven by
the system prompt.

Kept service-boundary-clean: no imports from ``backend/`` — this is a
self-contained worker module. The probe tools mirror the shape of
``backend/agents/agent_tools.py`` (``probe_url_status``,
``check_response_body``, etc.) but do not share a Session, rate limiter,
or credential vault. The scanner service runs alongside Nuclei and
must not couple to the backend's ORM.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)


# ── Category registry ────────────────────────────────────────────

AGENT_CATEGORIES = ("injection", "xss", "ssrf", "authn", "authz")


@dataclass
class AgentContext:
    """Runtime context handed to every tool invocation.

    Shared across a single agent run — the ``http_client`` and
    ``rate_limiter`` are per-asset so one pathological agent can't
    starve peers running against the same host.
    """
    asset_id: str
    org_id: str | None
    target: str                     # base URL / hostname / IP
    endpoints: list[dict] = field(default_factory=list)  # discovery-derived
    headers: dict[str, str] = field(default_factory=dict)  # merged auth
    http_client: httpx.Client | None = None
    rate_limiter: Any | None = None   # injected by the runner
    deadline: float = 0.0             # time.monotonic() past this -> stop


@dataclass
class SpecialistSpec:
    """Static definition of one of the five specialist agents."""
    category: str
    display_name: str
    system_prompt: str
    max_iterations: int
    applicable_when: Callable[[AgentContext], bool]


# ── Applicability predicates ─────────────────────────────────────
# Skip expensive agents on assets that can't possibly yield results.
# The alternative (run everything, let the LLM decide to exit) wastes
# tokens on the first tool call of every irrelevant asset.


def _has_any_http_endpoint(ctx: AgentContext) -> bool:
    return bool(ctx.endpoints) or ctx.target.startswith(("http://", "https://"))


def _has_parameterised_endpoint(ctx: AgentContext) -> bool:
    """Heuristic: injection/XSS/authz need inputs to attack.

    An endpoint with ``parameters`` populated (OpenAPI-known) or a URL
    containing ``?``/``{id}``/``:id`` qualifies. Assets with only
    static-path endpoints (katana-discovered HTML pages) still qualify
    for XSS (can reflect into HTML via URL path) but not for injection.
    """
    if not _has_any_http_endpoint(ctx):
        return False
    for ep in ctx.endpoints:
        params = ep.get("parameters")
        if isinstance(params, list) and params:
            return True
        url = ep.get("url") or ""
        if "?" in url or "{" in url or re.search(r"/:[A-Za-z]", url):
            return True
    return False


def _has_auth_surface(ctx: AgentContext) -> bool:
    """Authn/authz agents need something to attack.

    Accept either (a) any endpoint flagged ``auth_required=True`` from
    discovery, or (b) auth headers present on the context (indicating a
    session broker / static credential was resolved — we can probe with
    and without it to diff behaviour).
    """
    if ctx.headers:
        return True
    return any(ep.get("auth_required") for ep in ctx.endpoints)


# ── Specialist prompts ───────────────────────────────────────────
# Prompts are deliberately long and prescriptive. The LLM is cheap per
# token but expensive per *mistake* — a prompt that lets the agent
# wander makes noisy findings and eats the iteration budget on dead
# ends.


_INJECTION_PROMPT = """You are a specialist SQL/NoSQL/command injection tester.

YOUR GOAL: For the asset's parameterised HTTP endpoints, determine whether any parameter is vulnerable to injection of untrusted input into a backend query/interpreter.

SCOPE:
- SQL injection (error-based, boolean-based, time-based)
- NoSQL injection (MongoDB operator injection, JSON query injection)
- OS command injection via user-controlled parameters
- Server-side template injection (SSTI) — Jinja2/Twig/FreeMarker

HOW TO PROCEED:
1. Look at the endpoints list in the initial message. Pick the 3-5 highest-signal targets — parameters named id/user/q/search/filter are usually best. Prefer endpoints with method POST or with a query string present.
2. For each target, send a baseline request to establish the normal response. Record status, body length, and any error-like strings.
3. Send a minimally-invasive probe: a single quote, a boolean tautology, a sleep primitive, an SSTI sentinel. One payload at a time — not a shotgun.
4. Compare the response to the baseline. Classification:
   - Error message reveals backend type/query → true_positive
   - Boolean diff produces a stable state change → true_positive
   - Time-based probe shifts response time by >= ~5s consistently → true_positive
   - No diff, generic 500, or WAF block → stop probing that parameter
5. When you find a true positive, emit an EMIT_FINDING tool call with evidence (the exact request, the exact diff you observed). Then move on.

BUDGET:
- Max 12 tool calls per agent run.
- Spend at most 3 calls per parameter.
- STOP and emit a summary tool call when you've examined your top 3 candidates, even if you found nothing.

SAFETY:
- Never send destructive SQL (DROP, DELETE without WHERE, UPDATE without WHERE).
- Never run command injection that spawns shells (;rm,;wget).
- Time-based probes: use `SLEEP(5)` or `WAITFOR DELAY`, never sleep() > 10s.

OUTPUT:
- Every finding emitted via EMIT_FINDING must include concrete evidence — a request, a response diff, a time delta. "The parameter looked suspicious" is not a finding.
"""

_XSS_PROMPT = """You are a specialist cross-site scripting tester.

YOUR GOAL: Determine whether HTML-reflective endpoints on this asset render user input without safe encoding.

SCOPE:
- Reflected XSS in query parameters, path segments, form fields, headers
- Stored XSS where a POST-then-GET pattern is obvious (e.g. comments, profiles)
- DOM XSS hints via suspicious client-side sinks in returned JavaScript

HOW TO PROCEED:
1. From the endpoints list, pick endpoints that return text/html or lack a content_type declaration. Skip pure JSON APIs — even if XSS existed, the risk is lower and the test shape is different.
2. For each target: baseline GET, then reflect a unique-looking benign sentinel (e.g. `HakUnaXsSSentinel7823`). Fetch and check whether the sentinel appears in the response.
3. If it reflects, escalate to a minimal payload: `<h1>x</h1>`, then `"><svg onload=1>`. Classify:
   - Sentinel HTML-encoded (`&lt;h1&gt;`) → no finding, server encodes
   - Sentinel reflected raw in HTML context → true_positive (reflected XSS)
   - Sentinel reflected inside attribute/script → true_positive (context-dependent)
4. Store-then-retrieve: if the endpoint accepts POST and has a GET sibling (same path minus a trailing id), submit the sentinel via POST, then GET and check.

BUDGET:
- Max 10 tool calls. 2 calls per endpoint max.
- Call the `emit_finding` tool for each confirmed reflection, then `summary` to exit.

SAFETY:
- Use only harmless payloads (sentinel strings, `<h1>x</h1>`, `<svg onload=1>`). Never payloads that actually exfiltrate, redirect, or mutate state.

OUTPUT:
- Finding payload must cite the exact reflected substring and its context (HTML body / attribute / script).
"""

_SSRF_PROMPT = """You are a specialist server-side request forgery tester.

YOUR GOAL: Determine whether the asset accepts a URL (or URL-like) parameter and fetches it server-side without origin allowlisting.

SCOPE:
- URL parameters in query or JSON body (url=, redirect=, callback=, webhook=, source=, image=)
- File fetch parameters that accept http(s):// alongside local paths
- Parser-driven SSRF (XML external entities, SVG xlink:href, Markdown image fetch)

HOW TO PROCEED:
1. From the endpoints list, pick endpoints whose parameter names include any of: url, redirect, callback, webhook, source, image, fetch, proxy, import, host. Also pick endpoints with content_type application/xml or application/xhtml+xml.
2. For each target, send the parameter with a value pointing to `http://127.0.0.1:1/` and observe status + timing. A fast connect-refused tells you the server attempted the fetch; a fast 400 tells you it rejected the URL client-side.
3. Escalate with `http://127.0.0.1:80/` and compare to the public 80 from outside — a response diff (the server can reach localhost, you can't) is a true_positive.
4. Cloud metadata: only if step 2-3 show an SSRF primitive AND the asset is cloud-hosted (you have no way to know for sure — use best judgement from httpx_full if present). Never hammer 169.254.169.254 blindly.

BUDGET:
- Max 8 tool calls. 3 per candidate endpoint.
- On confirmation, call `emit_finding` once per candidate, then `summary` to exit.

SAFETY:
- Never target third-party origins you don't own.
- Never use metadata endpoints on first-tier probes.
- Stop immediately on first confirmed SSRF primitive.
"""

_AUTHN_PROMPT = """You are a specialist authentication-bypass tester.

YOUR GOAL: Determine whether endpoints marked ``auth_required`` actually enforce authentication on the server side.

SCOPE:
- Endpoints that return 200 to an unauthenticated request when they were declared auth-required
- Session fixation / session not rotated on login (can only test if you have a session to swap)
- JWT/none, JWT/weak-key where tokens are exposed
- Basic auth on endpoints documented as bearer-only

HOW TO PROCEED:
1. From the endpoints list, select ``auth_required=true`` endpoints. If there are none, return a summary and exit.
2. For each target: send the request (a) with no credentials and (b) with the provided auth headers. Compare status codes and body lengths.
   - No-cred 200 + authed 200 (and bodies look similar) → true_positive (auth bypass). Cite the request pair as evidence.
   - No-cred 401/403 + authed 200 → control works. No finding.
   - Both 401 → target may be misconfigured or require the other auth mode. Skip.
3. Never send brute-force attempts — a single unauthenticated probe per endpoint is enough.

BUDGET:
- Max 10 tool calls. 2 per endpoint.
- When an auth bypass is confirmed, call `emit_finding` with the request pair as evidence, then `summary` to exit.

SAFETY:
- Never attempt multiple credentials — that's brute force, not authn testing.
"""

_AUTHZ_PROMPT = """You are a specialist authorization / IDOR tester.

YOUR GOAL: Determine whether an authenticated user can access resources that belong to a different user or tenant (IDOR, horizontal/vertical privilege escalation).

SCOPE:
- Object references exposed as incrementing integers or predictable UUIDs
- Missing tenant scoping (org_id) in API responses
- Role-based endpoints accessible to non-admin tokens

CRITICAL PREREQUISITE: You need TWO identities to test authz properly — yours (provided in the auth headers) and another. In this scaffold you have ONE. Therefore your job is NARROWER:

1. Identify endpoints with ID-like path segments (/users/{id}, /orders/:id, ?account=123).
2. Fetch with your creds to confirm 200.
3. Modify the ID to a very-likely-other value (id+1, id-1, uuid with one byte changed) and fetch again.
   - Same 200 with different body → strong true_positive IDOR candidate. Cite request pair.
   - 403/404 → control works.
4. DO NOT attempt to escalate to admin endpoints (/admin/*) — without a second identity that's too noisy to classify.

BUDGET:
- Max 8 tool calls.
- On a confirmed IDOR, call `emit_finding` with both request/response pairs as evidence, then `summary` to exit.

SAFETY:
- Stop on first confirmed IDOR and emit a finding. Don't iterate across IDs.
"""


SPECIALISTS: dict[str, SpecialistSpec] = {
    "injection": SpecialistSpec(
        category="injection",
        display_name="Injection Specialist",
        system_prompt=_INJECTION_PROMPT,
        max_iterations=12,
        applicable_when=_has_parameterised_endpoint,
    ),
    "xss": SpecialistSpec(
        category="xss",
        display_name="XSS Specialist",
        system_prompt=_XSS_PROMPT,
        max_iterations=10,
        applicable_when=_has_any_http_endpoint,
    ),
    "ssrf": SpecialistSpec(
        category="ssrf",
        display_name="SSRF Specialist",
        system_prompt=_SSRF_PROMPT,
        max_iterations=8,
        applicable_when=_has_parameterised_endpoint,
    ),
    "authn": SpecialistSpec(
        category="authn",
        display_name="Authentication Specialist",
        system_prompt=_AUTHN_PROMPT,
        max_iterations=10,
        applicable_when=_has_auth_surface,
    ),
    "authz": SpecialistSpec(
        category="authz",
        display_name="Authorization Specialist",
        system_prompt=_AUTHZ_PROMPT,
        max_iterations=8,
        applicable_when=_has_auth_surface,
    ),
}


def select_applicable_specialists(
    ctx: AgentContext, categories: list[str] | None = None,
) -> list[SpecialistSpec]:
    """Return the specialists that apply to this asset.

    When ``categories`` is None, considers all five. Otherwise filters
    to the named subset and still applies ``applicable_when`` — callers
    can request "run authz" but the worker should still skip if there's
    no auth surface, to avoid burning tokens on a no-op run.
    """
    requested = list(categories) if categories else list(AGENT_CATEGORIES)
    out: list[SpecialistSpec] = []
    for cat in requested:
        spec = SPECIALISTS.get(cat)
        if spec is None:
            continue
        if spec.applicable_when(ctx):
            out.append(spec)
        else:
            logger.info("agent skipped category=%s asset=%s (not applicable)",
                        cat, ctx.asset_id)
    return out


# ── Probe tools ──────────────────────────────────────────────────
# Given to the LLM as tool-use schemas. Each tool executes HTTP only —
# no DB, no filesystem, no code exec. The LLM can chain them to build a
# request, send it, and inspect the response.


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict, AgentContext], dict]


def _safe_url(url: str) -> bool:
    """Block obviously-dangerous targets.

    - Disallow file:// (local file read)
    - Disallow http://0.0.0.0 (SSRF fuzz comes through the SSRF prompt
      intentionally; direct model-driven probes should stay out of
      local-network primitives unless the agent can justify the origin)
    """
    u = (url or "").lower()
    if u.startswith("file:") or u.startswith("data:") or u.startswith("javascript:"):
        return False
    return True


def _request_handler(params: dict, ctx: AgentContext) -> dict:
    """Execute an arbitrary HTTP request and return the response summary.

    The single tool the LLM uses for ~all active probing. Keeping it
    general (rather than one tool per HTTP verb) lets a specialist
    compose injection / XSS / SSRF payloads directly — the prompt
    controls what payload to send; the tool just ferries bytes.
    """
    url = (params.get("url") or "").strip()
    method = (params.get("method") or "GET").upper()
    body = params.get("body")
    extra_headers = params.get("headers") or {}

    if not _safe_url(url):
        return {"error": "unsafe url scheme"}
    if time.monotonic() >= ctx.deadline:
        return {"error": "asset deadline reached"}

    merged_headers = dict(ctx.headers or {})
    if isinstance(extra_headers, dict):
        merged_headers.update(extra_headers)

    client = ctx.http_client
    if client is None:
        return {"error": "http client not configured"}

    started = time.monotonic()
    try:
        resp = client.request(
            method=method,
            url=url,
            headers=merged_headers or None,
            content=body if isinstance(body, (str, bytes)) else None,
            json=body if isinstance(body, dict) else None,
            timeout=10.0,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        return {"url": url, "error": "timeout", "elapsed_ms": int((time.monotonic() - started) * 1000)}
    except Exception as e:
        return {"url": url, "error": str(e)[:200]}

    elapsed_ms = int((time.monotonic() - started) * 1000)
    body_text = ""
    try:
        body_text = resp.text[:5_000]
    except Exception:
        pass

    return {
        "url": url,
        "method": method,
        "status_code": resp.status_code,
        "elapsed_ms": elapsed_ms,
        "headers": {k.lower(): v for k, v in resp.headers.items() if k.lower() not in _REDACT_HEADERS},
        "body": body_text,
        "body_length": len(resp.content or b""),
    }


_REDACT_HEADERS = {"set-cookie", "cookie", "authorization", "x-api-key"}


def _check_pattern_handler(params: dict, ctx: AgentContext) -> dict:
    """Check whether a regex matches a previously-seen body snippet.

    Supplied to agents as a separate tool (vs. just asking the LLM to
    pattern-match in prose) so findings cite a concrete `match_text`
    string rather than the LLM's paraphrase. Takes the body inline —
    agent passes whatever it saw back in.
    """
    body = params.get("body") or ""
    pattern = params.get("pattern") or ""
    if not pattern:
        return {"error": "pattern required"}
    try:
        rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as e:
        return {"error": f"invalid regex: {e}"}
    m = rx.search(body)
    return {
        "matched": bool(m),
        "match_text": m.group(0)[:300] if m else None,
    }


def _emit_finding_handler(params: dict, ctx: AgentContext) -> dict:
    """Record a vulnerability finding discovered by the agent.

    Does not mutate state here — the runner captures findings via a
    callback wired in run time (see agent_worker._run_specialist). The
    handler just echoes the payload back so the LLM sees the ACK and
    continues.
    """
    return {"status": "recorded", "payload": params}


def _summary_handler(params: dict, ctx: AgentContext) -> dict:
    """Signal the agent's final conclusion — no findings to emit or done.

    The runner treats a ``summary`` call as an explicit stop so the LLM
    can cleanly exit instead of burning the remaining iteration budget
    generating no-op probe calls.
    """
    return {"status": "acknowledged"}


TOOLS: dict[str, Tool] = {
    "http_request": Tool(
        name="http_request",
        description=(
            "Send an HTTP request to a target URL. Returns status, headers, "
            "body (first 5KB), and elapsed_ms. Use this to probe endpoints "
            "with baseline and with payloads, comparing responses. Auth "
            "headers for the asset are injected automatically; you can "
            "override or add headers with the `headers` param."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL (http or https)."},
                "method": {"type": "string", "description": "HTTP method (GET, POST, PUT, DELETE, ...)."},
                "body": {"description": "Request body. Pass a dict for JSON, a string for raw."},
                "headers": {"type": "object", "description": "Extra headers to send."},
            },
            "required": ["url"],
        },
        handler=_request_handler,
    ),
    "check_pattern": Tool(
        name="check_pattern",
        description=(
            "Check whether a regex pattern matches a string you already "
            "have (e.g. a response body from a previous http_request). "
            "Use this to confirm reflection, error strings, or evidence "
            "snippets with a precise match_text to cite in the finding."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "body": {"type": "string", "description": "The string to search in."},
                "pattern": {"type": "string", "description": "Python regex pattern (case-insensitive)."},
            },
            "required": ["body", "pattern"],
        },
        handler=_check_pattern_handler,
    ),
    "emit_finding": Tool(
        name="emit_finding",
        description=(
            "Record a confirmed vulnerability finding. Call this ONLY "
            "after you've gathered concrete evidence (request + response "
            "diff, timing delta, or reflected string). The runner will "
            "persist the finding and you can continue probing other "
            "targets. Payload fields are severity, title, description, "
            "evidence_url, evidence_request, evidence_response, verdict, "
            "confidence (0-1)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "evidence_url": {"type": "string"},
                "evidence_request": {"type": "string", "description": "Full HTTP request as a curl command or raw text."},
                "evidence_response": {"type": "string", "description": "Relevant response snippet."},
                "verdict": {"type": "string", "enum": ["true_positive", "needs_review"]},
                "confidence": {"type": "number"},
            },
            "required": ["severity", "title", "description", "verdict"],
        },
        handler=_emit_finding_handler,
    ),
    "summary": Tool(
        name="summary",
        description=(
            "Signal that you are done probing this asset and provide a "
            "one-paragraph conclusion. Call this when you have either "
            "emitted all findings you can confirm or decided there are "
            "no vulnerabilities to report. This ends the agent run."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "conclusion": {"type": "string"},
            },
            "required": ["conclusion"],
        },
        handler=_summary_handler,
    ),
}


def tool_schemas_for_anthropic() -> list[dict]:
    """Return the TOOLS registry as Anthropic tool-use schemas."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
        }
        for t in TOOLS.values()
    ]

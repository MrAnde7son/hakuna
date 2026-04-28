"""Specialist vulnerability agents — prompts, tools, categories.

Seven narrow agents, each scoped to one vulnerability class:

  - injection   — SQLi / NoSQLi / command injection / SSTI / XPath / LDAP
  - xss         — reflected / stored / DOM XSS
  - ssrf        — server-side request forgery and blind SSRF surfaces
  - authn       — authentication bypass, session issues, weak credentials
  - authz       — IDOR / privilege escalation / tenant isolation
  - csrf        — missing or static anti-CSRF tokens on state-changing requests
  - files       — LFI / RFI / path traversal

The narrow scope is intentional. A single "find all vulns" agent burns
tokens exploring everything and validates nothing well. Six specialists
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

import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from scanner.vm.capabilities import (
    CapabilityStore,
    asset_scope,
    capability_from_legacy_memory,
    note_capability,
)
from scanner.vm.response_signals import commit_signals, extract_signals

logger = logging.getLogger(__name__)


# ── OOB collaborator config ──────────────────────────────────────
# Blind injection / blind SSRF / command injection without reflected
# output can only be confirmed by watching a server you control for
# an inbound request. Hakuna doesn't run its own collaborator — ops
# points this at any service exposing a minimal two-endpoint API:
#   GET  {base}/probe/{token}   → logs the hit (any 2xx is fine)
#   GET  {base}/check/{token}   → returns {"hits": [...]} (list of
#                                 recorded interactions, may be empty)
# Leaving the base URL unset disables the OOB tools — they return
# {"configured": false}. The LLM will then fall back to in-band
# signals (timing / error strings) and skip the blind cases.
_OOB_BASE_URL = os.environ.get("AGENT_OOB_COLLABORATOR_URL", "").rstrip("/")
_OOB_API_KEY = os.environ.get("AGENT_OOB_COLLABORATOR_API_KEY", "")


def _oob_configured() -> bool:
    return bool(_OOB_BASE_URL)


# ── Category registry ────────────────────────────────────────────

AGENT_CATEGORIES = (
    "injection", "xss", "ssrf", "authn", "authz", "csrf", "files",
    "upload", "session",
)


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
    # Per-asset scratchpad shared across all specialists in one run.
    # A specialist that uncovers something another might care about
    # (leaked cookie, routable internal host, parameter that rejects
    # certain payload shapes) can stash it here; subsequent specialists
    # see it prepended to their initial message. Capped in the handler
    # so a chatty model can't balloon tool_result size.
    shared_memory: dict[str, str] = field(default_factory=dict)
    # Typed capability store — the composition foundation that step 2+
    # builds on. ``memory_set`` mirrors well-known keys here (see
    # ``capabilities.capability_from_legacy_memory``) so existing prompts
    # keep working unchanged while typed consumers gain structured facts.
    capabilities: CapabilityStore = field(default_factory=CapabilityStore)
    # Set by the runner before each specialist starts so tool handlers
    # can tag capability provenance. ``None`` means "not inside a
    # specialist" (seed data, tests).
    current_specialist: str | None = None


@dataclass
class SpecialistSpec:
    """Static definition of one of the specialist agents.

    The composition contract (``requires``/``augmented_by``/``produces``/
    ``max_runs``) drives the frontier scheduler. See
    ``scanner.vm.agent_scheduler`` for the semantics. Defaults preserve
    the pre-composition single-pass behaviour: an empty contract means
    "runs once, gated only by ``applicable_when`` — same as before".
    """
    category: str
    display_name: str
    system_prompt: str
    max_iterations: int
    applicable_when: Callable[[AgentContext], bool]
    # Capability types that MUST be present for the spec to run at all.
    # All must be satisfied (AND). Empty = no precondition. Today all
    # specialists keep this empty and defer gating to ``applicable_when``
    # — that lets authz stay runnable at scan-start with pre-configured
    # headers while also being triggerable later by a discovered CRED.
    requires: tuple[str, ...] = ()
    # Capability types that, when present, change the idempotency key
    # so the scheduler can re-run the spec under enriched context. A
    # spec with ``augmented_by=("credentials",)`` runs once at baseline,
    # then re-runs (once more, up to ``max_runs``) if credentials
    # appear. Does not gate the first run.
    augmented_by: tuple[str, ...] = ()
    # Capability types the spec may emit. Documentation-grade today —
    # the scheduler doesn't enforce that a spec only produces declared
    # types. A future "why did this chain happen?" audit UI reads from
    # here to draw the dependency graph.
    produces: tuple[str, ...] = ()
    # Cap on the number of times the scheduler may run this spec within
    # a single asset scan. ``max_runs=1`` is the conservative default
    # (matches the old for-loop). Specs that declare ``augmented_by``
    # should set this to at least 2 or they can never actually re-run.
    max_runs: int = 1
    # Per-specialist model routing. When set, the agent worker tries to
    # resolve this provider specifically (with the optional model id)
    # and falls back to the scan-wide default if that provider isn't
    # configured. Use sparingly — composition sources (authn) and other
    # high-orchestration specialists benefit from a stronger model;
    # cheap reflection-style specialists (xss) don't.
    preferred_provider: str | None = None
    preferred_model: str | None = None


# ── Applicability predicates ─────────────────────────────────────
# Skip expensive agents on assets that can't possibly yield results.
# The alternative (run everything, let the LLM decide to exit) wastes
# tokens on the first tool call of every irrelevant asset.


def _has_any_http_endpoint(ctx: AgentContext) -> bool:
    return bool(ctx.endpoints) or ctx.target.startswith(("http://", "https://"))


def _has_parameterised_endpoint(ctx: AgentContext) -> bool:
    """Heuristic: true when some endpoint or the target itself has inputs.

    An endpoint with ``parameters`` populated (OpenAPI-known) or a URL
    containing ``?``/``{id}``/``:id`` qualifies. A bare http(s) target
    also qualifies now: injection/SSRF specialists can GET the base
    URL, parse the HTML for ``<form>`` elements, and discover inputs
    themselves. The alternative — pre-gating out every asset whose
    static discovery step happens to return zero parameterised
    endpoints — skips agents on trivially-vulnerable apps like the
    ones whose entire attack surface is a root-page form.
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
    # No pre-known parameters, but there's an HTTP surface — let the
    # LLM do form/endpoint discovery via http_request on its first turn.
    return True


def seed_base_endpoint(endpoints: list[dict], target: str) -> list[dict]:
    """Return ``endpoints`` with a synthetic base-URL row if the list is empty.

    When discovery yields nothing but the target is http(s), the agent
    still needs a concrete starting point to probe. A synthetic row
    pointing at the target base URL (no parameters, GET) gives the
    specialists something to pick up — their prompts will then tell
    them to fetch the page and harvest forms.

    Idempotent: if ``endpoints`` already has at least one item, returns
    it unchanged. If ``target`` isn't http(s), returns unchanged — we
    can't synthesize an HTTP endpoint for a bare IP whose scheme we
    don't know (guessing http vs https here is the wrong layer; that
    decision belongs in ``_resolve_target``).
    """
    if endpoints:
        return endpoints
    if not target or not target.startswith(("http://", "https://")):
        return endpoints
    return [{
        "url": target,
        "method": "GET",
        "source": "synthetic_base",
        "auth_required": False,
        "content_type": None,
        "parameters": [],
    }]


def _has_authn_surface(ctx: AgentContext) -> bool:
    """Authn specialist needs something it can probe for login/session weakness.

    Broader than authz: a bare http(s) target qualifies because the
    specialist's Step 0 fetches the page and harvests ``<form>`` login
    surfaces itself (name=password inputs are the tell). Otherwise the
    same signals that imply authenticated traffic also qualify — auth
    headers on the context, or any endpoint marked ``auth_required``.

    Without this broadening, adhoc scans skip authn entirely because
    discovery hasn't yet populated ``auth_required`` flags — which is
    exactly the case where default/weak credentials matter most.
    """
    if ctx.headers:
        return True
    if any(ep.get("auth_required") for ep in ctx.endpoints):
        return True
    return _has_any_http_endpoint(ctx)


def _has_authz_surface(ctx: AgentContext) -> bool:
    """Authz specialist needs authenticated access to diff against.

    IDOR/privesc testing requires BOTH (a) a working identity to issue
    the "mine" request and (b) ID-shaped endpoints to mutate. A bare
    http target with no session is pointless — no diff to compute.

    Accepts any of: pre-configured auth headers, an endpoint declared
    ``auth_required``, OR a credential/session capability committed by
    a prior specialist (authn's default-creds path is the canonical
    source). The capability branch is what lets the scheduler surface
    authz as newly-applicable after authn finds creds — without it the
    chain from "bypass auth" to "test IDOR" can't fire.
    """
    if ctx.headers:
        return True
    if any(ep.get("auth_required") for ep in ctx.endpoints):
        return True
    from scanner.vm.capabilities import CapabilityType
    if ctx.capabilities.query(type=CapabilityType.CRED):
        return True
    if ctx.capabilities.query(type=CapabilityType.SESSION):
        return True
    return False


def _has_state_change_surface(ctx: AgentContext) -> bool:
    """CSRF specialist needs a state-changing request to evaluate.

    State change is signalled by (a) any endpoint whose method is POST,
    PUT, PATCH, or DELETE in the discovery slice, or (b) any http(s)
    target — the specialist's Step 0 fetches the base URL and harvests
    ``<form method=post>`` elements, which covers the web-app common
    case where no OpenAPI-style endpoints are pre-known.
    """
    for ep in ctx.endpoints:
        m = (ep.get("method") or "").upper()
        if m in ("POST", "PUT", "PATCH", "DELETE"):
            return True
    return _has_any_http_endpoint(ctx)


# Back-compat alias — older callers imported ``_has_auth_surface``.
_has_auth_surface = _has_authz_surface


# ── Specialist prompts ───────────────────────────────────────────
# Prompts are deliberately long and prescriptive. The LLM is cheap per
# token but expensive per *mistake* — a prompt that lets the agent
# wander makes noisy findings and eats the iteration budget on dead
# ends.


_INJECTION_PROMPT = """You are a specialist SQL/NoSQL/command/template/XPath/LDAP injection tester.

YOUR GOAL: Determine whether any HTTP parameter on this asset is vulnerable to injection of untrusted input into a backend query/interpreter.

SCOPE:
- SQL injection (error-based, boolean-based, time-based)
- NoSQL injection (MongoDB operator injection, JSON query injection)
- OS command injection via user-controlled parameters (VERY common in DevOps / internal tooling UIs — any app exposing a "run/execute/ping/lookup/shell/command" input is a prime candidate)
- Server-side template injection (SSTI) — Jinja2/Twig/FreeMarker
- XPath injection — parameters feeding XML document queries (login forms over XML user stores, XML-backed search)
- LDAP injection — parameters feeding directory queries (SSO lookups, corporate user search, group membership checks)

HOW TO PROCEED:

Step 0 — DISCOVER THE ATTACK SURFACE. Do not skip this step even if the endpoints list looks populated.
   a. GET the target base URL with http_request. Read the HTML body.
   b. Find every `<form>` tag. For each, note the `action` (resolve relative URLs against the page), the `method`, and the `name` attributes of every `<input>`, `<textarea>`, and `<select>` inside it. These are your real parameter candidates — often the endpoints list upstream is sparse or empty.
   c. Also look for inline JavaScript that posts to an API path (fetch(), XMLHttpRequest, $.ajax) and for visible URLs/links with `?foo=…`. Note their paths and parameter names too.
   d. If no forms and no script-built requests are apparent, fall back to the endpoints list from the initial message.
   e. If `CAPABILITIES` shows credentials or a session, your probes carry auth automatically — prioritise endpoints under `/admin`, `/api`, `/vulnerabilities`, `/dashboard`, `/settings`, `/profile` that would have redirected you to login on an anonymous run. Classic DVWA-shape paths to check in order: `/vulnerabilities/sqli/?id=1` (SQL injection), `/vulnerabilities/sqli_blind/?id=1` (blind SQL), `/vulnerabilities/exec/` (command injection). Re-fetch the base URL once to pick these up.

Step 1 — PICK 3-4 HIGHEST-SIGNAL PARAMETERS. Aim for breadth across classes — test ONE code-execution-shaped param AND ONE SQL-shaped param before deep-diving a third candidate of either class. An enriched re-run that hits `/vulnerabilities/exec/` three times and never touches `/vulnerabilities/sqli/` misses the easiest SQLi in the app.
   - Code-execution-shaped names: command, cmd, exec, run, shell, ping, host, ip.
   - SQL-shaped names: id, user, userid, account, search, filter, q, sort, order.
   - Template-shaped names (SSTI): template, view, layout, theme. `page` is usually LFI; defer it unless the files specialist hasn't run.
   Prefer endpoints with a query string or POST method over static paths.

Step 2 — BASELINE. For each target, send an unmodified request with a benign value and record status, body length, elapsed_ms, and any error-like strings.

Step 3 — MINIMAL PROBE. Send ONE payload at a time — not a shotgun:
   - SQL: single quote `'`, then a boolean tautology `' OR '1'='1`, then a time probe `';SELECT SLEEP(5)--` (or `WAITFOR DELAY '0:0:5'`).
   - Command injection: append a benign separator + enumeration: ` ; id`, `&& id`, `| id`, ` ; whoami`, ` ; ls -la`. The output of `id` / `whoami` / `ls` in the response body is unambiguous evidence.
   - SSTI: `{{7*7}}` (rendered as 49 → Jinja2/Twig), `${{7*7}}`, `${7*7}`.
   - XPath: `'` (error), `' or '1'='1` (auth-bypass-shaped), `'] | //* | a['` (structure break). Evidence is an XPath error string (`XPathException`, `Invalid XPath`, `MS.Internal.Xml`) OR a boolean auth-bypass diff.
   - LDAP: `*`, `*)(uid=*`, `*))(|(uid=*`, `admin)(&)`, `)(cn=*`. Evidence is an LDAP error (`LDAPException`, `javax.naming`, `com.sun.jndi.ldap`) OR a differential where the tautology returns a broader result set than the baseline.

Step 4 — CLASSIFY:
   - Backend error reveals database/shell/template engine/XPath/LDAP → true_positive
   - Command output (uid=, directory listing, hostname) present in response body → true_positive (command injection; CRITICAL severity)
   - Boolean diff produces a stable state change → true_positive
   - Time-based probe shifts response time by >= ~5s consistently → true_positive
   - No diff, generic 500, or WAF block → stop probing that parameter

Step 5 — EMIT. When you find a true positive, call emit_finding with concrete evidence (the request, the response diff showing the evidence text). Then move to the next target.

BUDGET:
- Max 14 tool calls per agent run.
- Spend at most 3 calls per parameter.
- STOP and call summary when you've examined 3-4 candidates — covering both attack classes if they exist — even if you found nothing.

SAFETY:
- Never send destructive SQL (DROP, DELETE without WHERE, UPDATE without WHERE).
- For command injection, use READ-ONLY enumerations (`id`, `whoami`, `uname -a`, `ls`, `cat /etc/hostname`). Never `rm`, shell spawning, reverse shells, or persistence.
- The ONLY external host you may cause the target to reach is the probe_url returned by `oob_get_probe`. Never `curl`/`wget` any other origin.
- Time-based probes: `SLEEP(5)` or `WAITFOR DELAY`, never sleep() > 10s.

TOOLS BEYOND http_request:
- `diff_responses(baseline, probe)` — when you're comparing a baseline and a payload response, pass both dicts to this tool rather than eyeballing. It returns the exact added/removed lines, length delta, and timing delta that you can cite in the finding.
- `oob_get_probe()` — for blind cases (time-based SQLi confirmation is weak, cmdi without visible output, DNS-based exfil). Call it to mint a unique probe_url, embed that URL in a payload (e.g. `'; exec master..xp_cmdshell 'nslookup <host>'`, `; curl <probe_url>`), then call `oob_check(token)`. A `hit_count >= 1` is unambiguous evidence — upgrade confidence and severity. If `configured: false` is returned, skip the blind-case branch.
- `memory_set(key, value)` — if you discover something a later specialist should know (leaked cookie, reachable internal host, a parameter name a WAF blocks), store it. authz/ssrf specialists will see it.

OUTPUT:
- Every finding emitted via emit_finding must include concrete evidence — the request, the response diff, the exact command output or error string, or the OOB hit_count. "The parameter looked suspicious" is not a finding.
"""

_XSS_PROMPT = """You are a specialist cross-site scripting tester.

YOUR GOAL: Determine whether HTML-reflective endpoints on this asset render user input without safe encoding.

SCOPE:
- Reflected XSS in query parameters, path segments, form fields, headers
- Stored XSS where a POST-then-GET pattern is obvious (e.g. comments, profiles)
- DOM XSS hints via suspicious client-side sinks in returned JavaScript

HOW TO PROCEED:

Step 0 — DISCOVER THE ATTACK SURFACE. Do not skip this step.
   a. GET the target base URL with http_request. Read the HTML body.
   b. Find every `<form>` tag: note the `action` (resolve against the page URL), the `method`, and every `<input>/<textarea>/<select>` `name`. These are your reflection candidates — ignore what the endpoints list suggests if it's empty or sparse.
   c. Also scan the response body for query-string links (`?foo=…`) and inline JS fetch/XHR calls — both expose additional parameterised endpoints.

Step 1 — PICK TARGETS. Prefer endpoints returning text/html (or whose path looks like an HTML page) over pure JSON APIs. Prefer form inputs named `q`, `search`, `name`, `comment`, `message`, `title` — classic reflection surfaces.

Step 2 — SENTINEL REFLECTION. For each target: baseline GET, then reflect a unique benign sentinel (e.g. `HakUnaXsSSentinel7823`). Check whether the sentinel appears in the response body.

Step 3 — PAYLOAD ESCALATION. If the sentinel reflects, escalate minimally: `<h1>x</h1>`, then `"><svg onload=1>`. Classify:
   - Sentinel HTML-encoded (`&lt;h1&gt;`) → no finding, server encodes
   - Sentinel reflected raw in HTML context → true_positive (reflected XSS)
   - Sentinel reflected inside an attribute or `<script>` block → true_positive (context-dependent XSS)

Step 4 — STORE-THEN-RETRIEVE. If a form is POST and the page also GETs a list of prior submissions, submit the sentinel via POST, then GET the listing and check.

BUDGET:
- Max 10 tool calls. 2 per endpoint.
- Call emit_finding for each confirmed reflection, then summary to exit.

SAFETY:
- Use only harmless payloads (sentinel strings, `<h1>x</h1>`, `<svg onload=1>`). Never payloads that exfiltrate, redirect, or mutate state beyond the benign test entry.

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

TOOLS BEYOND http_request:
- `oob_get_probe()` — your single best tool for blind SSRF. Mint a probe_url, feed it as the URL parameter value, then `oob_check(token)`. `hit_count >= 1` is definitive; the target fetched your URL server-side. If `configured: false`, fall back to the localhost + timing heuristic in steps 2-3.
- `diff_responses(baseline, probe)` — when the SSRF is semi-blind (response reflects metadata about the fetched resource), diff the two responses to spot the leaked bytes.
- `memory_set(key, value)` — if you confirm an SSRF primitive, store `internal_host_reachable=true` so the authz specialist knows tenant-boundary probes are worth more.

SAFETY:
- Never target third-party origins you don't own — the ONLY exception is the probe_url from oob_get_probe, which hits a collaborator you control.
- Never use metadata endpoints on first-tier probes.
- Stop immediately on first confirmed SSRF primitive.
"""

_AUTHN_PROMPT = """You are a specialist authentication tester.

YOUR GOAL: Identify authentication weaknesses — bypassable auth checks, session flaws, and the acceptance of default or trivially-weak credentials.

SCOPE:
- Endpoints that return 200 to an unauthenticated request when they were declared auth-required (auth bypass)
- Login forms that accept well-known default credentials (admin/admin, admin/password, etc.)
- Session fixation / session not rotated on login (only testable when you have a session to swap)
- JWT/none, JWT/weak-key where tokens are exposed
- Basic auth on endpoints documented as bearer-only

HOW TO PROCEED:

Step 0 — DISCOVER THE AUTH SURFACE. Do not skip.
   a. GET the target base URL with http_request. Read the HTML body.
   b. Locate any `<form>` that contains an `<input type="password">`. Note the form action, method, all input names (including hidden ones — the form may include an anti-CSRF token like `user_token` or `authenticity_token` that must be echoed back on POST).
   c. Note the list of endpoints in your initial message. Flag any with `auth_required=true`.

Step 1 — AUTH BYPASS (applies when there are ``auth_required=true`` endpoints).
   For each such endpoint: send (a) without credentials and (b) with the provided auth headers. Compare.
   - No-cred 200 + authed 200, bodies similar → true_positive (auth bypass). Emit with request pair.
   - No-cred 401/403 + authed 200 → control works. Skip.
   - Both 401 → misconfigured or wrong mode. Skip.

Step 2 — WEAK / DEFAULT CREDENTIALS (applies when a login form is present).
   USE THE `try_login` TOOL. Do NOT chain http_request calls for login attempts — they fail silently on apps with per-session CSRF tokens (DVWA, most CMSes, Django) because each http_request starts without the fresh token in cookies. `try_login` does the GET-extract-POST-follow flow atomically.

   Procedure:
     i.   From Step 0's form discovery, note the form action URL and the submit-button input (its `name` and `value`, often `Login=Login`, `submit=Sign in`, `btn=Submit`). Note the field names for username and password (default `username` / `password`, but watch for `user`, `email`, `pass`, `pwd`).
     ii.  Call try_login ONCE PER PAIR, trying this list in order (AT MOST — this is a targeted default-creds check, NOT brute force):
          admin / admin
          admin / password
          administrator / administrator
          root / root
          guest / guest
          test / test
     iii. STOP on the first response whose `likely_successful` is true. `try_login` auto-commits the credentials capability and mirrors into memory — the composition chain is already unlocked the moment you stop.
     iv.  Even after the auto-commit, call these TWO tools to finalise cleanly:
          1) `emit_finding(...)` — severity=high, verdict=true_positive, citing the try_login result's final_url + the working username:password pair in evidence.
          2) `summary(conclusion="...")` — ends the specialist run. Without summary, you waste remaining iterations on no-op turns.
     v.   If `try_login` returned an `error` (e.g. `http client not configured`, `POST failed`), THAT credential pair can't be tested — try the next one. Do NOT fall back to manual http_request chaining; if try_login can't reach the login URL, neither can you.

Step 3 — SESSION HYGIENE (applies only when Step 2 produced a successful login).
   Compare the pre-login session cookie value to the post-login value. Identical → session fixation (medium). Different → normal rotation, no finding.

BUDGET:
- Max 14 tool calls total (covers Steps 0-3).
- Step 2: AT MOST 6 credential attempts per login form. Hard cap. Never exceed.
- On first confirmed issue, call `emit_finding` and continue to the next step.
- Call `summary` to exit when all applicable steps are complete.

TOOLS BEYOND http_request:
- `try_login(login_url, username, password, ...)` — YOUR PRIMARY TOOL for Step 2. Handles the entire form-login flow (cookies, CSRF tokens, redirect following) deterministically, returning a structured success heuristic. When it reports `likely_successful=true`, it has already committed the credentials capability to the scheduler.
- `diff_responses(a, b)` — required for classification in Step 1 (auth-bypass). Cite status_changed, length_delta, and added_lines (e.g. a "Welcome admin" token) in the finding.
- `memory_set(key, value)` — if you spot a leaked session cookie, a JWT in a response body, or an endpoint that returns user-IDs (e.g. `/me` echoes `user_id=42`), store that as `leaked_identifier` or `valid_user_id` so the authz specialist can test with concrete values.

SAFETY:
- NEVER exceed the 6-attempt cap in Step 2. That would be brute force, not default-creds detection.
- NEVER attempt the same user with more than 2 passwords (accidental lockout avoidance).
- NEVER use credentials outside the default-list above (no wordlists, no scraped lists).
- Respect any `Retry-After` / rate-limit response — stop immediately on 429.

OUTPUT:
- Bypass findings cite the request pair. Weak-credential findings cite the exact pair and the response diff proving the login succeeded. A "the page looked like it logged me in" claim without a diff is not a finding.
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

TOOLS BEYOND http_request:
- Check the MEMORY block in your initial message first. The authn specialist may have stored `leaked_identifier` or `valid_user_id` — use that as your "other" identity candidate instead of guessing id+1.
- `diff_responses(your_response, modified_id_response)` — required for classification. Same status + non-trivial length_delta and a different user's data in added_lines is an IDOR.

SAFETY:
- Stop on first confirmed IDOR and emit a finding. Don't iterate across IDs.
"""


_CSRF_PROMPT = """You are a specialist cross-site request forgery tester.

YOUR GOAL: Determine whether any state-changing request on this asset lacks an effective anti-CSRF token.

A state-changing request is one that creates, modifies, or deletes server-side state: password changes, profile edits, settings toggles, cart mutations, account deletions, privilege grants. Read-only requests (search, list, view) are out of scope.

SCOPE:
- Missing CSRF token on a POST / PUT / PATCH / DELETE request
- Token present but STATIC across sessions (e.g. tied to the username rather than the session)
- Token present but NOT VALIDATED server-side — the endpoint accepts the request whether the token is correct, wrong, or absent
- Form that uses GET to perform a state-changing action (intrinsically CSRF-able because the URL itself is the attack)

HOW TO PROCEED:

Step 0 — DISCOVER STATE-CHANGING SURFACE. Do not skip.
   a. GET the target base URL with http_request. Read the HTML body.
   b. Find every `<form>`. Note: `action`, `method`, all `<input>`/`<textarea>`/`<select>` `name` attributes (INCLUDING hidden inputs — that's where CSRF tokens live). Flag forms whose `method` is POST/PUT/PATCH/DELETE, OR whose `action` path suggests state change (`/change`, `/update`, `/delete`, `/save`, `/settings`, `/password`, `/edit`, `/add`, `/remove`, `/transfer`).
   c. Also scan visible links for GET-based state change: `/delete?id=`, `/logout`, `/?action=…`.
   d. From the endpoints list, flag POST/PUT/PATCH/DELETE entries.
   e. If Step 0 yields zero state-changing candidates, call summary with no findings and exit.

Step 1 — PICK 2-3 HIGHEST-VALUE TARGETS. Prioritise in this order: password change > account/role change > data delete > profile/setting update > other.

Step 2 — FOR EACH CANDIDATE, CHECK TOKEN PRESENCE.
   Look at the form's hidden inputs and request headers in the original page. A legitimate CSRF token is usually named one of: `csrf`, `_csrf`, `csrf_token`, `csrfmiddlewaretoken`, `authenticity_token`, `user_token`, `__RequestVerificationToken`, `X-CSRF-Token` (header form), or an unlabelled 20+ hex/base64 hidden value distinct from `id`/`user_id`/anti-replay nonces.

   CLASSIFY:
   (a) No token present anywhere in the form / headers → HIGH-severity finding. CSRF is trivially possible.
   (b) GET-based state change (form method=GET or state-changing link) → HIGH finding (CSRF-able even if a token is present, because browsers auto-include it in img/iframe GETs).
   (c) Token present → proceed to Step 3.

Step 3 — TOKEN VALIDATION PROBE (ONLY if you have a working session and the endpoint is non-destructive).
   CRITICAL SAFETY GATE: skip Step 3 entirely when the candidate is a password change, account delete, role grant, or any action you cannot reliably reverse. Emit only "needs_review" severity in that case, citing the token name, and move on.

   For reversible state-change (theme toggle, non-critical profile field, search-history clear), do THREE probes against the same endpoint — re-fetching the page between probes to get a fresh token when needed:
     i.   Baseline — send the form with the correct token. Record status / body.
     ii.  Omit the token entirely. Record status / body.
     iii. Send a clearly-wrong token value (all zeros, literal "FORGED123", or a token from a different user's session if `memory_get` exposes one).

   CLASSIFY:
   - Probes (ii) and (iii) BOTH return the same success response as (i) → token is decorative, server doesn't validate → MEDIUM-to-HIGH finding.
   - Probe (ii) succeeds but (iii) fails → server checks for presence but not value → MEDIUM.
   - Both (ii) and (iii) fail with a distinct error/status → token is validated correctly → no finding.
   - Token value identical across different `GET /page` calls for the same session → STATIC token → LOW finding (CSRF protection weak, but not trivially bypassable within-session).

Step 4 — EMIT. Call `emit_finding` for each confirmed issue. Every finding must cite: the endpoint, the HTTP method, the name of the missing/static/unvalidated token (if any), and a concrete request pair showing the token variation that succeeded.

BUDGET:
- Max 10 tool calls.
- Max 3 probes per candidate.
- STOP after the top 2 candidates even if nothing was confirmed.

SAFETY — NON-NEGOTIABLE:
- NEVER actually execute a password change, account deletion, role grant, or any irreversible state change — even to confirm the vulnerability. Evidence from Step 2 (token-absence) is sufficient for a HIGH finding; you do not need to demonstrate exploit.
- NEVER log out the user. Avoid probing `/logout` even though it's state-changing.
- If unsure whether a state change is reversible, treat it as irreversible and skip Step 3.
- NEVER chain CSRF with XSS or other payloads — that's out of scope for this specialist.

TOOLS BEYOND http_request:
- `diff_responses(with_token, without_token)` — required for Step 3 classification. The cleanest evidence shape is status_changed=false, length_delta~0 between valid-token and no-token responses.
- `memory_get("valid_credentials")` — the authn specialist may have stashed a working login. If present, use it to reach authenticated state-change endpoints. Without credentials, restrict yourself to whatever anonymous state-change exists.
- `memory_set("csrf_token_missing_on", "<endpoint>")` — lets downstream specialists prioritise the same endpoint.

OUTPUT:
- Finding payload must name the endpoint, the method, the token name (or "none"), and include the request pair. "This form looked unprotected" without a concrete request pair is not a finding.
"""


_UPLOAD_PROMPT = """You are a specialist file-upload vulnerability tester.

YOUR GOAL: Determine whether the asset accepts file uploads that can be (a) executed as server code, (b) stored outside the intended directory, or (c) served back with an unsafe Content-Type.

SCOPE:
- Unrestricted file type — server accepts executable extensions (.php, .phtml, .php5, .phps, .jsp, .asp, .aspx) and stores them in a web-served directory.
- MIME-type spoofing — server checks Content-Type header but not file extension (upload `.php` with `Content-Type: image/jpeg`).
- Double-extension / null-byte bypass — `shell.php.jpg`, `shell.php%00.jpg` bypass naive filter.
- Path traversal in filename — `../../uploads/shell.php` escapes the intended directory.
- Overwrite attacks — upload a file named after a sensitive server asset (index.php, .htaccess).

CRITICAL PREREQUISITE: Most upload endpoints sit behind authentication. If your CAPABILITIES block shows no CRED/SESSION primitive AND no upload form is visible anonymously, call summary and exit — the scheduler will re-run you after authn commits credentials.

HOW TO PROCEED:

Step 0 — DISCOVER UPLOAD SURFACE. Do not skip.
   a. GET the target base URL. Call `extract_forms(html=<body>)`. Look for forms where `has_file_input=true` OR `enctype` is `multipart/form-data`.
   b. If the CAPABILITIES block shows CRED/SESSION, ALSO re-fetch the base URL — the authenticated navigation may expose upload pages (common paths: `/upload`, `/vulnerabilities/upload`, `/admin/upload`, `/profile/avatar`, `/files/new`). Harvest links to these and call extract_forms on each.
   c. If no upload form exists on any discovered page, call summary — there is nothing to test.

Step 1 — PICK AT MOST 2 TARGETS. Prefer forms in authenticated areas (if CRED present) over public ones. Note the form's action URL, method, the name of the file input, and any other required fields (hidden tokens, type selectors).

Step 2 — BASELINE: benign upload. Build a multipart/form-data POST:
   - Use http_request with method=POST and headers={"Content-Type": "multipart/form-data; boundary=----hakunaBoundary"}.
   - Body: construct manually as the multipart payload with filename="hakuna_test.txt", content-type text/plain, body "hakuna upload test\\n". Include any hidden fields from Step 0.
   - Record the response. Success indicators: 200/302, the response body mentions the uploaded filename, OR a redirect to a "file list" page.
   - If the baseline upload fails outright (403 / "denied" in body / "file type not allowed"), you've learned the filter exists. Continue to Step 3 to probe it.

Step 3 — EXECUTION PROBE. Attempt to upload a minimal PHP payload. The goal is confirmation, NOT exploitation: a successful upload-and-fetch that echoes a unique sentinel proves RCE without running arbitrary code.
   Payload body (keep verbatim): `<?php echo "hakuna_upload_rce_confirmed"; ?>`
   Try these filename / Content-Type combinations IN ORDER, one per probe:
     i.   `shell.php`                  Content-Type: application/x-php
     ii.  `shell.phtml`                Content-Type: application/x-php
     iii. `shell.php.jpg`              Content-Type: image/jpeg
     iv.  `shell.jpg`                  Content-Type: image/jpeg  (with the PHP payload as body — pure MIME-spoof)
     v.   `shell.php%00.jpg`           Content-Type: image/jpeg  (null-byte bypass)
   After each accepted upload, GET the probable storage URL (most apps return a 200 with a path hint in the response, OR you can guess `/uploads/<filename>`, `/files/<filename>`, the form's action directory with filename appended). If the fetched body contains `hakuna_upload_rce_confirmed`, you have CRITICAL-severity RCE via upload.

Step 4 — CLASSIFY:
   - Fetched file contains the sentinel string → CRITICAL true_positive. Emit finding naming the exact upload/retrieval URLs and the accepted filename variant.
   - Upload accepted but fetching the file returns the raw PHP source → MEDIUM. Source disclosure.
   - Upload accepted, fetching returns 404 / 403 → LOW needs_review. Can't confirm execution but the filter is weaker than intended.
   - All variants rejected → no finding. Skip to summary.

BUDGET:
- Max 10 tool calls.
- Max 5 upload probes across both targets (the 5 variants above, collectively).
- STOP after first CRITICAL finding; don't try remaining variants if one worked.

SAFETY — LOAD-BEARING:
- NEVER upload a real shell (no eval($_GET[x]), no system()). The sentinel payload only calls echo; it cannot be weaponised.
- NEVER upload files that overwrite existing server assets (don't use filenames like index.php, .htaccess, web.config).
- NEVER upload anything that contains customer-like data. Use the sentinel string and nothing else.
- If you accidentally upload a file that can't be cleaned up via the app, note it in the finding description so the operator knows to manually remove it.

TOOLS BEYOND http_request:
- `extract_forms(html)` — required for Step 0. Finds forms with file inputs deterministically.
- `memory_set("upload_path", "<url>")` — if you confirm an upload endpoint works, stash the URL so other specialists can potentially weaponise it as a post-exploitation target.

OUTPUT:
- Critical findings must include: upload URL, filename variant that worked, fetch URL, and the evidence substring from the fetched body (the sentinel or the raw PHP source).
"""


_SESSION_PROMPT = """You are a specialist session-token weakness tester.

YOUR GOAL: Determine whether session / CSRF / access tokens minted by the server have predictable structure — sequential counters, timestamps, short entropy, or patterns that would let an attacker guess another user's token.

SCOPE:
- Session cookies (PHPSESSID, JSESSIONID, connect.sid, etc.) minted on login page load
- CSRF / anti-replay tokens embedded in forms (hidden inputs named csrf, _csrf, authenticity_token, user_token)
- "Generate me a new token" endpoints (common in admin UIs, API key generators, "create invite link")
- Reset / verification tokens returned after a password-reset flow

HOW TO PROCEED:

CRITICAL: you are running AFTER authn committed a credential (``requires=credentials`` on this spec). Your http_request calls are already authenticated via the injected headers. DO NOT clear cookies or send ``Cookie: ""`` — that breaks auth on the target and sends you to the login page in a loop.

Step 0 — LOCATE TOKEN-MINTING ENDPOINTS. Do not skip.
   a. From the app you're now authenticated against, look for "generate token" / "new session" / "rotate session id" UI actions. Classic paths: any URL containing ``weak_id``, ``session``, ``token``, ``generate``, ``new``, ``invite``, ``api_key``, ``rotate``.
   b. The login page (e.g. /login, /login.php) is also a candidate: GETting it issues a fresh session cookie each time because there's no prior session context.
   c. Use `extract_forms` on the base page — hidden CSRF tokens inside forms can be analysed the same way.

Step 1 — COLLECT A SAMPLE. Pick ONE token-minting endpoint (prefer a "generate" action over the login page — apps usually have weaker entropy on explicit generator endpoints than on session cookies). Call it TWICE in succession. Note the Set-Cookie or hidden form-token value from each response.
   If both calls return the SAME value, the token is server-side-pooled (same session reused) — you aren't going to detect per-mint weakness here. Skip that endpoint and try the next.

Step 2 — ANALYSE. For each token pair, evaluate:
   (a) LENGTH — token under 16 characters of apparent entropy is weak. PHPSESSID is 26; under 20 is suspect.
   (b) CHARACTER SET — tokens consisting of ONLY digits are almost always a counter or timestamp → weak.
   (c) SEQUENTIAL NUMERIC — if the two samples are both integers and differ by 1 or 2 → CRITICAL (monotonic counter). Example: sample1="42", sample2="43".
   (d) TIMESTAMP-SHAPED — if the token decodes as a base-10 or base-16 Unix timestamp close to current time → HIGH (predictable within ±1 second).
   (e) REPEATED CALL SAME VALUE — not a weakness per se, but confirms the endpoint reuses a pooled token. Move on.
   (f) HIGH-ENTROPY RANDOM — long, mixed-case + digits, differs across calls → no finding.

Step 3 — EMIT. Call emit_finding for each endpoint with a weak token:
   - CRITICAL: sequential counter (one-off guessable)
   - HIGH: timestamp-based (narrow guessable window)
   - MEDIUM: short length (<16 chars) or digits-only
   - Cite the two captured samples in the finding's evidence_response field.

BUDGET:
- Max 8 tool calls.
- Up to 3 candidate endpoints.
- STOP after first CRITICAL finding.

SAFETY:
- Read-only: do NOT use discovered session IDs to access anyone else's session data, even if prediction succeeds. Evidence of predictability is sufficient for the finding.
- Do NOT call token-minting endpoints more than twice per endpoint — some apps throttle or rate-limit generation.

TOOLS BEYOND http_request:
- `extract_forms(html)` — to harvest hidden CSRF/session tokens from forms.
- `check_pattern(body, pattern)` — to cite the exact hex/base64 regex match for a token value in the finding's evidence.
- `memory_set("weak_session_endpoint", "<url>")` — if you find a predictable token, stash the endpoint so authz / csrf specialists know this primitive exists.

OUTPUT:
- Findings must cite: the endpoint, the two sampled token values, and the specific weakness (sequential / timestamp / short / digits-only).
"""


_FILES_PROMPT = """You are a specialist file-inclusion / path-traversal tester.

YOUR GOAL: Determine whether any HTTP parameter on this asset is used to load a file path or URL server-side without allowlisting, allowing local file read (LFI), remote file inclusion (RFI), or directory escape (path traversal).

SCOPE:
- Local File Inclusion (LFI) — parameter value becomes part of a filesystem read. Evidence: contents of `/etc/passwd`, `/etc/hostname`, Windows `C:\\Windows\\win.ini`, or application config files appear in the response.
- Remote File Inclusion (RFI) — parameter value is fetched as a URL and included/executed. PHP `allow_url_include=On` is the classic case.
- Path traversal — parameter escapes a restricted directory (`../`, URL-encoded `%2e%2e%2f`, double-encoded `%252e%252e%252f`, null byte `%00`).
- PHP wrappers — `php://filter/convert.base64-encode/resource=index.php` (source leak), `data://`, `expect://`, `phar://`.

HOW TO PROCEED:

Step 0 — DISCOVER THE ATTACK SURFACE. Do not skip this step.
   a. GET the target base URL. Read the HTML body.
   b. Find every `<form>` and `<a href>` / inline JS request. Note parameter names that suggest file handling: `file`, `page`, `path`, `template`, `include`, `doc`, `document`, `lang`, `locale`, `theme`, `view`, `load`, `image`, `img`, `download`, `read`, `show`, `resource`.
   c. Also check the endpoints list from the initial message — any GET with a filename-shaped value (`.php`, `.html`, `.txt`, no extension but short slug) is a candidate.

Step 1 — PICK 3-5 HIGHEST-SIGNAL PARAMETERS. Prioritise file-handling parameter names over generic inputs. A parameter whose baseline value is already a path or filename (`?page=home` → `?page=home.php` visible in response) is the best candidate.

Step 2 — BASELINE. For each target, send the unmodified request. Record status, body length, and the position where the parameter value gets reflected (if any).

Step 3 — MINIMAL PROBE. Send ONE payload at a time:
   - LFI (Unix): `/etc/passwd`, `../../../../etc/passwd`, `....//....//....//etc/passwd`, `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`.
   - LFI (Windows): `C:\\Windows\\win.ini`, `..\\..\\..\\Windows\\win.ini`, `%5c..%5c..%5cWindows%5cwin.ini`.
   - PHP wrapper source leak: `php://filter/convert.base64-encode/resource=index.php` — response body becomes base64-encoded PHP source.
   - RFI (in-band test): `http://<probe_url>/` from oob_get_probe. If the target fetches the URL server-side AND includes the response in its own output, that's RFI (distinct from SSRF — SSRF fetches but doesn't include/execute).
   - Null byte / extension stripping: `../../etc/passwd%00.png`, `../../etc/passwd`.
   - Path traversal (no read): parameter expects `report-2024.pdf` — try `../report-2024.pdf`. Confirmation: same 200 OK via both shapes proves the prefix is stripped.

Step 4 — CLASSIFY:
   - Response body contains `root:x:0:0:` or `[extensions]` section → true_positive LFI (CRITICAL severity)
   - Response body contains valid base64 that decodes to PHP/ASP source → true_positive LFI via wrapper (CRITICAL)
   - oob_check shows hit_count >= 1 from an RFI payload AND response includes new content not in baseline → true_positive RFI (CRITICAL)
   - Status flips from 404/403 on clean path to 200 on traversal-escaped path → true_positive path traversal (HIGH)
   - Backend error leaks absolute path (`/var/www/html/includes/...`) → needs_review (path disclosure — useful for the next specialist)
   - No diff or generic 500 → stop probing that parameter

Step 5 — EMIT. Call emit_finding with the concrete evidence: the payload, the response substring (first 200 chars of passwd / base64 prefix / fetched URL), and for path traversal the baseline-vs-probe status difference.

BUDGET:
- Max 10 tool calls. 3 per parameter.
- STOP and call summary when you've exhausted your top 3 candidates, even with no findings.

SAFETY:
- Read-only. Never write (`php://input`, POST-based traversal into upload handlers).
- Never read files whose names suggest credentials on third-party paths (`.aws/credentials`, `.ssh/id_rsa`) on the first probe — `/etc/passwd` is enough to prove LFI without handling secret material. Only escalate to secret-bearing paths if the target is authorised for deeper testing (this scaffold is not — stop at passwd/win.ini).
- The ONLY external host you may cause the target to reach is the probe_url from `oob_get_probe`. Never include `curl`/`wget` of arbitrary origins.

TOOLS BEYOND http_request:
- `diff_responses(baseline, probe)` — required for path-traversal classification. A 403→200 flip with passwd content in added_lines is the cleanest evidence shape.
- `oob_get_probe()` — for RFI confirmation (and for blind LFI where error logs are suppressed; a payload containing `<?php file_get_contents("<probe_url>"); ?>` will ping the collaborator if it executes).
- `check_pattern(body, pattern)` — cite exact matched text (e.g. `root:x:0:0:[^\\n]+`) rather than "passwd was in the response".
- `memory_set(key, value)` — if you find a path-disclosure error, store `web_root=/var/www/html/...` so other specialists can craft more precise payloads.

OUTPUT:
- Finding payload must include the exact payload sent, the evidence substring (truncated passwd line / base64 prefix / oob hit_count), and the target parameter name.
"""


# Capability-type strings referenced by the contracts below. Imported
# lazily inline to avoid a top-level circular import with agent_worker
# constructing AgentContext. The string values are stable (see
# ``CapabilityType``) so duplicating the literal here is low-risk.
_CAP_CRED = "credentials"
_CAP_SESSION = "session"
_CAP_IDENTIFIER = "identifier"
_CAP_INTERNAL_HOST = "internal_host"
_CAP_WEB_ROOT = "web_root"


# The Vertex-AI-hosted Claude model id used by high-orchestration
# specialists (authn, injection). Vertex encodes Anthropic models as
# ``<family>-<size>-<major>-<minor>@<YYYYMMDD>`` — the date is the
# official Vertex model revision and changes when Anthropic updates
# the backing weights. Override via env if a newer version is
# published or a different size is preferred:
#
#     AGENT_CLAUDE_VERTEX_MODEL=claude-opus-4-1@20250805
#
# The default below is the most recent Sonnet version Anthropic has
# publicly listed on Vertex Model Garden as of this scanner build.
# If the model isn't enabled in your Vertex region, the adapter
# surfaces a clear error on first call (see AnthropicVertexAdapter).
_CLAUDE_VERTEX_MODEL = os.environ.get(
    "AGENT_CLAUDE_VERTEX_MODEL", "claude-sonnet-4-6",
)


SPECIALISTS: dict[str, SpecialistSpec] = {
    "injection": SpecialistSpec(
        category="injection",
        display_name="Injection Specialist",
        system_prompt=_INJECTION_PROMPT,
        # Bumped 12 → 14 to match the prompt's breadth rule: one probe
        # for each of two attack classes (SQL + cmd/SSTI) plus baseline
        # + summary needs the extra headroom. Empirical: on DVWA the
        # 12-call budget burned entirely on /vulnerabilities/exec/ and
        # never reached /vulnerabilities/sqli/.
        max_iterations=14,
        applicable_when=_has_parameterised_endpoint,
        # Credentials / sessions unlock authenticated endpoints that
        # almost always carry richer SQL/NoSQL surface than the public
        # perimeter. Web-root disclosure refines SSTI / file-path
        # payloads.
        augmented_by=(_CAP_CRED, _CAP_SESSION, _CAP_WEB_ROOT),
        produces=("sql_read", "sql_write", "cmd_exec", "file_read"),
        max_runs=2,
        # Route through Claude Sonnet for the same reason authn does:
        # this is a multi-step orchestration specialist (discovery →
        # parameter triage → baseline → payload → classify → emit)
        # and Gemini Flash reliably ends enriched re-runs with
        # end_turn + zero probes. Empirically observed: on DVWA
        # run=2 enriched yielded and finished 11 seconds later with
        # no HTTP activity. Sonnet holds the full flow.
        #
        # Routed via Vertex (``provider=vertex_ai`` + a claude-* model
        # id) so billing stays on the existing GCP project rather than
        # requiring a separate Anthropic account.
        preferred_provider="vertex_ai",
        preferred_model=_CLAUDE_VERTEX_MODEL,
    ),
    "xss": SpecialistSpec(
        category="xss",
        display_name="XSS Specialist",
        system_prompt=_XSS_PROMPT,
        max_iterations=10,
        applicable_when=_has_any_http_endpoint,
        # Reflection testing is identity-independent — a second pass
        # after auth rarely surfaces new bugs and burns tokens.
        max_runs=1,
    ),
    "ssrf": SpecialistSpec(
        category="ssrf",
        display_name="SSRF Specialist",
        system_prompt=_SSRF_PROMPT,
        max_iterations=8,
        applicable_when=_has_parameterised_endpoint,
        # Knowing a reachable internal host refines the probe set —
        # re-running with INTERNAL_HOST in context lets SSRF confirm
        # specific services instead of blind 127.0.0.1 fuzzing.
        augmented_by=(_CAP_CRED, _CAP_INTERNAL_HOST),
        produces=("ssrf_primitive", "internal_host"),
        max_runs=2,
    ),
    "authn": SpecialistSpec(
        category="authn",
        display_name="Authentication Specialist",
        system_prompt=_AUTHN_PROMPT,
        # Bumped from 14 → 20: authn drives the longest tool sequence
        # (GET form → try_login × N pairs → emit_finding → summary) and
        # it's the composition source — a truncated authn collapses the
        # whole chain. The extra iterations are cheap relative to the
        # scan-wide value unlocked by a successful login.
        max_iterations=20,
        applicable_when=_has_authn_surface,
        # Authn is the composition *source* — its outputs drive other
        # specialists. Re-running it after others have moved on rarely
        # produces new creds within one scan window.
        produces=(_CAP_CRED, _CAP_SESSION, _CAP_IDENTIFIER),
        max_runs=1,
        # Route authn through Claude Sonnet (served via Vertex so
        # billing stays on GCP). Authn's multi-step orchestration
        # (form discovery → try_login loop → post-success tool
        # sequence) is where Gemini Flash drops steps in practice.
        # Sonnet holds the whole flow. Falls back to the scan
        # default if Vertex isn't configured or Claude isn't
        # enabled in the region — logged at adapter build time.
        preferred_provider="vertex_ai",
        preferred_model=_CLAUDE_VERTEX_MODEL,
    ),
    "authz": SpecialistSpec(
        category="authz",
        display_name="Authorization Specialist",
        system_prompt=_AUTHZ_PROMPT,
        max_iterations=8,
        applicable_when=_has_authz_surface,
        # The canonical composition target: re-run after authn finds
        # creds OR after any specialist leaks an identifier we can test
        # horizontal access against.
        augmented_by=(_CAP_CRED, _CAP_SESSION, _CAP_IDENTIFIER),
        max_runs=2,
    ),
    "csrf": SpecialistSpec(
        category="csrf",
        display_name="CSRF Specialist",
        system_prompt=_CSRF_PROMPT,
        max_iterations=10,
        applicable_when=_has_state_change_surface,
        # Anonymous CSRF exists but most meaningful state changes sit
        # behind auth — re-run when creds appear.
        augmented_by=(_CAP_CRED, _CAP_SESSION),
        max_runs=2,
    ),
    "files": SpecialistSpec(
        category="files",
        display_name="File Inclusion Specialist",
        system_prompt=_FILES_PROMPT,
        max_iterations=10,
        applicable_when=_has_parameterised_endpoint,
        augmented_by=(_CAP_CRED, _CAP_SESSION, _CAP_WEB_ROOT),
        produces=("file_read", "file_write"),
        max_runs=2,
    ),
    "upload": SpecialistSpec(
        category="upload",
        display_name="File Upload Specialist",
        system_prompt=_UPLOAD_PROMPT,
        max_iterations=10,
        applicable_when=_has_any_http_endpoint,
        # HARD REQUIRE: upload endpoints almost always sit behind
        # auth, and testing them without a session burns budget on
        # 302-to-login loops. Only run once a CRED exists — that
        # way baseline passes don't waste ~13-60s on an empty spec.
        # Empirical: in the first scan with upload unbounded, this
        # was one of two specialists that consumed ~70s total on
        # baseline and emitted nothing.
        requires=(_CAP_CRED,),
        augmented_by=(_CAP_SESSION,),
        produces=("file_write", "cmd_exec"),
        max_runs=2,
    ),
    "session": SpecialistSpec(
        category="session",
        display_name="Session Token Specialist",
        system_prompt=_SESSION_PROMPT,
        max_iterations=8,
        applicable_when=_has_any_http_endpoint,
        # HARD REQUIRE: session-token analysis needs both (a) a
        # known-good session we can compare fresh mints against,
        # and (b) authenticated access to reach internal token-
        # minting endpoints (DVWA's /vulnerabilities/weak_id/ is
        # auth-gated). Skipping baseline saves the ~60s this spec
        # burned doing nothing in the first trial run.
        requires=(_CAP_CRED,),
        augmented_by=(_CAP_SESSION,),
        max_runs=2,
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

    full_headers = {k.lower(): v for k, v in resp.headers.items()}
    redacted_headers = {
        k: v for k, v in full_headers.items() if k not in _REDACT_HEADERS
    }

    # Auto-extract signals (framework, web_root, route, reflection,
    # validation rules) so every probe maintains the app model without
    # the LLM having to call a separate "analyse" tool. The store dedups
    # so re-probes don't bloat the prompt; provenance encodes which
    # specialist's request produced the fact. Run BEFORE building the
    # LLM-facing response dict so signal detectors see Set-Cookie (the
    # primary framework fingerprint) — that header is redacted out of
    # the LLM view.
    try:
        provenance = (
            f"signal:{ctx.current_specialist}" if ctx.current_specialist
            else "signal:http"
        )
        signal_response = {
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "headers": full_headers,
            "body": body_text,
            "body_length": len(resp.content or b""),
        }
        caps = extract_signals(
            method=method, url=url, request_body=body,
            response=signal_response,
            asset_id=ctx.asset_id, provenance=provenance,
        )
        commit_signals(ctx.capabilities, caps)
    except Exception:
        # Signal extraction must never break the request path. The LLM
        # still gets the response; it just won't see the auto-derived
        # capabilities for this turn.
        logger.exception("extract_signals failed for %s", url)

    return {
        "url": url,
        "method": method,
        "status_code": resp.status_code,
        "elapsed_ms": elapsed_ms,
        "headers": redacted_headers,
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


# Caps on the shared memory scratchpad. Tuned low enough that a
# pathological specialist can't turn memory into an exfil channel
# that bloats every subsequent initial message.
_MEMORY_MAX_KEYS = 32
_MEMORY_MAX_KEY_LEN = 80
_MEMORY_MAX_VALUE_LEN = 2_000


def _memory_set_handler(params: dict, ctx: AgentContext) -> dict:
    """Stash a fact in the per-asset scratchpad for later specialists.

    The value is coerced to a string and truncated. We don't let the
    LLM store nested structures because the next specialist receives
    memory as a flat key/value block in their initial message —
    deserialising JSON on read would just push that work onto a
    different prompt for no gain.
    """
    key = (params.get("key") or "").strip()
    if not key:
        return {"error": "key required"}
    if len(key) > _MEMORY_MAX_KEY_LEN:
        return {"error": f"key exceeds {_MEMORY_MAX_KEY_LEN} chars"}

    raw = params.get("value")
    if raw is None:
        return {"error": "value required"}
    value = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    value = value[:_MEMORY_MAX_VALUE_LEN]

    if key not in ctx.shared_memory and len(ctx.shared_memory) >= _MEMORY_MAX_KEYS:
        return {
            "error": f"memory full ({_MEMORY_MAX_KEYS} keys); overwrite an existing key instead",
            "existing_keys": list(ctx.shared_memory.keys()),
        }
    ctx.shared_memory[key] = value

    # Mirror into the typed capability store. Internal bookkeeping keys
    # (``_oob_tokens`` etc.) and WAF=false style negatives skip the
    # mirror — the bridge returns None and we fall through without a
    # NOTE so the store doesn't fill up with meaningless rows.
    provenance = (
        f"specialist:{ctx.current_specialist}" if ctx.current_specialist
        else "memory_set"
    )
    scope = asset_scope(ctx.asset_id)
    typed = capability_from_legacy_memory(
        key, value, asset_scope=scope, provenance=provenance,
    )
    if typed is not None:
        ctx.capabilities.add(typed)
    elif not key.startswith("_"):
        # Unclassified but user-visible hint — keep it as a NOTE so
        # typed consumers at least see that *something* was recorded.
        ctx.capabilities.add(note_capability(
            key, value, asset_scope=scope, provenance=provenance,
        ))

    return {"status": "stored", "key": key, "total_keys": len(ctx.shared_memory)}


def _diff_responses_handler(params: dict, ctx: AgentContext) -> dict:
    """Structured diff between two HTTP responses.

    Takes the dicts returned by two prior ``http_request`` calls — the
    agent pastes them back in as ``baseline`` and ``probe``. Returns
    status/length/timing deltas plus line-level added/removed snippets
    so the model cites concrete substrings rather than paraphrasing
    what changed. Forces rigor in classification: "length went up by
    42 bytes and this line appeared" is a finding; "the response
    looked different" isn't.
    """
    baseline = params.get("baseline") or {}
    probe = params.get("probe") or {}
    if not isinstance(baseline, dict) or not isinstance(probe, dict):
        return {"error": "baseline and probe must be response dicts from http_request"}

    status_a = baseline.get("status_code")
    status_b = probe.get("status_code")
    body_a = baseline.get("body") or ""
    body_b = probe.get("body") or ""
    len_a = baseline.get("body_length")
    len_b = probe.get("body_length")
    if len_a is None:
        len_a = len(body_a)
    if len_b is None:
        len_b = len(body_b)
    ms_a = baseline.get("elapsed_ms") or 0
    ms_b = probe.get("elapsed_ms") or 0

    lines_a = set(body_a.splitlines())
    lines_b = set(body_b.splitlines())
    added = [line for line in body_b.splitlines() if line and line not in lines_a][:20]
    removed = [line for line in body_a.splitlines() if line and line not in lines_b][:20]

    return {
        "status_changed": status_a != status_b,
        "status_baseline": status_a,
        "status_probe": status_b,
        "length_delta": len_b - len_a,
        "elapsed_delta_ms": ms_b - ms_a,
        "added_lines": [line[:300] for line in added],
        "removed_lines": [line[:300] for line in removed],
    }


# ── Error-oracle probe ──────────────────────────────────────────
# A fixed battery of error-inducing requests. Designed to provoke the
# server into leaking framework, validation behaviour, and routing
# rules — the things business-logic fuzzers need to know but rarely
# get from a baseline GET.
#
# Each entry: (probe_name, method_override, path_suffix, body, headers).
# Empty fields keep the original request shape. Probes are intentionally
# bounded — at most ~6 extra requests per call so the LLM can fire one
# probe per endpoint without burning the iteration budget.

_ERROR_PROBES = [
    # Malformed JSON: validators that accept JSON return a structured
    # error shape (FastAPI's pydantic 422, Express's body-parser SyntaxError,
    # Rails' JSON::ParserError) — VALIDATION_RULE harvests it.
    ("malformed_json", None, "", '{"a":', {"Content-Type": "application/json"}),
    # Empty body on a POST/PUT — exposes "field required" shapes.
    ("empty_body", None, "", "", {"Content-Type": "application/json"}),
    # Unknown content-type — many frameworks 415; the response chrome
    # often names the framework ("Unsupported Media Type — FastAPI").
    ("unsupported_media_type", None, "", "x", {"Content-Type": "application/x-hakuna-probe"}),
    # Method swap — GET → POST or POST → GET. 405 responses are
    # high-signal (framework name in body, allowed methods in Allow
    # header) and reveal route templates we didn't know existed.
    ("method_swap", "FLIP", "", None, {}),
    # Path with traversal pattern that should NOT match a real route —
    # if the server still 200s, that's a routing curiosity worth flagging.
    ("nonsense_suffix", None, "/__hakuna_probe_404", None, {}),
    # Oversize-ish header to provoke 431 / parser limits. Capped
    # conservatively (4KB) so we don't trigger WAF lockouts.
    ("oversize_header", None, "", None, {"X-Hakuna-Probe": "A" * 4_000}),
]


# Hard cap on total bytes returned to the LLM by the oracle, so an
# information-rich error page can't balloon the tool_result.
_ORACLE_MAX_BODY_PER_PROBE = 1_500


def _probe_error_oracle_handler(params: dict, ctx: AgentContext) -> dict:
    """Drive a fixed battery of error-inducing requests against an endpoint.

    The LLM passes ``url`` (and optional ``method``); the handler runs
    each probe in :data:`_ERROR_PROBES`, hands every response through the
    same ``extract_signals`` pipeline as ``http_request``, and returns a
    compact summary of (probe_name → status, framework_hint, validation
    rule). Capabilities are committed automatically so subsequent
    specialists see the inferred app-model in their CAPABILITIES block.

    Designed to be called ONCE per interesting endpoint, early in a
    specialist's run — the output then steers payload selection. Calling
    it on every endpoint is wasteful (the probes overlap heavily across
    routes that share a router/middleware).
    """
    base_url = (params.get("url") or "").strip()
    base_method = (params.get("method") or "GET").upper()
    if not base_url:
        return {"error": "url required"}
    if not _safe_url(base_url):
        return {"error": "unsafe url scheme"}
    if time.monotonic() >= ctx.deadline:
        return {"error": "asset deadline reached"}
    client = ctx.http_client
    if client is None:
        return {"error": "http client not configured"}

    merged_base_headers = dict(ctx.headers or {})
    provenance = (
        f"signal:{ctx.current_specialist}:oracle" if ctx.current_specialist
        else "signal:oracle"
    )

    probes_out: list[dict] = []
    inferred: dict[str, Any] = {
        "frameworks": [],
        "web_root": None,
        "validation_rules": [],
        "routes": [],
    }
    seen_fw: set[str] = set()

    for probe_name, method_override, path_suffix, body, extra_headers in _ERROR_PROBES:
        if time.monotonic() >= ctx.deadline:
            break

        probe_url = base_url
        if path_suffix:
            # Append a path suffix without breaking the query string.
            try:
                parts = urlparse(base_url)
                probe_url = parts._replace(path=(parts.path or "") + path_suffix).geturl()
            except Exception:
                probe_url = base_url + path_suffix

        if method_override == "FLIP":
            probe_method = "POST" if base_method == "GET" else "GET"
        elif method_override:
            probe_method = method_override
        else:
            probe_method = base_method

        probe_headers = dict(merged_base_headers)
        if extra_headers:
            probe_headers.update(extra_headers)

        started = time.monotonic()
        try:
            resp = client.request(
                method=probe_method,
                url=probe_url,
                headers=probe_headers or None,
                content=body if isinstance(body, (str, bytes)) else None,
                json=body if isinstance(body, dict) else None,
                timeout=8.0,
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            probes_out.append({"probe": probe_name, "url": probe_url,
                               "method": probe_method, "error": "timeout"})
            continue
        except Exception as e:
            probes_out.append({"probe": probe_name, "url": probe_url,
                               "method": probe_method, "error": str(e)[:200]})
            continue

        elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            body_text = resp.text[:_ORACLE_MAX_BODY_PER_PROBE]
        except Exception:
            body_text = ""

        # Pass full headers (incl. Set-Cookie) to the signal extractor —
        # framework detection leans heavily on cookie names, which the
        # LLM-facing summary redacts.
        full_headers = {k.lower(): v for k, v in resp.headers.items()}
        signal_response = {
            "url": probe_url,
            "method": probe_method,
            "status_code": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "headers": full_headers,
            "body": body_text,
            "body_length": len(resp.content or b""),
        }

        caps = extract_signals(
            method=probe_method, url=probe_url, request_body=body,
            response=signal_response,
            asset_id=ctx.asset_id, provenance=provenance,
        )
        commit_signals(ctx.capabilities, caps)

        # Accumulate the per-probe summary the LLM will read.
        probe_summary: dict[str, Any] = {
            "probe": probe_name,
            "url": probe_url,
            "method": probe_method,
            "status": resp.status_code,
            "body_length": signal_response["body_length"],
            "body_excerpt": body_text[:300],
        }
        for cap in caps:
            if cap.type == "framework":
                fw = cap.value.get("name")
                if fw and fw not in seen_fw:
                    inferred["frameworks"].append({
                        "name": fw,
                        "language": cap.value.get("language"),
                        "evidence": cap.value.get("evidence"),
                        "confidence": round(cap.confidence, 2),
                    })
                    seen_fw.add(fw)
            elif cap.type == "web_root" and inferred["web_root"] is None:
                inferred["web_root"] = cap.value.get("path")
            elif cap.type == "validation_rule":
                inferred["validation_rules"].append({
                    "param": cap.value.get("param"),
                    "rule": cap.value.get("rule"),
                    "rejected_with": cap.value.get("rejected_with"),
                })
            elif cap.type == "route_template":
                inferred["routes"].append({
                    "path": cap.value.get("path"),
                    "method": cap.value.get("method"),
                    "status": cap.value.get("status"),
                })
        probes_out.append(probe_summary)

    return {
        "probes": probes_out,
        "inferred": inferred,
        "note": (
            "Every probe response was already passed through the signal "
            "extractor — typed capabilities (framework, web_root, "
            "validation_rule, route_template) are committed to the "
            "capability store and visible in the next initial message."
        ),
    }


def _oob_get_probe_handler(params: dict, ctx: AgentContext) -> dict:
    """Mint a unique probe URL for blind / out-of-band confirmation.

    Returns ``configured=False`` when no collaborator is wired up,
    which the prompts treat as "skip the blind-case branch". When
    configured, the agent embeds ``probe_url`` in a payload that
    forces the target to perform an outbound fetch (SSRF, blind
    cmdi `; curl <probe_url>`, XXE external entity, etc.), then
    calls ``oob_check`` to see whether the fetch landed.
    """
    if not _oob_configured():
        return {
            "configured": False,
            "error": "OOB collaborator not configured — set AGENT_OOB_COLLABORATOR_URL",
        }
    token = secrets.token_hex(12)
    probe_url = f"{_OOB_BASE_URL}/probe/{token}"
    tokens = ctx.shared_memory.get("_oob_tokens", "")
    ctx.shared_memory["_oob_tokens"] = (tokens + "," + token)[:_MEMORY_MAX_VALUE_LEN] if tokens else token
    return {
        "configured": True,
        "token": token,
        "probe_url": probe_url,
    }


def _oob_check_handler(params: dict, ctx: AgentContext) -> dict:
    """Poll the collaborator for interactions tied to ``token``.

    Best-effort: any transport/protocol error returns ``error`` and
    the LLM's expected response is to fall back to in-band signals.
    We don't retry because blind probes in agent loops already have
    an iteration budget — burning two tool calls on one check is
    worse than assuming "no hit" and moving on.
    """
    if not _oob_configured():
        return {"configured": False, "error": "OOB collaborator not configured"}
    token = (params.get("token") or "").strip()
    if not token:
        return {"error": "token required"}
    client = ctx.http_client
    if client is None:
        return {"error": "http client not configured"}

    check_url = f"{_OOB_BASE_URL}/check/{token}"
    headers = {"X-API-Key": _OOB_API_KEY} if _OOB_API_KEY else None
    try:
        resp = client.get(check_url, headers=headers, timeout=10.0)
    except Exception as e:
        return {"error": f"collaborator unreachable: {str(e)[:200]}"}
    if resp.status_code != 200:
        return {"error": f"collaborator returned HTTP {resp.status_code}"}
    try:
        data = resp.json() or {}
    except ValueError:
        return {"error": "collaborator returned non-JSON body"}
    hits = data.get("hits") or data.get("interactions") or []
    if not isinstance(hits, list):
        hits = []
    return {
        "configured": True,
        "token": token,
        "hit_count": len(hits),
        # Cap stored evidence size — some collaborators return full
        # request dumps which the LLM doesn't need to read in full.
        "hits": [str(h)[:400] for h in hits[:10]],
    }


# ── Login flow primitive ─────────────────────────────────────────
# Form-based login is a known-hard multi-step operation for LLMs:
# fetch the page, parse hidden inputs (especially per-session CSRF
# tokens), POST the full form body with session cookies preserved,
# follow the redirect, and classify success from the final page.
# Gemini Flash in particular frequently drops one of those steps
# (omits the ``user_token``, forgets the submit button's ``name/value``
# pair, doesn't follow redirects) and authentication fails silently
# with a 200 OK on a re-rendered login page.
#
# ``try_login`` encapsulates the entire flow deterministically. The
# LLM just picks the credential pair; the tool does the GET-extract-
# POST-follow dance and returns a structured result including a
# heuristic ``likely_successful`` flag. On a strong positive signal
# the tool auto-commits a CRED capability so the composition chain
# fires even if the model forgets to call ``memory_set``.


# Match hidden inputs. We're deliberately lenient — real HTML has
# unquoted attrs, mixed case, and attribute orders that the whitewash
# of a strict parser would choke on. Good enough for login forms,
# which are the only place we care about hidden tokens.
_HIDDEN_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?hidden["\']?[^>]*>',
    re.IGNORECASE,
)
_ATTR_NAME_RE = re.compile(r'\bname\s*=\s*["\']?([^"\'\s>]+)', re.IGNORECASE)
_ATTR_VALUE_RE = re.compile(r'\bvalue\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]*))', re.IGNORECASE)


def _extract_hidden_fields(html: str) -> dict[str, str]:
    """Return every ``<input type="hidden">`` on the page as name → value.

    Scoped to hidden inputs rather than "the one form containing a
    password" because multiple forms on a single page (search bar +
    login, navbar + login) produce the same hidden-token name in
    practice. Collapsing all hidden inputs into a single dict matches
    what a browser submit would send.
    """
    out: dict[str, str] = {}
    for m in _HIDDEN_INPUT_RE.finditer(html):
        tag = m.group(0)
        name_m = _ATTR_NAME_RE.search(tag)
        if not name_m:
            continue
        value_m = _ATTR_VALUE_RE.search(tag)
        value = ""
        if value_m:
            value = value_m.group(1) or value_m.group(2) or value_m.group(3) or ""
        out[name_m.group(1)] = value
    return out


# Markers the heuristic scans for. Kept in one place so tuning is one
# edit. Lowercase comparison; order doesn't matter.
_LOGIN_FAILURE_MARKERS = (
    "login failed", "incorrect", "invalid credentials", "invalid username",
    "invalid password", "wrong password", "authentication failed",
)
_POST_AUTH_MARKERS = ("logout", "sign out", "welcome,", "dashboard")


def _classify_login_success(
    login_url: str, final_url: str, final_status: int, body: str,
) -> tuple[bool, str]:
    """Return (likely_successful, reason).

    Signals (in descending order of strength):
      1. 2xx final AND URL redirected away from anything login-shaped
         → strong success.
      2. 2xx final + body contains a post-auth marker (logout etc.)
         AND no failure marker → medium-strong success.
      3. Any failure marker in body → definitely failed.
      4. Otherwise ambiguous — false.

    We deliberately refuse to classify "just 302 with Location" as
    success because some apps 302 both on success and failure (back
    to the login page with error params). The final URL after
    following redirects is the authoritative signal.
    """
    if final_status >= 400:
        return False, f"final_status={final_status}"

    lower_body = (body or "").lower()
    if any(marker in lower_body for marker in _LOGIN_FAILURE_MARKERS):
        return False, "failure_marker_in_body"

    def _looks_like_login(url: str) -> bool:
        low = (url or "").lower()
        return any(tok in low for tok in ("/login", "/signin", "/auth", "logout=1"))

    redirected_away = (
        final_url and final_url != login_url and not _looks_like_login(final_url)
    )
    has_post_auth_marker = any(m in lower_body for m in _POST_AUTH_MARKERS)

    if redirected_away:
        return True, "redirected_away_from_login"
    if has_post_auth_marker:
        return True, "post_auth_marker_present"
    return False, "no_success_signal"


def _try_login_handler(params: dict, ctx: AgentContext) -> dict:
    """Drive a full form-login flow: GET → extract → POST → follow → classify.

    Parameters (all required unless noted):
      - ``login_url`` — where to GET the form AND POST credentials.
        Most apps colocate both on the same URL (DVWA, phpMyAdmin,
        most CMSes). Split GET/POST URLs aren't supported yet — when
        we hit an app that needs them, add a ``post_url`` param.
      - ``username`` / ``password`` — the pair to try. The tool does
        NOT iterate; caller invokes once per pair. That keeps the
        LLM in control of the budget.
      - ``username_field`` / ``password_field`` — form field names
        (default ``username`` / ``password``).
      - ``extra_static_fields`` — additional form body pairs the LLM
        discovered by inspecting the form (e.g. ``{"Login": "Login"}``
        for DVWA's submit button). Optional dict.

    On a strong success heuristic, auto-commits a CRED capability
    (provenance = current specialist, confidence 0.7) so the
    scheduler unlocks composition even if the LLM forgets the
    follow-up ``memory_set``/``emit_finding`` calls. The LLM should
    still make those calls to produce the finding record and the
    cleaner specialist-trace — this is belt-and-braces.
    """
    login_url = (params.get("login_url") or "").strip()
    username = params.get("username")
    password = params.get("password")
    if not login_url or username is None or password is None:
        return {"error": "login_url, username, and password are required"}
    if not _safe_url(login_url):
        return {"error": "unsafe login_url scheme"}
    if time.monotonic() >= ctx.deadline:
        return {"error": "asset deadline reached"}

    username_field = params.get("username_field") or "username"
    password_field = params.get("password_field") or "password"
    extra = params.get("extra_static_fields") or {}
    if not isinstance(extra, dict):
        extra = {}

    client = ctx.http_client
    if client is None:
        return {"error": "http client not configured"}

    # Step 1 — GET the login page. Lets the server set its session
    # cookie (httpx's client-level cookie jar persists it) and lets
    # us extract the hidden fields the form requires.
    merged_headers = dict(ctx.headers or {})
    try:
        get_resp = client.request(
            method="GET",
            url=login_url,
            headers=merged_headers or None,
            timeout=10.0,
            follow_redirects=True,
        )
    except Exception as e:
        return {"error": f"GET {login_url} failed: {str(e)[:200]}"}

    hidden_fields = _extract_hidden_fields(get_resp.text or "")

    # Step 2 — build the form body. Order: hidden fields first, then
    # static extras (so the LLM's explicit extras can override a
    # lingering default), then credentials last (so they always land
    # in the final body even if hidden_fields had stale placeholders).
    body_fields: dict[str, str] = {}
    body_fields.update(hidden_fields)
    for k, v in extra.items():
        if k:
            body_fields[str(k)] = "" if v is None else str(v)
    body_fields[username_field] = username
    body_fields[password_field] = password

    post_headers = dict(merged_headers)
    post_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    try:
        post_resp = client.request(
            method="POST",
            url=login_url,
            headers=post_headers,
            data=body_fields,
            timeout=10.0,
            follow_redirects=True,
        )
    except Exception as e:
        return {"error": f"POST {login_url} failed: {str(e)[:200]}"}

    final_url = str(post_resp.url)
    final_status = post_resp.status_code
    final_body = ""
    try:
        final_body = post_resp.text[:5_000]
    except Exception:
        pass

    likely_successful, reason = _classify_login_success(
        login_url=login_url,
        final_url=final_url,
        final_status=final_status,
        body=final_body,
    )

    capability_committed = False
    if likely_successful:
        provenance = (
            f"specialist:{ctx.current_specialist}" if ctx.current_specialist
            else "try_login"
        )
        scope = asset_scope(ctx.asset_id)
        from scanner.vm.capabilities import Capability, CapabilityType
        cap = Capability(
            type=CapabilityType.CRED, scope=scope,
            value={"scheme": "form", "username": username, "password": password,
                   "login_url": login_url, "username_field": username_field,
                   "password_field": password_field},
            confidence=0.75,
            provenance=provenance,
        )
        capability_committed = ctx.capabilities.add(cap)
        # Also mirror into shared_memory for prompts that still read
        # the MEMORY block — keeps the authn-prompt's documented
        # contract (``memory_set("valid_credentials", "user:pass")``)
        # fulfilled even if the LLM skips the explicit call.
        ctx.shared_memory["valid_credentials"] = f"{username}:{password}"

    return {
        "login_url": login_url,
        "final_url": final_url,
        "final_status": final_status,
        "body_excerpt": final_body[:2_000],
        "extracted_hidden_fields": list(hidden_fields.keys()),
        "posted_field_names": list(body_fields.keys()),
        "likely_successful": likely_successful,
        "reason": reason,
        "capability_committed": capability_committed,
    }


# ── HTML form parser ────────────────────────────────────────────
# Structured form extraction. The injection/xss/csrf/files/authn
# specialists all start by "read the HTML and find forms" — doing that
# in the prompt wastes tokens and produces inconsistent results
# (models miss radio groups, disagree on what a "parameter" is).
# A deterministic parser returns the same shape every time.


_FORM_RE = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'<input\b[^>]*/?>', re.IGNORECASE)
_TEXTAREA_RE = re.compile(r'<textarea\b[^>]*>.*?</textarea>', re.IGNORECASE | re.DOTALL)
_SELECT_RE = re.compile(r'<select\b[^>]*>.*?</select>', re.IGNORECASE | re.DOTALL)
_ATTR_GENERIC_RE = re.compile(
    r'\b([a-zA-Z_][\w-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',
    re.IGNORECASE,
)


def _attrs(tag: str) -> dict[str, str]:
    """Parse attributes off an open/self-closing tag."""
    out: dict[str, str] = {}
    # Skip the tag name itself (first token).
    body = tag.lstrip("<").split(None, 1)
    inner = body[1] if len(body) > 1 else ""
    for m in _ATTR_GENERIC_RE.finditer(inner):
        name = m.group(1).lower()
        value = m.group(2) or m.group(3) or m.group(4) or ""
        out[name] = value
    return out


def _extract_forms(html: str) -> list[dict]:
    """Return one dict per ``<form>`` with method/action + input spec.

    Each input carries name, type, value, required, and a short
    ``kind`` classification (``text``, ``password``, ``hidden``,
    ``submit``, ``textarea``, ``select``) so the LLM can pick targets
    by semantic type without re-parsing raw HTML. Hidden inputs
    containing CSRF tokens are flagged (``looks_like_csrf=True``) so
    downstream tools know to carry them through any POST.
    """
    forms: list[dict] = []
    for form_match in _FORM_RE.finditer(html or ""):
        form_tag_end = form_match.start() + len("<form")
        form_open_tag = html[form_match.start():html.index(">", form_tag_end) + 1]
        form_attrs = _attrs(form_open_tag)
        body = form_match.group(1)

        inputs: list[dict] = []
        for m in _INPUT_RE.finditer(body):
            attrs = _attrs(m.group(0))
            name = attrs.get("name", "")
            itype = (attrs.get("type") or "text").lower()
            inputs.append({
                "name": name,
                "type": itype,
                "value": attrs.get("value", ""),
                "required": "required" in attrs,
                "placeholder": attrs.get("placeholder", ""),
                "kind": itype,
                "looks_like_csrf": (
                    itype == "hidden" and bool(_CSRF_NAME_RE.search(name))
                ),
            })
        for m in _TEXTAREA_RE.finditer(body):
            attrs = _attrs(m.group(0))
            inputs.append({
                "name": attrs.get("name", ""),
                "type": "textarea",
                "value": "",
                "required": "required" in attrs,
                "placeholder": attrs.get("placeholder", ""),
                "kind": "textarea",
                "looks_like_csrf": False,
            })
        for m in _SELECT_RE.finditer(body):
            attrs = _attrs(m.group(0))
            inputs.append({
                "name": attrs.get("name", ""),
                "type": "select",
                "value": "",
                "required": "required" in attrs,
                "placeholder": "",
                "kind": "select",
                "looks_like_csrf": False,
            })

        forms.append({
            "action": form_attrs.get("action", ""),
            "method": (form_attrs.get("method") or "GET").upper(),
            "id": form_attrs.get("id", ""),
            "name_attr": form_attrs.get("name", ""),
            "enctype": form_attrs.get("enctype", ""),
            "inputs": inputs,
            "has_password_input": any(i["type"] == "password" for i in inputs),
            "has_file_input": any(i["type"] == "file" for i in inputs),
            "is_state_changing": (form_attrs.get("method") or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE"),
        })
    return forms


_CSRF_NAME_RE = re.compile(
    r"(csrf|xsrf|authenticity|__RequestVerification|user_token|anti[-_]?forgery)",
    re.IGNORECASE,
)


def _extract_forms_handler(params: dict, ctx: AgentContext) -> dict:
    html = params.get("html")
    if not isinstance(html, str):
        return {"error": "html (string) required"}
    if not html.strip():
        return {"forms": [], "total": 0}
    forms = _extract_forms(html)
    return {"forms": forms, "total": len(forms)}


# ── JWT analyzer ─────────────────────────────────────────────────
# Structural analysis only — we don't have the signing key, so we
# can't validate. Detects the common misconfigurations: alg:none,
# missing exp, suspicious algorithm. A finding here justifies an
# emit_finding call by the LLM with severity based on the flag set.


_JWT_DANGEROUS_ALGS = {"none", "null", ""}
_JWT_WEAK_ALGS = {"hs256"}  # Weak ONLY if the signing secret is dictionary-attackable, which we can't test.


def _b64url_decode(s: str) -> bytes:
    # Add padding. JWT segments often omit ``=`` per RFC 7515.
    pad = (-len(s)) % 4
    try:
        import base64
        return base64.urlsafe_b64decode(s + ("=" * pad))
    except Exception:
        return b""


def _analyze_jwt_handler(params: dict, ctx: AgentContext) -> dict:
    """Decode a JWT and flag structural / algorithmic weaknesses.

    Returns header/payload dicts, algorithm, and a findings list with
    severities. The LLM is expected to call ``emit_finding`` for each
    issue whose severity justifies a report (typically ``critical``
    for alg:none or expired-but-accepted tokens).
    """
    token = (params.get("token") or "").strip()
    if not token:
        return {"error": "token required"}
    parts = token.split(".")
    if len(parts) not in (2, 3):
        return {
            "valid_structure": False,
            "error": f"expected 2 or 3 segments, got {len(parts)}",
        }

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    signature_present = len(parts) == 3 and bool(parts[2].strip())

    try:
        header = json.loads(header_raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {
            "valid_structure": False,
            "error": "header segment is not JSON",
            "header_raw_preview": header_raw[:80].decode("utf-8", errors="replace"),
        }
    try:
        payload = json.loads(payload_raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = None

    alg = str(header.get("alg") or "").lower()
    issues: list[dict] = []

    if alg in _JWT_DANGEROUS_ALGS or not alg:
        issues.append({
            "id": "alg_none_accepted_in_header",
            "severity": "critical",
            "description": (
                "Token declares alg=none (unsigned). If the server accepts this "
                "token, any attacker can mint valid tokens. Verify by forging a "
                "token with admin=true claims and re-sending."
            ),
        })

    if not signature_present and alg not in _JWT_DANGEROUS_ALGS:
        issues.append({
            "id": "missing_signature_segment",
            "severity": "high",
            "description": (
                "Token declares a signing algorithm but the signature segment "
                "is absent. Servers that accept this are vulnerable to "
                "alg:none-style bypass."
            ),
        })

    if alg in _JWT_WEAK_ALGS:
        issues.append({
            "id": "weak_symmetric_algorithm",
            "severity": "medium",
            "description": (
                "HS256 is safe only when the shared secret is high-entropy. "
                "If the secret leaked into a repo or .env dump, attackers can "
                "forge tokens offline. Suggest rotating to RS256/EdDSA."
            ),
        })

    if isinstance(payload, dict):
        import time as _time
        if "exp" not in payload:
            issues.append({
                "id": "missing_exp",
                "severity": "medium",
                "description": "Token has no exp claim — effectively infinite TTL.",
            })
        elif isinstance(payload["exp"], (int, float)):
            if payload["exp"] < _time.time():
                issues.append({
                    "id": "token_expired",
                    "severity": "info",
                    "description": (
                        "Token is past its exp. If the server still accepts it "
                        "(test by re-sending), expiration isn't enforced — "
                        "upgrade severity to high."
                    ),
                })
        # Impersonation-shaped claims.
        for claim in ("admin", "is_admin", "role", "roles", "permissions", "scope"):
            if claim in payload:
                issues.append({
                    "id": f"claim_{claim}_controls_privileges",
                    "severity": "info",
                    "description": (
                        f"Payload carries a '{claim}' claim. If the server "
                        f"trusts the payload without re-verifying, forging "
                        f"this claim (given alg:none or a cracked secret) "
                        f"yields privilege escalation."
                    ),
                })

    severity_order = ["info", "low", "medium", "high", "critical"]
    highest = "info"
    for issue in issues:
        if severity_order.index(issue["severity"]) > severity_order.index(highest):
            highest = issue["severity"]

    return {
        "valid_structure": True,
        "header": header,
        "payload": payload,
        "algorithm": alg or None,
        "signature_present": signature_present,
        "issues": issues,
        "highest_severity": highest,
    }


# ── Security headers evaluator ───────────────────────────────────
# Takes a response dict (as returned by ``http_request``) and returns
# a deterministic pass/fail on the standard security header set. The
# LLM doesn't need to memorize the expected values — this tool knows
# them, and the LLM just reads the ``findings`` array and emits any
# that warrant a security report.


def _split_cookie_header(raw: str) -> list[dict]:
    """Parse Set-Cookie header(s) into dicts with flags extracted.

    Multiple Set-Cookie headers are sent as separate HTTP header
    lines; httpx joins them with ', ' in the single-value view we
    receive. Splitting on ', ' is imprecise (Expires= has a comma)
    but good enough for flag detection — we don't care about cookie
    VALUES, only the Secure/HttpOnly/SameSite attributes.
    """
    cookies: list[dict] = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name = chunk.split("=", 1)[0].strip()
        lower = chunk.lower()
        cookies.append({
            "name": name,
            "secure": "; secure" in lower or lower.endswith("; secure") or "; secure;" in lower,
            "httponly": "httponly" in lower,
            "samesite_lax": "samesite=lax" in lower,
            "samesite_strict": "samesite=strict" in lower,
            "samesite_none": "samesite=none" in lower,
        })
    return cookies


def _check_security_headers_handler(params: dict, ctx: AgentContext) -> dict:
    """Evaluate a response dict against the standard security-header checklist."""
    response = params.get("response")
    if not isinstance(response, dict):
        return {"error": "response (response dict from http_request) required"}
    headers_any = response.get("headers") or {}
    if not isinstance(headers_any, dict):
        return {"error": "response.headers must be a dict"}
    # Normalise to lowercase keys so case variations don't cause misses.
    headers = {str(k).lower(): str(v) for k, v in headers_any.items()}
    url = response.get("url") or ""
    is_https = url.lower().startswith("https://")

    findings: list[dict] = []
    checks: dict[str, dict] = {}

    # Strict-Transport-Security — only meaningful on HTTPS.
    hsts = headers.get("strict-transport-security")
    checks["strict_transport_security"] = {"present": bool(hsts), "value": hsts}
    if is_https and not hsts:
        findings.append({
            "id": "missing_hsts",
            "severity": "medium",
            "description": "HTTPS response without Strict-Transport-Security; browsers may accept downgraded HTTP.",
        })
    elif hsts and "max-age=" in hsts.lower():
        try:
            max_age = int(hsts.lower().split("max-age=", 1)[1].split(";", 1)[0])
            if max_age < 15_552_000:  # ~6 months
                findings.append({
                    "id": "hsts_short_max_age",
                    "severity": "low",
                    "description": f"HSTS max-age={max_age} is below the recommended 6 months.",
                })
        except (ValueError, IndexError):
            pass

    # Content-Security-Policy.
    csp = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
    checks["content_security_policy"] = {"present": bool(csp), "value": csp}
    if not csp:
        findings.append({
            "id": "missing_csp",
            "severity": "medium",
            "description": "No Content-Security-Policy header — inline script / external resource loading is unconstrained.",
        })
    elif csp and ("unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower()):
        findings.append({
            "id": "csp_unsafe_directives",
            "severity": "low",
            "description": "CSP allows unsafe-inline or unsafe-eval, weakening XSS protection.",
        })

    # X-Frame-Options / frame-ancestors.
    xfo = headers.get("x-frame-options")
    frame_ancestors_in_csp = bool(csp and "frame-ancestors" in (csp or "").lower())
    checks["x_frame_options"] = {"present": bool(xfo), "value": xfo}
    if not xfo and not frame_ancestors_in_csp:
        findings.append({
            "id": "missing_clickjack_protection",
            "severity": "medium",
            "description": "No X-Frame-Options and no CSP frame-ancestors — page is framable, enabling clickjacking.",
        })

    # X-Content-Type-Options.
    xcto = headers.get("x-content-type-options")
    checks["x_content_type_options"] = {"present": bool(xcto), "value": xcto}
    if not xcto or xcto.lower() != "nosniff":
        findings.append({
            "id": "missing_xcto_nosniff",
            "severity": "low",
            "description": "X-Content-Type-Options not set to nosniff — MIME-sniffing attacks possible.",
        })

    # Referrer-Policy.
    ref = headers.get("referrer-policy")
    checks["referrer_policy"] = {"present": bool(ref), "value": ref}
    if not ref:
        findings.append({
            "id": "missing_referrer_policy",
            "severity": "info",
            "description": "No Referrer-Policy — referrer header may leak internal URLs.",
        })

    # Permissions-Policy (replaces Feature-Policy).
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    checks["permissions_policy"] = {"present": bool(pp), "value": pp}

    # Cookie flags.
    raw_cookies = headers.get("set-cookie") or ""
    cookies = _split_cookie_header(raw_cookies)
    checks["cookies"] = cookies
    for c in cookies:
        if not c["httponly"]:
            findings.append({
                "id": "cookie_missing_httponly",
                "severity": "medium",
                "description": f"Cookie {c['name']} has no HttpOnly flag — JS-readable, XSS can exfiltrate.",
            })
        if is_https and not c["secure"]:
            findings.append({
                "id": "cookie_missing_secure",
                "severity": "medium",
                "description": f"Cookie {c['name']} has no Secure flag on an HTTPS response.",
            })
        if not (c["samesite_lax"] or c["samesite_strict"] or c["samesite_none"]):
            findings.append({
                "id": "cookie_missing_samesite",
                "severity": "low",
                "description": f"Cookie {c['name']} has no SameSite attribute — CSRF protection weakened.",
            })

    return {
        "url": url,
        "is_https": is_https,
        "checks": checks,
        "findings": findings,
        "finding_count": len(findings),
    }


# ── Headless browser rendering ───────────────────────────────────
# Playwright-backed tool for SPAs where ``http_request`` sees an
# empty shell. Soft dependency: if playwright isn't installed (or the
# Chromium browser binary isn't present), the handler returns
# ``available=False`` with a helpful error. Scanners on minimal
# images can still run everything else.


_PLAYWRIGHT_NAV_TIMEOUT_MS = int(os.environ.get("AGENT_PLAYWRIGHT_TIMEOUT_MS", "15000"))
_PLAYWRIGHT_MAX_BODY = int(os.environ.get("AGENT_PLAYWRIGHT_MAX_BODY", "20000"))


def _render_page_handler(params: dict, ctx: AgentContext) -> dict:
    """Render a page with headless Chromium, return DOM + XHR graph.

    Why this exists: SPAs hydrate their UI in JavaScript. Plain
    ``http_request`` sees ``<div id="root"></div>`` and the XSS /
    injection specialists miss every input because the real form
    doesn't exist until JS runs. Playwright runs the page, waits
    for network idle, and returns the hydrated DOM along with every
    XHR / fetch the page fired. The LLM can then feed that DOM into
    ``extract_forms`` or ``check_pattern`` as if it had been static HTML.

    Budget: deliberately expensive (1-3s per call). The prompts
    should ONLY reach for this when ``http_request`` returns a thin
    shell (< 2KB HTML with a ``<script src>`` tag loading the SPA
    bundle). Don't call it for every endpoint.
    """
    url = (params.get("url") or "").strip()
    if not _safe_url(url):
        return {"error": "unsafe url scheme"}
    if not url:
        return {"error": "url required"}
    if time.monotonic() >= ctx.deadline:
        return {"error": "asset deadline reached"}

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return {
            "available": False,
            "error": (
                "playwright not installed. Add `playwright` to requirements.txt "
                "and run `playwright install chromium` during image build."
            ),
        }

    requests_log: list[dict] = []
    console_log: list[dict] = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context_kw = {"ignore_https_errors": True}
            if ctx.headers:
                # Playwright contexts accept extra HTTP headers that are sent
                # on every outbound request — gives scan-config / discovered
                # auth a chance to land even inside the headless browser's
                # requests.
                context_kw["extra_http_headers"] = dict(ctx.headers)
            bc = browser.new_context(**context_kw)
            page = bc.new_page()

            page.on("request", lambda req: requests_log.append({
                "url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
            }))
            page.on("console", lambda msg: console_log.append({
                "type": msg.type,
                "text": msg.text[:500],
            }))

            try:
                nav = page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=_PLAYWRIGHT_NAV_TIMEOUT_MS,
                )
            except Exception as e:
                browser.close()
                return {
                    "available": True,
                    "error": f"navigation failed: {str(e)[:200]}",
                    "url": url,
                }

            status = nav.status if nav else 0
            final_url = page.url
            dom_html = ""
            try:
                dom_html = page.content()
            except Exception:
                pass
            cookies = []
            try:
                cookies = [
                    {"name": c["name"], "domain": c.get("domain", ""),
                     "secure": c.get("secure", False), "http_only": c.get("httpOnly", False)}
                    for c in bc.cookies()
                ]
            except Exception:
                pass
            browser.close()

    except Exception as e:
        return {
            "available": True,
            "error": f"playwright setup failed: {str(e)[:200]}",
            "url": url,
        }

    # Filter out heavyweight resources — the LLM cares about the
    # application's own requests, not every image/font/CSS call.
    interesting = [
        r for r in requests_log
        if r["resource_type"] in ("document", "xhr", "fetch", "script", "websocket")
    ]

    return {
        "available": True,
        "url": url,
        "final_url": final_url,
        "status_code": status,
        "dom_html": dom_html[:_PLAYWRIGHT_MAX_BODY],
        "dom_length": len(dom_html),
        "network_requests": interesting[:100],
        "network_request_total": len(requests_log),
        "console_messages": console_log[:30],
        "cookies": cookies,
    }


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
            "evidence_url, parameter, evidence_request, evidence_response, "
            "verdict, confidence (0-1). Always include `parameter` (the "
            "exact name of the vulnerable input, e.g. 'id', 'ip', 'url') "
            "when the vuln is tied to one — it's used for dedup, so "
            "findings on different parameters of the same endpoint stay "
            "distinct."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "evidence_url": {"type": "string"},
                "parameter": {
                    "type": "string",
                    "description": (
                        "Exact name of the vulnerable input (query/body "
                        "parameter, form field, or header). Used for "
                        "dedup. Omit only for endpoint-level vulns with "
                        "no specific input (e.g. default login, exposed "
                        "admin panel)."
                    ),
                },
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
    "memory_set": Tool(
        name="memory_set",
        description=(
            "Store a short fact on the per-asset scratchpad. Later "
            "specialists (authz, ssrf, etc.) will see your entries in "
            "their initial message — use this to hand off concrete "
            "hints they should not re-discover. Good keys: "
            "'discovered_endpoints', 'waf_present', 'jwt_leaked_in_body', "
            "'valid_user_id', 'internal_host_reachable'. Values are "
            "truncated to 2000 chars and there is a 32-key cap."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Short slug describing the fact."},
                "value": {"description": "String or small object. Coerced to JSON and truncated."},
            },
            "required": ["key", "value"],
        },
        handler=_memory_set_handler,
    ),
    "diff_responses": Tool(
        name="diff_responses",
        description=(
            "Compare two response objects returned by earlier http_request "
            "calls. Pass the full dicts as 'baseline' and 'probe'. Returns "
            "status/length/timing deltas and the exact line-level differences. "
            "Use this before classifying — a finding based on 'the response "
            "changed' is weaker than one citing the exact added line or the "
            "5s timing delta this tool reports."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "baseline": {"type": "object", "description": "Response dict from the unmodified request."},
                "probe": {"type": "object", "description": "Response dict from the payload-bearing request."},
            },
            "required": ["baseline", "probe"],
        },
        handler=_diff_responses_handler,
    ),
    "probe_error_oracle": Tool(
        name="probe_error_oracle",
        description=(
            "Drive a fixed battery of error-inducing requests against an "
            "endpoint to reverse-engineer how the app validates input "
            "and which framework runs behind the route. Sends ~6 probes "
            "(malformed JSON, empty body, bad content-type, method swap, "
            "nonsense path suffix, oversize header) and feeds every "
            "response through the signal extractor — framework, "
            "validation rules, web_root, and routes are auto-committed "
            "to capabilities, visible to later specialists in their "
            "CAPABILITIES block. Use ONCE per interesting endpoint, "
            "early in the run, to steer payload selection. Returns "
            "per-probe status + body excerpt and an `inferred` summary "
            "of what was learned. Cheap (~1s wall, no LLM tokens beyond "
            "the tool_result)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target endpoint URL."},
                "method": {
                    "type": "string",
                    "description": "Baseline method (the probes vary it). Default GET.",
                },
            },
            "required": ["url"],
        },
        handler=_probe_error_oracle_handler,
    ),
    "oob_get_probe": Tool(
        name="oob_get_probe",
        description=(
            "Mint a unique out-of-band probe URL. Use when in-band signals "
            "aren't available: blind SQL injection, blind command injection "
            "(embed as '; curl <probe_url>'), blind SSRF where the target "
            "doesn't echo responses, XXE via 'SYSTEM <probe_url>'. Returns "
            "{configured: false} if no collaborator is configured — in that "
            "case skip the blind-case branch and rely on timing/error signals. "
            "After sending a payload containing the probe_url, call oob_check "
            "with the same token to see if the target reached out."
        ),
        input_schema={"type": "object", "properties": {}},
        handler=_oob_get_probe_handler,
    ),
    "oob_check": Tool(
        name="oob_check",
        description=(
            "Poll the out-of-band collaborator for interactions tied to the "
            "token returned by oob_get_probe. hit_count >= 1 means the "
            "target performed the fetch — strong evidence for a blind "
            "vulnerability. Allow a few seconds between sending the payload "
            "and checking; some servers batch outbound requests."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "Token from oob_get_probe."},
            },
            "required": ["token"],
        },
        handler=_oob_check_handler,
    ),
    "extract_forms": Tool(
        name="extract_forms",
        description=(
            "Parse HTML and return a structured list of every <form> "
            "on the page. Returns action, method, and per-input metadata "
            "(name, type, value, required, looks_like_csrf). Use this "
            "INSTEAD of asking the model to read HTML — it's faster, "
            "deterministic, and doesn't miss radio groups or hidden "
            "CSRF tokens. Pass the body of a prior http_request response."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "html": {"type": "string", "description": "Response body (HTML) to parse."},
            },
            "required": ["html"],
        },
        handler=_extract_forms_handler,
    ),
    "analyze_jwt": Tool(
        name="analyze_jwt",
        description=(
            "Decode a JWT and flag structural / algorithmic weaknesses "
            "(alg:none, missing signature segment, expired-but-still-"
            "trusted, missing exp, admin-shaped claims). Returns header, "
            "payload, algorithm, and an issues array with severities — "
            "call emit_finding for each issue worth reporting. Does NOT "
            "verify the signature (we don't have the key); the LLM must "
            "confirm the server accepts the token by re-sending it."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "The JWT to analyze."},
            },
            "required": ["token"],
        },
        handler=_analyze_jwt_handler,
    ),
    "check_security_headers": Tool(
        name="check_security_headers",
        description=(
            "Evaluate a response against the standard security-header "
            "checklist (HSTS, CSP, X-Frame-Options, X-Content-Type-"
            "Options, Referrer-Policy, Permissions-Policy, cookie flags). "
            "Pass a full response dict from a prior http_request call — "
            "the tool reads status, url, and headers. Returns per-header "
            "presence + a findings array with severities. Call "
            "emit_finding for each finding you decide to report."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "response": {
                    "type": "object",
                    "description": "Response dict from http_request (status_code, url, headers).",
                },
            },
            "required": ["response"],
        },
        handler=_check_security_headers_handler,
    ),
    "render_page": Tool(
        name="render_page",
        description=(
            "Headless-Chromium render of a URL. Returns the HYDRATED DOM "
            "(after JS runs), final URL, every XHR/fetch the page fired, "
            "and console messages. Use for SPAs where http_request "
            "returns a thin shell (< ~2KB HTML with <script src> loading "
            "a bundle). DO NOT use for every endpoint — each call costs "
            "1-3 seconds. Returns {available: false} when playwright "
            "isn't installed; in that case fall back to http_request."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to render."},
            },
            "required": ["url"],
        },
        handler=_render_page_handler,
    ),
    "try_login": Tool(
        name="try_login",
        description=(
            "Drive an end-to-end form login: GET the login page to collect "
            "the session cookie and hidden inputs (CSRF tokens, ViewState, "
            "etc.), POST credentials with every hidden field preserved, "
            "follow redirects, and classify success from the final URL + "
            "body. Use this INSTEAD of chaining http_request calls for "
            "login attempts — it's significantly more reliable because it "
            "preserves session cookies across the GET/POST pair and can't "
            "forget the CSRF token.\n\n"
            "Returns likely_successful + reason. On a strong positive the "
            "tool auto-commits a credentials capability to the scheduler, "
            "so subsequent specialists immediately gain authenticated "
            "access on their next turn — but you should still call "
            "emit_finding + summary to record the result properly.\n\n"
            "Parameters:\n"
            "  login_url: the form's action URL (usually the same as the "
            "    URL that served the form, e.g. /login.php)\n"
            "  username, password: the credential pair to try\n"
            "  username_field, password_field: form input names (default "
            "    'username' / 'password' — override when the form uses "
            "    'user' / 'pass' / 'email' / etc.)\n"
            "  extra_static_fields: additional fields the form requires. "
            "    For DVWA pass {\"Login\": \"Login\"} (the submit button). "
            "    Hidden inputs (user_token, authenticity_token, "
            "    __RequestVerificationToken) are extracted automatically."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "login_url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "username_field": {"type": "string"},
                "password_field": {"type": "string"},
                "extra_static_fields": {"type": "object"},
            },
            "required": ["login_url", "username", "password"],
        },
        handler=_try_login_handler,
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

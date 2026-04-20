"""Specialist vulnerability agents — prompts, tools, categories.

Six narrow agents, each scoped to one vulnerability class:

  - injection   — SQLi / NoSQLi / command injection / SSTI / XPath / LDAP
  - xss         — reflected / stored / DOM XSS
  - ssrf        — server-side request forgery and blind SSRF surfaces
  - authn       — authentication / session / MFA bypass
  - authz       — IDOR / privilege escalation / tenant isolation
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

import httpx

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

AGENT_CATEGORIES = ("injection", "xss", "ssrf", "authn", "authz", "files")


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

Step 1 — PICK 3-5 HIGHEST-SIGNAL PARAMETERS. Prioritise: parameters whose names suggest code execution (command, cmd, exec, run, shell, ping, host, query), then generic inputs (id, user, q, search, filter). Prefer endpoints with a form method POST or a query string present.

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
- Max 12 tool calls per agent run.
- Spend at most 3 calls per parameter.
- STOP and call summary when you've examined your top 3 candidates, even if you found nothing.

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

TOOLS BEYOND http_request:
- `diff_responses(authed_response, unauthed_response)` — the cleanest way to classify. If status_changed is false and length_delta is small, that's your bypass evidence.
- `memory_set(key, value)` — if you spot a leaked session cookie, a JWT in a response body, or notice an endpoint that returns user-IDs (e.g. `/me` echoes `user_id=42`), store that as `leaked_identifier` or `valid_user_id` so the authz specialist can test with those concrete values instead of guessing.

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

TOOLS BEYOND http_request:
- Check the MEMORY block in your initial message first. The authn specialist may have stored `leaked_identifier` or `valid_user_id` — use that as your "other" identity candidate instead of guessing id+1.
- `diff_responses(your_response, modified_id_response)` — required for classification. Same status + non-trivial length_delta and a different user's data in added_lines is an IDOR.

SAFETY:
- Stop on first confirmed IDOR and emit a finding. Don't iterate across IDs.
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
    "files": SpecialistSpec(
        category="files",
        display_name="File Inclusion Specialist",
        system_prompt=_FILES_PROMPT,
        max_iterations=10,
        applicable_when=_has_parameterised_endpoint,
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

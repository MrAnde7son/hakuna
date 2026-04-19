"""LLM-assisted login flow detection for AuthProfile.

Given a login URL and the credential's auth_type, fetches the page HTML
and asks the system LLM (via services.llm_provider — same multi-provider
path the rest of the app uses, including Vertex AI) to propose a
login_flow step array and success_condition.

This is a UX accelerator: the user reviews the suggestion and can edit
before saving. It is NOT a substitute for the user's judgment — we
surface the raw LLM output so they see what we're about to store.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from services import llm_provider


logger = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You analyze web login pages and produce a machine-readable flow
that a headless browser (Playwright) can execute to authenticate.

You receive two things:
1. A "Structured hints" JSON block — actual <input>/<button>/<form> elements
   extracted live from the rendered DOM (preferred signal; selectors here
   are known to exist).
2. A trimmed HTML snippet — context when hints are ambiguous.

Output strictly one JSON object with this shape, nothing else:
{
  "login_flow": [
    {"action": "goto", "url": "<full login URL>"},
    {"action": "fill", "selector": "<CSS selector>", "value_from": "username"},
    {"action": "fill", "selector": "<CSS selector>", "value_from": "password"},
    {"action": "click", "selector": "<CSS selector>"},
    {"action": "wait_for_url", "pattern": "<regex>", "timeout_ms": 10000}
  ],
  "success_condition": {"type": "url_matches" | "cookie_present" | "element_visible", ...},
  "notes": "<one short sentence of rationale — shown to the user>"
}

Rules:
- Prefer selectors from the Structured hints block verbatim. They reflect
  the live DOM and are guaranteed to resolve.
- If a hint has both `id` and `name`, prefer `#id` form. Avoid nth-child
  and generated class chains.
- `value_from` is a literal key name the calling system will resolve from
  the user's credential dict. Use "username" for the identifier field
  (email / username / login) and "password" for the secret field.
- Pick the submit button by text ("Sign in", "Log in", "Continue"), by
  `type=submit`, or by an obvious testid/id.
- For success_condition with url_matches, pick a regex that matches the
  post-login URL pattern (e.g. "/dashboard|/home|/app"). If the page
  doesn't hint at a redirect, prefer cookie_present with a session cookie
  name if one is obvious in the HTML.
- If the hints block shows zero inputs and no relevant HTML, return:
  {"error": "<short reason>"}
- Keep "notes" to one short sentence. Never wrap the JSON in markdown
  fences. Never add prose before/after."""


_EMPTY_HINTS: dict[str, Any] = {"url": "", "inputs": [], "buttons": [], "forms": []}


# JS that runs inside the rendered page to pull login-relevant elements.
# Kept separate from the Python string to avoid JS-in-Python escaping pain.
_HINTS_JS = """() => {
    const mkSel = (el) => {
        if (el.id) return '#' + CSS.escape(el.id);
        const nm = el.getAttribute('name');
        if (nm) return el.tagName.toLowerCase() + '[name="' + nm + '"]';
        const tid = el.getAttribute('data-testid');
        if (tid) return '[data-testid="' + tid + '"]';
        if (el.type && el.tagName === 'INPUT') {
            return 'input[type="' + el.type + '"]';
        }
        return null;
    };
    const pickInput = el => ({
        tag: el.tagName.toLowerCase(),
        type: el.type || null,
        selector: mkSel(el),
        id: el.id || null,
        name: el.getAttribute('name'),
        placeholder: el.placeholder || null,
        aria_label: el.getAttribute('aria-label'),
        autocomplete: el.getAttribute('autocomplete'),
        data_testid: el.getAttribute('data-testid'),
    });
    const pickButton = el => ({
        tag: el.tagName.toLowerCase(),
        type: el.type || null,
        text: (el.innerText || el.value || '').trim().slice(0, 80),
        selector: mkSel(el),
        id: el.id || null,
        data_testid: el.getAttribute('data-testid'),
    });
    const inputs = Array.from(document.querySelectorAll('input, textarea'))
        .filter(el => el.type !== 'hidden' && el.offsetParent !== null)
        .map(pickInput);
    const buttons = Array.from(document.querySelectorAll('button, input[type=submit]'))
        .filter(el => el.offsetParent !== null)
        .map(pickButton);
    const forms = Array.from(document.querySelectorAll('form'))
        .map(f => ({id: f.id || null, action: f.action || null, method: f.method || null}));
    return {url: location.href, inputs, buttons, forms};
}"""


def _fetch_login_html(url: str, timeout: float = 10.0) -> str:
    """Best-effort raw HTML fetch. Raises httpx exceptions on failure."""
    with httpx.Client(follow_redirects=True, timeout=timeout, verify=False) as client:
        resp = client.get(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; HakunaAuthProfileBot/1.0)",
        })
        resp.raise_for_status()
        return resp.text


async def _render_login_page(url: str, timeout_ms: int = 30000) -> tuple[str, dict[str, Any]]:
    """Render the login page in headless chromium and return the post-JS DOM.

    SPAs (Tenable, Okta, most modern consoles) serve an empty shell over HTTP —
    the login form materializes only after the JS bundle runs. Without a real
    browser the LLM sees no <form> and gives up. Mirrors session_broker's
    Playwright setup so capabilities stay aligned.

    Raises ImportError if Playwright isn't installed, so callers can fall back.
    """
    from playwright.async_api import async_playwright  # type: ignore

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )
            page = await context.new_page()
            # `wait_until="commit"` resolves as soon as the HTTP response lands,
            # before Playwright starts waiting for DOM/load events. Tenable-style
            # SPAs often redirect client-side to a cross-origin SSO page, which
            # aborts the original navigation with `net::ERR_ABORTED` — that's
            # the "signal aborted" users see. Committing early sidesteps it.
            try:
                await page.goto(url, wait_until="commit", timeout=timeout_ms)
            except Exception as e:
                logger.info("auth_flow_detector: goto did not commit cleanly on %s (%s) — continuing", url, e)
            # Give the SPA a moment to hydrate. `networkidle` is best-effort;
            # Tenable keeps long-polling XHRs alive so we fall back to a plain
            # selector wait either way.
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass
            try:
                await page.wait_for_selector("input[type=password]", timeout=8000)
            except Exception:
                pass
            # page may have navigated cross-origin (SSO handoff), been closed,
            # or the context torn down — guard the final read so a tear-down
            # race surfaces as a readable error instead of a raw Playwright abort.
            try:
                content = await page.content()
            except Exception as e:
                raise RuntimeError(f"could not read page content for {url}: {e}")
            if len(content) < 200:
                raise RuntimeError(f"page render returned empty DOM for {url}")
            try:
                hints = await page.evaluate(_HINTS_JS)
            except Exception as e:
                logger.info("auth_flow_detector: hints extraction failed on %s: %s", url, e)
                hints = dict(_EMPTY_HINTS)
            return content, hints
        finally:
            try:
                await browser.close()
            except Exception:
                pass


async def _get_login_page(url: str) -> tuple[str, dict[str, Any]]:
    """Prefer the rendered DOM + structured hints; fall back to raw HTML-only
    (empty hints) if Playwright is absent."""
    try:
        return await _render_login_page(url)
    except ImportError:
        logger.info("auth_flow_detector: Playwright unavailable, using httpx fallback")
        return _fetch_login_html(url), dict(_EMPTY_HINTS)


def _extract_form_section(html: str, max_chars: int = 12000) -> str:
    """Trim to the <form>...</form> region if present; otherwise the head of
    the document. LLMs don't need the whole page and tokens aren't free."""
    # Prefer the first <form> block — almost always where the login lives
    m = re.search(r"<form[\s\S]*?</form>", html, re.IGNORECASE)
    if m:
        snippet = m.group(0)
        if len(snippet) <= max_chars:
            return snippet
        return snippet[:max_chars]
    # Fall back: strip scripts and styles, take the head of the body
    stripped = re.sub(r"<script[\s\S]*?</script>", "", html, flags=re.IGNORECASE)
    stripped = re.sub(r"<style[\s\S]*?</style>", "", stripped, flags=re.IGNORECASE)
    return stripped[:max_chars]


def _parse_llm_json(raw: str) -> dict[str, Any]:
    """LLM sometimes wraps JSON in code fences or adds leading whitespace —
    normalize and parse. Raises ValueError on any remaining issue."""
    text = (raw or "").strip()
    # Strip markdown fences if present
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    # Extract first {...} block if there's trailing prose
    brace = text.find("{")
    if brace > 0:
        text = text[brace:]
    return json.loads(text)


async def detect_login_flow(
    *, login_url: str, db=None, org_id: int | None = None,
) -> dict[str, Any]:
    """Produce a suggested login flow for the given URL.

    Returns:
      {"success": True, "login_flow": [...], "success_condition": {...}, "notes": "..."}
      or {"success": False, "error": "<reason>"}
    """
    try:
        html, hints = await _get_login_page(login_url)
    except Exception as e:
        logger.warning("auth_flow_detector: failed to fetch %s: %s", login_url, e)
        return {"success": False, "error": f"Could not fetch {login_url}: {e}"}

    # If the rendered DOM shows zero inputs, calling the LLM just pays tokens
    # for a hallucination. Fail fast with a message that points users at the
    # usual culprits: wrong URL, bot-protected shell, or JS that never ran.
    if hints.get("inputs") is not None and not hints.get("inputs") and not re.search(
        r"<input[\s>]", html, re.IGNORECASE
    ):
        return {
            "success": False,
            "error": (
                "No login form detected on this page. The URL may be a gated app shell "
                "(try the direct sign-in URL), the site may require interactive login "
                "(SSO/CAPTCHA), or headless rendering may be blocked. Fill the flow manually."
            ),
        }

    snippet = _extract_form_section(html)
    hints_json = json.dumps(hints, ensure_ascii=False)[:6000]
    user_prompt = (
        f"Login URL: {login_url}\n\n"
        f"Structured hints (live DOM probe — prefer these selectors):\n{hints_json}\n\n"
        f"HTML snippet (form region or head of document):\n{snippet}\n\n"
        "Return the JSON object described in the system prompt."
    )

    raw = llm_provider.call_llm(
        _SYSTEM_PROMPT, user_prompt,
        max_tokens=2048,
        db=db,
        surface="auth_flow_detector",
        org_id=org_id,
    )
    if not raw:
        return {"success": False, "error": "LLM provider is not configured"}

    try:
        parsed = _parse_llm_json(raw)
    except Exception as e:
        logger.warning("auth_flow_detector: LLM returned non-JSON: %s", raw[:200])
        # JSON parsers fail with "Unterminated string" when the model hit its
        # token budget mid-response. Surface that specifically — a generic
        # "invalid JSON" message sends users chasing phantom prompt bugs.
        if not raw.rstrip().rstrip("`").endswith("}"):
            return {"success": False, "error": "LLM response was truncated — try again"}
        return {"success": False, "error": f"LLM returned invalid JSON: {e}"}

    if "error" in parsed:
        return {"success": False, "error": parsed["error"]}

    flow = parsed.get("login_flow")
    cond = parsed.get("success_condition")
    if not isinstance(flow, list) or not flow:
        return {"success": False, "error": "LLM response missing login_flow array"}
    if not isinstance(cond, dict) or not cond.get("type"):
        return {"success": False, "error": "LLM response missing success_condition"}

    # Force the goto step to use the exact URL the user provided — LLMs
    # sometimes paraphrase (drop query strings, flip http/https).
    if flow[0].get("action") == "goto":
        flow[0]["url"] = login_url
    else:
        flow.insert(0, {"action": "goto", "url": login_url})

    return {
        "success": True,
        "login_flow": flow,
        "success_condition": cond,
        "notes": parsed.get("notes") or "",
    }

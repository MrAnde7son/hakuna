"""auth_flow_detector tests — Playwright render path + httpx fallback.

CI doesn't install browsers, so Playwright is mocked throughout. These
tests pin the wiring: SPA pages get rendered before the LLM sees them,
structured DOM hints are passed to the LLM alongside the HTML, and a
missing Playwright install falls back to raw httpx instead of crashing.
"""

import asyncio
from unittest.mock import AsyncMock, patch

from services import auth_flow_detector


_SAMPLE_HINTS = {
    "url": "https://example.com/login",
    "inputs": [
        {"tag": "input", "type": "email", "id": "email", "name": "email", "selector": "#email"},
        {"tag": "input", "type": "password", "id": "pw", "name": "password", "selector": "#pw"},
    ],
    "buttons": [
        {"tag": "button", "type": "submit", "text": "Sign in", "selector": "button[type=\"submit\"]"},
    ],
    "forms": [{"id": "login-form", "action": "/api/auth", "method": "post"}],
}


def test_get_login_page_prefers_playwright_render():
    """When Playwright is available, we render the page and return post-JS DOM
    + structured hints. httpx fallback stays unused.

    Regression guard: httpx.get on a SPA returns the shell, which leads the
    LLM to report "Login form content is dynamically loaded…" — the exact
    failure that motivated this module using a browser in the first place.
    """
    rendered_dom = "<html><body><input name='email'/><input type='password'/></body></html>"

    with patch.object(
        auth_flow_detector, "_render_login_page",
        new=AsyncMock(return_value=(rendered_dom, _SAMPLE_HINTS)),
    ) as mock_render, patch.object(
        auth_flow_detector, "_fetch_login_html"
    ) as mock_httpx:
        html, hints = asyncio.run(
            auth_flow_detector._get_login_page("https://cloud.tenable.com/")
        )

    assert html == rendered_dom
    assert hints == _SAMPLE_HINTS
    mock_render.assert_awaited_once()
    mock_httpx.assert_not_called()


def test_get_login_page_falls_back_to_httpx_when_playwright_missing():
    with patch.object(
        auth_flow_detector, "_render_login_page",
        new=AsyncMock(side_effect=ImportError("playwright not installed")),
    ), patch.object(
        auth_flow_detector, "_fetch_login_html",
        return_value="<html>raw shell</html>",
    ) as mock_httpx:
        html, hints = asyncio.run(
            auth_flow_detector._get_login_page("https://example.com/")
        )

    assert html == "<html>raw shell</html>"
    assert hints == auth_flow_detector._EMPTY_HINTS
    mock_httpx.assert_called_once_with("https://example.com/")


def test_detect_login_flow_uses_structured_hints_and_forces_goto_url():
    """End-to-end wiring: render → extract hints → LLM → shape response.

    We also verify the forced-goto override (LLMs sometimes paraphrase the
    URL and drop query strings), since that's the one non-trivial bit of
    business logic in detect_login_flow.
    """
    rendered_dom = "<html><input id='email'/><input id='pw' type='password'/></html>"
    llm_response = (
        '{"login_flow": ['
        '{"action": "goto", "url": "https://paraphrased.example.com/login"},'
        '{"action": "fill", "selector": "#email", "value_from": "username"},'
        '{"action": "fill", "selector": "#pw", "value_from": "password"},'
        '{"action": "click", "selector": "button[type=submit]"}'
        '], "success_condition": {"type": "url_matches", "pattern": "/app"},'
        ' "notes": "standard form"}'
    )
    captured_prompt = {}

    def fake_llm(system, user, **kw):
        captured_prompt["user"] = user
        return llm_response

    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(return_value=(rendered_dom, _SAMPLE_HINTS)),
    ), patch.object(
        auth_flow_detector.llm_provider, "call_llm",
        side_effect=fake_llm,
    ):
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://example.com/login?tenant=acme",
        ))

    assert result["success"] is True
    assert result["login_flow"][0]["url"] == "https://example.com/login?tenant=acme"
    assert result["success_condition"]["pattern"] == "/app"
    # Hints must reach the LLM — this is the whole point of the probe.
    assert "Structured hints" in captured_prompt["user"]
    assert "#email" in captured_prompt["user"] or "email" in captured_prompt["user"]


def test_detect_login_flow_short_circuits_when_dom_has_no_inputs():
    """Bot-protected shells (cloud.tenable.com under headless chromium) render
    zero inputs. Returning a direct error avoids paying LLM tokens for a
    hallucinated flow that will fail at Playwright time anyway."""
    shell_only = "<html><body><div id='root'></div></body></html>"
    empty_hints = {"url": "https://cloud.tenable.com/", "inputs": [], "buttons": [], "forms": []}

    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(return_value=(shell_only, empty_hints)),
    ), patch.object(
        auth_flow_detector.llm_provider, "call_llm",
    ) as mock_llm:
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://cloud.tenable.com/",
        ))

    assert result["success"] is False
    assert "No login form detected" in result["error"]
    mock_llm.assert_not_called()


def test_detect_login_flow_calls_llm_on_httpx_fallback_with_form_in_html():
    """httpx fallback path: hints are empty but HTML contains <input> markup —
    the LLM still gets a shot, using the HTML snippet alone."""
    html_with_form = (
        "<html><body><form><input name='user'/>"
        "<input type='password' name='pass'/></form></body></html>"
    )
    empty_hints = dict(auth_flow_detector._EMPTY_HINTS)
    llm_response = (
        '{"login_flow": [{"action": "goto", "url": "https://example.com/"}],'
        ' "success_condition": {"type": "url_matches", "pattern": "/home"}}'
    )

    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(return_value=(html_with_form, empty_hints)),
    ), patch.object(
        auth_flow_detector.llm_provider, "call_llm",
        return_value=llm_response,
    ) as mock_llm:
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://example.com/",
        ))

    assert result["success"] is True
    mock_llm.assert_called_once()


def test_detect_login_flow_surfaces_llm_error_payload():
    """If the LLM returns {"error": "..."}, surface it as a failure result."""
    html_with_form = "<html><body><input name='x'/></body></html>"
    empty_hints = dict(auth_flow_detector._EMPTY_HINTS)

    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(return_value=(html_with_form, empty_hints)),
    ), patch.object(
        auth_flow_detector.llm_provider, "call_llm",
        return_value='{"error": "no form detected"}',
    ):
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://example.com/",
        ))

    assert result["success"] is False
    assert "no form detected" in result["error"]


def test_detect_login_flow_reports_truncated_response_specifically():
    """Output budget overflow → clear "truncated" error, not the raw
    "Unterminated string" json.JSONDecodeError message."""
    truncated = '```json\n{\n  "login_flow": [\n    {"action": "goto",\n      "url": "https://cloud.tenable.com/tio/app'
    html_with_form = "<html><body><input name='x'/></body></html>"
    empty_hints = dict(auth_flow_detector._EMPTY_HINTS)

    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(return_value=(html_with_form, empty_hints)),
    ), patch.object(
        auth_flow_detector.llm_provider, "call_llm",
        return_value=truncated,
    ):
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://cloud.tenable.com/",
        ))

    assert result["success"] is False
    assert "truncated" in result["error"].lower()


def test_detect_login_flow_reports_fetch_failure():
    with patch.object(
        auth_flow_detector, "_get_login_page",
        new=AsyncMock(side_effect=RuntimeError("net unreachable")),
    ):
        result = asyncio.run(auth_flow_detector.detect_login_flow(
            login_url="https://offline.example.com/",
        ))

    assert result["success"] is False
    assert "net unreachable" in result["error"]

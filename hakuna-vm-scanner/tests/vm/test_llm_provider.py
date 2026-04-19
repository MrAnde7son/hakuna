"""Tests for the LLM provider resolver + message-format adapters.

Covers the deterministic surface:
  - resolve_provider priority order (matches backend get_default_model)
  - DB config wins over env; env fallback works
  - default_model override from DB is respected
  - Vertex AI gating on project presence (DB or env)
  - Anthropic → OpenAI message-format conversion
  - Anthropic → Gemini message-format conversion (requires SDK)
  - Gemini schema cleaning (strip unknown JSON-schema fields)

Adapter turn()s are NOT exercised against real providers — that belongs
in an integration suite. What we own here is the routing, priority, and
message conversion correctness.
"""

from __future__ import annotations

import json

import pytest

from scanner.vm.llm_provider import (
    LLMProviderInfo,
    _anthropic_to_openai_messages,
    _clean_gemini_schema,
    _coerce_gemini_tool_response,
    _coerce_tool_result_content,
    _guess_tool_name_for_result,
    _is_provider_configured,
    resolve_provider,
)


# ── Resolver priority + gating ───────────────────────────────────


class TestResolvePriority:
    def test_anthropic_wins_when_all_keys_present(self):
        """Same order as backend — Anthropic is priority 1."""
        info = resolve_provider(
            integration_configs={},
            env={
                "ANTHROPIC_API_KEY": "a",
                "OPENAI_API_KEY": "o",
                "GOOGLE_CLOUD_PROJECT": "p",
                "GOOGLE_API_KEY": "g",
                "GROQ_API_KEY": "r",
            },
        )
        assert info is not None
        assert info.provider == "anthropic"
        assert info.model == "claude-sonnet-4-6"

    def test_openai_selected_when_anthropic_missing(self):
        info = resolve_provider(
            integration_configs={},
            env={"OPENAI_API_KEY": "o", "GROQ_API_KEY": "r"},
        )
        assert info.provider == "openai"
        assert info.model == "gpt-4o"

    def test_vertex_beats_gemini_when_both_present(self):
        """This is the common case for a GCP deployment — users have
        both GOOGLE_CLOUD_PROJECT (for Vertex) and GOOGLE_API_KEY (for
        legacy Gemini SDK). Backend prefers Vertex. We must match."""
        info = resolve_provider(
            integration_configs={},
            env={"GOOGLE_CLOUD_PROJECT": "p", "GOOGLE_API_KEY": "g"},
        )
        assert info.provider == "vertex_ai"
        assert info.model == "vertex/gemini-2.5-flash"
        assert info.config["project_id"] == "p"

    def test_gemini_selected_when_only_api_key_present(self):
        info = resolve_provider(
            integration_configs={},
            env={"GOOGLE_API_KEY": "g"},
        )
        assert info.provider == "google_gemini"

    def test_returns_none_when_nothing_configured(self):
        """Air-gapped deployment — resolver must return None so the
        agent worker can skip with a clean reason."""
        assert resolve_provider(integration_configs={}, env={}) is None

    def test_groq_and_ollama_last(self):
        """Verify tail of the priority list behaves correctly."""
        info = resolve_provider(
            integration_configs={},
            env={"GROQ_API_KEY": "k"},
        )
        assert info.provider == "groq"

    def test_ollama_only_when_explicitly_enabled(self):
        """Ollama has no env-var gate — the DB row's is_enabled flag is
        the only signal. An unset row must not select Ollama."""
        assert resolve_provider(
            integration_configs={"ollama": {"is_enabled": False}},
            env={},
        ) is None

        info = resolve_provider(
            integration_configs={"ollama": {"is_enabled": True, "base_url": "http://ollama:11434"}},
            env={},
        )
        assert info.provider == "ollama"
        assert info.config["base_url"].endswith("/v1")


class TestDBOverridesEnv:
    def test_db_api_key_preferred_over_env(self):
        """Operator sets key in Settings > Integrations — that must
        beat any stale env var the scanner container inherits."""
        info = resolve_provider(
            integration_configs={"anthropic": {"is_enabled": True, "api_key": "db-key"}},
            env={"ANTHROPIC_API_KEY": "env-key"},
        )
        assert info.provider == "anthropic"
        assert info.config["api_key"] == "db-key"

    def test_db_default_model_override_respected(self):
        """UI lets users change the default model per provider — the
        scanner must honor that rather than baking in its own default."""
        info = resolve_provider(
            integration_configs={
                "anthropic": {"is_enabled": True, "api_key": "k", "default_model": "claude-opus-4-6"},
            },
            env={},
        )
        assert info.model == "claude-opus-4-6"

    def test_vertex_project_from_db_preferred_over_env(self):
        info = resolve_provider(
            integration_configs={"vertex_ai": {"project_id": "db-proj", "location": "europe-west1"}},
            env={"GOOGLE_CLOUD_PROJECT": "env-proj"},
        )
        assert info.provider == "vertex_ai"
        assert info.config["project_id"] == "db-proj"
        assert info.config["location"] == "europe-west1"

    def test_vertex_project_from_env_used_when_db_absent(self):
        info = resolve_provider(
            integration_configs={},
            env={"GOOGLE_CLOUD_PROJECT": "env-proj"},
        )
        assert info.provider == "vertex_ai"
        assert info.config["project_id"] == "env-proj"
        assert info.config["location"] == "us-central1"

    def test_gcloud_project_env_also_recognized(self):
        """Legacy env-var name — some GCP images export GCLOUD_PROJECT
        instead of GOOGLE_CLOUD_PROJECT. Must work for both."""
        info = resolve_provider(
            integration_configs={},
            env={"GCLOUD_PROJECT": "legacy-proj"},
        )
        assert info.provider == "vertex_ai"
        assert info.config["project_id"] == "legacy-proj"


class TestProviderConfiguredHelper:
    def test_api_key_gating_requires_a_key(self):
        assert not _is_provider_configured("anthropic", {}, {}, "ANTHROPIC_API_KEY")
        assert _is_provider_configured("anthropic", {"api_key": "k"}, {}, "ANTHROPIC_API_KEY")
        assert _is_provider_configured("anthropic", {}, {"ANTHROPIC_API_KEY": "k"}, "ANTHROPIC_API_KEY")

    def test_vertex_accepts_project_without_api_key(self):
        """Vertex uses ADC — no API key, just a project."""
        assert _is_provider_configured("vertex_ai", {"project_id": "p"}, {}, "GOOGLE_CLOUD_PROJECT")
        assert not _is_provider_configured("vertex_ai", {}, {}, "GOOGLE_CLOUD_PROJECT")


# ── Message-format conversion (Anthropic → OpenAI) ──────────────


class TestAnthropicToOpenAI:
    def test_plain_user_string_passthrough(self):
        out = _anthropic_to_openai_messages([{"role": "user", "content": "hi"}])
        assert out == [{"role": "user", "content": "hi"}]

    def test_assistant_with_text_only(self):
        out = _anthropic_to_openai_messages([
            {"role": "assistant", "content": [{"type": "text", "text": "hello"}]},
        ])
        assert out[0]["role"] == "assistant"
        assert out[0]["content"] == "hello"
        # No tool_calls when assistant didn't call any.
        assert "tool_calls" not in out[0] or out[0].get("tool_calls") is None

    def test_assistant_with_tool_use_emits_tool_calls(self):
        out = _anthropic_to_openai_messages([
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "running probe"},
                    {"type": "tool_use", "id": "tu1", "name": "http_request",
                     "input": {"url": "https://x/"}},
                ],
            },
        ])
        assert out[0]["role"] == "assistant"
        assert out[0]["content"] == "running probe"
        tc = out[0]["tool_calls"][0]
        assert tc["id"] == "tu1"
        assert tc["type"] == "function"
        assert tc["function"]["name"] == "http_request"
        assert json.loads(tc["function"]["arguments"]) == {"url": "https://x/"}

    def test_assistant_with_no_text_still_produces_content_key(self):
        """OpenAI rejects assistant messages missing `content`, even when
        `tool_calls` is present. Must set content=None as a placeholder."""
        out = _anthropic_to_openai_messages([
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "tu1", "name": "x", "input": {}}],
            },
        ])
        assert "content" in out[0]
        assert out[0]["content"] is None

    def test_tool_result_becomes_tool_message(self):
        out = _anthropic_to_openai_messages([
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu1",
                     "content": '{"status": 200}'},
                ],
            },
        ])
        assert len(out) == 1
        assert out[0]["role"] == "tool"
        assert out[0]["tool_call_id"] == "tu1"
        assert out[0]["content"] == '{"status": 200}'

    def test_mixed_user_text_and_tool_results_split_correctly(self):
        """If a user turn has both free text and tool_result blocks,
        OpenAI needs them split into separate messages."""
        out = _anthropic_to_openai_messages([
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "before"},
                    {"type": "tool_result", "tool_use_id": "tu1", "content": "r1"},
                    {"type": "text", "text": "between"},
                    {"type": "tool_result", "tool_use_id": "tu2", "content": "r2"},
                ],
            },
        ])
        roles = [m["role"] for m in out]
        assert roles == ["user", "tool", "user", "tool"]
        # tool_call_id pairing preserved
        tool_msgs = [m for m in out if m["role"] == "tool"]
        assert tool_msgs[0]["tool_call_id"] == "tu1"
        assert tool_msgs[1]["tool_call_id"] == "tu2"


class TestCoerceToolResultContent:
    def test_str_passthrough(self):
        assert _coerce_tool_result_content("hi") == "hi"

    def test_dict_json_encoded(self):
        assert _coerce_tool_result_content({"a": 1}) == '{"a": 1}'

    def test_list_json_encoded(self):
        assert _coerce_tool_result_content([1, 2]) == "[1, 2]"


# ── Gemini schema / tool-response helpers ────────────────────────


class TestCleanGeminiSchema:
    def test_strips_unknown_fields(self):
        """Gemini rejects JSON-Schema extensions (draft-specific keywords)
        that OpenAPI-style schemas often carry. Strip them."""
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string"},
            },
            "required": ["url"],
        }
        cleaned = _clean_gemini_schema(schema)
        assert "$schema" not in cleaned
        assert "additionalProperties" not in cleaned
        assert cleaned["type"] == "object"
        assert cleaned["required"] == ["url"]
        assert cleaned["properties"]["url"] == {"type": "string"}

    def test_recurses_into_nested_properties(self):
        schema = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "additionalProperties": True,
                    "properties": {"inner": {"type": "string", "$ref": "#/defs/x"}},
                },
            },
        }
        cleaned = _clean_gemini_schema(schema)
        assert "additionalProperties" not in cleaned["properties"]["outer"]
        assert "$ref" not in cleaned["properties"]["outer"]["properties"]["inner"]

    def test_recurses_into_array_items(self):
        schema = {"type": "array", "items": {"type": "string", "$ref": "x"}}
        cleaned = _clean_gemini_schema(schema)
        assert "$ref" not in cleaned["items"]

    def test_non_dict_returns_safe_default(self):
        assert _clean_gemini_schema("not a schema") == {"type": "object"}


class TestCoerceGeminiToolResponse:
    def test_dict_passthrough(self):
        assert _coerce_gemini_tool_response({"a": 1}) == {"a": 1}

    def test_json_string_decoded(self):
        assert _coerce_gemini_tool_response('{"a": 1}') == {"a": 1}

    def test_non_json_string_wrapped(self):
        """Gemini needs a dict — a bare string result gets wrapped in
        {"result": ...} so the SDK doesn't reject the turn."""
        assert _coerce_gemini_tool_response("plain text") == {"result": "plain text"}

    def test_none_becomes_result_none_string(self):
        assert _coerce_gemini_tool_response(None) == {"result": "None"}


class TestGuessToolName:
    def test_looks_up_name_by_id_from_history(self):
        """Gemini keys function_response by name; the agent loop carries
        only id. We must reverse-lookup the name from the previous
        assistant turn's tool_use blocks."""
        messages = [
            {"role": "user", "content": "start"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "tu1", "name": "http_request", "input": {}},
            ]},
        ]
        result_block = {"type": "tool_result", "tool_use_id": "tu1", "content": "{}"}
        assert _guess_tool_name_for_result(messages, result_block) == "http_request"

    def test_missing_id_falls_back_to_placeholder(self):
        assert _guess_tool_name_for_result([], {"tool_use_id": "nope"}) == "unknown_tool"


# ── Adapter construction (SDK availability smoke test) ──────────


class TestBuildAdapter:
    def test_unknown_provider_raises(self):
        from scanner.vm.llm_provider import LLMProviderError, build_adapter
        info = LLMProviderInfo(provider="fictional", model="x", config={})
        with pytest.raises(LLMProviderError):
            build_adapter(info)

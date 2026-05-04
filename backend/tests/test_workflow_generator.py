"""Unit tests for services/workflow_generator.py."""
import json

import pytest

from services import workflow_generator as wg


# ── _extract_json ────────────────────────────────────────────────────────────

def test_extract_json_plain():
    text = '{"name": "x", "nodes": []}'
    assert wg._extract_json(text) == {"name": "x", "nodes": []}


def test_extract_json_with_fence():
    text = 'Here you go:\n```json\n{"name": "x"}\n```\nDone.'
    assert wg._extract_json(text) == {"name": "x"}


def test_extract_json_with_prose_around():
    text = 'Sure! Here is the workflow:\n{"a": 1, "b": [1,2]}\nLet me know if you need changes.'
    assert wg._extract_json(text) == {"a": 1, "b": [1, 2]}


def test_extract_json_nested_braces():
    text = '{"name": "x", "config": {"nested": {"deep": true}}}'
    assert wg._extract_json(text) == {"name": "x", "config": {"nested": {"deep": True}}}


def test_extract_json_returns_none_on_garbage():
    assert wg._extract_json("not json at all") is None


def test_extract_json_returns_none_on_empty():
    assert wg._extract_json("") is None


# ── _validate_workflow ───────────────────────────────────────────────────────

def _good_workflow():
    return {
        "name": "Test", "description": "x",
        "nodes": [
            {"node_id": "t1", "node_type": "trigger", "node_subtype": "on_campaign_run",
             "label": "Trigger", "config": {}, "position_x": 60, "position_y": 200},
            {"node_id": "f1", "node_type": "filter", "node_subtype": "severity_filter",
             "label": "Filter", "config": {"operator": "gte", "value": "4"},
             "position_x": 360, "position_y": 200},
            {"node_id": "a1", "node_type": "action", "node_subtype": "slack_notify",
             "label": "Notify", "config": {}, "position_x": 660, "position_y": 200},
        ],
        "edges": [
            {"edge_id": "e1", "source_node_id": "t1", "target_node_id": "f1",
             "source_handle": "output", "target_handle": "input"},
            {"edge_id": "e2", "source_node_id": "f1", "target_node_id": "a1",
             "source_handle": "output", "target_handle": "input"},
        ],
    }


def test_validate_passes_clean_workflow():
    errors, warnings = wg._validate_workflow(_good_workflow())
    assert errors == []
    assert warnings == []


def test_validate_rejects_unknown_subtype():
    wf = _good_workflow()
    wf["nodes"][2]["node_subtype"] = "bogus_action"
    errors, _ = wg._validate_workflow(wf)
    assert any("bogus_action" in e for e in errors)


def test_validate_corrects_wrong_node_type():
    wf = _good_workflow()
    wf["nodes"][1]["node_type"] = "action"  # severity_filter is a filter
    errors, warnings = wg._validate_workflow(wf)
    assert errors == []
    assert any("corrected" in w for w in warnings)
    assert wf["nodes"][1]["node_type"] == "filter"  # fixed in place


def test_validate_requires_trigger():
    wf = _good_workflow()
    wf["nodes"] = [n for n in wf["nodes"] if n["node_type"] != "trigger"]
    wf["edges"] = []  # remove dangling edges
    errors, _ = wg._validate_workflow(wf)
    assert any("trigger" in e.lower() for e in errors)


def test_validate_rejects_dangling_edge():
    wf = _good_workflow()
    wf["edges"].append({
        "edge_id": "e_bad", "source_node_id": "f1", "target_node_id": "nonexistent",
        "source_handle": "output", "target_handle": "input",
    })
    errors, _ = wg._validate_workflow(wf)
    assert any("nonexistent" in e or "unknown node" in e for e in errors)


def test_validate_rejects_duplicate_node_id():
    wf = _good_workflow()
    wf["nodes"][1]["node_id"] = "t1"  # collide with trigger
    errors, _ = wg._validate_workflow(wf)
    assert any("duplicate" in e.lower() for e in errors)


def test_validate_warns_on_unknown_config_key():
    wf = _good_workflow()
    wf["nodes"][1]["config"]["bogus_key"] = "x"
    errors, warnings = wg._validate_workflow(wf)
    assert errors == []
    assert any("bogus_key" in w for w in warnings)


def test_validate_rejects_empty_workflow():
    errors, _ = wg._validate_workflow({"nodes": [], "edges": []})
    assert errors != []


# ── generate_workflow (end-to-end with mocked LLM) ───────────────────────────

class _StubRouter:
    def __init__(self, response):
        self._response = response
        self.last_call = None

    def call(self, db, *, system, user, max_tokens=2048, model=None):
        self.last_call = {"system": system, "user": user, "model": model}
        return self._response, "stub-model"


def test_generate_workflow_happy_path(monkeypatch):
    stub = _StubRouter(json.dumps(_good_workflow()))
    monkeypatch.setattr(wg, "llm_router", stub)

    result = wg.generate_workflow(db=None, description="critical findings to slack")
    assert result["name"] == "Test"
    assert len(result["nodes"]) == 3
    assert result["model"] == "stub-model"
    assert result["original_prompt"] == "critical findings to slack"
    assert result["warnings"] == []
    # Catalog should appear in the system prompt
    assert "on_campaign_run" in stub.last_call["system"]


def test_generate_workflow_handles_fenced_response(monkeypatch):
    fenced = "```json\n" + json.dumps(_good_workflow()) + "\n```"
    monkeypatch.setattr(wg, "llm_router", _StubRouter(fenced))
    result = wg.generate_workflow(db=None, description="x")
    assert len(result["nodes"]) == 3


def test_generate_workflow_raises_on_unparseable(monkeypatch):
    monkeypatch.setattr(wg, "llm_router", _StubRouter("Sorry, I can't help with that."))
    with pytest.raises(ValueError, match="parseable"):
        wg.generate_workflow(db=None, description="x")


def test_generate_workflow_raises_on_validation_failure(monkeypatch):
    bad = _good_workflow()
    bad["nodes"][2]["node_subtype"] = "totally_made_up"
    monkeypatch.setattr(wg, "llm_router", _StubRouter(json.dumps(bad)))
    with pytest.raises(ValueError, match="validation"):
        wg.generate_workflow(db=None, description="x")


def test_generate_workflow_rejects_empty_description():
    with pytest.raises(ValueError, match="required"):
        wg.generate_workflow(db=None, description="")


def test_generate_workflow_passes_warnings_through(monkeypatch):
    wf = _good_workflow()
    wf["nodes"][1]["config"]["bogus_key"] = "x"
    monkeypatch.setattr(wg, "llm_router", _StubRouter(json.dumps(wf)))
    result = wg.generate_workflow(db=None, description="x")
    assert any("bogus_key" in w for w in result["warnings"])

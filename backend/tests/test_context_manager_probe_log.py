"""Regression tests for hakuna.utils.context_manager probe-log behavior.

The old summary only carried "ssh_run_command×34" — the agent forgot what
it had already learned and re-ran the same probes until budget exhaustion.
The probe log now embeds tool_use+truncated_result pairs so the agent can
recognize prior observations.
"""

import json

from hakuna.utils.context_manager import (
    _build_probe_log,
    _build_summary,
    _format_tool_input,
    _format_tool_result,
    rolling_context,
)


def _assistant_tool_use(call_id: str, name: str, tool_input: dict) -> dict:
    return {
        "role": "assistant",
        "content": [{"type": "tool_use", "id": call_id, "name": name, "input": tool_input}],
    }


def _user_tool_result(call_id: str, content: str) -> dict:
    return {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": call_id, "content": content}],
    }


def test_format_tool_input_surfaces_command_for_shell_tools():
    out = _format_tool_input({"asset_id": 20, "command": "cat /etc/passwd"})
    assert out == "command=cat /etc/passwd"


def test_format_tool_input_falls_back_to_json_for_unknown_shape():
    out = _format_tool_input({"foo": "bar", "n": 3})
    assert "foo" in out and "bar" in out


def test_format_tool_result_extracts_stdout_from_relay_envelope():
    raw = json.dumps({
        "exit_code": 0,
        "stdout": "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin",
        "stderr": "",
        "error": None,
    })
    out = _format_tool_result(raw)
    assert "root:x:0:0:root" in out
    assert "exit=" not in out  # exit 0 isn't surfaced


def test_format_tool_result_surfaces_nonzero_exit_and_stderr():
    raw = json.dumps({
        "exit_code": 1,
        "stdout": "",
        "stderr": "permission denied",
        "error": None,
    })
    out = _format_tool_result(raw)
    assert "exit=1" in out
    assert "permission denied" in out


def test_format_tool_result_truncates_long_output():
    big = "x" * 5000
    raw = json.dumps({"exit_code": 0, "stdout": big, "stderr": "", "error": None})
    out = _format_tool_result(raw)
    assert len(out) <= 250
    assert out.endswith("…")


def test_probe_log_pairs_tool_use_with_tool_result():
    messages = [
        _assistant_tool_use("c1", "ssh_run_command", {"asset_id": 1, "command": "uname -a"}),
        _user_tool_result(
            "c1",
            json.dumps({"exit_code": 0, "stdout": "Linux ssh 6.12.72", "stderr": "", "error": None}),
        ),
        _assistant_tool_use("c2", "ssh_read_file", {"asset_id": 1, "path": "/etc/passwd"}),
        _user_tool_result(
            "c2",
            json.dumps({"exit_code": 0, "stdout": "root:x:0:0:root", "stderr": "", "error": None}),
        ),
    ]
    log = _build_probe_log(messages)
    assert len(log) == 2
    assert "ssh_run_command(command=uname -a) →" in log[0]
    assert "Linux ssh 6.12.72" in log[0]
    assert "ssh_read_file(path=/etc/passwd) →" in log[1]
    assert "root:x:0:0:root" in log[1]


def test_probe_log_skips_tool_use_with_no_matching_result():
    messages = [
        _assistant_tool_use("c1", "ssh_run_command", {"command": "uname -a"}),
        # No tool_result for c1 yet (race in trace) — should be skipped.
    ]
    assert _build_probe_log(messages) == []


def test_probe_log_caps_to_recent_entries():
    messages = []
    for i in range(60):
        messages.append(_assistant_tool_use(f"c{i}", "ssh_run_command", {"command": f"echo {i}"}))
        messages.append(_user_tool_result(
            f"c{i}",
            json.dumps({"exit_code": 0, "stdout": str(i), "stderr": "", "error": None}),
        ))
    log = _build_probe_log(messages)
    assert len(log) == 30
    # Most recent entries kept (echo 30..59), oldest dropped (echo 0..29).
    assert "echo 30" in log[0]
    assert "echo 59" in log[-1]


def test_summary_includes_probe_log_and_steers_toward_emit_finding():
    messages = [
        _assistant_tool_use("c1", "ssh_run_command", {"command": "cat /etc/passwd"}),
        _user_tool_result(
            "c1",
            json.dumps({"exit_code": 0, "stdout": "root:x:0:0:root:/root:/bin/sh", "stderr": "", "error": None}),
        ),
    ]
    summary = _build_summary(messages)
    assert "Probe log" in summary
    assert "do NOT re-run probes" in summary
    assert "emit_finding" in summary
    assert "cat /etc/passwd" in summary
    assert "root:x:0:0:root" in summary


def test_rolling_context_compression_now_carries_observed_data():
    """End-to-end: a 12-message history (well past the 5*2 cutoff) gets
    compressed. The synthetic summary message must contain the actual
    probe results, not just a tool-name tally."""
    messages = [{"role": "user", "content": "Audit this host"}]
    for i in range(6):
        messages.append(_assistant_tool_use(
            f"c{i}", "ssh_run_command", {"command": f"probe_{i}"},
        ))
        messages.append(_user_tool_result(
            f"c{i}",
            json.dumps({"exit_code": 0, "stdout": f"result_{i}", "stderr": "", "error": None}),
        ))
    compressed = rolling_context(messages, max_turns=5, keep_verbatim=3)
    assert compressed[0]["role"] == "user"
    summary_text = compressed[0]["content"]
    assert "Probe log" in summary_text
    # At least some of the older probe results survived the compression.
    assert any(f"result_{i}" in summary_text for i in range(6))


def test_rolling_context_short_history_is_unchanged():
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    assert rolling_context(messages, max_turns=5) == messages

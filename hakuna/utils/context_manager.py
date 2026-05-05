"""
Context Manager — rolling conversation history compression for multi-turn agents.

Prevents unbounded token growth in long multi-step agent runs by summarizing
old conversation turns into a compact summary while keeping recent turns verbatim.

Usage:
    from hakuna.utils.context_manager import rolling_context

    compressed_messages = rolling_context(messages, max_turns=5)
    # compressed_messages can be passed directly to cl.messages.create(messages=...)

The summary is injected as a synthetic "user" message at the start of the history
so the agent retains context about what was decided/done earlier without re-reading
every tool call/result pair.

Summary content:
    - Decisions made (triage calls, ticket IDs, campaign actions)
    - Assets processed
    - Tickets created
    - Pending actions
    - Tool calls invoked and their outcomes

Token budget:
    Full history          → O(steps × 600 tokens/step)
    Rolling history       → min(max_turns × 600, N) + ~200 (summary) tokens
    Typical saving        → 40-60% on runs with > 5 steps
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# ── Summary extractor ─────────────────────────────────────────────────

_DECISION_KEYWORDS = {
    "IMMEDIATE", "URGENT", "PLANNED", "MONITOR", "ACCEPT",
    "ticket", "campaign", "exception", "patch", "CVE",
    "created", "updated", "tagged", "escalated", "resolved",
}


def _extract_decisions(messages: List[Dict[str, Any]]) -> List[str]:
    """Extract decision-like sentences from assistant messages."""
    decisions = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    for line in block.get("text", "").splitlines():
                        if any(kw in line for kw in _DECISION_KEYWORDS):
                            decisions.append(line.strip()[:120])
        elif isinstance(content, str):
            for line in content.splitlines():
                if any(kw in line for kw in _DECISION_KEYWORDS):
                    decisions.append(line.strip()[:120])
    return decisions[:15]  # cap at 15 decisions in summary


def _extract_tool_calls(messages: List[Dict[str, Any]]) -> List[str]:
    """Extract tool call names from assistant content blocks."""
    tools_called = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    name = block.get("name", "?")
                    tools_called.append(name)
    return tools_called


# Maximum chars of a tool_result body to inline in the probe log. Long
# enough to expose key fields (sshd_config flags, /etc/passwd lines, find
# output) but short enough that 30 entries fit in a few KB.
_PROBE_RESULT_CAP = 240
# Cap on number of probe entries kept in the summary. Older ones are dropped
# (the high-level "Tools called: x×N" tally still records they happened).
_PROBE_LOG_MAX = 30
# Single-line input preview length for tool_use args.
_PROBE_INPUT_CAP = 160


def _format_tool_input(tool_input: Any) -> str:
    """One-line preview of a tool_use input, optimized for shell-style tools.
    For ssh_run_command/ssh_read_file we surface the command/path directly
    rather than dumping JSON, since that's what the agent needs to recognize
    'I already ran this'."""
    if not isinstance(tool_input, dict):
        return str(tool_input)[:_PROBE_INPUT_CAP]
    # Prefer the most diagnostic field if present
    for key in ("command", "path", "query", "url", "method"):
        if key in tool_input and isinstance(tool_input[key], str):
            return f"{key}={tool_input[key][:_PROBE_INPUT_CAP]}"
    try:
        s = json.dumps(tool_input, separators=(",", ":"), default=str)
    except TypeError:
        s = str(tool_input)
    return s[:_PROBE_INPUT_CAP]


def _format_tool_result(raw: Any) -> str:
    """One-line gist of a tool_result body. Tries to surface stdout when
    the relay returns the standard ``{exit_code, stdout, stderr, error}``
    envelope; otherwise truncates the raw string."""
    if isinstance(raw, str):
        # Cheap shortcut for the common shell-tool envelope.
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            stdout = obj.get("stdout")
            stderr = obj.get("stderr")
            err = obj.get("error")
            exit_code = obj.get("exit_code")
            parts = []
            if exit_code is not None and exit_code != 0:
                parts.append(f"exit={exit_code}")
            if stdout:
                parts.append(stdout.strip())
            elif stderr:
                parts.append(f"stderr: {stderr.strip()}")
            if err:
                parts.append(f"error: {err}")
            text = " | ".join(parts) if parts else raw
        else:
            text = raw
    else:
        try:
            text = json.dumps(raw, default=str)
        except TypeError:
            text = str(raw)
    text = " ".join(text.split())  # collapse whitespace
    if len(text) > _PROBE_RESULT_CAP:
        return text[:_PROBE_RESULT_CAP] + "…"
    return text


def _build_probe_log(messages: List[Dict[str, Any]]) -> List[str]:
    """Pair each tool_use block with its tool_result and render a compact
    one-line entry per pair. Returns the most recent ``_PROBE_LOG_MAX``
    entries — older ones are still represented in the high-level tool
    counter, but their bodies are dropped to bound size.

    Without this, the rolling-context summary only told the agent what it
    *did*, not what it *learned*. The agent would re-run probes from
    scratch — burning the step budget without ever reaching emit_finding.
    """
    # Index tool_results by tool_use_id so we can match them to calls.
    results_by_id: Dict[str, Any] = {}
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                tid = block.get("tool_use_id")
                if tid:
                    results_by_id[tid] = block.get("content", "")

    entries: List[str] = []
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", "")
        if not isinstance(content, list):
            continue
        for block in content:
            if not (isinstance(block, dict) and block.get("type") == "tool_use"):
                continue
            name = block.get("name", "?")
            input_preview = _format_tool_input(block.get("input"))
            tid = block.get("id", "")
            result = results_by_id.get(tid)
            if result is None:
                # Tool result not yet available (race in trace) — skip.
                continue
            result_preview = _format_tool_result(result)
            entries.append(f"{name}({input_preview}) → {result_preview}")

    # Keep the most recent N — older facts are usually superseded.
    if len(entries) > _PROBE_LOG_MAX:
        entries = entries[-_PROBE_LOG_MAX:]
    return entries


def _extract_assets_processed(messages: List[Dict[str, Any]]) -> List[str]:
    """Extract asset IPs/hostnames mentioned in tool results."""
    assets = []
    seen = set()
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                result_str = block.get("content", "")
                try:
                    result = json.loads(result_str) if isinstance(result_str, str) else result_str
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(result, list):
                    for item in result:
                        if isinstance(item, dict):
                            for field in ("ip", "asset_ip", "hostname"):
                                val = item.get(field)
                                if val and val not in seen:
                                    seen.add(val)
                                    assets.append(str(val))
                                    if len(assets) >= 10:
                                        return assets
    return assets


def _build_summary(old_messages: List[Dict[str, Any]]) -> str:
    """Build a compact summary of old conversation turns.

    Covers: decisions, tools used, assets processed, and a probe log of
    recent tool calls + result gists so the agent can recognize work it
    has already done instead of re-running the same probes.
    """
    decisions = _extract_decisions(old_messages)
    tools_called = _extract_tool_calls(old_messages)
    assets = _extract_assets_processed(old_messages)
    probe_log = _build_probe_log(old_messages)

    tool_summary = ""
    if tools_called:
        from collections import Counter
        tool_counts = Counter(tools_called)
        tool_summary = ", ".join(f"{t}×{c}" for t, c in tool_counts.most_common(8))

    lines = ["[CONVERSATION SUMMARY — earlier turns compressed]"]
    if decisions:
        lines.append("Decisions made: " + "; ".join(decisions[:8]))
    if tool_summary:
        lines.append(f"Tools called: {tool_summary}")
    if assets:
        lines.append("Assets processed: " + ", ".join(assets[:8]))
    if probe_log:
        lines.append("")
        lines.append(
            f"Probe log (last {len(probe_log)} calls — do NOT re-run probes "
            "whose results already appear here; reason from these and call "
            "emit_finding for each issue you've identified):"
        )
        lines.extend(probe_log)
    lines.append("")
    lines.append("[End of summary — recent turns follow verbatim]")

    return "\n".join(lines)


# ── Public API ────────────────────────────────────────────────────────

def rolling_context(
    history: List[Dict[str, Any]],
    max_turns: int = 5,
    keep_verbatim: int = 3,
) -> List[Dict[str, Any]]:
    """Compress conversation history to a rolling window.

    If len(history) <= max_turns, returns history unchanged.
    Otherwise, summarizes turns older than the last `keep_verbatim` turns
    into a single synthetic summary message and prepends it.

    A "turn" is one user+assistant exchange pair (2 messages), plus any
    tool_result messages that belong to that exchange.

    Args:
        history: Full message list as passed to cl.messages.create().
                 Expected format: [{"role": "user"|"assistant", "content": ...}, ...]
        max_turns: Maximum number of turns to keep before summarizing.
                   Defaults to 5 (as per spec).
        keep_verbatim: Number of most recent turns to keep verbatim.
                       Must be <= max_turns. Defaults to 3.

    Returns:
        Compressed message list safe to pass directly to the API.
    """
    if len(history) <= max_turns * 2:
        # No compression needed
        return history

    keep_verbatim = min(keep_verbatim, max_turns)
    # Preserve the last keep_verbatim * 2 messages verbatim
    cutoff = len(history) - (keep_verbatim * 2)
    if cutoff <= 0:
        return history

    old_messages = history[:cutoff]
    recent_messages = history[cutoff:]

    summary_text = _build_summary(old_messages)

    # Inject summary as a user message at the start of the compressed history
    summary_message = {
        "role": "user",
        "content": summary_text,
    }
    # Follow the summary with a synthetic assistant acknowledgment to maintain
    # the user/assistant turn alternation required by Anthropic's API
    ack_message = {
        "role": "assistant",
        "content": "Understood. I have reviewed the earlier context summary and will continue from where we left off.",
    }

    return [summary_message, ack_message] + recent_messages


def estimate_rolling_savings(
    history: List[Dict[str, Any]],
    max_turns: int = 5,
) -> Dict[str, Any]:
    """Estimate token savings from applying rolling_context().

    Returns dict with original_tokens, compressed_tokens, savings_pct.
    """
    original_json = json.dumps(history)
    original_tokens = len(original_json) // 4

    compressed = rolling_context(history, max_turns=max_turns)
    compressed_json = json.dumps(compressed)
    compressed_tokens = len(compressed_json) // 4

    reduction = round((1 - compressed_tokens / max(original_tokens, 1)) * 100, 1)
    return {
        "original_turns": len(history),
        "compressed_turns": len(compressed),
        "original_tokens": original_tokens,
        "compressed_tokens": compressed_tokens,
        "reduction_pct": reduction,
        "tokens_saved": original_tokens - compressed_tokens,
    }

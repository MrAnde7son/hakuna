"""
TokenTracker — centralized token consumption tracking for all LLM API calls.

Usage:
    from hakuna.utils.token_tracker import get_tracker, track_tokens

    tracker = get_tracker()

    # Decorator form:
    @track_tokens("my_agent")
    def call_llm(...):
        response = client.messages.create(...)
        return response          # must return Anthropic response object

    # Manual form (inside loops / multi-step runs):
    response = client.messages.create(...)
    tracker.track_call(
        agent_name="daily_triage",
        model="claude-sonnet-4-6",
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        cached_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
        call_metadata={"step": step, "function": "_run_anthropic"},
    )
"""
from __future__ import annotations

import functools
import json
import logging
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Pricing table (per 1M tokens, USD) ────────────────────────────────
#   Source: Anthropic pricing page, March 2026
#   cache_write costs same as regular input tokens
_PRICING: Dict[str, Dict[str, float]] = {
    "claude-sonnet-4-6": {
        "input": 3.00,
        "output": 15.00,
        "cache_read": 0.30,
    },
    "claude-haiku-4-5-20251001": {
        "input": 0.80,
        "output": 4.00,
        "cache_read": 0.08,
    },
    # Fallback for unknown Sonnet/Haiku variants
    "claude-sonnet": {
        "input": 3.00,
        "output": 15.00,
        "cache_read": 0.30,
    },
    "claude-haiku": {
        "input": 0.80,
        "output": 4.00,
        "cache_read": 0.08,
    },
    "claude-opus-4-6": {
        "input": 15.00,
        "output": 75.00,
        "cache_read": 1.50,
    },
}

_DEFAULT_PRICING = {"input": 3.00, "output": 15.00, "cache_read": 0.30}


def _get_pricing(model: str) -> Dict[str, float]:
    """Return pricing for a model, falling back to prefix matching then default."""
    if model in _PRICING:
        return _PRICING[model]
    for prefix, pricing in _PRICING.items():
        if model.startswith(prefix):
            return pricing
    return _DEFAULT_PRICING


def _cost_usd(input_tokens: int, output_tokens: int, cached_tokens: int, model: str) -> float:
    """Compute total USD cost for a single API call."""
    p = _get_pricing(model)
    billable_input = max(0, input_tokens - cached_tokens)
    cost = (
        billable_input * p["input"] / 1_000_000
        + output_tokens * p["output"] / 1_000_000
        + cached_tokens * p["cache_read"] / 1_000_000
    )
    return round(cost, 8)


# ── TokenTracker ──────────────────────────────────────────────────────

class TokenTracker:
    """Singleton token tracker for a pipeline run.

    Thread-safe: uses a lock for all mutations.

    All costs are in USD. Token counts are integers.
    Cached tokens = cache_read_input_tokens from Anthropic usage object.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._calls: List[Dict[str, Any]] = []
        self._session_start = datetime.utcnow().isoformat()

    def track_call(
        self,
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        call_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a single API call and its token usage.

        Returns the call record (for logging / chaining).
        """
        cost = _cost_usd(input_tokens, output_tokens, cached_tokens, model)
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_name": agent_name,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "total_tokens": input_tokens + output_tokens,
            "cost_usd": cost,
            "metadata": call_metadata or {},
        }
        with self._lock:
            self._calls.append(record)

        logger.debug(
            "TokenTracker | agent=%s model=%s in=%d out=%d cached=%d cost=$%.6f",
            agent_name, model, input_tokens, output_tokens, cached_tokens, cost,
        )
        return record

    def get_session_summary(self) -> Dict[str, Any]:
        """Return aggregate stats and per-agent breakdown for this session."""
        with self._lock:
            calls = list(self._calls)

        if not calls:
            return {
                "session_start": self._session_start,
                "total_calls": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_cached_tokens": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "per_agent": {},
                "per_model": {},
            }

        total_input = sum(c["input_tokens"] for c in calls)
        total_output = sum(c["output_tokens"] for c in calls)
        total_cached = sum(c["cached_tokens"] for c in calls)
        total_cost = sum(c["cost_usd"] for c in calls)

        # Per-agent breakdown
        per_agent: Dict[str, Any] = {}
        for c in calls:
            a = c["agent_name"]
            if a not in per_agent:
                per_agent[a] = {
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cached_tokens": 0,
                    "cost_usd": 0.0,
                    "models_used": set(),
                }
            per_agent[a]["calls"] += 1
            per_agent[a]["input_tokens"] += c["input_tokens"]
            per_agent[a]["output_tokens"] += c["output_tokens"]
            per_agent[a]["cached_tokens"] += c["cached_tokens"]
            per_agent[a]["cost_usd"] = round(per_agent[a]["cost_usd"] + c["cost_usd"], 8)
            per_agent[a]["models_used"].add(c["model"])

        # Convert sets to lists for JSON serialization
        for a in per_agent:
            per_agent[a]["models_used"] = list(per_agent[a]["models_used"])

        # Per-model breakdown
        per_model: Dict[str, Any] = {}
        for c in calls:
            m = c["model"]
            if m not in per_model:
                per_model[m] = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
            per_model[m]["calls"] += 1
            per_model[m]["input_tokens"] += c["input_tokens"]
            per_model[m]["output_tokens"] += c["output_tokens"]
            per_model[m]["cost_usd"] = round(per_model[m]["cost_usd"] + c["cost_usd"], 8)

        return {
            "session_start": self._session_start,
            "generated_at": datetime.utcnow().isoformat(),
            "total_calls": len(calls),
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_cached_tokens": total_cached,
            "total_tokens": total_input + total_output,
            "total_cost_usd": round(total_cost, 6),
            "per_agent": per_agent,
            "per_model": per_model,
        }

    def get_call_log(self) -> List[Dict[str, Any]]:
        """Return the full ordered log of all API calls this session."""
        with self._lock:
            return list(self._calls)

    def reset(self):
        """Clear all recorded calls (start a new session)."""
        with self._lock:
            self._calls.clear()
            self._session_start = datetime.utcnow().isoformat()

    def save_report(self, path: str) -> None:
        """Write a JSON report to disk at the given path."""
        import os
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        report = {
            "summary": self.get_session_summary(),
            "calls": self.get_call_log(),
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info("TokenTracker report saved to %s", path)


# ── Singleton ─────────────────────────────────────────────────────────

_tracker_instance: Optional[TokenTracker] = None
_tracker_lock = threading.Lock()


def get_tracker() -> TokenTracker:
    """Return the process-level singleton TokenTracker instance."""
    global _tracker_instance
    if _tracker_instance is None:
        with _tracker_lock:
            if _tracker_instance is None:
                _tracker_instance = TokenTracker()
    return _tracker_instance


def reset_tracker() -> TokenTracker:
    """Reset the singleton and return a fresh instance (for testing)."""
    global _tracker_instance
    with _tracker_lock:
        _tracker_instance = TokenTracker()
    return _tracker_instance


# ── Decorator ─────────────────────────────────────────────────────────

def track_tokens(agent_name: str):
    """Decorator that wraps a function making a single Anthropic API call.

    The wrapped function must return an Anthropic Message response object
    that has a .usage attribute with .input_tokens, .output_tokens, and
    optionally .cache_read_input_tokens.

    Example:
        @track_tokens("connectivity_test")
        def _test_call(client, model):
            return client.messages.create(model=model, max_tokens=10,
                                           messages=[{"role": "user", "content": "Hi"}])
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = fn(*args, **kwargs)
            # Extract token usage from Anthropic response object
            if result is not None and hasattr(result, "usage"):
                usage = result.usage
                get_tracker().track_call(
                    agent_name=agent_name,
                    model=getattr(result, "model", "unknown"),
                    input_tokens=getattr(usage, "input_tokens", 0),
                    output_tokens=getattr(usage, "output_tokens", 0),
                    cached_tokens=getattr(usage, "cache_read_input_tokens", 0),
                    call_metadata={"function": fn.__name__},
                )
            return result
        return wrapper
    return decorator

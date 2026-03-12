"""
CampaignScratchpad — persistent campaign state for multi-session remediation campaigns.

Agents read the scratchpad at the start of each turn (< 500 tokens) instead of
receiving full conversation history. Agents write updates at the end of each turn.

Usage:
    from hakuna.utils.scratchpad import CampaignScratchpad

    pad = CampaignScratchpad(campaign_id="campaign_42")

    # At turn start: read state summary (< 500 tokens)
    context = pad.get_context_for_llm()
    # → compact JSON string safe to inject into agent input

    # At turn end: write updates
    pad.update({
        "tickets_created": ["JIRA-101", "JIRA-102"],
        "assets_remediated": ["10.0.0.1"],
        "pending_actions": ["Patch CVE-2021-44228 on web-server-03"],
    })

    # Save to disk
    pad.flush()

Storage: one JSON file per campaign_id at reports/campaign_states/{campaign_id}.json
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Campaign state directory (relative to repo root)
_STATE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "reports", "campaign_states"
)

# Maximum tokens for LLM context injection (enforced by truncation)
_MAX_CONTEXT_TOKENS = 500
_CHARS_PER_TOKEN = 4


class CampaignScratchpad:
    """Per-campaign persistent key-value state store.

    The scratchpad maintains:
        - assets_in_scope: list of asset IDs/IPs targeted by this campaign
        - assets_remediated: assets where remediation is confirmed complete
        - tickets_created: list of ticket IDs created this campaign
        - pending_actions: what still needs to be done
        - decisions: key decisions made by the agent across turns
        - turn_count: number of agent turns executed so far
        - created_at / last_updated: timestamps

    The `get_context_for_llm()` method returns a compact JSON summary
    that fits within 500 tokens for injection into the agent's input.
    """

    def __init__(self, campaign_id: str, state_dir: Optional[str] = None):
        self.campaign_id = str(campaign_id)
        self._dir = state_dir or _STATE_DIR
        self._path = os.path.join(self._dir, f"{self.campaign_id}.json")
        self._state: Dict[str, Any] = self._load()

    # ── Public API ────────────────────────────────────────────────────

    def get_context_for_llm(self) -> str:
        """Return a compact JSON summary of campaign state for LLM injection.

        Guaranteed to fit within _MAX_CONTEXT_TOKENS (~500 tokens / 2000 chars).
        Truncates lists if needed to stay within budget.
        """
        s = self._state

        summary = {
            "campaign_id": self.campaign_id,
            "turn": s.get("turn_count", 0),
            "scope": s.get("assets_in_scope", [])[:20],
            "remediated": s.get("assets_remediated", [])[:20],
            "tickets": s.get("tickets_created", [])[:15],
            "pending": s.get("pending_actions", [])[:10],
            "decisions": s.get("decisions", [])[-10:],  # last 10 decisions
        }

        text = json.dumps(summary, separators=(",", ":"))

        # Enforce token budget by progressively truncating
        budget = _MAX_CONTEXT_TOKENS * _CHARS_PER_TOKEN
        if len(text) <= budget:
            return text

        # Trim lists until within budget
        for key in ("decisions", "pending", "tickets", "remediated", "scope"):
            lst = summary.get(key, [])
            while lst and len(json.dumps(summary, separators=(",", ":"))) > budget:
                lst.pop()
            summary[key] = lst
            if len(json.dumps(summary, separators=(",", ":"))) <= budget:
                break

        return json.dumps(summary, separators=(",", ":"))

    def update(self, updates: Dict[str, Any]) -> None:
        """Merge updates into the scratchpad state.

        Supported update patterns:
            - Scalar fields (last_write wins): campaign_name, status, etc.
            - List fields (appended, deduplicated):
              assets_in_scope, assets_remediated, tickets_created,
              pending_actions, decisions
        """
        list_fields = {
            "assets_in_scope", "assets_remediated", "tickets_created",
            "pending_actions", "decisions",
        }

        for key, value in updates.items():
            if key in list_fields:
                existing = self._state.get(key, [])
                if isinstance(value, list):
                    # Append and deduplicate
                    combined = existing + [v for v in value if v not in existing]
                    self._state[key] = combined
                else:
                    if value not in existing:
                        existing.append(value)
                    self._state[key] = existing
            else:
                self._state[key] = value

        self._state["turn_count"] = self._state.get("turn_count", 0) + 1
        self._state["last_updated"] = datetime.utcnow().isoformat()

    def remove_pending(self, action: str) -> None:
        """Remove a completed action from the pending_actions list."""
        pending = self._state.get("pending_actions", [])
        self._state["pending_actions"] = [p for p in pending if p != action]

    def get(self, key: str, default: Any = None) -> Any:
        """Read a specific key from the scratchpad state."""
        return self._state.get(key, default)

    def flush(self) -> None:
        """Persist current state to disk."""
        os.makedirs(self._dir, exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._state, f, indent=2, default=str)
        logger.debug("CampaignScratchpad flushed: %s", self._path)

    def reset(self) -> None:
        """Clear all state (start fresh for this campaign ID)."""
        self._state = self._initial_state()
        if os.path.exists(self._path):
            os.remove(self._path)

    def to_dict(self) -> Dict[str, Any]:
        """Return full state as a plain dict."""
        return dict(self._state)

    # ── Internal ──────────────────────────────────────────────────────

    def _initial_state(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "turn_count": 0,
            "assets_in_scope": [],
            "assets_remediated": [],
            "tickets_created": [],
            "pending_actions": [],
            "decisions": [],
            "created_at": datetime.utcnow().isoformat(),
            "last_updated": datetime.utcnow().isoformat(),
        }

    def _load(self) -> Dict[str, Any]:
        """Load state from disk. Returns initial state if file missing/corrupt."""
        if not os.path.exists(self._path):
            return self._initial_state()
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("CampaignScratchpad: failed to load %s: %s", self._path, e)
            return self._initial_state()

"""LLM-assisted source mapping inference.

Problem: format parsers (CEF/LEEF/HEC/JSON) produce a fixed canonical schema
(event_type, outcome, action, user_name, source_ip, dest_ip, host_name, …).
When a source sends unstructured messages like `"Failed password for root from
192.168.1.100 port 22 ssh2"`, those typed fields stay empty and rules that
depend on them silently miss.

Approach:
1. At onboarding, sample N real events (or the connector's `sample_payload`).
2. Ask an LLM, once, to propose a list of deterministic extractors (regex /
   JSONPath / constants / value-maps) that populate the canonical fields from
   what's actually in the payloads.
3. Persist the spec on the ingest endpoint.
4. At runtime, `apply_extractors` runs the spec deterministically for every
   event — zero LLM calls in the hot path.

The runtime is pure, testable, and cheap. The LLM only runs at onboarding and
when the operator re-infers because new event shapes have arrived.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Canonical SIEMEvent fields that extractors can write to.
# Kept in sync with SIEMEvent columns the detection engine filters on.
CANONICAL_FIELDS = (
    "event_type",
    "event_category",
    "severity",
    "action",
    "outcome",
    "user_name",
    "source_ip",
    "dest_ip",
    "host_name",
    "message",
)

# Hard limits to keep the spec bounded and the runtime fast.
MAX_EXTRACTORS = 24
MAX_SAMPLES = 50
MAX_SAMPLE_CHARS = 2000


# ─────────────────────────────────────────────────────────
# Extractor schema
# ─────────────────────────────────────────────────────────
#
# A spec is:
#   {
#     "version": 1,
#     "generated_at": "2026-04-16T12:43:12",
#     "model": "claude-haiku-4-5-20251001",
#     "sample_count": 50,
#     "extractors": [ <extractor>, ... ]
#   }
#
# Supported extractor shapes:
#
# regex on a parsed field (commonly "message"):
#   { "target": "outcome",
#     "type": "regex", "source": "message",
#     "pattern": "(?i)\\bfailed\\b",
#     "if_match": "failure" }
#
#   { "target": "user_name",
#     "type": "regex", "source": "message",
#     "pattern": "for (\\w+) from",
#     "group": 1 }
#
# JSONPath-lite on the raw payload (dot notation, supports list[0]):
#   { "target": "user_name",
#     "type": "jsonpath", "source": "raw",
#     "path": "event.user" }
#
# constant (fills empty field with a fixed value — useful when every event from
# this source is the same event_type):
#   { "target": "event_type", "type": "constant", "value": "authentication" }
#
# value map (normalize raw strings into canonical values):
#   { "target": "outcome", "type": "map", "source": "message",
#     "cases": [
#       {"pattern": "(?i)fail|denied|invalid", "value": "failure"},
#       {"pattern": "(?i)accept|success",      "value": "success"}
#     ] }


# ─────────────────────────────────────────────────────────
# Runtime: apply extractors
# ─────────────────────────────────────────────────────────

def apply_extractors(event: dict, spec: Optional[dict]) -> dict:
    """Apply a compiled extractor spec to an event dict.

    Only fills canonical fields that are currently empty (None/"") so the
    format parser's output always wins. Returns the same dict mutated in place.
    Never raises — malformed extractors are skipped with a debug log.
    """
    if not spec or not isinstance(spec, dict):
        return event

    extractors = spec.get("extractors") or []
    if not isinstance(extractors, list):
        return event

    for ex in extractors:
        try:
            _apply_one(event, ex)
        except Exception as e:  # pragma: no cover — defensive
            logger.debug("Extractor failed: %s (%s)", ex, e)

    return event


def _apply_one(event: dict, ex: dict) -> None:
    target = ex.get("target")
    if target not in CANONICAL_FIELDS:
        return
    # Never overwrite a value the format parser already populated.
    current = event.get(target)
    if current not in (None, ""):
        return

    ex_type = ex.get("type")
    if ex_type == "constant":
        val = ex.get("value")
        if val not in (None, ""):
            event[target] = val
        return

    src_val = _resolve_source(event, ex)
    if src_val in (None, ""):
        return

    if ex_type == "regex":
        pattern = ex.get("pattern")
        if not pattern:
            return
        m = re.search(pattern, str(src_val))
        if not m:
            return
        if "group" in ex:
            try:
                event[target] = m.group(int(ex["group"]))
            except (IndexError, ValueError):
                return
        elif "if_match" in ex:
            event[target] = ex["if_match"]
        else:
            # If there's a capture group, use it; otherwise the full match.
            event[target] = m.group(1) if m.groups() else m.group(0)

    elif ex_type == "jsonpath":
        path = ex.get("path")
        if not path:
            return
        val = _read_jsonpath(src_val, path)
        if val not in (None, ""):
            event[target] = val

    elif ex_type == "map":
        for case in ex.get("cases") or []:
            pat = case.get("pattern")
            val = case.get("value")
            if not pat or val is None:
                continue
            if re.search(pat, str(src_val)):
                event[target] = val
                return


def _resolve_source(event: dict, ex: dict) -> Any:
    """Resolve the `source` field of an extractor.

    "message" / any canonical field name → read from event top-level.
    "raw"  → return the raw payload dict (for jsonpath).
    """
    src = ex.get("source", "message")
    if src == "raw":
        return event.get("raw")
    return event.get(src)


def _read_jsonpath(obj: Any, path: str) -> Any:
    """Minimal JSONPath-lite: dot-separated keys, list indexing via [N]."""
    if obj is None or not path:
        return None
    cur = obj
    for part in _split_path(path):
        if isinstance(part, int):
            if isinstance(cur, list) and 0 <= part < len(cur):
                cur = cur[part]
            else:
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        if cur is None:
            return None
    return cur


_PATH_PART_RE = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _split_path(path: str) -> Iterable:
    for m in _PATH_PART_RE.finditer(path):
        key, idx = m.groups()
        if idx is not None:
            yield int(idx)
        else:
            yield key


# ─────────────────────────────────────────────────────────
# Onboarding: infer extractors from samples (LLM call)
# ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a SIEM log-normalization engineer.

You will receive a small set of sample events from a single log source. Each
sample is a JSON object with any shape. Your job is to produce a deterministic
extractor spec that, applied at ingest time, fills these canonical fields
(only when they are missing) so that downstream detection rules can match:

  event_type, event_category, severity, action, outcome,
  user_name, source_ip, dest_ip, host_name, message

You MUST return ONLY a JSON array of extractor objects — no prose, no markdown.

Each extractor is one of:

1) regex — pull a value from a string field (usually "message"):
   {"target": "<canonical>", "type": "regex", "source": "message",
    "pattern": "<python regex>", "group": <int, optional>,
    "if_match": "<literal to set when pattern matches, instead of a group>"}

2) jsonpath — pull from the raw payload (dot notation, supports [0]):
   {"target": "<canonical>", "type": "jsonpath", "source": "raw",
    "path": "event.user"}

3) constant — fixed value for every event from this source:
   {"target": "<canonical>", "type": "constant", "value": "authentication"}

4) map — normalize a string field to canonical values via patterns:
   {"target": "outcome", "type": "map", "source": "message",
    "cases": [
      {"pattern": "(?i)fail|denied|invalid", "value": "failure"},
      {"pattern": "(?i)accept|success",      "value": "success"}
    ]}

Rules:
- Only emit extractors that clearly apply across the samples you see.
- Prefer jsonpath when the value is already in the raw payload under a stable key.
- Prefer map over regex when normalizing text outcomes (failure/success).
- Keep the array short (<= 24 entries). No duplicates.
- Do NOT emit extractors for fields the samples already populate correctly.
- Outcome must be one of: success | failure | unknown.
- Severity must be one of: info | low | medium | high | critical.
"""


def infer_extractors_from_samples(db: Session, samples: list[dict], *,
                                   current_extractors: Optional[list] = None) -> dict:
    """Call the org's configured LLM once to produce an extractor spec.

    `samples` should be a list of event dicts post-format-parser (i.e. what
    `parse_events()` returns). Each dict typically has the canonical fields
    plus a `raw` payload.

    Provider selection follows `agents.agent_engine.get_default_model` — the
    org's configured provider wins (Anthropic / OpenAI / Gemini / Vertex / ...).

    Returns a compiled spec dict ready to store on IngestEndpoint.field_extractors.
    Raises RuntimeError if no LLM provider is configured or if the response is
    unparseable.
    """
    if not samples:
        raise ValueError("No samples provided")

    trimmed = _trim_samples(samples[:MAX_SAMPLES])
    user_message = json.dumps({"samples": trimmed}, default=str)[:150_000]

    from services.llm_dispatch import call_llm
    response_text, model_used = call_llm(db, _SYSTEM_PROMPT, user_message, max_tokens=2048)
    if not response_text:
        raise RuntimeError("LLM returned empty response")

    extractors = _parse_extractor_json(response_text)
    extractors = _sanitize_extractors(extractors)

    return {
        "version": 1,
        "generated_at": datetime.utcnow().isoformat(),
        "model": model_used,
        "sample_count": len(trimmed),
        "extractors": extractors[:MAX_EXTRACTORS],
    }


def _trim_samples(samples: list[dict]) -> list[dict]:
    """Drop bulky fields and cap total bytes to keep the prompt cheap."""
    trimmed = []
    for s in samples:
        # Keep both the parser's output and a compact view of the raw payload
        # so the LLM can see how to bridge them.
        entry = {k: s.get(k) for k in CANONICAL_FIELDS if s.get(k) not in (None, "")}
        raw = s.get("raw")
        if raw is not None:
            try:
                raw_str = json.dumps(raw, default=str)
            except (TypeError, ValueError):
                raw_str = str(raw)
            if len(raw_str) > MAX_SAMPLE_CHARS:
                raw_str = raw_str[:MAX_SAMPLE_CHARS] + "…"
            entry["raw"] = raw_str
        msg = s.get("message")
        if msg and "message" not in entry:
            entry["message"] = str(msg)[:MAX_SAMPLE_CHARS]
        trimmed.append(entry)
    return trimmed


def _parse_extractor_json(text: str) -> list:
    """Extract the JSON array from an LLM response tolerantly."""
    t = text.strip()
    # Strip ``` fences if present
    if t.startswith("```"):
        t = re.sub(r"^```\w*\n?", "", t)
        t = re.sub(r"\n?```$", "", t).strip()
    try:
        parsed = json.loads(t)
    except json.JSONDecodeError:
        m = re.search(r"\[.*\]", t, re.DOTALL)
        if not m:
            raise RuntimeError("LLM response was not valid JSON array")
        parsed = json.loads(m.group())
    if not isinstance(parsed, list):
        raise RuntimeError("LLM response was not a JSON array")
    return parsed


def _sanitize_extractors(raw: list) -> list:
    """Drop malformed extractors, compile-check regex patterns."""
    clean = []
    for ex in raw:
        if not isinstance(ex, dict):
            continue
        if ex.get("target") not in CANONICAL_FIELDS:
            continue
        ex_type = ex.get("type")
        if ex_type not in ("regex", "jsonpath", "constant", "map"):
            continue
        # Compile regex to surface bad patterns now rather than at runtime
        try:
            if ex_type == "regex":
                re.compile(ex.get("pattern", ""))
            elif ex_type == "map":
                for c in ex.get("cases") or []:
                    re.compile(c.get("pattern", ""))
        except re.error as e:
            logger.warning("Dropping extractor with invalid regex: %s (%s)", ex, e)
            continue
        clean.append(ex)
    return clean


# ─────────────────────────────────────────────────────────
# Preview: diff before/after
# ─────────────────────────────────────────────────────────

def preview_spec(samples: list[dict], spec: dict) -> list[dict]:
    """Return a before/after diff for each sample.

    Used by the onboarding UI so operators can see exactly which fields the
    spec populates before saving it.
    """
    out = []
    for s in samples:
        before = {k: s.get(k) for k in CANONICAL_FIELDS}
        after = {k: s.get(k) for k in CANONICAL_FIELDS}
        # Apply on a shallow copy so we don't mutate the caller's event
        working = dict(s)
        apply_extractors(working, spec)
        after = {k: working.get(k) for k in CANONICAL_FIELDS}
        filled = {k: after[k] for k in CANONICAL_FIELDS
                  if before.get(k) in (None, "") and after.get(k) not in (None, "")}
        out.append({
            "before": before,
            "after": after,
            "filled": filled,
        })
    return out



"""LLM feedback-loop logger + tenant-scoped exemplar retrieval.

Every LLM call — the agent loop and any one-shot services.llm_provider call
— passes through a span here. On span end we flush one row to the
`llm_interactions` table. A separate async job links each row to an outcome
signal (finding status, ticket resolution, approval decision, user rating)
and a nightly job populates the embedding column.

The retrieval path (`retrieve_exemplars`) pulls tenant-scoped, high-outcome
past interactions via pgvector cosine distance and returns them as few-shot
examples to inject into a fresh prompt — a lightweight feedback loop that
personalizes the LLM per org without fine-tuning.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, Optional

from core.database import SessionLocal

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────

_ENABLED = os.environ.get("LLM_FEEDBACK_ENABLED", "1") not in ("0", "false", "False")
_MAX_PROMPT_BYTES = int(os.environ.get("LLM_FEEDBACK_MAX_PROMPT_BYTES", "32000"))
_MAX_RESPONSE_BYTES = int(os.environ.get("LLM_FEEDBACK_MAX_RESPONSE_BYTES", "32000"))


# ── Redaction ──────────────────────────────────────────────────────────
# Run before writing prompts/responses to the log. Not exhaustive — the
# goal is to strip the obvious high-value secrets (API keys, tokens,
# passwords). Customers can extend via LLM_FEEDBACK_REDACT_EXTRA (regex,
# pipe-separated).

_BASE_REDACT_PATTERNS = [
    # Anthropic / OpenAI / Google style keys
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED:api-key]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-access-key]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "[REDACTED:github-token]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:slack-token]"),
    # Bearer tokens
    (re.compile(r"(?i)\b(bearer|authorization)\s*[:=]\s*[A-Za-z0-9._\-~+/]{16,}"), r"\1: [REDACTED]"),
    # password=..., password: ..., "password": "...", password "..." — any
    # of the common key/value shapes. Trailing value stops at quote/comma/
    # brace/whitespace so we don't eat surrounding JSON.
    # Exclude '[' from the value class so our own "[REDACTED]" output is
    # not itself treated as a value on a second pass (keeps redact()
    # idempotent).
    (re.compile(r'(?i)\b(password|passwd|pwd|api[_-]?key|secret|token)\b\s*["\']?\s*[:=]\s*["\']?([^"\'\[\],\s}]+)["\']?'),
     r'\1=[REDACTED]'),
    # JWT-ish (three dot-separated base64 segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED:jwt]"),
    # Private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED:private-key]"),
]


def _build_redact_patterns() -> list[tuple[re.Pattern, str]]:
    patterns = list(_BASE_REDACT_PATTERNS)
    extra = os.environ.get("LLM_FEEDBACK_REDACT_EXTRA", "")
    for pat in [p for p in extra.split("|") if p]:
        try:
            patterns.append((re.compile(pat), "[REDACTED:custom]"))
        except re.error:
            logger.warning("Invalid LLM_FEEDBACK_REDACT_EXTRA pattern skipped: %s", pat)
    return patterns


_REDACT_PATTERNS = _build_redact_patterns()


def redact(text: Optional[str]) -> tuple[Optional[str], bool]:
    """Return (redacted_text, did_redact). Idempotent on already-redacted input."""
    if not text:
        return text, False
    out = text
    did = False
    for pat, repl in _REDACT_PATTERNS:
        new = pat.sub(repl, out)
        if new != out:
            did = True
            out = new
    return out, did


def _truncate(text: Optional[str], max_bytes: int) -> Optional[str]:
    if text is None:
        return None
    b = text.encode("utf-8", errors="replace")
    if len(b) <= max_bytes:
        return text
    return b[:max_bytes].decode("utf-8", errors="replace") + "…[truncated]"


# ── Span state ─────────────────────────────────────────────────────────
# A span collects everything known about a single LLM call. Agents wrap a
# whole run in one span; the inner per-step provider calls attach their
# token counts to the same span. One-shot `call_llm()` uses a self-closing
# span per call.

@dataclass
class _Span:
    org_id: int
    surface: str
    user_id: Optional[int] = None
    surface_ref_type: Optional[str] = None
    surface_ref_id: Optional[str] = None
    agent_id: Optional[int] = None
    agent_run_id: Optional[int] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    system_prompt: Optional[str] = None
    messages: list = field(default_factory=list)
    response_text: Optional[str] = None
    tool_calls: list = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    error: Optional[str] = None
    status: str = "ok"
    started_at: float = field(default_factory=time.perf_counter)
    flushed: bool = False


_current: contextvars.ContextVar[Optional[_Span]] = contextvars.ContextVar("llm_feedback_span", default=None)


def current_span() -> Optional[_Span]:
    return _current.get()


# ── Public API ─────────────────────────────────────────────────────────

@contextmanager
def span(
    *,
    surface: str,
    org_id: Optional[int],
    user_id: Optional[int] = None,
    surface_ref_type: Optional[str] = None,
    surface_ref_id: Optional[str] = None,
    agent_id: Optional[int] = None,
    agent_run_id: Optional[int] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    system_prompt: Optional[str] = None,
    messages: Optional[list] = None,
) -> Iterator[Optional[_Span]]:
    """Open a logging span. On exit, the span is flushed to llm_interactions.

    Nested spans are collapsed: if a span is already active the inner block
    is a no-op and the outer span keeps collecting. This lets agent_engine
    open the outer run span while internal services.llm_provider calls made
    from tools (which also try to open a span) attach to the outer.

    org_id=None disables logging for this span (defensive — never log
    cross-tenant rows).
    """
    if not _ENABLED or org_id is None:
        yield None
        return

    outer = _current.get()
    if outer is not None:
        # Merge metadata that the outer might not yet have.
        outer.provider = outer.provider or provider
        outer.model = outer.model or model
        yield outer
        return

    s = _Span(
        org_id=org_id,
        surface=surface,
        user_id=user_id,
        surface_ref_type=surface_ref_type,
        surface_ref_id=surface_ref_id,
        agent_id=agent_id,
        agent_run_id=agent_run_id,
        provider=provider,
        model=model,
        system_prompt=system_prompt,
        messages=list(messages or []),
    )
    token = _current.set(s)
    try:
        yield s
    except Exception as exc:
        s.status = "error"
        s.error = str(exc)[:2000]
        raise
    finally:
        _current.reset(token)
        try:
            _flush(s)
        except Exception:
            logger.exception("llm_feedback: flush failed (non-fatal)")


def record_response(text: Optional[str], *, input_tokens: int = 0, output_tokens: int = 0) -> None:
    """Called from inside the span after the LLM returns.

    Accumulates tokens across multi-step agent runs. `text` is the most
    recent response (gets overwritten each step; the final step wins).
    """
    s = _current.get()
    if s is None:
        return
    if text is not None:
        s.response_text = text
    s.input_tokens += int(input_tokens or 0)
    s.output_tokens += int(output_tokens or 0)


_SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(password|passwd|pwd|api[_-]?key|secret|token|authorization|bearer|access[_-]?key)$"
)


def _redact_obj(obj: Any) -> Any:
    """Recursively scrub sensitive-looking keys in a dict/list tree."""
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if _SENSITIVE_KEY_RE.match(str(k)) else _redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    if isinstance(obj, str):
        red, _ = redact(obj)
        return red
    return obj


def record_tool_call(
    *,
    name: str,
    args: Optional[dict] = None,
    result: Any = None,
    ok: bool = True,
    duration_ms: Optional[int] = None,
) -> None:
    """Called from agent_engine._execute_tool. Stores a compact summary."""
    s = _current.get()
    if s is None:
        return
    safe_args = _redact_obj(args or {})
    result_summary = _summarize_result(result)
    s.tool_calls.append({
        "name": name,
        "args": safe_args,
        "result_summary": result_summary,
        "ok": ok,
        "ms": duration_ms,
    })


def record_error(exc: BaseException) -> None:
    s = _current.get()
    if s is None:
        return
    s.status = "error"
    s.error = f"{type(exc).__name__}: {exc}"[:2000]


def record_provider(provider: str, model: str) -> None:
    """Called when a span is opened without knowing the provider yet
    (e.g. agent_engine sets this after fallback resolution)."""
    s = _current.get()
    if s is None:
        return
    s.provider = provider
    s.model = model


def _summarize_result(result: Any) -> str:
    if result is None:
        return ""
    try:
        if isinstance(result, (dict, list)):
            text = json.dumps(result, default=str)
        else:
            text = str(result)
    except Exception:
        text = repr(result)
    red, _ = redact(text)
    return (red or "")[:2000]


# ── Flush path ─────────────────────────────────────────────────────────

def _flush(s: _Span) -> None:
    if s.flushed:
        return
    s.flushed = True
    latency_ms = int((time.perf_counter() - s.started_at) * 1000)

    system_prompt, redacted_sys = redact(s.system_prompt)
    response_text, redacted_resp = redact(s.response_text)
    did_redact = redacted_sys or redacted_resp

    # Messages may contain nested dicts; serialize → redact → reparse.
    messages_serialized = json.dumps(s.messages, default=str) if s.messages else "[]"
    messages_red, msg_redacted = redact(messages_serialized)
    try:
        messages_final = json.loads(messages_red) if messages_red else []
    except Exception:
        messages_final = [{"role": "raw", "content": messages_red or ""}]
    did_redact = did_redact or msg_redacted

    sph = None
    if system_prompt:
        sph = hashlib.sha1(system_prompt.encode("utf-8", errors="replace")).hexdigest()

    row = {
        "org_id": s.org_id,
        "user_id": s.user_id,
        "surface": s.surface,
        "surface_ref_type": s.surface_ref_type,
        "surface_ref_id": s.surface_ref_id,
        "agent_id": s.agent_id,
        "agent_run_id": s.agent_run_id,
        "provider": s.provider,
        "model": s.model,
        "system_prompt_hash": sph,
        "system_prompt": _truncate(system_prompt, _MAX_PROMPT_BYTES),
        "messages": messages_final,
        "response_text": _truncate(response_text, _MAX_RESPONSE_BYTES),
        "tool_calls": s.tool_calls,
        "input_tokens": s.input_tokens or None,
        "output_tokens": s.output_tokens or None,
        "latency_ms": latency_ms,
        "error": s.error,
        "status": s.status,
        "redacted": did_redact,
        "created_at": datetime.utcnow(),
    }

    # Short-lived write session — do not reuse the caller's session since
    # a caller rollback would also drop our audit row.
    db = SessionLocal()
    interaction_id: Optional[int] = None
    try:
        from models.models import LLMInteraction
        obj = LLMInteraction(**row)
        db.add(obj)
        db.commit()
        interaction_id = obj.id
    except Exception:
        db.rollback()
        logger.exception("llm_feedback: insert failed")
    finally:
        db.close()

    # Mirror to BigQuery for COGS tracking. Best-effort, non-blocking,
    # no-ops when COGS_BQ_DATASET is unset (dev/test).
    try:
        from services import cogs_writer
        cogs_writer.post(
            interaction_id=interaction_id,
            org_id=s.org_id,
            user_id=s.user_id,
            surface=s.surface,
            agent_id=s.agent_id,
            agent_run_id=s.agent_run_id,
            provider=s.provider,
            model=s.model,
            input_tokens=s.input_tokens or None,
            output_tokens=s.output_tokens or None,
            latency_ms=latency_ms,
            status=s.status,
            created_at=row["created_at"],
        )
    except Exception:
        logger.debug("cogs_writer.post raised (non-fatal)", exc_info=True)


# ── Retrieval (Postgres + pgvector only) ───────────────────────────────

def retrieve_exemplars(
    *,
    org_id: int,
    surface: str,
    query_text: str,
    k: int = 5,
    min_outcome_score: float = 0.5,
) -> list[dict]:
    """Return top-K past interactions for this org + surface ranked by
    embedding similarity and positive outcome_score.

    Returns [] when pgvector is unavailable or feedback is disabled —
    callers should treat "no exemplars" as the default state.
    """
    if not _ENABLED or not query_text:
        return []

    try:
        from services.llm_embeddings import embed_text
    except Exception:
        return []
    q_embed = embed_text(query_text)
    if q_embed is None:
        return []

    from sqlalchemy import text as _sql
    db = SessionLocal()
    try:
        rows = db.execute(
            _sql("""
                SELECT i.id, i.messages, i.response_text, i.tool_calls,
                       o.outcome_score
                FROM llm_interactions i
                JOIN llm_interaction_outcomes o
                  ON o.interaction_id = i.id
                WHERE i.org_id = :org_id
                  AND i.surface = :surface
                  AND i.embedding IS NOT NULL
                  AND o.outcome_score >= :min_score
                ORDER BY i.embedding <=> (:embedding)::vector
                LIMIT :k
            """),
            {
                "org_id": org_id,
                "surface": surface,
                "min_score": min_outcome_score,
                "embedding": q_embed,
                "k": k,
            },
        ).fetchall()
    except Exception:
        logger.exception("llm_feedback: retrieval failed")
        return []
    finally:
        db.close()

    return [
        {
            "id": r.id,
            "messages": r.messages,
            "response": r.response_text,
            "tool_calls": r.tool_calls,
            "score": r.outcome_score,
        }
        for r in rows
    ]


def format_exemplars_block(exemplars: list[dict]) -> str:
    """Render exemplars as a system-prompt block. Callers append this to
    their system prompt when `exemplars` is non-empty."""
    if not exemplars:
        return ""
    lines = [
        "## Examples from past interactions in this organization",
        "The following turns were rated helpful. Prefer consistent style and decisions:",
    ]
    for i, ex in enumerate(exemplars, 1):
        msgs = ex.get("messages") or []
        user_msg = next((m.get("content", "") for m in msgs if m.get("role") == "user"), "")
        response = ex.get("response") or ""
        lines.append(f"\n### Example {i}\nUser: {user_msg[:800]}\nAssistant: {response[:1200]}")
    return "\n".join(lines)

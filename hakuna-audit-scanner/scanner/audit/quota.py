"""Token-quota enforcement interface.

The engine asks ``QuotaProvider.check(org_id)`` *before* each LLM turn
and ``record(org_id, in, out)`` *after*. ``check`` raises
``QuotaExceeded`` when the org is over the limit; the engine catches
that and stops the run cleanly with ``stop_reason="quota_exceeded"``.

Two implementations ship:

  - ``NullQuotaProvider`` — no-op (OSS standalone). check() never
    raises, record() drops counts on the floor.
  - ``InMemoryQuotaProvider`` — useful for tests; counts in a dict.

The Hakuna backend ships its own ``SqlAlchemyQuotaProvider`` (in
``backend/services/audit_runner.py``) that calls
``core.token_quota.check_token_quota`` and ``increment_token_usage``.
The audit-scanner package never imports that — backend wires it via
the worker dispatch (``run_audit_scan(quota_provider=...)`` is not how
it's done; instead the worker imports a quota provider factory from
its config; see ``audit_worker.py`` for the resolution order).
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Protocol

logger = logging.getLogger(__name__)


class QuotaExceeded(Exception):
    """Raised by ``QuotaProvider.check`` when the org has hit its limit."""


class QuotaProvider(Protocol):
    def check(self, org_id: str | int | None) -> None: ...

    def record(
        self,
        org_id: str | int | None,
        input_tokens: int,
        output_tokens: int,
    ) -> None: ...


# ── Null impl (OSS standalone default) ───────────────────────────


class NullQuotaProvider:
    """No quotas. Used when no provider has been wired."""

    def check(self, org_id: str | int | None) -> None:
        return None

    def record(self, org_id: str | int | None, input_tokens: int, output_tokens: int) -> None:
        return None


# ── In-memory impl (useful for tests & local rate-caps) ──────────


class InMemoryQuotaProvider:
    """Per-process counter with a fixed monthly limit. Resets on
    process restart — not for production, but fine for tests and for
    smoke-checking that the engine actually invokes the provider."""

    def __init__(self, limit: int = 5_000_000):
        self._limit = limit
        self._counts: dict[str | int | None, int] = defaultdict(int)
        self._lock = threading.Lock()

    def check(self, org_id: str | int | None) -> None:
        with self._lock:
            used = self._counts.get(org_id, 0)
        if used >= self._limit:
            raise QuotaExceeded(
                f"org {org_id!r}: {used:,} / {self._limit:,} tokens used"
            )

    def record(self, org_id: str | int | None, input_tokens: int, output_tokens: int) -> None:
        delta = max(0, int(input_tokens or 0)) + max(0, int(output_tokens or 0))
        if not delta:
            return
        with self._lock:
            self._counts[org_id] += delta

    # Test helper — not in the protocol.
    def usage(self, org_id: str | int | None) -> int:
        with self._lock:
            return self._counts.get(org_id, 0)


# ── Factory + global injection point ─────────────────────────────


_provider: QuotaProvider = NullQuotaProvider()


def get_provider() -> QuotaProvider:
    """The engine reads through this so the backend can install a
    quota provider at startup without touching the Celery task signature.

    Backend wiring::

        from scanner.audit.quota import set_provider
        from backend.services.audit_runner import SqlAlchemyQuotaProvider
        set_provider(SqlAlchemyQuotaProvider())

    This module-level swap point keeps the OSS contract simple — no
    extra Celery kwargs, no plugin discovery — at the cost of one
    process-global. Each Celery worker process sets it once at
    startup.
    """
    return _provider


def set_provider(provider: QuotaProvider) -> None:
    global _provider
    _provider = provider
    logger.info("quota: provider set to %s", type(provider).__name__)

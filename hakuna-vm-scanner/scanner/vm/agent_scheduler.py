"""Frontier-based scheduler for specialist agents.

Replaces the single-pass ``for spec in selected`` loop with a worklist
driven by the capability store. After each specialist runs and commits
typed facts, the scheduler re-evaluates which specialists are now
applicable (or re-applicable under enriched context) and runs them
next. That's how the composition chain — authn finds creds, authz
re-runs with them — fires without any explicit "after X, do Y"
wiring.

Core invariants:

  - **Idempotency**: a specialist is only (re-)yielded when its input
    set has actually changed. "Input set" = the capability rows whose
    type appears in the spec's ``requires`` or ``augmented_by`` list
    at the spec's asset scope. An unrelated note landing in the store
    doesn't trigger a redundant re-run.
  - **Bounded**: a specialist is capped at ``spec.max_runs`` runs per
    scan. Belt-and-braces with the global ``max_chain_depth`` so a
    pathological idempotency-key drift (e.g. a timestamp sneaking
    into a value) can't spin forever.
  - **Deadline-aware**: the scheduler refuses to yield past
    ``ctx.deadline``. The per-specialist runner also honours a
    per-spec deadline — the outer cap here is just for the overall
    asset budget.
  - **Prerequisite gating**: specs with ``requires`` only become
    eligible once all required types are present. Empty ``requires``
    means "always eligible" — same behaviour as the pre-composition
    for-loop.

What this scheduler deliberately is NOT:

  - A planner. It doesn't predict which specialists a future spec's
    outputs would unlock. It reacts.
  - A priority engine with heuristics. Ties are broken by the fixed
    ``AGENT_CATEGORIES`` order — predictable beats clever for scans
    the user has to reason about.
  - Concurrent. Specialists run one at a time against the same asset
    (they share one rate-limited HTTP client and one capability store).
    Per-asset concurrency is an orthogonal layer above the scheduler.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field

from scanner.vm.agent_specialists import (
    AGENT_CATEGORIES,
    AgentContext,
    SpecialistSpec,
)
from scanner.vm.capabilities import asset_scope

logger = logging.getLogger(__name__)


# Outer safety limit on the total number of specialist executions per
# asset — belt-and-braces with ``spec.max_runs``. Tuned against typical
# fan-out (7 specialists × max 2 runs each = 14) plus headroom. Hitting
# this is a bug signal, not a normal scan outcome.
DEFAULT_MAX_CHAIN_DEPTH = 20


def idempotency_key(spec: SpecialistSpec, ctx: AgentContext) -> str:
    """Stable hash of the inputs this spec would see right now.

    The key folds in the spec category and, for each capability type in
    ``requires`` + ``augmented_by``, the dedup keys of matching caps at
    the asset scope. Two invariants:

      - Changes only when the spec's *relevant* input set changes.
        Unrelated caps landing in the store (e.g. a WAF note while
        computing the authz key) leave the key untouched.
      - Deterministic regardless of insertion order — we sort
        capability dedup keys before hashing so a race between two
        concurrent specialists committing caps doesn't produce
        different keys for the same effective state.
    """
    scope = asset_scope(ctx.asset_id)
    relevant_types = sorted(set(spec.requires) | set(spec.augmented_by))
    parts: list[str] = [f"cat={spec.category}"]
    for t in relevant_types:
        caps = ctx.capabilities.query(type=t, scope=scope)
        dedup_keys = sorted(repr(cap.dedup_key()) for cap in caps)
        parts.append(f"{t}={len(caps)}:{','.join(dedup_keys)}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def requires_satisfied(spec: SpecialistSpec, ctx: AgentContext) -> bool:
    """True when every type in ``spec.requires`` has at least one cap."""
    if not spec.requires:
        return True
    scope = asset_scope(ctx.asset_id)
    for t in spec.requires:
        if not ctx.capabilities.query(type=t, scope=scope):
            return False
    return True


@dataclass
class ScheduledRun:
    """Return record describing one scheduler decision.

    Carries enough context that the worker's specialists_run audit log
    can record *why* the spec was picked — particularly important for
    re-runs, so an operator reviewing a scan trace can see that authz
    ran twice because creds appeared, not because of a retry loop.
    """
    spec: SpecialistSpec
    run_number: int           # 1-indexed within this asset scan
    idempotency_key: str
    reason: str               # "baseline" | "composition" | "enriched"


@dataclass
class FrontierScheduler:
    """Stateful scheduler — call ``next`` in a loop until it returns None.

    The scheduler itself performs no I/O. The caller runs the returned
    spec (mutating ``ctx.capabilities`` via tool handlers as it goes)
    and then asks for the next one. That keeps the scheduler unit-
    testable without the httpx / LLM stack in scope.
    """
    specialists: list[SpecialistSpec]
    max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH
    _seen_keys: set[str] = field(default_factory=set)
    _run_counts: dict[str, int] = field(default_factory=dict)
    _total_runs: int = 0

    def next(self, ctx: AgentContext) -> ScheduledRun | None:
        """Return the next specialist to run, or ``None`` to stop."""
        if self._total_runs >= self.max_chain_depth:
            logger.info(
                "scheduler stopping: max_chain_depth=%d reached (total_runs=%d)",
                self.max_chain_depth, self._total_runs,
            )
            return None
        if time.monotonic() >= ctx.deadline:
            return None

        eligible = self._eligible(ctx)
        if not eligible:
            return None

        # Priority: fresh specs (run_count=0) before re-runs, and within
        # each tier the fixed AGENT_CATEGORIES order. Predictable
        # ordering lets the existing test suite's "injection runs before
        # authz when both apply" expectations stay intact, and matches
        # the baseline-then-composition story operators expect.
        eligible.sort(key=self._priority_key, reverse=True)
        spec = eligible[0]
        key = idempotency_key(spec, ctx)
        run_count = self._run_counts.get(spec.category, 0)
        run_number = run_count + 1

        self._seen_keys.add(key)
        self._run_counts[spec.category] = run_number
        self._total_runs += 1

        reason = self._classify_reason(spec, run_count)
        logger.info(
            "scheduler yielding spec=%s run=%d reason=%s key=%s",
            spec.category, run_number, reason, key,
        )
        return ScheduledRun(
            spec=spec, run_number=run_number,
            idempotency_key=key, reason=reason,
        )

    def _eligible(self, ctx: AgentContext) -> list[SpecialistSpec]:
        out: list[SpecialistSpec] = []
        for spec in self.specialists:
            if self._run_counts.get(spec.category, 0) >= spec.max_runs:
                continue
            if not spec.applicable_when(ctx):
                continue
            if not requires_satisfied(spec, ctx):
                continue
            key = idempotency_key(spec, ctx)
            if key in self._seen_keys:
                continue
            out.append(spec)
        return out

    def _priority_key(self, spec: SpecialistSpec) -> tuple:
        first_run = self._run_counts.get(spec.category, 0) == 0
        # AGENT_CATEGORIES gives stable intra-tier order. Specs not in
        # the registry sort last (shouldn't happen; defensive).
        try:
            cat_idx = AGENT_CATEGORIES.index(spec.category)
        except ValueError:
            cat_idx = len(AGENT_CATEGORIES)
        # Higher tuple sorts first under reverse=True. First tuple
        # element: first_run (True > False). Second: -cat_idx so
        # earlier categories rank higher.
        return (first_run, -cat_idx)

    def _classify_reason(self, spec: SpecialistSpec, prior_run_count: int) -> str:
        """Human-readable label for the scheduler trace."""
        if prior_run_count == 0:
            return "baseline" if not spec.requires else "composition"
        return "enriched"


__all__ = [
    "DEFAULT_MAX_CHAIN_DEPTH",
    "FrontierScheduler",
    "ScheduledRun",
    "idempotency_key",
    "requires_satisfied",
]

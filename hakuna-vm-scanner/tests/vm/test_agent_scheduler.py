"""Tests for the frontier scheduler.

The scheduler is the composition engine — if its idempotency or
re-run gating breaks, every planned exploit chain breaks silently.
These tests pin down the invariants without any LLM / httpx in scope:

  - Baseline: with an empty capability store, behaves like the old
    for-loop (each applicable spec runs exactly once, in
    AGENT_CATEGORIES order).
  - Composition: once authn commits a CRED capability, authz becomes
    eligible and re-runs with a new idempotency key.
  - Idempotency: an unrelated capability (a NOTE, a WAF flag) does
    NOT invalidate a spec's idempotency key — no spurious re-runs.
  - ``max_runs``: a spec is never yielded more than its own cap.
  - Global cap: ``max_chain_depth`` stops the scheduler even if the
    per-spec caps would allow more.
  - Deadline: past ``ctx.deadline``, the scheduler returns None.

The tests build ``SpecialistSpec`` instances directly with stub
``applicable_when`` predicates so we're exercising scheduler logic in
isolation, not the real specialist registry.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scanner.vm.agent_scheduler import (
    FrontierScheduler,
    idempotency_key,
    requires_satisfied,
)
from scanner.vm.agent_specialists import AgentContext, SpecialistSpec
from scanner.vm.capabilities import (
    Capability,
    CapabilityStore,
    CapabilityType,
    asset_scope,
)


def _ctx(**overrides) -> AgentContext:
    defaults = dict(
        asset_id="a-1", org_id="o-1",
        target="https://example.com",
        endpoints=[],
        headers={},
        http_client=None,
        rate_limiter=None,
        deadline=10**10,
    )
    defaults.update(overrides)
    return AgentContext(**defaults)


def _spec(
    category: str,
    *,
    applicable: bool = True,
    requires: tuple = (),
    augmented_by: tuple = (),
    max_runs: int = 1,
) -> SpecialistSpec:
    """Minimal stub SpecialistSpec — no prompt needed for scheduler tests."""
    return SpecialistSpec(
        category=category,
        display_name=f"{category.title()} Specialist",
        system_prompt="",
        max_iterations=1,
        applicable_when=lambda c, _a=applicable: _a,
        requires=requires,
        augmented_by=augmented_by,
        max_runs=max_runs,
    )


def _cred_cap(ctx: AgentContext) -> Capability:
    return Capability(
        type=CapabilityType.CRED,
        scope=asset_scope(ctx.asset_id),
        value={"scheme": "basic", "username": "admin", "password": "admin"},
        confidence=0.95,
        provenance="specialist:authn",
    )


def _note_cap(ctx: AgentContext, key: str = "waf_present") -> Capability:
    return Capability(
        type=CapabilityType.NOTE,
        scope=asset_scope(ctx.asset_id),
        value={"key": key, "text": "cloudflare"},
    )


class TestIdempotencyKey:
    def test_stable_for_identical_state(self):
        ctx = _ctx()
        spec = _spec("authz", augmented_by=(CapabilityType.CRED,))
        k1 = idempotency_key(spec, ctx)
        k2 = idempotency_key(spec, ctx)
        assert k1 == k2

    def test_changes_when_relevant_capability_appears(self):
        """The composition trigger — key must change on CRED commit so
        the scheduler sees authz as newly-eligible."""
        ctx = _ctx()
        spec = _spec("authz", augmented_by=(CapabilityType.CRED,))
        before = idempotency_key(spec, ctx)
        ctx.capabilities.add(_cred_cap(ctx))
        after = idempotency_key(spec, ctx)
        assert before != after

    def test_ignores_irrelevant_capabilities(self):
        """A NOTE capability has no bearing on authz's inputs. Key must
        stay stable so authz doesn't uselessly re-run on every note."""
        ctx = _ctx()
        spec = _spec("authz", augmented_by=(CapabilityType.CRED,))
        before = idempotency_key(spec, ctx)
        ctx.capabilities.add(_note_cap(ctx))
        after = idempotency_key(spec, ctx)
        assert before == after

    def test_different_specs_have_different_keys(self):
        """Two specs with the same augmented_by must not collide —
        authz and csrf both consuming CRED are distinct work items."""
        ctx = _ctx()
        ctx.capabilities.add(_cred_cap(ctx))
        k_authz = idempotency_key(
            _spec("authz", augmented_by=(CapabilityType.CRED,)), ctx,
        )
        k_csrf = idempotency_key(
            _spec("csrf", augmented_by=(CapabilityType.CRED,)), ctx,
        )
        assert k_authz != k_csrf


class TestRequiresSatisfied:
    def test_empty_requires_always_satisfied(self):
        assert requires_satisfied(_spec("xss"), _ctx()) is True

    def test_missing_required_type_blocks(self):
        spec = _spec("postauth_enum", requires=(CapabilityType.CRED,))
        assert requires_satisfied(spec, _ctx()) is False

    def test_all_required_types_present(self):
        ctx = _ctx()
        ctx.capabilities.add(_cred_cap(ctx))
        spec = _spec("postauth_enum", requires=(CapabilityType.CRED,))
        assert requires_satisfied(spec, ctx) is True

    def test_partial_requires_fails(self):
        """AND semantics: missing any required type blocks the spec."""
        ctx = _ctx()
        ctx.capabilities.add(_cred_cap(ctx))
        spec = _spec(
            "deep_enum",
            requires=(CapabilityType.CRED, CapabilityType.SESSION),
        )
        assert requires_satisfied(spec, ctx) is False


class TestFrontierSchedulerBaseline:
    def test_empty_specialist_list_stops_immediately(self):
        sched = FrontierScheduler(specialists=[])
        assert sched.next(_ctx()) is None

    def test_runs_each_applicable_spec_once(self):
        """Baseline behaviour with empty capability store — reproduces
        the pre-composition for-loop semantics."""
        specs = [_spec("injection"), _spec("xss"), _spec("authn")]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()
        order = []
        while (run := sched.next(ctx)) is not None:
            order.append(run.spec.category)
        assert order == ["injection", "xss", "authn"]

    def test_respects_agent_categories_order(self):
        """AGENT_CATEGORIES is the canonical order — scheduler must
        honour it so operators can reason about scan traces."""
        specs = [
            _spec("files"), _spec("authn"), _spec("injection"),
        ]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()
        order = []
        while (run := sched.next(ctx)) is not None:
            order.append(run.spec.category)
        # AGENT_CATEGORIES order: injection, xss, ssrf, authn, authz, csrf, files
        assert order == ["injection", "authn", "files"]

    def test_skips_inapplicable_specs(self):
        specs = [
            _spec("injection", applicable=True),
            _spec("authz", applicable=False),
            _spec("xss", applicable=True),
        ]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()
        order = []
        while (run := sched.next(ctx)) is not None:
            order.append(run.spec.category)
        assert order == ["injection", "xss"]

    def test_skips_specs_with_unmet_requires(self):
        """A spec requiring CRED stays out of the frontier while the
        store is empty — it should *become* eligible only after authn
        commits creds."""
        specs = [
            _spec("authn"),
            _spec("postauth_enum", requires=(CapabilityType.CRED,)),
        ]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()
        order = []
        while (run := sched.next(ctx)) is not None:
            order.append(run.spec.category)
        assert order == ["authn"]


class TestFrontierSchedulerComposition:
    def test_authz_reruns_after_creds_appear(self):
        """The canonical composition chain: authn runs first (baseline),
        commits CRED, authz was already eligible with no creds, but
        now gets a second run under enriched context."""
        specs = [
            _spec("authn"),
            _spec(
                "authz",
                augmented_by=(CapabilityType.CRED,),
                max_runs=2,
            ),
        ]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()

        run1 = sched.next(ctx)
        assert run1.spec.category == "authn"
        assert run1.reason == "baseline"

        # authz runs once with no creds — baseline.
        run2 = sched.next(ctx)
        assert run2.spec.category == "authz"
        assert run2.reason == "baseline"

        # Simulate authn's discovery: CRED committed mid-chain.
        ctx.capabilities.add(_cred_cap(ctx))

        # authz's idempotency key has changed → eligible again.
        run3 = sched.next(ctx)
        assert run3 is not None
        assert run3.spec.category == "authz"
        assert run3.run_number == 2
        assert run3.reason == "enriched"

        # No further work.
        assert sched.next(ctx) is None

    def test_spec_becomes_newly_eligible_via_requires(self):
        """A spec that requires CRED and has never run before should
        appear in the frontier the moment CRED is committed."""
        specs = [
            _spec("authn"),
            _spec(
                "postauth_enum",
                requires=(CapabilityType.CRED,),
                max_runs=1,
            ),
        ]
        sched = FrontierScheduler(specialists=specs)
        ctx = _ctx()

        run1 = sched.next(ctx)
        assert run1.spec.category == "authn"
        assert sched.next(ctx) is None

        # Authn would have committed creds. Simulate that.
        ctx.capabilities.add(_cred_cap(ctx))

        run2 = sched.next(ctx)
        assert run2 is not None
        assert run2.spec.category == "postauth_enum"
        assert run2.reason == "composition"

    def test_unrelated_note_does_not_trigger_rerun(self):
        """A note committed between runs shouldn't push authz back
        onto the frontier — it doesn't appear in authz's augmented_by."""
        spec = _spec(
            "authz",
            augmented_by=(CapabilityType.CRED,),
            max_runs=2,
        )
        sched = FrontierScheduler(specialists=[spec])
        ctx = _ctx()

        run1 = sched.next(ctx)
        assert run1.spec.category == "authz"

        ctx.capabilities.add(_note_cap(ctx))
        assert sched.next(ctx) is None


class TestFrontierSchedulerCaps:
    def test_max_runs_respected(self):
        """A spec with max_runs=2 runs at most twice, even if its
        idempotency key keeps changing."""
        spec = _spec(
            "authz",
            augmented_by=(CapabilityType.CRED,),
            max_runs=2,
        )
        sched = FrontierScheduler(specialists=[spec])
        ctx = _ctx()

        # Run 1: baseline.
        r1 = sched.next(ctx)
        assert r1 is not None
        # Enrich: add first cred.
        ctx.capabilities.add(_cred_cap(ctx))
        r2 = sched.next(ctx)
        assert r2 is not None
        assert r2.run_number == 2
        # Enrich again with a different cred — still capped at 2.
        different_cred = Capability(
            type=CapabilityType.CRED, scope=asset_scope(ctx.asset_id),
            value={"scheme": "basic", "username": "other", "password": "x"},
        )
        ctx.capabilities.add(different_cred)
        assert sched.next(ctx) is None

    def test_global_chain_depth_caps_total_runs(self):
        """max_chain_depth overrides individual max_runs as a safety
        belt — if a bug causes keys to drift forever, we stop."""
        specs = [
            _spec(f"spec_{i}") for i in range(5)
        ]
        # AGENT_CATEGORIES doesn't know about our synthetic names, but
        # that's fine — the scheduler still yields each once.
        sched = FrontierScheduler(specialists=specs, max_chain_depth=3)
        ctx = _ctx()

        count = 0
        while sched.next(ctx) is not None:
            count += 1
        assert count == 3


class TestFrontierSchedulerDeadline:
    def test_deadline_blocks_next(self):
        """Past the asset deadline, the scheduler refuses to yield —
        protects the enclosing Celery task from exceeding its SLA."""
        spec = _spec("injection")
        sched = FrontierScheduler(specialists=[spec])
        ctx = _ctx(deadline=0)
        assert sched.next(ctx) is None


class TestScheduledRunMetadata:
    def test_baseline_reason_for_first_run_without_requires(self):
        spec = _spec("injection")
        run = FrontierScheduler(specialists=[spec]).next(_ctx())
        assert run is not None
        assert run.reason == "baseline"
        assert run.run_number == 1

    def test_composition_reason_for_requires_satisfied_first_run(self):
        """First run of a spec that needed CRED — we classify this as
        'composition' (it exists because authn enabled it), distinct
        from a baseline spec that always runs first."""
        spec = _spec(
            "postauth_enum",
            requires=(CapabilityType.CRED,),
            max_runs=1,
        )
        ctx = _ctx()
        ctx.capabilities.add(_cred_cap(ctx))
        run = FrontierScheduler(specialists=[spec]).next(ctx)
        assert run is not None
        assert run.reason == "composition"

"""Tests for adaptive scan plan persistence on the Asset model.

Covers PR 1 of the APSP feature:
- compute_plan_signature is stable over the inputs that drive a plan
- compute_and_persist_scan_plan caches on signature match (no LLM re-call)
- compute_and_persist_scan_plan re-plans when force=True
- invalidate_stale_plans returns NULL/stale/post-enrichment plans
- _gather_asset_context tolerates missing endpoint table

The deterministic fallback path (no LLM) keeps these tests free from
network calls — _llm_plan raises and the planner falls back as designed.
"""
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from services import scan_planner


# ── compute_plan_signature ──────────────────────────────────────


class TestPlanSignature:
    """Signature must be stable on noise (timestamps, finding count jitter)
    and unstable on the inputs that meaningfully change a plan."""

    def _base(self):
        return {
            "cpes": ["cpe:2.3:a:apache:http_server:2.4:*"],
            "tech_stack": ["Apache", "PHP"],
            "open_ports": [80, 443],
            "criticality": 7,
            "risk_score": 6.0,
            "is_internet_facing": True,
            "device_type": "server",
            "asset_type": "web_app",
            "environment": "prod",
            "endpoint_count": 5,
            "js_vuln_lib_count": 0,
            "leaked_secret_count": 0,
        }

    def test_identical_inputs_produce_same_signature(self):
        a = scan_planner.compute_plan_signature(self._base())
        b = scan_planner.compute_plan_signature(self._base())
        assert a == b

    def test_port_order_does_not_change_signature(self):
        ctx_a = self._base()
        ctx_b = self._base()
        ctx_b["open_ports"] = [443, 80]  # reversed
        assert scan_planner.compute_plan_signature(ctx_a) == scan_planner.compute_plan_signature(ctx_b)

    def test_tech_stack_change_changes_signature(self):
        ctx = self._base()
        sig1 = scan_planner.compute_plan_signature(ctx)
        ctx["tech_stack"] = ["Apache", "PHP", "WordPress"]
        sig2 = scan_planner.compute_plan_signature(ctx)
        assert sig1 != sig2

    def test_endpoint_count_change_changes_signature(self):
        ctx = self._base()
        sig1 = scan_planner.compute_plan_signature(ctx)
        ctx["endpoint_count"] = 25
        sig2 = scan_planner.compute_plan_signature(ctx)
        assert sig1 != sig2, "endpoint count drives per-endpoint targeting decisions"

    def test_micro_risk_jitter_does_not_change_signature(self):
        """Risk scores wobble by ±0.1 from finding refreshes; we bucket to 0.5
        so cache hits don't get busted by noise that won't change the plan."""
        ctx_a = self._base()
        ctx_a["risk_score"] = 6.0
        ctx_b = self._base()
        ctx_b["risk_score"] = 6.1
        assert scan_planner.compute_plan_signature(ctx_a) == scan_planner.compute_plan_signature(ctx_b)

    def test_large_risk_change_changes_signature(self):
        ctx_a = self._base()
        ctx_a["risk_score"] = 6.0
        ctx_b = self._base()
        ctx_b["risk_score"] = 8.5
        assert scan_planner.compute_plan_signature(ctx_a) != scan_planner.compute_plan_signature(ctx_b)


# ── compute_and_persist_scan_plan ───────────────────────────────


@pytest.fixture
def asset_with_context(db_session, test_org, test_scan):
    """An Asset with enough context for a deterministic plan."""
    from models.models import Asset
    asset = Asset(
        scan_id=test_scan.id,
        ip="10.0.0.5",
        hostname="api.example.com",
        criticality=7,
        risk_score=6.0,
        is_internet_facing=True,
        asset_type="web_app",
        device_type="server",
        environment_tag="prod",
        cpe=["cpe:2.3:a:apache:http_server:2.4:*"],
        easm_data={
            "tech_stack": ["Apache", "PHP"],
            "open_ports": [80, 443],
        },
    )
    db_session.add(asset)
    db_session.flush()
    # org_id lives on assets via ALTER TABLE — set it directly so the planner's
    # join filter resolves the asset.
    from sqlalchemy import text
    db_session.execute(
        text("UPDATE assets SET org_id = :org WHERE id = :id"),
        {"org": test_org.id, "id": asset.id},
    )
    db_session.flush()
    return asset


def _persist(db_session, org_id, asset_id, force=False):
    """Sync wrapper — backend convention is asyncio.run, not pytest-asyncio."""
    with patch.object(scan_planner, "_llm_plan", side_effect=RuntimeError("no LLM in tests")):
        return asyncio.run(
            scan_planner.compute_and_persist_scan_plan(
                db_session, org_id, asset_id, force=force,
            )
        )


class TestComputeAndPersist:
    def test_first_call_persists_plan(self, db_session, test_org, asset_with_context):
        """Plan is computed, written to the asset row, version bumps to 1."""
        plan = _persist(db_session, test_org.id, asset_with_context.id)

        assert plan is not None
        assert plan.actions, "deterministic plan always produces at least nuclei"

        db_session.refresh(asset_with_context)
        assert asset_with_context.scan_plan is not None
        assert asset_with_context.scan_plan_version == 1
        assert asset_with_context.scan_plan_signature is not None
        assert asset_with_context.scan_plan_computed_at is not None

    def test_second_call_with_unchanged_context_hits_cache(
        self, db_session, test_org, asset_with_context,
    ):
        """If nothing meaningful changed, no replanning happens — the plan
        body, signature, and version stay put."""
        _persist(db_session, test_org.id, asset_with_context.id)

        db_session.refresh(asset_with_context)
        v1 = asset_with_context.scan_plan_version
        sig1 = asset_with_context.scan_plan_signature

        # Patch generate_scan_plan to track whether it was called the second time.
        with patch.object(
            scan_planner, "generate_scan_plan",
            side_effect=AssertionError("planner should NOT be called on cache hit"),
        ):
            plan = asyncio.run(
                scan_planner.compute_and_persist_scan_plan(
                    db_session, test_org.id, asset_with_context.id,
                )
            )

        assert plan is not None
        db_session.refresh(asset_with_context)
        assert asset_with_context.scan_plan_version == v1, "version must not bump on cache hit"
        assert asset_with_context.scan_plan_signature == sig1

    def test_force_true_bypasses_cache(self, db_session, test_org, asset_with_context):
        """force=True replans even when the signature matches."""
        _persist(db_session, test_org.id, asset_with_context.id)
        db_session.refresh(asset_with_context)
        v1 = asset_with_context.scan_plan_version

        _persist(db_session, test_org.id, asset_with_context.id, force=True)

        db_session.refresh(asset_with_context)
        assert asset_with_context.scan_plan_version == v1 + 1

    def test_signature_change_triggers_replan(
        self, db_session, test_org, asset_with_context,
    ):
        """Mutating the asset's tech stack should bust the cache on next call."""
        _persist(db_session, test_org.id, asset_with_context.id)
        db_session.refresh(asset_with_context)
        v1 = asset_with_context.scan_plan_version
        sig1 = asset_with_context.scan_plan_signature

        # Add a tech to easm_data so the signature changes.
        easm = dict(asset_with_context.easm_data)
        easm["tech_stack"] = ["Apache", "PHP", "WordPress"]
        asset_with_context.easm_data = easm
        db_session.flush()

        _persist(db_session, test_org.id, asset_with_context.id)

        db_session.refresh(asset_with_context)
        assert asset_with_context.scan_plan_version == v1 + 1
        assert asset_with_context.scan_plan_signature != sig1

    def test_missing_asset_returns_none(self, db_session, test_org):
        plan = asyncio.run(
            scan_planner.compute_and_persist_scan_plan(
                db_session, test_org.id, asset_id=999_999,
            )
        )
        assert plan is None


# ── invalidate_stale_plans ──────────────────────────────────────


class TestInvalidateStalePlans:
    def test_returns_assets_without_plan(
        self, db_session, test_org, asset_with_context,
    ):
        """Assets that have never been planned (NULL computed_at) come first."""
        ids = scan_planner.invalidate_stale_plans(db_session, test_org.id)
        assert asset_with_context.id in ids

    def test_excludes_fresh_plans(
        self, db_session, test_org, asset_with_context,
    ):
        """A plan computed within max_age_hours and after last_enriched is fresh."""
        now = datetime.utcnow()
        asset_with_context.scan_plan = {"asset_id": asset_with_context.id, "actions": []}
        asset_with_context.scan_plan_computed_at = now
        asset_with_context.last_enriched = now - timedelta(hours=1)
        db_session.flush()

        ids = scan_planner.invalidate_stale_plans(db_session, test_org.id)
        assert asset_with_context.id not in ids

    def test_includes_plans_older_than_enrichment(
        self, db_session, test_org, asset_with_context,
    ):
        """Enrichment after the plan should mark the plan stale even if it's recent."""
        now = datetime.utcnow()
        asset_with_context.scan_plan = {"asset_id": asset_with_context.id, "actions": []}
        asset_with_context.scan_plan_computed_at = now - timedelta(hours=2)
        asset_with_context.last_enriched = now - timedelta(minutes=10)
        db_session.flush()

        ids = scan_planner.invalidate_stale_plans(db_session, test_org.id)
        assert asset_with_context.id in ids

    def test_includes_plans_past_max_age(
        self, db_session, test_org, asset_with_context,
    ):
        """Past max_age_hours, plans are stale regardless of enrichment activity."""
        very_old = datetime.utcnow() - timedelta(days=30)
        asset_with_context.scan_plan = {"asset_id": asset_with_context.id, "actions": []}
        asset_with_context.scan_plan_computed_at = very_old
        asset_with_context.last_enriched = very_old
        db_session.flush()

        ids = scan_planner.invalidate_stale_plans(db_session, test_org.id, max_age_hours=24)
        assert asset_with_context.id in ids


# ── _gather_asset_context tolerates missing endpoint table ──────


class TestGatherContextTolerance:
    def test_missing_asset_endpoints_table_does_not_crash(
        self, db_session, test_org, asset_with_context,
    ):
        """In dev SQLite the asset_endpoints table doesn't exist; planner
        must default the count to 0 rather than raising."""
        ctx = scan_planner._gather_asset_context(
            db_session, test_org.id, asset_with_context.id,
        )
        assert ctx is not None
        assert ctx["endpoint_count"] == 0
        assert ctx["js_vuln_lib_count"] == 0
        assert ctx["leaked_secret_count"] == 0

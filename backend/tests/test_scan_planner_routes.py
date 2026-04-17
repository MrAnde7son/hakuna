"""Tests for the persisted scan-planner routes (PR 5)."""
import asyncio
import hashlib
import hmac
import json
import os
from unittest.mock import patch

import pytest

from services import scan_planner


# ── Fixtures ───────────────────────────────────────────────────


@pytest.fixture
def asset_with_plan(db_session, test_org, test_scan):
    """Asset with a precomputed plan written to its row."""
    from models.models import Asset
    from sqlalchemy import text
    asset = Asset(
        scan_id=test_scan.id,
        ip="10.0.0.5",
        hostname="api.example.com",
        criticality=7,
        risk_score=6.0,
        is_internet_facing=True,
        cpe=["cpe:2.3:a:apache:http_server:2.4:*"],
        easm_data={"tech_stack": ["Apache"], "open_ports": [443]},
    )
    db_session.add(asset)
    db_session.flush()
    db_session.execute(
        text("UPDATE assets SET org_id = :org WHERE id = :id"),
        {"org": test_org.id, "id": asset.id},
    )
    with patch.object(scan_planner, "_llm_plan", side_effect=RuntimeError("no LLM")):
        asyncio.run(scan_planner.compute_and_persist_scan_plan(
            db_session, test_org.id, asset.id,
        ))
    db_session.refresh(asset)
    return asset


# ── /persisted/{asset_id} ──────────────────────────────────────


class TestGetPersistedPlan:
    def test_returns_plan_for_owning_org(self, authed_client, asset_with_plan):
        r = authed_client.get(f"/api/scan-planner/persisted/{asset_with_plan.id}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["asset_id"] == asset_with_plan.id
        assert body["plan"] is not None
        assert body["version"] == 1
        assert body["signature"]

    def test_404_when_asset_outside_org(self, authed_client):
        r = authed_client.get("/api/scan-planner/persisted/999999")
        assert r.status_code == 404


# ── /refresh/{asset_id} ────────────────────────────────────────


class TestRefreshPlan:
    def test_force_true_bumps_version(self, authed_client, asset_with_plan, db_session):
        v_before = asset_with_plan.scan_plan_version
        with patch.object(scan_planner, "_llm_plan", side_effect=RuntimeError("no LLM")):
            r = authed_client.post(
                f"/api/scan-planner/refresh/{asset_with_plan.id}?force=true",
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["version"] == v_before + 1
        assert body["risk_tier"] in ("critical", "high", "medium", "low")
        assert body["actions_count"] >= 1

    def test_404_for_unknown_asset(self, authed_client):
        r = authed_client.post("/api/scan-planner/refresh/999999?force=true")
        assert r.status_code == 404


# ── /stale ─────────────────────────────────────────────────────


class TestListStalePlans:
    def test_empty_when_no_assets(self, authed_client):
        r = authed_client.get("/api/scan-planner/stale")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_assets_without_plan(self, authed_client, db_session, test_org, test_scan):
        from models.models import Asset
        from sqlalchemy import text
        a = Asset(scan_id=test_scan.id, ip="10.0.0.99", hostname="unplanned.example.com")
        db_session.add(a)
        db_session.flush()
        db_session.execute(
            text("UPDATE assets SET org_id = :org WHERE id = :id"),
            {"org": test_org.id, "id": a.id},
        )
        db_session.commit()

        r = authed_client.get("/api/scan-planner/stale?max_age_hours=24")
        assert r.status_code == 200
        ids = [row["asset_id"] for row in r.json()]
        assert a.id in ids


# ── /internal/compute ──────────────────────────────────────────


class TestInternalCompute:
    SECRET = "test-internal-secret"

    def _signed(self, body: bytes) -> dict:
        return {
            "X-Internal-Signature": hmac.new(
                self.SECRET.encode(), body, hashlib.sha256,
            ).hexdigest(),
        }

    def test_rejects_when_secret_unset(self, client):
        # Default — secret env var not set
        r = client.post(
            "/api/scan-planner/internal/compute",
            json={"org_id": 1, "asset_ids": [1]},
        )
        assert r.status_code == 503

    def test_rejects_missing_signature(self, client, monkeypatch):
        monkeypatch.setenv("INTERNAL_PLANNER_HMAC_SECRET", self.SECRET)
        r = client.post(
            "/api/scan-planner/internal/compute",
            json={"org_id": 1, "asset_ids": [1]},
        )
        assert r.status_code == 401

    def test_rejects_bad_signature(self, client, monkeypatch):
        monkeypatch.setenv("INTERNAL_PLANNER_HMAC_SECRET", self.SECRET)
        body = json.dumps({"org_id": 1, "asset_ids": [1]}).encode()
        r = client.post(
            "/api/scan-planner/internal/compute",
            content=body,
            headers={"X-Internal-Signature": "deadbeef", "Content-Type": "application/json"},
        )
        assert r.status_code == 401

    def test_accepts_signed_request_and_computes(
        self, client, monkeypatch, asset_with_plan, test_org,
    ):
        """Signed request triggers compute_and_persist_scan_plan per asset."""
        monkeypatch.setenv("INTERNAL_PLANNER_HMAC_SECRET", self.SECRET)
        body = json.dumps({
            "org_id": test_org.id,
            "asset_ids": [asset_with_plan.id],
            "force": True,
        }).encode()
        with patch.object(scan_planner, "_llm_plan", side_effect=RuntimeError("no LLM")):
            r = client.post(
                "/api/scan-planner/internal/compute",
                content=body,
                headers={**self._signed(body), "Content-Type": "application/json"},
            )
        assert r.status_code == 200, r.text
        body_out = r.json()
        assert body_out["requested"] == 1
        # Either computed (force=True) or skipped — but never failed.
        assert body_out["failed"] == 0

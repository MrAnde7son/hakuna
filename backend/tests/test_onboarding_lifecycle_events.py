"""Tests for the three onboarding-lifecycle feed events:

  * ``scan_started`` — fired from ``trigger_easm_for_new_org`` after the
    scan is queued. Closes the silent-middle between user landing on the
    feed and the first ``finalize_scan``.
  * ``org_onboarded`` — fired from the apply_packages route at the end
    of the wizard. Welcome narrator posts the first feed entry.
  * ``scan_batch_complete`` — fired from ``finalize_batch`` while the
    scan is still streaming. Narrator posts progress entries.

Each emit is verified against ``services.event_bus.emit`` (mocked) so we
don't need a real LLM or job manager. Dispatcher integration is covered
by the existing test_agent_dispatcher.py.
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from models.models import Asset, Organization, Scan
from services import agent_dispatcher


# ── Drift guard: templates ↔ EVENT_TO_AGENT_NAME ───────────────────


def test_event_map_covers_all_lifecycle_events():
    """Every event referenced by the emit sites must have a mapping in
    ``EVENT_TO_AGENT_NAME``. Drift here would make the events silently
    no-op (dispatcher returns ``no_mapping``)."""
    expected = {
        "scan_started", "scan_batch_complete", "scan_complete",
        "asset_created", "validated_chain", "org_onboarded",
    }
    assert expected.issubset(set(agent_dispatcher.EVENT_TO_AGENT_NAME.keys()))


def test_lifecycle_agent_names_have_templates():
    """Every agent name the lifecycle events route to must have a
    matching template in feed_agent_templates.json — otherwise lazy-create
    returns no_template and the user never sees an entry."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "feed_agent_templates.json",
    )
    with open(path) as f:
        data = json.load(f)
    template_names = {t["name"] for t in data["templates"]}

    for event in ("scan_started", "scan_batch_complete", "scan_complete", "org_onboarded"):
        agent_name = agent_dispatcher.EVENT_TO_AGENT_NAME[event]
        assert agent_name in template_names, (
            f"event {event} → agent {agent_name} has no template"
        )


def test_triage_scan_results_template_handles_three_states():
    """The single agent that handles three scan-lifecycle events must
    have prompt content that branches on each. Drift guard: someone
    swapping in a single-state prompt would break the started + batch
    paths silently."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "feed_agent_templates.json",
    )
    with open(path) as f:
        data = json.load(f)
    triage = next(t for t in data["templates"] if t["name"] == "triage_scan_results")
    prompt = triage["system_prompt"]
    assert "scan_started" in prompt
    assert "scan_batch_complete" in prompt
    assert "scan_complete" in prompt


def test_welcome_narrator_template_minimal_tools():
    """The welcome narrator only needs post_feed_entry — it doesn't
    query findings or assets (the scan hasn't surfaced anything yet).
    Tighter tool list = faster runs + smaller LLM token footprint."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "feed_agent_templates.json",
    )
    with open(path) as f:
        data = json.load(f)
    welcome = next(t for t in data["templates"] if t["name"] == "welcome_narrator")
    assert welcome["tools"] == ["post_feed_entry"]
    assert welcome["guardrails"]["max_steps"] <= 3


# ── scan_started emit from trigger_easm_for_new_org ────────────────


def _stub_scan_domain_success(db, org, domain, scan_type="full", **kw):
    """Stand-in for scan_domain that finds the existing Scan row and
    flips its status to running — the real function does this via
    _find_existing_easm_scan + a status write."""
    scan = (
        db.query(Scan)
        .filter(Scan.org_id == org.id, Scan.source_type == "easm")
        .order_by(Scan.id.desc())
        .first()
    )
    if scan is None:
        return None
    scan.status = "running"
    db.commit()
    return {"scan_id": scan.id, "run_id": 1, "domain": domain, "status": "running", "error": None}


def test_trigger_easm_creates_scan_row_and_emits_scan_started(db_session, test_org):
    """Happy path: scanner reachable, full chain succeeds. A Scan row
    is created up-front (so the failure mode would be visible if it
    occurred) and scan_started fires with the row's id."""
    import asyncio
    from services import easm

    with patch.object(easm, "extract_corporate_domain", return_value="example.com"), \
         patch.object(easm, "create_easm_org", new=AsyncMock(return_value="hakuna-org-uuid")), \
         patch.object(easm, "add_easm_domain", new=AsyncMock(return_value=True)), \
         patch.object(easm, "scan_domain", new=AsyncMock(side_effect=_stub_scan_domain_success)), \
         patch("services.easm_scheduler.register_scan"), \
         patch("services.event_bus.emit") as mock_emit:
        result = asyncio.run(
            easm.trigger_easm_for_new_org(db_session, test_org, "alice@example.com")
        )

    assert result is not None
    assert result.status == "running"

    # A real Scan row exists in the DB — visible to the Scans page query.
    scan = (
        db_session.query(Scan)
        .filter(Scan.org_id == test_org.id, Scan.source_type == "easm")
        .first()
    )
    assert scan is not None
    assert scan.status == "running"

    mock_emit.assert_called_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["event_type"] == "scan_started"
    assert kwargs["payload"]["scan_id"] == scan.id
    assert kwargs["payload"]["trigger"] == "auto_register"
    assert kwargs["dedup_key"] == scan.id


def test_trigger_easm_marks_scan_failed_when_scanner_unreachable(db_session, test_org):
    """The bug the user actually hit: hakuna-scanner container was off.
    create_easm_org returns None. We must STILL leave a Scan row in
    'failed' state so the Scans page shows the failure (and the welcome
    narrator doesn't lie). No scan_started event fires."""
    import asyncio
    from services import easm

    with patch.object(easm, "extract_corporate_domain", return_value="nadlaner.com"), \
         patch.object(easm, "create_easm_org", new=AsyncMock(return_value=None)), \
         patch("services.event_bus.emit") as mock_emit:
        result = asyncio.run(
            easm.trigger_easm_for_new_org(db_session, test_org, "alice@nadlaner.com")
        )

    assert result is not None
    assert result.status == "failed"
    assert (result.raw_metadata or {}).get("failed_stage") == "create_org"
    assert "scanner" in (result.raw_metadata or {}).get("error", "").lower()

    # The row is in the DB — the Scans page would render it.
    scan = (
        db_session.query(Scan)
        .filter(Scan.org_id == test_org.id, Scan.source_type == "easm")
        .first()
    )
    assert scan is not None
    assert scan.status == "failed"

    # No scan_started — there's no scan to narrate as starting.
    mock_emit.assert_not_called()


def test_trigger_easm_marks_scan_failed_when_add_domain_fails(db_session, test_org):
    """Stage 2 failure: scanner accepts the org but rejects the domain.
    Same outcome: Scan row stays in DB with a clear failure reason."""
    import asyncio
    from services import easm

    with patch.object(easm, "extract_corporate_domain", return_value="example.com"), \
         patch.object(easm, "create_easm_org", new=AsyncMock(return_value="uuid")), \
         patch.object(easm, "add_easm_domain", new=AsyncMock(return_value=False)), \
         patch("services.event_bus.emit") as mock_emit:
        result = asyncio.run(
            easm.trigger_easm_for_new_org(db_session, test_org, "alice@example.com")
        )

    assert result.status == "failed"
    assert (result.raw_metadata or {}).get("failed_stage") == "add_domain"
    mock_emit.assert_not_called()


def test_retry_easm_scan_clears_error_and_succeeds_on_second_try(db_session, test_org):
    """First attempt fails (scanner off). User restarts the scanner. Retry
    re-uses the same Scan row, clears the error, and runs the external
    chain again — this time successfully."""
    import asyncio
    from services import easm

    # First attempt — scanner off.
    with patch.object(easm, "extract_corporate_domain", return_value="example.com"), \
         patch.object(easm, "create_easm_org", new=AsyncMock(return_value=None)), \
         patch("services.event_bus.emit"):
        first = asyncio.run(
            easm.trigger_easm_for_new_org(db_session, test_org, "alice@example.com")
        )
    assert first.status == "failed"
    failed_id = first.id

    # Second attempt — scanner back. retry_easm_scan reuses the row.
    with patch.object(easm, "create_easm_org", new=AsyncMock(return_value="uuid")), \
         patch.object(easm, "add_easm_domain", new=AsyncMock(return_value=True)), \
         patch.object(easm, "scan_domain", new=AsyncMock(side_effect=_stub_scan_domain_success)), \
         patch("services.event_bus.emit") as mock_emit:
        retried = asyncio.run(easm.retry_easm_scan(db_session, test_org, failed_id))

    assert retried.id == failed_id   # same row
    assert retried.status == "running"
    assert (retried.raw_metadata or {}).get("error") is None
    assert (retried.raw_metadata or {}).get("failed_stage") is None

    # Retry should re-fire scan_started so the narrator gets a fresh chance.
    mock_emit.assert_called_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["event_type"] == "scan_started"
    assert kwargs["payload"]["trigger"] == "retry"


def test_retry_endpoint_404_for_other_org_scan(db_session, authed_client, test_org):
    """Retry must enforce org isolation."""
    from models.models import Organization
    other = Organization(name="Other", slug="other-retry")
    db_session.add(other)
    db_session.flush()
    foreign_scan = Scan(org_id=other.id, filename="x", source_type="easm", status="failed")
    db_session.add(foreign_scan)
    db_session.flush()

    resp = authed_client.post(f"/api/easm/scans/{foreign_scan.id}/retry")
    # The retry function raises ValueError for cross-org scans, mapped to 404.
    assert resp.status_code == 404


def test_retry_endpoint_idempotent_on_running_scan(db_session, authed_client, test_org):
    """Already-running scan: retry is a no-op and returns the row as-is."""
    test_org.easm_domain = "example.com"
    db_session.flush()
    scan = Scan(
        org_id=test_org.id, filename="x", source_type="easm",
        status="running", raw_metadata={"domain": "example.com"},
    )
    db_session.add(scan)
    db_session.flush()

    resp = authed_client.post(f"/api/easm/scans/{scan.id}/retry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "running"


# ── org_onboarded emit from apply_packages route ───────────────────


def test_apply_packages_emits_with_running_scan(db_session, authed_client, test_org):
    """Happy path: domain set AND scan is running. Narrator gets the
    full picture in the payload."""
    test_org.easm_domain = "example.com"
    db_session.flush()
    s = Scan(
        org_id=test_org.id, filename="example.com", source_type="easm",
        status="running", raw_metadata={"domain": "example.com"},
    )
    db_session.add(s)
    db_session.flush()

    with patch("services.event_bus.emit") as mock_emit, \
         patch("routes.onboarding_routes.apply_packages", return_value={
             "tags": 4, "campaigns": 2, "agents": 3, "reports": 1,
             "auto_tag_rules": 2, "sla_configs": 0, "roles": 0,
             "ownership_rules": 0, "workflows": 0, "exceptions": 0,
         }):
        resp = authed_client.post(
            "/api/onboarding/apply",
            json={
                "industry": "fintech",
                "org_size": "mid",
                "team_size": "6-15",
                "team_functions": ["security", "platform"],
                "objectives": ["cloud_first"],
                "selected_packages": ["cloud_first"],
                "notification_prefs": ["in_app"],
            },
        )
    assert resp.status_code == 200, resp.text

    mock_emit.assert_called_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["event_type"] == "org_onboarded"
    assert kwargs["payload"]["easm_domain"] == "example.com"
    assert kwargs["payload"]["easm_scan_status"] == "running"
    assert kwargs["payload"]["easm_scan_id"] == s.id
    assert kwargs["payload"]["easm_scan_error"] is None
    assert kwargs["payload"]["objectives"] == ["cloud_first"]


def test_apply_packages_emits_failed_status_with_error(db_session, authed_client, test_org):
    """Failure path: scan exists but failed. Payload carries the error
    so the narrator can quote it back to the user."""
    test_org.easm_domain = "nadlaner.com"
    db_session.flush()
    failed_scan = Scan(
        org_id=test_org.id, filename="nadlaner.com", source_type="easm",
        status="failed",
        raw_metadata={
            "domain": "nadlaner.com",
            "error": "Scanner unreachable: could not create EASM org",
            "failed_stage": "create_org",
        },
    )
    db_session.add(failed_scan)
    db_session.flush()

    with patch("services.event_bus.emit") as mock_emit, \
         patch("routes.onboarding_routes.apply_packages", return_value={"tags": 0}):
        resp = authed_client.post(
            "/api/onboarding/apply",
            json={
                "industry": "fintech", "org_size": "mid", "team_size": "1-5",
                "team_functions": [], "objectives": ["cloud_first"],
                "selected_packages": ["cloud_first"], "notification_prefs": [],
            },
        )
    assert resp.status_code == 200

    _, kwargs = mock_emit.call_args
    assert kwargs["payload"]["easm_scan_status"] == "failed"
    assert kwargs["payload"]["easm_scan_id"] == failed_scan.id
    assert "scanner unreachable" in (kwargs["payload"]["easm_scan_error"] or "").lower()


def test_apply_packages_emits_null_status_for_free_email_signups(db_session, authed_client, test_org):
    """Free-email signups don't get an EASM scan — no Scan row, status null."""
    assert test_org.easm_domain is None

    with patch("services.event_bus.emit") as mock_emit, \
         patch("routes.onboarding_routes.apply_packages", return_value={"tags": 0}):
        resp = authed_client.post(
            "/api/onboarding/apply",
            json={
                "industry": "fintech", "org_size": "mid", "team_size": "1-5",
                "team_functions": [], "objectives": [],
                "selected_packages": [], "notification_prefs": [],
            },
        )
    assert resp.status_code == 200

    _, kwargs = mock_emit.call_args
    assert kwargs["payload"]["easm_domain"] is None
    assert kwargs["payload"]["easm_scan_status"] is None
    assert kwargs["payload"]["easm_scan_id"] is None
    assert kwargs["payload"]["easm_scan_error"] is None


# ── scan_batch_complete emit from finalize_batch ───────────────────


@pytest.fixture
def scan(db_session, test_org):
    s = Scan(org_id=test_org.id, filename="streaming-scan", status="running")
    db_session.add(s)
    db_session.flush()
    return s


def test_finalize_batch_emits_scan_batch_complete(db_session, test_org, scan):
    """During EASM streaming ingest, each batch should fire its own
    progress event so the narrator can post incremental entries."""
    from services import post_ingest

    with patch("services.event_bus.emit") as mock_emit, \
         patch.object(post_ingest, "_run_os_software_tags", return_value=None), \
         patch.object(post_ingest, "_run_auto_tag_rules", return_value=None), \
         patch.object(post_ingest, "_run_ownership_rules", return_value=None), \
         patch.object(post_ingest, "_run_ownership_inference", return_value=None), \
         patch.object(post_ingest, "_recompute_asset_severity_counts", return_value=None), \
         patch.object(post_ingest, "_recompute_risk_scores", return_value=None), \
         patch.object(post_ingest, "_fire_data_triggers", return_value=None), \
         patch.object(post_ingest, "_run_apply_exceptions_to_findings", return_value=None) if hasattr(post_ingest, "_run_apply_exceptions_to_findings") else patch.object(post_ingest, "_step", side_effect=lambda db, name, fn: fn() if "exceptions" not in name.lower() else None):
        post_ingest.finalize_batch(
            db_session,
            scan_id=scan.id,
            org_id=test_org.id,
            new_asset_ids=[100, 101, 102],
            new_finding_ids=[500, 501],
        )

    # Find the scan_batch_complete call (other emits may have been
    # made by mocked-out steps).
    calls = [c for c in mock_emit.call_args_list if c.kwargs.get("event_type") == "scan_batch_complete"]
    assert len(calls) == 1
    kwargs = calls[0].kwargs
    assert kwargs["org_id"] == test_org.id
    assert kwargs["payload"]["scan_id"] == scan.id
    assert kwargs["payload"]["new_asset_count"] == 3
    assert kwargs["payload"]["new_finding_count"] == 2
    # First-finding key — auto-increment guarantees uniqueness across
    # consecutive batches.
    assert kwargs["dedup_key"] == f"{scan.id}:f:500"


def test_finalize_batch_skips_emit_for_empty_batch(db_session, test_org, scan):
    """An empty batch shouldn't fire — there's nothing to narrate."""
    from services import post_ingest

    with patch("services.event_bus.emit") as mock_emit, \
         patch.object(post_ingest, "_step", return_value=None):
        post_ingest.finalize_batch(
            db_session,
            scan_id=scan.id,
            org_id=test_org.id,
            new_asset_ids=[],
            new_finding_ids=[],
        )

    batch_calls = [c for c in mock_emit.call_args_list if c.kwargs.get("event_type") == "scan_batch_complete"]
    assert batch_calls == []


def test_emit_scan_batch_complete_uses_asset_id_when_no_findings(db_session, test_org, scan):
    """When a batch only adds assets (no findings), the dedup_key should
    fall back to the first asset id."""
    from services import post_ingest

    with patch("services.event_bus.emit") as mock_emit:
        post_ingest._emit_scan_batch_complete(
            db_session, org_id=test_org.id, scan_id=scan.id,
            new_asset_ids=[200, 201], new_finding_ids=[],
        )

    mock_emit.assert_called_once()
    assert mock_emit.call_args.kwargs["dedup_key"] == f"{scan.id}:a:200"

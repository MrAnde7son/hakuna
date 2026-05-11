"""Tests for services.feed_emitters — deterministic activity-feed cards
posted on scan ingest completion and integration runs."""
from datetime import datetime

import pytest

from models.models import Integration, IntegrationRun, OrgFeedEntry
from services.feed_emitters import (
    INTEGRATION_RUN_EVENT_TYPE,
    SCAN_INGESTED_EVENT_TYPE,
    post_integration_run_card,
    post_scan_ingest_card,
)


def _query(db_session, org_id, event_type):
    return (
        db_session.query(OrgFeedEntry)
        .filter(
            OrgFeedEntry.org_id == org_id,
            OrgFeedEntry.event_type == event_type,
        )
        .order_by(OrgFeedEntry.id)
        .all()
    )


def test_scan_ingest_card_is_posted(db_session, test_org, test_scan):
    eid = post_scan_ingest_card(
        db_session,
        org_id=test_org.id,
        scan=test_scan,
        source_type="nessus",
        total_assets=10,
        total_findings=42,
        crit_high=3,
        filename="x.nessus",
    )
    assert eid is not None

    entries = _query(db_session, test_org.id, SCAN_INGESTED_EVENT_TYPE)
    assert len(entries) == 1
    e = entries[0]
    assert e.kind == "observation"
    assert e.severity == "high"  # crit_high > 0
    assert "Nessus" in e.headline
    assert e.event_ref["scan_id"] == test_scan.id
    assert e.event_ref["source_type"] == "nessus"
    assert any(a.get("href", "").startswith("/findings") for a in e.proposed_actions)


def test_scan_ingest_card_severity_info_when_no_crit_high(db_session, test_org, test_scan):
    eid = post_scan_ingest_card(
        db_session,
        org_id=test_org.id,
        scan=test_scan,
        source_type="qualys",
        total_assets=5,
        total_findings=8,
        crit_high=0,
    )
    assert eid is not None
    e = _query(db_session, test_org.id, SCAN_INGESTED_EVENT_TYPE)[0]
    assert e.severity == "info"
    assert "Qualys" in e.headline


def test_scan_ingest_card_deduped_within_window(db_session, test_org, test_scan):
    first = post_scan_ingest_card(
        db_session, org_id=test_org.id, scan=test_scan,
        source_type="nessus", total_assets=1, total_findings=1, crit_high=0,
    )
    second = post_scan_ingest_card(
        db_session, org_id=test_org.id, scan=test_scan,
        source_type="nessus", total_assets=1, total_findings=1, crit_high=0,
    )
    assert first is not None
    assert second is None
    assert len(_query(db_session, test_org.id, SCAN_INGESTED_EVENT_TYPE)) == 1


@pytest.fixture
def integration_and_run(db_session, test_org):
    integ = Integration(
        org_id=test_org.id,
        name="ACME Jira",
        direction="pull",
        entity="finding",
        transport_type="api",
        transport_config={},
    )
    db_session.add(integ)
    db_session.flush()
    run = IntegrationRun(
        integration_id=integ.id,
        triggered_by="manual",
        started_at=datetime.utcnow(),
        status="success",
        records_fetched=120,
        records_inserted=20,
        records_updated=5,
        records_skipped=95,
    )
    db_session.add(run)
    db_session.flush()
    return integ, run


def test_integration_run_card_success(db_session, test_org, integration_and_run):
    integ, run = integration_and_run
    eid = post_integration_run_card(db_session, integration=integ, run=run)
    assert eid is not None
    entries = _query(db_session, test_org.id, INTEGRATION_RUN_EVENT_TYPE)
    assert len(entries) == 1
    e = entries[0]
    assert e.kind == "observation"
    assert e.severity == "info"
    assert "Pulled" in e.headline
    assert "ACME Jira" in e.headline
    assert e.event_ref["integration_id"] == integ.id
    assert e.event_ref["run_id"] == run.id


def test_integration_run_card_error_is_action(db_session, test_org, integration_and_run):
    integ, run = integration_and_run
    run.status = "error"
    run.error_message = "boom"
    db_session.flush()

    eid = post_integration_run_card(db_session, integration=integ, run=run)
    assert eid is not None
    e = _query(db_session, test_org.id, INTEGRATION_RUN_EVENT_TYPE)[0]
    assert e.kind == "action"
    assert e.severity == "high"
    assert "failed" in e.headline.lower()
    assert "boom" in (e.body_md or "")


def test_integration_run_card_push_direction(db_session, test_org, integration_and_run):
    integ, run = integration_and_run
    integ.direction = "push"
    db_session.flush()

    post_integration_run_card(db_session, integration=integ, run=run)
    e = _query(db_session, test_org.id, INTEGRATION_RUN_EVENT_TYPE)[0]
    assert "Pushed" in e.headline


def test_integration_run_card_deduped_within_window(db_session, test_org, integration_and_run):
    integ, run = integration_and_run
    first = post_integration_run_card(db_session, integration=integ, run=run)
    second = post_integration_run_card(db_session, integration=integ, run=run)
    assert first is not None
    assert second is None
    assert len(_query(db_session, test_org.id, INTEGRATION_RUN_EVENT_TYPE)) == 1

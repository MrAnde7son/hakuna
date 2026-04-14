"""Tests for ReportSchedule CRUD, renderer, and workflow handler."""
import pytest


@pytest.fixture
def sample_template(db_session, test_org):
    from models.models import ReportTemplate
    tpl = ReportTemplate(
        org_id=test_org.id,
        name="Weekly Exec",
        description="Weekly executive dashboard",
        config={"widgets": [{"id": "w1", "type": "stat_card", "title": "Assets"}]},
    )
    db_session.add(tpl)
    db_session.flush()
    return tpl


# ─── CRUD ────────────────────────────────────────────────

def test_list_schedules_empty(authed_client, sample_template):
    r = authed_client.get(f"/api/report-templates/{sample_template.id}/schedules")
    assert r.status_code == 200, r.text
    assert r.json() == []


def test_create_weekly_schedule(authed_client, sample_template):
    body = {
        "recipients": "ceo@corp.com, cto@corp.com",
        "frequency": "weekly",
        "day_of_week": 0,
        "hour": 8,
        "minute": 0,
        "timezone": "UTC",
    }
    r = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json=body,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["id"]
    assert data["recipients"] == "ceo@corp.com, cto@corp.com"
    assert data["frequency"] == "weekly"
    assert data["day_of_week"] == 0
    assert data["is_enabled"] is True
    assert data["format"] == "pdf"


def test_create_rejects_empty_recipients(authed_client, sample_template):
    body = {"recipients": "   ", "frequency": "daily", "hour": 8, "minute": 0}
    r = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json=body,
    )
    assert r.status_code == 400


def test_create_rejects_non_pdf_format(authed_client, sample_template):
    body = {"recipients": "a@b.com", "frequency": "daily", "format": "pptx"}
    r = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json=body,
    )
    assert r.status_code == 400


def test_create_rejects_custom_without_cron(authed_client, sample_template):
    body = {"recipients": "a@b.com", "frequency": "custom", "cron_expression": ""}
    r = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json=body,
    )
    assert r.status_code == 400


def test_update_schedule(authed_client, sample_template):
    create = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json={"recipients": "a@b.com", "frequency": "daily"},
    )
    schedule_id = create.json()["id"]

    r = authed_client.patch(
        f"/api/report-schedules/{schedule_id}",
        json={"is_enabled": False, "hour": 18},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["is_enabled"] is False
    assert data["hour"] == 18
    # unchanged
    assert data["recipients"] == "a@b.com"


def test_delete_schedule(authed_client, sample_template):
    create = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json={"recipients": "a@b.com", "frequency": "daily"},
    )
    schedule_id = create.json()["id"]

    r = authed_client.delete(f"/api/report-schedules/{schedule_id}")
    assert r.status_code == 200

    r = authed_client.get(f"/api/report-schedules/{schedule_id}")
    assert r.status_code == 404


def test_list_all_schedules(authed_client, sample_template):
    authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json={"recipients": "a@b.com", "frequency": "daily"},
    )
    r = authed_client.get("/api/report-schedules")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_run_now_queues(authed_client, sample_template, monkeypatch):
    import services.report_scheduler as rs
    called = {}

    def fake_deliver(sid):
        called["id"] = sid
        return {"status": "success"}

    monkeypatch.setattr(rs, "deliver_schedule", fake_deliver)

    create = authed_client.post(
        f"/api/report-templates/{sample_template.id}/schedules",
        json={"recipients": "a@b.com", "frequency": "daily"},
    )
    schedule_id = create.json()["id"]

    r = authed_client.post(f"/api/report-schedules/{schedule_id}/run-now")
    assert r.status_code == 200
    assert r.json()["status"] == "queued"
    assert called.get("id") == schedule_id


def test_schedule_scoped_by_org(authed_client, db_session, test_org):
    """A schedule on a template belonging to a different org is not visible."""
    from models.models import Organization, ReportTemplate, ReportSchedule
    other_org = Organization(name="Other", slug="other-org")
    db_session.add(other_org)
    db_session.flush()

    tpl = ReportTemplate(org_id=other_org.id, name="Other", config={})
    db_session.add(tpl)
    db_session.flush()

    sched = ReportSchedule(
        org_id=other_org.id,
        report_template_id=tpl.id,
        recipients="x@y.com",
        frequency="daily",
    )
    db_session.add(sched)
    db_session.flush()

    # Listing the other org's template schedules should 404
    r = authed_client.get(f"/api/report-templates/{tpl.id}/schedules")
    assert r.status_code == 404

    r = authed_client.get(f"/api/report-schedules/{sched.id}")
    assert r.status_code == 404


# ─── Renderer fallback ──────────────────────────────────

def test_fallback_pdf_renders(db_session, sample_template, monkeypatch):
    """When Playwright is unavailable, fallback produces a valid-looking PDF."""
    from services import report_renderer

    def _boom(db, template):
        raise report_renderer._PlaywrightUnavailable("no browser")

    monkeypatch.setattr(report_renderer, "_render_with_playwright", _boom)
    pdf = report_renderer.render_report_pdf(db_session, sample_template)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert b"Hakuna Report" in pdf
    assert b"Weekly Exec" in pdf


# ─── Workflow handler ──────────────────────────────────

def test_workflow_generate_report_action(db_session, sample_template, monkeypatch):
    """generate_report action attaches PDF so downstream send_email picks it up."""
    from services import workflow_engine
    from services import report_renderer

    # Stub the renderer so the test doesn't require Playwright.
    monkeypatch.setattr(report_renderer, "render_report_pdf",
                        lambda db, tpl: b"%PDF-1.4\nfake")

    affected, items = workflow_engine._action_generate_report(
        db_session,
        {"report_template_id": sample_template.id},
        [{"finding_id": 1}],
    )
    assert affected == 1
    # First item should now be the attachment carrier
    carrier = items[0]
    assert carrier["_report_attachment"]["mime_type"] == "application/pdf"
    assert carrier["_report_attachment"]["content"].startswith(b"%PDF-")


def test_workflow_send_email_picks_up_carrier(db_session, monkeypatch):
    """send_email action merges carrier PDFs into config.attachments."""
    from services import workflow_engine
    import services.integrations as integrations

    captured = {}

    def fake_send_email(db, config, items):
        captured["config"] = config
        captured["items"] = items
        return {"status": "sent", "recipients": config.get("to", "").split(",")}

    monkeypatch.setattr(integrations, "send_email", fake_send_email)

    carrier = {"_report_attachment": {"filename": "r.pdf", "content": b"%PDF-1.4",
                                       "mime_type": "application/pdf"}}
    items = [carrier, {"finding_id": 1}, {"finding_id": 2}]
    workflow_engine._action_send_email(db_session, {"to": "a@b.com"}, items)

    assert len(captured["config"]["attachments"]) == 1
    assert captured["config"]["attachments"][0]["filename"] == "r.pdf"
    # Real items passed through without the carrier
    assert captured["items"] == [{"finding_id": 1}, {"finding_id": 2}]

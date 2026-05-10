"""Tests for services.onboarding_tour — deterministic feed cards seeded
right after the wizard finishes.
"""
from models.models import OrgFeedEntry
from services.onboarding_tour import seed_onboarding_tour, _TOUR_EVENT_TYPE


def _query_tour(db_session, org_id):
    return (
        db_session.query(OrgFeedEntry)
        .filter(
            OrgFeedEntry.org_id == org_id,
            OrgFeedEntry.event_type == _TOUR_EVENT_TYPE,
        )
        .order_by(OrgFeedEntry.id)
        .all()
    )


def test_seed_creates_three_default_cards(db_session, test_org):
    """Without provisioning data, the tour seeds the three always-on
    cards: copilot, integrations, invites."""
    result = seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    assert result == {"seeded": 3}
    entries = _query_tour(db_session, test_org.id)
    assert len(entries) == 3
    headlines = [e.headline for e in entries]
    assert any("copilot" in h.lower() for h in headlines)
    assert any("connect" in h.lower() for h in headlines)
    assert any("invite" in h.lower() for h in headlines)


def test_seed_adds_provisioning_card_when_things_were_created(db_session, test_org):
    """When the wizard provisioned campaigns/agents/etc, the tour adds a
    fourth card pointing at them."""
    result = seed_onboarding_tour(
        db_session,
        org_id=test_org.id,
        payload={
            "provisioning": {
                "campaigns": [{"id": 1}, {"id": 2}],
                "agents": [{"id": 10}],
                "reports": [],
                "tags": [{"id": 5}, {"id": 6}, {"id": 7}],
            }
        },
    )

    assert result == {"seeded": 4}
    entries = _query_tour(db_session, test_org.id)
    summary_card = entries[-1]
    assert "set up" in summary_card.headline.lower() or "provision" in summary_card.headline.lower()
    # Counts should appear in the body — surfaces what the user actually got.
    assert "2" in summary_card.body_md
    assert "campaigns" in summary_card.body_md
    # CTA points at the populated area (campaigns wins over agents).
    assert summary_card.proposed_actions[0]["href"] == "/campaigns"


def test_seed_skips_provisioning_card_when_nothing_created(db_session, test_org):
    """No campaigns/agents/reports/tags ⇒ no summary card. We don't want
    a card that says 'I provisioned 0 of everything'."""
    result = seed_onboarding_tour(
        db_session,
        org_id=test_org.id,
        payload={"provisioning": {"campaigns": [], "agents": [], "reports": []}},
    )

    assert result == {"seeded": 3}


def test_seed_is_idempotent(db_session, test_org):
    """Replaying the wizard or the emit must not double-seed the tour."""
    first = seed_onboarding_tour(db_session, org_id=test_org.id, payload={})
    second = seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    assert first["seeded"] == 3
    assert second == {"seeded": 0, "reason": "already_seeded"}
    assert len(_query_tour(db_session, test_org.id)) == 3


def test_seed_returns_missing_org_id_when_org_id_falsy(db_session):
    result = seed_onboarding_tour(db_session, org_id=0, payload={})
    assert result == {"seeded": 0, "reason": "missing_org_id"}


def test_seeded_cards_have_navigate_ctas(db_session, test_org):
    """Each card must render a working CTA — the whole point of the tour
    is to direct the user somewhere useful."""
    seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    entries = _query_tour(db_session, test_org.id)
    for entry in entries:
        assert entry.proposed_actions, f"card {entry.headline!r} has no CTAs"
        action = entry.proposed_actions[0]
        assert action["kind"] == "navigate"
        assert action["href"].startswith("/")
        assert action["label"]


def test_integrations_card_uses_integrate_intent(db_session, test_org):
    """The integrations CTA should use intent=integrate so the frontend
    renders the Plug icon + accent border for Connect-style affordances."""
    seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    entries = _query_tour(db_session, test_org.id)
    integ = next(e for e in entries if "integration" in e.headline.lower() or "connect" in e.headline.lower())
    action = integ.proposed_actions[0]
    assert action["href"] == "/settings?tab=integrations"
    assert action.get("intent") == "integrate"


def test_seeded_cards_default_to_open_status_and_info_severity(db_session, test_org):
    seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    for entry in _query_tour(db_session, test_org.id):
        assert entry.status == "open"
        assert entry.severity == "info"
        assert entry.agent_id is None  # system-authored, no agent


def test_seed_isolates_orgs(db_session, test_org):
    """Tour seeded for org A must not appear under org B."""
    from models.models import Organization

    other = Organization(name="Other Org", slug="other-org")
    db_session.add(other)
    db_session.flush()

    seed_onboarding_tour(db_session, org_id=test_org.id, payload={})

    assert len(_query_tour(db_session, test_org.id)) == 3
    assert len(_query_tour(db_session, other.id)) == 0

    # Other org can still seed its own tour.
    seed_onboarding_tour(db_session, org_id=other.id, payload={})
    assert len(_query_tour(db_session, other.id)) == 3

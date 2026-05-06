"""Tests for external campaign collaborators — invite, accept, scope, revoke."""
from datetime import datetime, timedelta


# ─── Invite + accept happy path ─────────────────────────────


def test_invite_creates_pending_collaborator(authed_client, test_campaign):
    r = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "alice@vendor.example"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email"] == "alice@vendor.example"
    assert body["role"] == "contributor"
    assert body["status"] == "pending"
    assert body["accept_url"].startswith("http")
    assert "token=" in body["accept_url"]


def test_invite_rejects_invalid_email(authed_client, test_campaign):
    r = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "not-an-email"},
    )
    assert r.status_code == 400


def test_list_collaborators(authed_client, test_campaign):
    authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "bob@vendor.example"},
    )
    r = authed_client.get(f"/api/campaigns/{test_campaign.id}/collaborators")
    assert r.status_code == 200
    rows = r.json()["collaborators"]
    assert len(rows) == 1
    assert rows[0]["email"] == "bob@vendor.example"


def _invite_and_get_token(authed_client, campaign_id, email="ext@vendor.example"):
    """Invite a collaborator and pull the plaintext token from the accept_url."""
    r = authed_client.post(
        f"/api/campaigns/{campaign_id}/collaborators", json={"email": email}
    )
    assert r.status_code == 200
    accept_url = r.json()["accept_url"]
    return accept_url.split("token=", 1)[1], r.json()["id"]


def test_accept_returns_session_token(client, authed_client, test_campaign):
    token, _ = _invite_and_get_token(authed_client, test_campaign.id)
    r = client.post("/api/campaigns/collaborator/accept", json={"token": token})
    assert r.status_code == 200
    body = r.json()
    assert body["campaign_id"] == test_campaign.id
    assert body["email"] == "ext@vendor.example"
    assert body["role"] == "contributor"
    assert isinstance(body["access_token"], str) and len(body["access_token"]) > 20


def test_accept_unknown_token_404(client):
    r = client.post("/api/campaigns/collaborator/accept", json={"token": "hci_garbage"})
    assert r.status_code == 404


def test_accept_revoked_token_403(client, authed_client, test_campaign, db_session):
    token, collab_id = _invite_and_get_token(authed_client, test_campaign.id)
    authed_client.delete(f"/api/campaigns/{test_campaign.id}/collaborators/{collab_id}")
    r = client.post("/api/campaigns/collaborator/accept", json={"token": token})
    assert r.status_code == 403


def test_accept_expired_token_403(client, authed_client, test_campaign, db_session):
    token, collab_id = _invite_and_get_token(authed_client, test_campaign.id)
    from models.models import CampaignCollaborator
    row = db_session.query(CampaignCollaborator).filter(
        CampaignCollaborator.id == collab_id
    ).first()
    row.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db_session.commit()
    r = client.post("/api/campaigns/collaborator/accept", json={"token": token})
    assert r.status_code == 403


# ─── Session token scope ───────────────────────────────────


def _accept_and_get_session(client, authed_client, campaign_id, email="scoped@v.example"):
    token, _ = _invite_and_get_token(authed_client, campaign_id, email=email)
    r = client.post("/api/campaigns/collaborator/accept", json={"token": token})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_collaborator_token_can_read_their_campaign(client, authed_client, test_campaign):
    session = _accept_and_get_session(client, authed_client, test_campaign.id)
    r = client.get(
        f"/api/campaigns/{test_campaign.id}",
        headers={"Authorization": f"Bearer {session}"},
    )
    assert r.status_code == 200
    assert r.json()["id"] == test_campaign.id


def test_collaborator_token_blocked_from_org_routes(client, authed_client, test_campaign):
    session = _accept_and_get_session(client, authed_client, test_campaign.id)
    r = client.get(
        "/api/campaigns",
        headers={"Authorization": f"Bearer {session}"},
    )
    assert r.status_code == 403


def test_collaborator_blocked_from_other_campaigns(client, authed_client, db_session, test_org, test_user):
    """A collaborator on campaign A must not read campaign B in the same org."""
    from models.models import Campaign
    camp_a = Campaign(org_id=test_org.id, name="A", owner_id=test_user.id)
    camp_b = Campaign(org_id=test_org.id, name="B", owner_id=test_user.id)
    db_session.add_all([camp_a, camp_b])
    db_session.flush()

    session = _accept_and_get_session(client, authed_client, camp_a.id, email="bound@v.example")
    headers = {"Authorization": f"Bearer {session}"}
    assert client.get(f"/api/campaigns/{camp_a.id}", headers=headers).status_code == 200
    assert client.get(f"/api/campaigns/{camp_b.id}", headers=headers).status_code == 403


def test_collaborator_can_create_workflow_for_their_campaign(client, authed_client, test_campaign):
    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="wf@v.example")
    headers = {"Authorization": f"Bearer {session}"}
    r = client.post(
        "/api/workflows",
        json={"name": "Collab WF", "campaign_id": test_campaign.id},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["campaign_id"] == test_campaign.id


def test_collaborator_cannot_create_org_level_workflow(client, authed_client, test_campaign):
    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="orgwf@v.example")
    r = client.post(
        "/api/workflows",
        json={"name": "Org WF", "campaign_id": None},
        headers={"Authorization": f"Bearer {session}"},
    )
    assert r.status_code == 403


def test_collaborator_cannot_target_other_campaign_in_workflow(client, authed_client, db_session, test_org, test_user, test_campaign):
    from models.models import Campaign
    other = Campaign(org_id=test_org.id, name="Other", owner_id=test_user.id)
    db_session.add(other)
    db_session.flush()
    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="x@v.example")
    r = client.post(
        "/api/workflows",
        json={"name": "Cross", "campaign_id": other.id},
        headers={"Authorization": f"Bearer {session}"},
    )
    assert r.status_code == 403


def test_collaborator_workflow_list_shows_only_their_campaign(client, authed_client, db_session, test_org, test_user, test_campaign):
    from models.models import Campaign, Workflow
    other = Campaign(org_id=test_org.id, name="Other2", owner_id=test_user.id)
    db_session.add(other)
    db_session.flush()
    wf_mine = Workflow(org_id=test_org.id, campaign_id=test_campaign.id, name="Mine")
    wf_other = Workflow(org_id=test_org.id, campaign_id=other.id, name="Other")
    wf_orglevel = Workflow(org_id=test_org.id, campaign_id=None, name="Org")
    db_session.add_all([wf_mine, wf_other, wf_orglevel])
    db_session.flush()

    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="ls@v.example")
    r = client.get("/api/workflows", headers={"Authorization": f"Bearer {session}"})
    assert r.status_code == 200
    names = {w["name"] for w in r.json()}
    assert names == {"Mine"}


def test_collaborator_integration_create_forces_campaign_scope(client, authed_client, db_session, test_campaign):
    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="int@v.example")
    headers = {"Authorization": f"Bearer {session}"}
    r = client.post(
        "/api/integration-builder/integrations",
        json={
            "name": "Slack via Collab",
            "direction": "push",
            "entity": "action",
            "transport_type": "api",
            "transport_config": {},
            "field_map": [], "dedup_key": [], "params": {}, "enabled": False,
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    integ_id = r.json()["id"]
    from models.models import Integration
    row = db_session.query(Integration).filter(Integration.id == integ_id).first()
    assert row.campaign_id == test_campaign.id


def test_collaborator_integration_list_isolated(client, authed_client, db_session, test_org, test_campaign):
    from models.models import Integration
    org_only = Integration(
        id="org-int-1", org_id=test_org.id, campaign_id=None,
        name="Org Slack", direction="push", entity="action", transport_type="api",
    )
    db_session.add(org_only)
    db_session.flush()

    session = _accept_and_get_session(client, authed_client, test_campaign.id, email="iso@v.example")
    headers = {"Authorization": f"Bearer {session}"}
    r = client.get("/api/integration-builder/integrations", headers=headers)
    assert r.status_code == 200
    names = {i["name"] for i in r.json()}
    assert "Org Slack" not in names


def test_collaborator_token_invalid_after_revoke(client, authed_client, test_campaign):
    token, collab_id = _invite_and_get_token(authed_client, test_campaign.id, email="rev@v.example")
    accept = client.post("/api/campaigns/collaborator/accept", json={"token": token})
    session = accept.json()["access_token"]

    # Confirm session works first.
    headers = {"Authorization": f"Bearer {session}"}
    assert client.get(f"/api/campaigns/{test_campaign.id}", headers=headers).status_code == 200

    authed_client.delete(f"/api/campaigns/{test_campaign.id}/collaborators/{collab_id}")

    # Now session is dead.
    r = client.get(f"/api/campaigns/{test_campaign.id}", headers=headers)
    assert r.status_code == 401


# ─── Re-invite / resend ────────────────────────────────────


def test_reinvite_revokes_prior_pending(authed_client, test_campaign, db_session):
    r1 = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "dup@v.example"},
    )
    r2 = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "dup@v.example"},
    )
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["id"] != r2.json()["id"]

    from models.models import CampaignCollaborator
    rows = db_session.query(CampaignCollaborator).filter(
        CampaignCollaborator.campaign_id == test_campaign.id,
        CampaignCollaborator.email == "dup@v.example",
    ).all()
    revoked = [r for r in rows if r.revoked_at is not None]
    active = [r for r in rows if r.revoked_at is None]
    assert len(revoked) == 1 and len(active) == 1


def test_resend_rotates_token(authed_client, test_campaign, db_session):
    token1, collab_id = _invite_and_get_token(authed_client, test_campaign.id, email="rot@v.example")
    r = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators/{collab_id}/resend"
    )
    assert r.status_code == 200
    assert "token=" in r.json()["accept_url"]
    new_token = r.json()["accept_url"].split("token=", 1)[1]
    assert new_token != token1


def test_resend_rejected_after_acceptance(client, authed_client, test_campaign):
    token, collab_id = _invite_and_get_token(authed_client, test_campaign.id, email="acc@v.example")
    client.post("/api/campaigns/collaborator/accept", json={"token": token})
    r = authed_client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators/{collab_id}/resend"
    )
    assert r.status_code == 400


# ─── Cross-org isolation ───────────────────────────────────


def test_invite_requires_campaign_access(client, db_session, test_campaign):
    """A user from a different org cannot invite collaborators to someone else's campaign."""
    from models.models import Organization
    from tests.conftest import create_user, make_auth_headers
    other_org = Organization(name="Other Co", slug="other-co")
    db_session.add(other_org)
    db_session.flush()
    other_user = create_user(db_session, other_org, email="outsider@other.com", role="org_admin")
    headers = make_auth_headers(other_user, other_org)

    r = client.post(
        f"/api/campaigns/{test_campaign.id}/collaborators",
        json={"email": "evil@v.example"},
        headers=headers,
    )
    assert r.status_code in (403, 404)

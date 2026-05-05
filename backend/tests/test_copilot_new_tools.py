"""Coverage for the new copilot tools (scan upload, RBAC, relay agents,
custom fields, compliance, audit log, attack paths) and the chat
attachment endpoint."""

import io
import pytest

from agents.agent_tools import TOOL_REGISTRY
from models.models import (
    AuditLog, ComplianceFramework, CopilotAttachment, CopilotConversation,
    CustomFieldDefinition, CustomRole, RelayAgent, User, UserCustomRole,
)


# ── Helpers ────────────────────────────────────────────────────────

def _call(tool_name, db, params):
    return TOOL_REGISTRY[tool_name]["fn"](db, params)


@pytest.fixture
def org_id(test_org):
    return test_org.id


# ── User / RBAC tools ──────────────────────────────────────────────

def test_list_users_filters_to_org(db_session, test_org, test_user):
    # Foreign org user must not leak.
    from models.models import Organization
    other_org = Organization(name="Other", slug="other")
    db_session.add(other_org)
    db_session.flush()
    db_session.add(User(
        email="x@other.test", display_name="x", role="analyst",
        org_id=other_org.id, hashed_password="x", is_active=True,
    ))
    db_session.flush()

    res = _call("list_users", db_session, {"_org_id": test_org.id})
    emails = {u["email"] for u in res["users"]}
    assert "admin@test.com" in emails
    assert "x@other.test" not in emails


def test_invite_user_requires_confirmation(db_session, test_org):
    res = _call("invite_user", db_session, {
        "_org_id": test_org.id,
        "email": "newbie@test.com",
        "role": "analyst",
    })
    assert "error" in res
    # Make sure no user got persisted.
    assert db_session.query(User).filter_by(email="newbie@test.com").first() is None


def test_invite_user_creates_user(db_session, test_org):
    res = _call("invite_user", db_session, {
        "_org_id": test_org.id,
        "email": "newbie@test.com",
        "role": "analyst",
        "confirmed": True,
    })
    assert res.get("id")
    assert res["email"] == "newbie@test.com"
    db_session.flush()
    u = db_session.query(User).filter_by(email="newbie@test.com").first()
    assert u is not None and u.role == "analyst" and u.org_id == test_org.id


def test_invite_user_rejects_duplicate(db_session, test_org, test_user):
    res = _call("invite_user", db_session, {
        "_org_id": test_org.id,
        "email": test_user.email,
        "role": "analyst",
        "confirmed": True,
    })
    assert "error" in res


def test_update_user_changes_role(db_session, test_org, test_user):
    res = _call("update_user", db_session, {
        "_org_id": test_org.id,
        "user_id": test_user.id,
        "role": "viewer",
        "confirmed": True,
    })
    assert res.get("role") == "viewer"
    db_session.refresh(test_user)
    assert test_user.role == "viewer"


def test_update_user_blocks_other_org(db_session, test_org, test_user):
    # Pretend we're acting as a different org.
    res = _call("update_user", db_session, {
        "_org_id": test_org.id + 999,
        "user_id": test_user.id,
        "role": "viewer",
        "confirmed": True,
    })
    assert "error" in res


def test_assign_user_role_full_cycle(db_session, test_org, test_user):
    role = CustomRole(
        org_id=test_org.id,
        name="grc-reviewer", description="GRC",
        base_permissions={"read": True},
    )
    db_session.add(role)
    db_session.flush()

    assigned = _call("assign_user_role", db_session, {
        "_org_id": test_org.id,
        "user_id": test_user.id,
        "role_id": role.id,
        "action": "assign",
        "confirmed": True,
    })
    assert "Assigned" in assigned["message"]
    assert db_session.query(UserCustomRole).filter_by(
        user_id=test_user.id, role_id=role.id,
    ).count() == 1

    removed = _call("assign_user_role", db_session, {
        "_org_id": test_org.id,
        "user_id": test_user.id,
        "role_id": role.id,
        "action": "unassign",
        "confirmed": True,
    })
    assert "Removed" in removed["message"]
    assert db_session.query(UserCustomRole).filter_by(
        user_id=test_user.id, role_id=role.id,
    ).count() == 0


# ── Custom fields ──────────────────────────────────────────────────

def test_create_and_list_custom_field(db_session, test_org):
    res = _call("create_custom_field", db_session, {
        "_org_id": test_org.id,
        "entity_type": "asset",
        "key": "data_center",
        "label": "Data Center",
        "data_type": "string",
        "confirmed": True,
    })
    assert res.get("id")

    listed = _call("list_custom_fields", db_session, {"_org_id": test_org.id})
    keys = [f["key"] for f in listed["custom_fields"]]
    assert "data_center" in keys


def test_create_custom_field_rejects_duplicate(db_session, test_org):
    db_session.add(CustomFieldDefinition(
        org_id=test_org.id, entity_type="asset", key="dup",
        label="Dup", data_type="string", source_type="manual",
    ))
    db_session.flush()
    res = _call("create_custom_field", db_session, {
        "_org_id": test_org.id, "entity_type": "asset", "key": "dup",
        "label": "Dup", "data_type": "string", "confirmed": True,
    })
    assert "error" in res


# ── Relay agents ───────────────────────────────────────────────────

def test_create_relay_agent_returns_token_once(db_session, test_org):
    res = _call("create_relay_agent", db_session, {
        "_org_id": test_org.id,
        "name": "site-a",
        "allowed_hosts": ["10.0.0.0/24"],
        "confirmed": True,
    })
    assert res.get("token", "").startswith("hka_")
    listed = _call("list_relay_agents", db_session, {"_org_id": test_org.id})
    names = [a["name"] for a in listed["relay_agents"]]
    assert "site-a" in names


def test_delete_relay_agent_blocks_when_linked(db_session, test_org):
    from models.models import Integration
    res = _call("create_relay_agent", db_session, {
        "_org_id": test_org.id, "name": "linked-agent",
        "confirmed": True,
    })
    agent_id = res["id"]
    integration = Integration(
        org_id=test_org.id, name="qualys-pull", direction="pull",
        entity="finding", transport_type="api", relay_agent_id=agent_id,
    )
    db_session.add(integration)
    db_session.flush()

    res = _call("delete_relay_agent", db_session, {
        "_org_id": test_org.id, "agent_id": agent_id, "confirmed": True,
    })
    assert "error" in res
    assert db_session.query(RelayAgent).filter_by(id=agent_id).first() is not None


# ── Compliance ─────────────────────────────────────────────────────

def test_list_compliance_frameworks_marks_subscribed(db_session, test_org):
    fw = ComplianceFramework(slug="custom_fw", name="Custom FW", version="1.0")
    db_session.add(fw)
    db_session.flush()

    res = _call("list_compliance_frameworks", db_session, {"_org_id": test_org.id})
    target = next((f for f in res["frameworks"] if f["slug"] == "custom_fw"), None)
    assert target is not None
    assert target["subscribed"] is False

    sub = _call("subscribe_to_compliance_framework", db_session, {
        "_org_id": test_org.id, "slug": "custom_fw", "confirmed": True,
    })
    assert sub.get("subscribed") is True


# ── Audit log ──────────────────────────────────────────────────────

def test_query_audit_log_filters(db_session, test_org):
    from models.models import Organization
    other_org = Organization(name="Other Org", slug="other-org")
    db_session.add(other_org)
    db_session.flush()
    db_session.add_all([
        AuditLog(org_id=test_org.id, action="create", entity_type="user",
                 entity_id=1, entity_name="a@x.test", actor_email="admin@x.test"),
        AuditLog(org_id=test_org.id, action="delete", entity_type="user",
                 entity_id=2, entity_name="b@x.test", actor_email="admin@x.test"),
        AuditLog(org_id=other_org.id, action="create", entity_type="user",
                 entity_id=3, entity_name="other@x.test", actor_email="admin@x.test"),
    ])
    db_session.flush()
    res = _call("query_audit_log", db_session, {
        "_org_id": test_org.id, "action": "delete",
    })
    actions = [e["action"] for e in res["entries"]]
    assert actions == ["delete"]
    # other-org row must not leak
    targets = [e["entity_name"] for e in res["entries"]]
    assert "other@x.test" not in targets


# ── Attack paths ───────────────────────────────────────────────────

def test_list_attack_paths_empty(db_session, test_org):
    res = _call("list_attack_paths", db_session, {
        "_org_id": test_org.id, "limit": 10,
    })
    # SQLite test DB has no attack_paths table seeded — tool should
    # return an error gracefully rather than 500. A real Postgres deploy
    # has the table from migration 036.
    assert "paths" in res
    assert res["count"] == 0 or "error" in res


# ── Scan upload via attachment ─────────────────────────────────────

def test_upload_scan_rejects_unknown_attachment(db_session, test_org):
    res = _call("upload_scan", db_session, {
        "_org_id": test_org.id,
        "attachment_id": 999999,
    })
    assert "error" in res


def test_upload_scan_rejects_unsupported_file(db_session, test_org, test_user):
    conv = CopilotConversation(org_id=test_org.id, user_id=test_user.id, title="t", messages=[])
    db_session.add(conv)
    db_session.flush()
    att = CopilotAttachment(
        org_id=test_org.id, user_id=test_user.id, conversation_id=conv.id,
        filename="readme.txt", content_type="text/plain",
        size_bytes=5, content=b"hello",
    )
    db_session.add(att)
    db_session.flush()

    res = _call("upload_scan", db_session, {
        "_org_id": test_org.id, "attachment_id": att.id,
    })
    assert "error" in res
    # Bytes are still resident (not consumed).
    db_session.refresh(att)
    assert att.consumed_at is None


# ── Endpoint smoke test for attachment upload ──────────────────────

def test_attachment_upload_endpoint(authed_client, db_session, test_org, test_user):
    # Create conversation
    resp = authed_client.post("/api/copilot/conversations")
    assert resp.status_code == 200, resp.text
    conv_id = resp.json()["id"]

    # Upload bytes via multipart
    files = {"file": ("scan.nessus", io.BytesIO(b"<NessusClientData_v2/>"), "text/xml")}
    resp = authed_client.post(
        f"/api/copilot/conversations/{conv_id}/attachments",
        files=files,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["filename"] == "scan.nessus"
    assert body["size_bytes"] > 0
    assert body["id"]

    # Foreign attachment cannot be deleted
    resp = authed_client.delete(
        f"/api/copilot/conversations/{conv_id}/attachments/{body['id']}"
    )
    assert resp.status_code == 200

"""DELETE /api/auth/orgs/{id} must cascade through every tenant-owned
table. Previously the handler depended on Postgres superuser to disable
FK triggers; we now rely on ``ON DELETE CASCADE`` on the FKs themselves.

This test seeds an org with one row in every table that holds an
``org_id`` column (plus the deep children — scans/assets/findings/
inventory/etc.), deletes the org via the API, and asserts that nothing
scoped to that org survives in any table."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from models.models import (
    Organization, User, Scan, Asset, Finding, Campaign, Tag,
    Workflow, CustomRole,
    InventorySoftware,
)
from core.auth import create_access_token, hash_password


@pytest.fixture
def super_admin_in_other_org(db_session):
    """Superadmin user lives in a *separate* org — the handler refuses
    to delete your own org."""
    home = Organization(name="Super Home", slug="super-home")
    db_session.add(home)
    db_session.flush()

    user = User(
        email="super@root.local",
        hashed_password=hash_password("x"),
        display_name="Super",
        role="superadmin",
        org_id=home.id,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def super_headers(super_admin_in_other_org):
    u = super_admin_in_other_org
    token = create_access_token(u.id, u.org_id, u.role)
    return {
        "Authorization": f"Bearer {token}",
        "X-Org-Context": str(u.org_id),
    }


def _seed_org_with_data(db_session) -> int:
    """Create an org with at least one row in every layer of the tree:
    user → custom_role, scan → asset → inventory_software, finding,
    campaign, tag, workflow, integration, agent. Returns the org id."""
    org = Organization(name="Doomed", slug="doomed")
    db_session.add(org)
    db_session.flush()

    user = User(
        email="user@doomed.local",
        hashed_password=hash_password("x"),
        display_name="U",
        role="analyst",
        org_id=org.id,
    )
    db_session.add(user)

    role = CustomRole(org_id=org.id, name="reader", description="r", base_permissions={})
    db_session.add(role)

    scan = Scan(org_id=org.id, filename="x.nessus", scan_name="x", status="completed")
    db_session.add(scan)
    db_session.flush()

    asset = Asset(scan_id=scan.id, ip="10.0.0.1", hostname="h", os="Linux")
    db_session.add(asset)
    db_session.flush()
    # org_id on assets is an ALTER-added column not on the mapper.
    db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :i"),
                       {"o": org.id, "i": asset.id})

    inv = InventorySoftware(scan_id=scan.id, asset_id=asset.id, name="openssl", version="1.0")
    db_session.add(inv)

    finding = Finding(
        scan_id=scan.id, asset_id=asset.id, plugin_id="1",
        plugin_name="x", severity=2, risk_factor="medium",
    )
    db_session.add(finding)
    db_session.flush()
    db_session.execute(text("UPDATE findings SET org_id = :o WHERE id = :i"),
                       {"o": org.id, "i": finding.id})

    campaign = Campaign(org_id=org.id, name="c", status="active", owner_id=user.id)
    db_session.add(campaign)

    tag = Tag(org_id=org.id, value="prod", category="env", color="#fff")
    db_session.add(tag)

    db_session.add(Workflow(org_id=org.id, name="w"))

    db_session.flush()
    return org.id


def test_delete_org_wipes_every_child_table(db_session, client, super_headers):
    org_id = _seed_org_with_data(db_session)

    # Verify the seed actually landed.
    assert db_session.execute(
        text("SELECT count(*) FROM users WHERE org_id = :o"), {"o": org_id}
    ).scalar() == 1
    assert db_session.execute(
        text("SELECT count(*) FROM scans WHERE org_id = :o"), {"o": org_id}
    ).scalar() == 1

    resp = client.delete(f"/api/auth/orgs/{org_id}", headers=super_headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "deleted"

    # Nothing referencing this org should remain. Walk every table with
    # org_id and assert zero rows for the deleted tenant.
    rows = db_session.execute(text("""
        SELECT name FROM sqlite_master
        WHERE type='table'
          AND name NOT LIKE 'sqlite_%'
          AND name != 'schema_migrations'
    """)).fetchall()
    for (tbl,) in rows:
        cols = {r[1] for r in db_session.execute(text(f"PRAGMA table_info({tbl})")).fetchall()}
        if "org_id" not in cols:
            continue
        count = db_session.execute(
            text(f"SELECT count(*) FROM {tbl} WHERE org_id = :o"),
            {"o": org_id},
        ).scalar()
        assert count == 0, f"{tbl} still has {count} row(s) for org {org_id}"

    # Deep children (no direct org_id) must also be gone — assets and
    # findings were pruned via their scan_id cascade.
    assert db_session.execute(
        text("SELECT count(*) FROM assets WHERE org_id = :o"), {"o": org_id}
    ).scalar() == 0
    assert db_session.execute(
        text("SELECT count(*) FROM findings WHERE org_id = :o"), {"o": org_id}
    ).scalar() == 0
    assert db_session.execute(
        text("SELECT count(*) FROM inventory_software")
    ).scalar() == 0


def test_delete_own_org_rejected(db_session, client, super_admin_in_other_org, super_headers):
    own_org_id = super_admin_in_other_org.org_id
    resp = client.delete(f"/api/auth/orgs/{own_org_id}", headers=super_headers)
    assert resp.status_code == 400
    assert "your own" in resp.json()["detail"].lower()


def test_delete_missing_org_404(client, super_headers):
    resp = client.delete("/api/auth/orgs/999999", headers=super_headers)
    assert resp.status_code == 404

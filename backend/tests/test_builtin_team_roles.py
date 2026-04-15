"""Tests for built-in team-scoped RBAC roles."""
import pytest

from core.builtin_team_roles import (
    builtin_team_role_specs,
    seed_builtin_team_roles,
    user_owner_scopes,
    apply_owner_scope_to_findings,
    apply_owner_scope_to_assets,
)
from core.ownership_teams import OWNERSHIP_ROLES
from models.models import CustomRole, UserCustomRole, User, Asset, Finding, Scan, Tag, TagPermission
from core.auth import hash_password


class TestBuiltinRoleSpecs:
    def test_one_role_per_team_excluding_custom(self):
        specs = builtin_team_role_specs()
        expected = [r for r in OWNERSHIP_ROLES if r != "Custom"]
        assert len(specs) == len(expected)
        scopes = {s["scope_owner_role"] for s in specs}
        assert scopes == set(expected)

    def test_every_spec_marked_builtin(self):
        assert all(s["is_builtin"] for s in builtin_team_role_specs())

    def test_vm_role_present(self):
        specs = {s["scope_owner_role"]: s for s in builtin_team_role_specs()}
        assert "VM" in specs
        assert specs["VM"]["name"] == "VM"
        assert specs["VM"]["base_permissions"]["read_findings"] is True


class TestSeeding:
    def test_seed_creates_one_role_per_team(self, db_session, test_org):
        count = seed_builtin_team_roles(db_session, test_org.id)
        expected_count = len([r for r in OWNERSHIP_ROLES if r != "Custom"])
        assert count == expected_count

        roles = db_session.query(CustomRole).filter(
            CustomRole.org_id == test_org.id, CustomRole.is_builtin == True  # noqa: E712
        ).all()
        assert len(roles) == expected_count

    def test_seed_is_idempotent(self, db_session, test_org):
        seed_builtin_team_roles(db_session, test_org.id)
        first_count = db_session.query(CustomRole).filter(
            CustomRole.org_id == test_org.id
        ).count()
        first_tag_count = db_session.query(Tag).filter(Tag.category == "team").count()
        first_perm_count = db_session.query(TagPermission).count()
        # Second run should not add any new roles, tags, or permissions.
        added = seed_builtin_team_roles(db_session, test_org.id)
        assert added == 0
        second_count = db_session.query(CustomRole).filter(
            CustomRole.org_id == test_org.id
        ).count()
        assert first_count == second_count
        assert db_session.query(Tag).filter(Tag.category == "team").count() == first_tag_count
        assert db_session.query(TagPermission).count() == first_perm_count

    def test_seed_creates_team_tags(self, db_session, test_org):
        seed_builtin_team_roles(db_session, test_org.id)
        expected_teams = [r for r in OWNERSHIP_ROLES if r != "Custom"]
        tags = db_session.query(Tag).filter(Tag.category == "team").all()
        tag_values = {t.value for t in tags}
        assert tag_values == set(expected_teams)

    def test_seed_creates_tag_permissions(self, db_session, test_org):
        seed_builtin_team_roles(db_session, test_org.id)
        expected_teams = [r for r in OWNERSHIP_ROLES if r != "Custom"]
        for team in expected_teams:
            role = db_session.query(CustomRole).filter(
                CustomRole.org_id == test_org.id,
                CustomRole.scope_owner_role == team,
            ).first()
            tag = db_session.query(Tag).filter(
                Tag.category == "team", Tag.value == team,
            ).first()
            perms = db_session.query(TagPermission).filter(
                TagPermission.role_id == role.id,
                TagPermission.target_id == tag.id,
            ).all()
            perm_set = {p.permission for p in perms}
            assert perm_set == {"read", "write"}, f"Missing permissions for {team}"


class TestUserOwnerScopes:
    def _make_user(self, db_session, test_org, email: str) -> User:
        user = User(
            email=email, hashed_password=hash_password("x"),
            role="custom", org_id=test_org.id, is_active=True,
        )
        db_session.add(user)
        db_session.flush()
        return user

    def test_user_with_no_custom_roles_is_unrestricted(self, db_session, test_org):
        user = self._make_user(db_session, test_org, "no-roles@t.com")
        assert user_owner_scopes(db_session, user.id) is None

    def test_user_with_scoped_roles_returns_scope_union(self, db_session, test_org):
        seed_builtin_team_roles(db_session, test_org.id)
        user = self._make_user(db_session, test_org, "vm-soc@t.com")
        for team in ("VM", "SOC"):
            role = db_session.query(CustomRole).filter(
                CustomRole.org_id == test_org.id,
                CustomRole.scope_owner_role == team,
            ).first()
            db_session.add(UserCustomRole(user_id=user.id, role_id=role.id))
        db_session.flush()

        scopes = user_owner_scopes(db_session, user.id)
        assert scopes == {"VM", "SOC"}

    def test_unscoped_role_grants_unrestricted(self, db_session, test_org):
        seed_builtin_team_roles(db_session, test_org.id)
        user = self._make_user(db_session, test_org, "mixed@t.com")

        # Scoped role
        vm = db_session.query(CustomRole).filter(
            CustomRole.org_id == test_org.id, CustomRole.scope_owner_role == "VM",
        ).first()
        db_session.add(UserCustomRole(user_id=user.id, role_id=vm.id))

        # Unscoped role that grants read_findings
        unscoped = CustomRole(
            org_id=test_org.id, name="Global Reader",
            base_permissions={"read_findings": True, "read_assets": True},
            is_active=True,
        )
        db_session.add(unscoped)
        db_session.flush()
        db_session.add(UserCustomRole(user_id=user.id, role_id=unscoped.id))
        db_session.flush()

        assert user_owner_scopes(db_session, user.id) is None


class TestScopeFilters:
    def test_none_scope_returns_query_unchanged(self, db_session):
        q = db_session.query(Finding)
        assert apply_owner_scope_to_findings(q, None) is q
        assert apply_owner_scope_to_assets(q, None) is q

    def test_empty_scope_returns_nothing(self, db_session, test_org):
        scan = Scan(org_id=test_org.id, filename="a.nessus", scan_name="s", scan_type="nessus", scan_date="2026-01-01")
        db_session.add(scan)
        db_session.flush()
        asset = Asset(scan_id=scan.id, ip="1.1.1.1", inferred_team="VM")
        db_session.add(asset)
        db_session.flush()
        db_session.add(Finding(
            scan_id=scan.id, asset_id=asset.id,
            plugin_id="1", plugin_name="x", severity=3, owner_suggestion="VM",
        ))
        db_session.flush()

        findings_q = apply_owner_scope_to_findings(db_session.query(Finding), set())
        assert findings_q.count() == 0
        assets_q = apply_owner_scope_to_assets(db_session.query(Asset), set())
        assert assets_q.count() == 0

    def test_vm_scope_matches_vm_findings_only(self, db_session, test_org):
        scan = Scan(org_id=test_org.id, filename="b.nessus", scan_name="s2", scan_type="nessus", scan_date="2026-01-01")
        db_session.add(scan)
        db_session.flush()
        asset = Asset(scan_id=scan.id, ip="2.2.2.2")
        db_session.add(asset)
        db_session.flush()

        db_session.add(Finding(
            scan_id=scan.id, asset_id=asset.id,
            plugin_id="nuc-1", plugin_name="nuclei find", severity=3, owner_suggestion="VM",
        ))
        db_session.add(Finding(
            scan_id=scan.id, asset_id=asset.id,
            plugin_id="soc-1", plugin_name="soc find", severity=3, owner_suggestion="SOC",
        ))
        db_session.flush()

        q = apply_owner_scope_to_findings(db_session.query(Finding), {"VM"})
        results = q.all()
        assert len(results) == 1
        assert results[0].owner_suggestion == "VM"

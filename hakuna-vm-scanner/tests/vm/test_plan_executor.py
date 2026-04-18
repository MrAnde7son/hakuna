"""Tests for plan_executor — translating an adaptive scan plan into nuclei commands.

Covers PR 2 of the APSP feature:
- Plan with target_list writes a tmpfile and uses -list
- Per-asset target cap is enforced
- Cross-origin URLs are filtered out (credential-leak prevention)
- All-cross-origin plan falls back to host targeting
- Plan with skip_reason returns no commands
- Plan with no nuclei action raises ScanPlanInvalidError (caller falls back)
- Malformed flags.target_list per-action degrades gracefully
- GraphQL profile injects graphql tag + JSON Content-Type
- Multiple actions produce multiple commands sorted by priority

The fixtures use a tmpdir for tmpfile cleanup verification — every test
that produces tmpfiles must clean them up.
"""
import os

import pytest

from scanner.vm.plan_executor import (
    NUCLEI_MAX_TARGETS_PER_ASSET,
    ScanPlanInvalidError,
    build_nuclei_commands_from_plan,
    cleanup_tempfiles,
    extract_nuclei_actions,
    filter_same_origin_targets,
)


# ── extract_nuclei_actions ──────────────────────────────────────


class TestExtractNucleiActions:
    def test_filters_to_nuclei_only(self):
        plan = {
            "actions": [
                {"tool": "nmap", "priority": 1},
                {"tool": "nuclei", "priority": 2},
                {"tool": "testssl", "priority": 3},
            ]
        }
        actions = extract_nuclei_actions(plan)
        assert len(actions) == 1
        assert actions[0]["tool"] == "nuclei"

    def test_sorts_by_priority_ascending(self):
        plan = {
            "actions": [
                {"tool": "nuclei", "priority": 5, "tags": ["five"]},
                {"tool": "nuclei", "priority": 1, "tags": ["one"]},
                {"tool": "nuclei", "priority": 3, "tags": ["three"]},
            ]
        }
        actions = extract_nuclei_actions(plan)
        assert [a["priority"] for a in actions] == [1, 3, 5]

    def test_empty_plan_returns_empty(self):
        assert extract_nuclei_actions({"actions": []}) == []

    def test_missing_actions_key_returns_empty(self):
        assert extract_nuclei_actions({}) == []


# ── filter_same_origin_targets ──────────────────────────────────


class TestFilterSameOriginTargets:
    def test_drops_cross_origin_urls(self):
        urls = [
            "https://example.com/api/v1/users",
            "https://cdn.thirdparty.com/script.js",
            "https://example.com/api/v1/orders",
        ]
        kept = filter_same_origin_targets(urls, "https://example.com")
        assert kept == [
            "https://example.com/api/v1/users",
            "https://example.com/api/v1/orders",
        ]

    def test_compares_hostname_case_insensitive(self):
        urls = ["https://Example.COM/api"]
        assert filter_same_origin_targets(urls, "https://example.com") == ["https://Example.COM/api"]

    def test_bare_hostname_target_strips_port(self):
        urls = ["https://example.com/api"]
        assert filter_same_origin_targets(urls, "example.com:8080") == ["https://example.com/api"]

    def test_unparseable_target_keeps_all_urls(self):
        """Plain IP target with no http_url path — same-origin filter is a
        no-op so per-endpoint scanning still works."""
        urls = ["https://example.com/api"]
        assert filter_same_origin_targets(urls, "") == ["https://example.com/api"]

    def test_drops_unparseable_urls(self):
        urls = ["https://example.com/api", "not a url"]
        kept = filter_same_origin_targets(urls, "https://example.com")
        assert kept == ["https://example.com/api"]


# ── build_nuclei_commands_from_plan ──────────────────────────────


@pytest.fixture
def tmp_target_dir(tmp_path):
    return str(tmp_path)


def _basic_plan(tags=None, target_list=None, profile=None, **action_extra):
    flags = {}
    if target_list is not None:
        flags["target_list"] = target_list
    if profile is not None:
        flags["profile"] = profile
    action = {
        "tool": "nuclei",
        "priority": 1,
        "tags": tags or ["generic"],
        "flags": flags,
        **action_extra,
    }
    return {"asset_id": 1, "actions": [action]}


class TestBuildFromPlan:
    def _kwargs(self, tmp_target_dir):
        return {
            "nuclei_bin": "/usr/bin/nuclei",
            "cred_args": [],
            "nuclei_timeout": 30,
            "rate_limit": 150,
            "target_list_dir": tmp_target_dir,
        }

    def test_target_list_writes_tmpfile_and_uses_list_flag(self, tmp_target_dir):
        urls = ["https://api.example.com/v1/users", "https://api.example.com/v1/orders"]
        plan = _basic_plan(target_list=urls)
        try:
            cmds = build_nuclei_commands_from_plan(
                plan=plan, target="https://api.example.com",
                **self._kwargs(tmp_target_dir),
            )
            assert len(cmds) == 1
            cmd = cmds[0]["cmd"]
            # -list <path> appears
            assert "-list" in cmd
            list_path = cmd[cmd.index("-list") + 1]
            assert os.path.exists(list_path)
            with open(list_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            assert lines == urls
            # No -target when -list is used
            assert "-target" not in cmd
        finally:
            cleanup_tempfiles(cmds[0].get("tempfiles") or [])

    def test_target_list_capped_at_per_asset_max(self, tmp_target_dir, monkeypatch):
        """Cap the target list so a misbehaving plan can't produce hours of work."""
        # Build a list larger than the cap.
        many = [f"https://api.example.com/path{i}" for i in range(NUCLEI_MAX_TARGETS_PER_ASSET + 50)]
        plan = _basic_plan(target_list=many)
        try:
            cmds = build_nuclei_commands_from_plan(
                plan=plan, target="https://api.example.com",
                **self._kwargs(tmp_target_dir),
            )
            list_path = cmds[0]["cmd"][cmds[0]["cmd"].index("-list") + 1]
            with open(list_path) as f:
                lines = [l for l in f if l.strip()]
            assert len(lines) == NUCLEI_MAX_TARGETS_PER_ASSET
        finally:
            cleanup_tempfiles(cmds[0].get("tempfiles") or [])

    def test_cross_origin_urls_filtered_out(self, tmp_target_dir):
        plan = _basic_plan(target_list=[
            "https://api.example.com/users",
            "https://cdn.thirdparty.com/script.js",
        ])
        try:
            cmds = build_nuclei_commands_from_plan(
                plan=plan, target="https://api.example.com",
                **self._kwargs(tmp_target_dir),
            )
            list_path = cmds[0]["cmd"][cmds[0]["cmd"].index("-list") + 1]
            with open(list_path) as f:
                lines = [l.strip() for l in f if l.strip()]
            assert lines == ["https://api.example.com/users"]
        finally:
            cleanup_tempfiles(cmds[0].get("tempfiles") or [])

    def test_all_cross_origin_falls_back_to_host_target(self, tmp_target_dir):
        """When every URL in target_list is cross-origin, fall back to the
        host-level target rather than skipping the scan entirely."""
        plan = _basic_plan(target_list=[
            "https://cdn.thirdparty.com/script.js",
            "https://analytics.thirdparty.com/track.js",
        ])
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://api.example.com",
            **self._kwargs(tmp_target_dir),
        )
        assert "-list" not in cmds[0]["cmd"]
        assert "-target" in cmds[0]["cmd"]
        assert not cmds[0]["tempfiles"], "no tmpfile should be created on fallback"

    def test_skip_reason_returns_no_commands(self, tmp_target_dir):
        plan = {
            "asset_id": 1,
            "actions": [{"tool": "nuclei", "priority": 1, "tags": ["x"]}],
            "skip_reason": "asset is decommissioned",
        }
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://example.com",
            **self._kwargs(tmp_target_dir),
        )
        assert cmds == []

    def test_no_nuclei_action_raises_invalid(self, tmp_target_dir):
        """Plan with only non-nuclei actions has nothing this worker can run."""
        plan = {"asset_id": 1, "actions": [{"tool": "nmap", "priority": 1}]}
        with pytest.raises(ScanPlanInvalidError):
            build_nuclei_commands_from_plan(
                plan=plan, target="https://example.com",
                **self._kwargs(tmp_target_dir),
            )

    def test_none_plan_raises_invalid(self, tmp_target_dir):
        with pytest.raises(ScanPlanInvalidError):
            build_nuclei_commands_from_plan(
                plan=None, target="https://example.com",
                **self._kwargs(tmp_target_dir),
            )

    def test_malformed_target_list_per_action_skips_only_that_action(self, tmp_target_dir):
        """One bad action shouldn't take down the whole plan if other actions
        are still runnable."""
        plan = {
            "asset_id": 1,
            "actions": [
                {"tool": "nuclei", "priority": 1, "flags": {"target_list": "not a list"}},
                {"tool": "nuclei", "priority": 2, "tags": ["wordpress"]},
            ],
        }
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://example.com",
            **self._kwargs(tmp_target_dir),
        )
        assert len(cmds) == 1
        assert "wordpress" in " ".join(cmds[0]["cmd"])

    def test_plan_with_only_invalid_actions_raises(self, tmp_target_dir):
        plan = {
            "asset_id": 1,
            "actions": [
                {"tool": "nuclei", "priority": 1, "flags": {"target_list": 123}},
            ],
        }
        with pytest.raises(ScanPlanInvalidError):
            build_nuclei_commands_from_plan(
                plan=plan, target="https://example.com",
                **self._kwargs(tmp_target_dir),
            )

    def test_graphql_profile_injects_tag_and_content_type(self, tmp_target_dir):
        plan = _basic_plan(profile="graphql", tags=[])
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://api.example.com/graphql",
            **self._kwargs(tmp_target_dir),
        )
        cmd = cmds[0]["cmd"]
        # graphql tag added
        tag_idx = cmd.index("-tags")
        assert "graphql" in cmd[tag_idx + 1]
        # JSON content-type header injected
        assert "Content-Type: application/json" in cmd

    def test_multiple_actions_produce_multiple_commands_by_priority(self, tmp_target_dir):
        plan = {
            "asset_id": 1,
            "actions": [
                {"tool": "nuclei", "priority": 3, "tags": ["last"]},
                {"tool": "nuclei", "priority": 1, "tags": ["first"]},
                {"tool": "nuclei", "priority": 2, "tags": ["middle"]},
            ],
        }
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://example.com",
            **self._kwargs(tmp_target_dir),
        )
        assert len(cmds) == 3
        # Verify order matches priority sort
        joined = [" ".join(c["cmd"]) for c in cmds]
        assert "first" in joined[0]
        assert "middle" in joined[1]
        assert "last" in joined[2]

    def test_empty_tags_and_templates_falls_back_to_generic(self, tmp_target_dir):
        """An action with neither tags nor templates would emit a no-op
        command. We default to generic,exposure to keep something running."""
        plan = {"asset_id": 1, "actions": [{"tool": "nuclei", "priority": 1}]}
        cmds = build_nuclei_commands_from_plan(
            plan=plan, target="https://example.com",
            **self._kwargs(tmp_target_dir),
        )
        cmd = cmds[0]["cmd"]
        tag_idx = cmd.index("-tags")
        assert "generic" in cmd[tag_idx + 1]


# ── cleanup_tempfiles ──────────────────────────────────────────


class TestCleanupTempfiles:
    def test_removes_files(self, tmp_path):
        paths = []
        for i in range(3):
            p = tmp_path / f"target-{i}.txt"
            p.write_text("x")
            paths.append(str(p))
        cleanup_tempfiles(paths)
        for p in paths:
            assert not os.path.exists(p)

    def test_missing_files_do_not_raise(self):
        # Must never raise — partial cleanup must complete.
        cleanup_tempfiles(["/tmp/does-not-exist-12345.txt"])

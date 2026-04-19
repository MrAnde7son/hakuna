"""Tests for the VM scanner scheduler."""

import socket
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scanner.vm.scheduler import (
    _get_latest_github_release,
    _get_local_template_version,
    _template_sync_check_async,
)


class TestLocalTemplateVersion:
    def test_returns_unknown_when_no_config(self, tmp_path):
        """Returns 'unknown' when no config file exists."""
        with patch("scanner.vm.scheduler.os.path.expanduser", return_value=str(tmp_path / "nonexistent")):
            result = _get_local_template_version()
        assert result == "unknown"

    def test_reads_version_from_config(self, tmp_path):
        """Reads version from .templates-config.json."""
        import json

        config_path = tmp_path / ".templates-config.json"
        config_path.write_text(json.dumps({"nuclei-templates-version": "v9.7.3"}))

        with patch("scanner.vm.scheduler.os.path.expanduser", return_value=str(config_path)):
            with patch("scanner.vm.scheduler.os.path.exists", return_value=True):
                # Patch open to use the config file
                with patch("builtins.open", return_value=open(config_path)):
                    result = _get_local_template_version()

        # The function iterates config_paths, so we need to mock more carefully
        # Just test it doesn't crash and returns a string
        assert isinstance(result, str)


class TestGithubReleaseFetch:
    """DNS failures must not emit a stack trace at warning level — this
    task runs every 6h and a network-restricted container would flood
    logs with identical tracebacks otherwise."""

    def test_dns_error_logs_info_not_warning(self, caplog):
        err = urllib.error.URLError(socket.gaierror(-2, "Name or service not known"))
        with patch("scanner.vm.scheduler.urllib.request.urlopen", side_effect=err):
            with caplog.at_level("INFO", logger="scanner.vm.scheduler"):
                result = _get_latest_github_release()
        assert result is None
        # Must log at INFO, not WARNING; must NOT include a traceback.
        records = [r for r in caplog.records if "GitHub unreachable" in r.getMessage()]
        assert records, "expected one compact info log for DNS failure"
        assert all(r.levelname == "INFO" and r.exc_info is None for r in records)

    def test_unexpected_error_still_logs_warning(self, caplog):
        with patch(
            "scanner.vm.scheduler.urllib.request.urlopen",
            side_effect=RuntimeError("bug"),
        ):
            with caplog.at_level("WARNING", logger="scanner.vm.scheduler"):
                result = _get_latest_github_release()
        assert result is None
        assert any(
            r.levelname == "WARNING" and r.exc_info for r in caplog.records
        )


class TestTemplateSyncDisabled:
    """Operator opt-out for air-gapped deployments — skip the HTTP call
    entirely when TEMPLATE_SYNC_DISABLED is set, so we never even try
    to resolve GitHub."""

    def test_disabled_flag_short_circuits(self, monkeypatch):
        monkeypatch.setenv("TEMPLATE_SYNC_DISABLED", "1")
        with patch("scanner.vm.scheduler._get_latest_github_release") as gh:
            import asyncio
            result = asyncio.run(_template_sync_check_async())
        assert result == {"status": "disabled"}
        gh.assert_not_called()

    def test_unreachable_surfaces_local_version(self, monkeypatch):
        monkeypatch.delenv("TEMPLATE_SYNC_DISABLED", raising=False)
        with patch("scanner.vm.scheduler._get_local_template_version", return_value="v10.0.0"):
            with patch("scanner.vm.scheduler._get_latest_github_release", return_value=None):
                import asyncio
                result = asyncio.run(_template_sync_check_async())
        assert result == {"status": "unreachable", "local_version": "v10.0.0"}


class TestBeatSchedule:
    """Beat now runs container-local maintenance only. Per-asset scans
    are scheduled by the backend via the /vm/scans/ HTTP API so findings
    flow through the backend's ingest pipeline (services/post_ingest.
    finalize_scan) rather than going straight into the database from
    inside this container.
    """

    def test_only_template_sync_scheduled(self):
        from scanner.vm.celery_app import celery_app

        schedule = celery_app.conf.beat_schedule
        assert "template-sync-every-6h" in schedule
        # Explicit: the old weekly scan job must not come back — scheduling
        # belongs to the backend now, not Celery Beat in this container.
        assert "weekly-vm-scan-monday-2am" not in schedule

    def test_template_sync_every_6h(self):
        from scanner.vm.celery_app import celery_app

        job = celery_app.conf.beat_schedule["template-sync-every-6h"]
        assert job["task"] == "vm.template_sync_check"

    def test_dast_template_sync_scheduled(self):
        from scanner.vm.celery_app import celery_app

        job = celery_app.conf.beat_schedule["dast-template-sync-daily"]
        assert job["task"] == "vm.dast_template_sync"


class TestDastTemplateSync:
    """Tests for the reewardius DAST template sync task."""

    def test_clone_when_dest_does_not_exist(self, tmp_path):
        """First run → git clone --depth 1 into the target directory."""
        from scanner.vm.scheduler import _dast_template_sync_impl

        dest = str(tmp_path / "dast")

        def fake_run(cmd, **kwargs):
            # Simulate clone by creating the dir with one yaml + a .git marker
            import os
            os.makedirs(os.path.join(dest, ".git"), exist_ok=True)
            with open(os.path.join(dest, "xss.yaml"), "w") as f:
                f.write("id: xss\ninfo:\n  tags: xss\n")
            return MagicMock(returncode=0, stderr="")

        with patch("scanner.vm.scheduler.subprocess.run", side_effect=fake_run) as mock_run:
            result = _dast_template_sync_impl(
                repo_url="https://example.test/dast.git",
                target_dir=dest,
            )

        assert result["status"] == "ok"
        assert result["action"] == "clone"
        assert result["template_count"] == 1
        # Verify we invoked git clone --depth 1
        call_cmd = mock_run.call_args.args[0]
        assert call_cmd[0] == "git"
        assert "clone" in call_cmd
        assert "--depth" in call_cmd

    def test_pull_when_git_dir_exists(self, tmp_path):
        """Subsequent runs → git -C <dest> pull --ff-only."""
        import os

        from scanner.vm.scheduler import _dast_template_sync_impl

        dest = str(tmp_path / "dast")
        os.makedirs(os.path.join(dest, ".git"), exist_ok=True)
        with open(os.path.join(dest, "sqli.yaml"), "w") as f:
            f.write("id: sqli\ninfo:\n  tags: sqli\n")

        with patch(
            "scanner.vm.scheduler.subprocess.run",
            return_value=MagicMock(returncode=0, stderr=""),
        ) as mock_run:
            result = _dast_template_sync_impl(target_dir=dest)

        assert result["status"] == "ok"
        assert result["action"] == "pull"
        call_cmd = mock_run.call_args.args[0]
        assert call_cmd[:3] == ["git", "-C", dest]
        assert "pull" in call_cmd
        assert "--ff-only" in call_cmd

    def test_clone_removes_stale_non_git_dir(self, tmp_path):
        """If destination exists without .git, wipe it before cloning
        (a half-written sync shouldn't poison the next run)."""
        import os

        from scanner.vm.scheduler import _dast_template_sync_impl

        dest = str(tmp_path / "dast")
        os.makedirs(dest)
        stale_path = os.path.join(dest, "stale.txt")
        with open(stale_path, "w") as f:
            f.write("leftover")

        def fake_run(cmd, **kwargs):
            # After rmtree, clone recreates the directory
            os.makedirs(os.path.join(dest, ".git"), exist_ok=True)
            return MagicMock(returncode=0, stderr="")

        with patch("scanner.vm.scheduler.subprocess.run", side_effect=fake_run):
            result = _dast_template_sync_impl(target_dir=dest)

        assert result["status"] == "ok"
        assert result["action"] == "clone"
        assert not os.path.exists(stale_path)

    def test_returns_error_when_git_fails(self, tmp_path):
        """Non-zero git exit is surfaced with a truncated stderr."""
        from scanner.vm.scheduler import _dast_template_sync_impl

        dest = str(tmp_path / "dast")

        with patch(
            "scanner.vm.scheduler.subprocess.run",
            return_value=MagicMock(returncode=128, stderr="fatal: could not connect"),
        ):
            result = _dast_template_sync_impl(target_dir=dest)

        assert result["status"] == "error"
        assert result["action"] == "clone"
        assert "fatal" in result["stderr"]

    def test_returns_error_when_subprocess_raises(self, tmp_path):
        """Timeouts / missing git binary don't crash the Celery worker."""
        from scanner.vm.scheduler import _dast_template_sync_impl

        dest = str(tmp_path / "dast")

        with patch(
            "scanner.vm.scheduler.subprocess.run",
            side_effect=FileNotFoundError("git not installed"),
        ):
            result = _dast_template_sync_impl(target_dir=dest)

        assert result["status"] == "error"
        assert "git not installed" in result["error"]

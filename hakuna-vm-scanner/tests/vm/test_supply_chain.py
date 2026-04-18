"""Tests for npm supply_chain helpers — version-range parsing and unmaintained detection."""

from datetime import datetime, timedelta, timezone

from scanner.vm.code_repo.supply_chain import (
    _is_unmaintained,
    _version_in_range,
)


class TestIsUnmaintained:
    def test_recent_publish_not_unmaintained(self):
        recent = datetime.now(timezone.utc) - timedelta(days=30)
        assert not _is_unmaintained(recent)

    def test_old_publish_unmaintained(self):
        old = datetime.now(timezone.utc) - timedelta(days=500)
        assert _is_unmaintained(old)

    def test_none_not_unmaintained(self):
        # Unknown publish date ≠ unmaintained — prefer under-reporting.
        assert not _is_unmaintained(None)


class TestVersionInRange:
    def test_gte_lt_range(self):
        assert _version_in_range("1.5.0", ">= 1.0.0, < 2.0.0")
        assert not _version_in_range("2.0.0", ">= 1.0.0, < 2.0.0")
        assert not _version_in_range("0.9.0", ">= 1.0.0, < 2.0.0")

    def test_exact_version(self):
        assert _version_in_range("1.2.3", "= 1.2.3")
        assert not _version_in_range("1.2.4", "= 1.2.3")

    def test_lte_range(self):
        assert _version_in_range("2.0.0", "<= 2.0.0")
        assert not _version_in_range("2.0.1", "<= 2.0.0")

    def test_parse_failure_errs_on_reporting(self):
        # Un-parseable range → we return True rather than silently drop the advisory.
        assert _version_in_range("1.0.0", "~~broken~~")

    def test_v_prefix_tolerated(self):
        assert _version_in_range("v1.2.3", ">= 1.0.0")

"""Tests for the new GitHub/npm finding generators:

- OSV-driven npm dependency CVEs
- npm package hygiene (deprecated, unmaintained)
- repo hygiene (branch protection, SECURITY.md, archived w/ activity)

Pure-function and stubbed-client only — network paths are out of scope here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.ingest.github_npm.discovery import (
    _earliest_fixed_version,
    _normalize_osv_severity,
    _osv_advisory_url,
    _osv_primary_id,
    _parse_iso8601,
    analyze_workflow_content,
    scan_npm_dependency_cves,
    scan_npm_package_hygiene,
    scan_repo_hygiene,
    scan_workflow_risks,
)
from app.ingest.github_npm.models import (
    AttributedNpmPackage,
    AttributedRepo,
)


# ── OSV helpers ───────────────────────────────────────────────────────


class TestNormalizeOsvSeverity:
    def test_database_specific_takes_precedence(self):
        assert _normalize_osv_severity({"database_specific": {"severity": "HIGH"}}) == "high"

    def test_moderate_maps_to_medium(self):
        assert _normalize_osv_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"

    def test_falls_back_to_numeric_cvss(self):
        assert _normalize_osv_severity({"severity": [{"score": "9.5"}]}) == "critical"
        assert _normalize_osv_severity({"severity": [{"score": "7.0"}]}) == "high"
        assert _normalize_osv_severity({"severity": [{"score": "5.5"}]}) == "medium"
        assert _normalize_osv_severity({"severity": [{"score": "1.0"}]}) == "low"

    def test_default_is_medium(self):
        assert _normalize_osv_severity({}) == "medium"


class TestEarliestFixedVersion:
    def test_extracts_fixed_event(self):
        vuln = {"affected": [{
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "0"}, {"fixed": "4.17.12"},
            ]}],
        }]}
        assert _earliest_fixed_version(vuln) == "4.17.12"

    def test_returns_none_when_no_fix(self):
        vuln = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
        assert _earliest_fixed_version(vuln) is None


class TestOsvPrimaryId:
    def test_prefers_ghsa_in_id(self):
        assert _osv_primary_id({"id": "GHSA-1", "aliases": ["CVE-2020-1"]}) == "GHSA-1"

    def test_prefers_ghsa_alias_over_osv_id(self):
        assert _osv_primary_id({"id": "OSV-2020-1", "aliases": ["GHSA-2"]}) == "GHSA-2"

    def test_falls_back_to_cve_alias(self):
        assert _osv_primary_id({"id": "OSV-2020-1", "aliases": ["CVE-2020-1"]}) == "CVE-2020-1"


class TestOsvAdvisoryUrl:
    def test_prefers_github_advisory_reference(self):
        url = _osv_advisory_url({
            "references": [
                {"url": "https://nvd.nist.gov/vuln/CVE-1"},
                {"url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"},
            ],
            "id": "GHSA-aaaa-bbbb-cccc",
        })
        assert url == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"

    def test_falls_back_to_osv_page(self):
        assert _osv_advisory_url({"id": "GHSA-x"}) == "https://osv.dev/vulnerability/GHSA-x"


# ── ISO timestamp parsing ─────────────────────────────────────────────


class TestParseIso:
    def test_z_suffix(self):
        dt = _parse_iso8601("2023-04-12T14:22:01Z")
        assert dt is not None and dt.tzinfo is not None

    def test_millis(self):
        dt = _parse_iso8601("2023-04-12T14:22:01.123Z")
        assert dt is not None

    def test_invalid_returns_none(self):
        assert _parse_iso8601("not-a-date") is None
        assert _parse_iso8601("") is None


# ── npm dependency CVEs (stubbed OSV client) ──────────────────────────


class _StubOsv:
    """Stand-in for OsvClient — returns a canned vulns list per package."""

    def __init__(self, by_package: dict[str, list[dict]]):
        self._by_package = by_package

    async def query(self, package_name: str, version, ecosystem: str = "npm"):
        return list(self._by_package.get(package_name, []))


@pytest.mark.asyncio
async def test_scan_npm_dependency_cves_emits_one_finding_per_advisory():
    osv = _StubOsv({
        "lodash": [
            {
                "id": "GHSA-jf85-cpcp-j695",
                "aliases": ["CVE-2019-10744"],
                "summary": "Prototype Pollution in lodash",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.12"},
                ]}]}],
                "references": [
                    {"url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"},
                ],
            },
        ],
        "left-pad": [],
    })
    pkgs = [
        AttributedNpmPackage(name="lodash", version="4.17.10", reasons=["npm_maintainer"]),
        AttributedNpmPackage(name="left-pad", version="1.0.0", reasons=["npm_maintainer"]),
    ]
    cves = await scan_npm_dependency_cves(osv, pkgs)

    assert len(cves) == 1
    cve = cves[0]
    assert cve.package == "lodash"
    assert cve.installed_version == "4.17.10"
    assert cve.cve == "GHSA-jf85-cpcp-j695"
    assert cve.severity == "high"
    assert cve.fix_available is True
    assert cve.fixed_version == "4.17.12"
    assert "GHSA" in (cve.advisory_url or "")
    assert "CVE-2019-10744" in cve.aliases


@pytest.mark.asyncio
async def test_scan_npm_dependency_cves_skips_packages_without_version():
    """No version → OSV would return *every* historical advisory; that's
    pure noise. We must skip those packages entirely."""
    osv = _StubOsv({"lodash": [{"id": "GHSA-x", "database_specific": {"severity": "LOW"}}]})
    pkgs = [AttributedNpmPackage(name="lodash", version=None, reasons=["npm_maintainer"])]
    cves = await scan_npm_dependency_cves(osv, pkgs)
    assert cves == []


# ── npm package hygiene ───────────────────────────────────────────────


class TestPackageHygiene:
    def test_deprecated_emits_finding(self):
        pkgs = [AttributedNpmPackage(
            name="oldpkg", version="1.0.0",
            deprecated=True, deprecated_message="use newpkg instead",
            reasons=["npm_maintainer"],
        )]
        out = scan_npm_package_hygiene(pkgs)
        rules = {h.rule_id for h in out}
        assert "deprecated" in rules
        dep = next(h for h in out if h.rule_id == "deprecated")
        assert "use newpkg" in dep.detail

    def test_unmaintained_threshold(self):
        # Last published ~3 years before our fixed `now`.
        pkg = AttributedNpmPackage(
            name="dusty", version="0.1.0",
            last_published="2022-01-01T00:00:00Z",
            reasons=["npm_maintainer"],
        )
        now = datetime(2026, 5, 6, tzinfo=timezone.utc)
        out = scan_npm_package_hygiene([pkg], unmaintained_after_days=730, now=now)
        rules = {h.rule_id for h in out}
        assert "unmaintained" in rules

    def test_recent_publish_no_finding(self):
        pkg = AttributedNpmPackage(
            name="fresh", version="1.0.0",
            last_published="2026-04-01T00:00:00Z",
            reasons=["npm_maintainer"],
        )
        now = datetime(2026, 5, 6, tzinfo=timezone.utc)
        out = scan_npm_package_hygiene([pkg], unmaintained_after_days=730, now=now)
        assert all(h.rule_id != "unmaintained" for h in out)

    def test_deprecated_message_truncated(self):
        # Some maintainers paste massive migration guides; we cap at 500
        # chars so the finding detail stays readable.
        pkg = AttributedNpmPackage(
            name="huge", version="1.0.0",
            deprecated=True, deprecated_message="x" * 5000,
            reasons=["npm_maintainer"],
        )
        out = scan_npm_package_hygiene([pkg])
        dep = next(h for h in out if h.rule_id == "deprecated")
        assert len(dep.detail) <= 500


# ── repo hygiene (stubbed GitHub client) ──────────────────────────────


class _StubGH:
    """Minimal GitHub client: configurable branch responses + raw existence map."""

    def __init__(
        self,
        *,
        branch_responses: dict[tuple[str, str, str], dict | None],
        existing_files: set[tuple[str, str, str]],
    ):
        self._branches = branch_responses
        self._files = existing_files

    async def get_branch(self, owner, repo, branch):
        return self._branches.get((owner, repo, branch))

    async def raw_file_exists(self, owner, repo, path, *, ref=None):
        return (owner, repo, path) in self._files


@pytest.mark.asyncio
async def test_repo_hygiene_flags_unprotected_default_branch():
    gh = _StubGH(
        branch_responses={("acme", "widget", "main"): {"name": "main", "protected": False}},
        existing_files={("acme", "widget", "SECURITY.md")},  # security policy present
    )
    repos = [AttributedRepo(
        full_name="acme/widget", url="", clone_url="",
        default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos)
    rules = {f.rule_id for f in out}
    assert "no_branch_protection" in rules
    assert "missing_security_md" not in rules


@pytest.mark.asyncio
async def test_repo_hygiene_flags_missing_security_md():
    gh = _StubGH(
        branch_responses={("acme", "widget", "main"): {"name": "main", "protected": True}},
        existing_files=set(),
    )
    repos = [AttributedRepo(
        full_name="acme/widget", url="", clone_url="",
        default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos)
    rules = {f.rule_id for f in out}
    assert "missing_security_md" in rules
    assert "no_branch_protection" not in rules


@pytest.mark.asyncio
async def test_repo_hygiene_clean_repo_emits_nothing():
    gh = _StubGH(
        branch_responses={("acme", "widget", "main"): {"name": "main", "protected": True}},
        existing_files={("acme", "widget", ".github/SECURITY.md")},
    )
    repos = [AttributedRepo(
        full_name="acme/widget", url="", clone_url="",
        default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos)
    assert out == []


@pytest.mark.asyncio
async def test_repo_hygiene_skips_forks():
    gh = _StubGH(
        branch_responses={("acme", "forked", "main"): {"name": "main", "protected": False}},
        existing_files=set(),
    )
    repos = [AttributedRepo(
        full_name="acme/forked", url="", clone_url="",
        default_branch="main", is_fork=True,
        reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos)
    assert out == []


@pytest.mark.asyncio
async def test_repo_hygiene_archived_with_recent_activity():
    # Archived but pushed within the active window → archived_with_recent_activity
    # only. We must NOT also emit branch-protection / SECURITY.md findings,
    # because we can't change them on an archived repo (it's noise).
    gh = _StubGH(branch_responses={}, existing_files=set())
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    repos = [AttributedRepo(
        full_name="acme/frozen", url="", clone_url="",
        default_branch="main", archived=True,
        pushed_at="2026-04-01T00:00:00Z",  # ~35 days ago
        reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos, archived_active_days=180, now=now)
    rules = {f.rule_id for f in out}
    assert rules == {"archived_with_recent_activity"}


@pytest.mark.asyncio
async def test_repo_hygiene_archived_long_ago_no_finding():
    gh = _StubGH(branch_responses={}, existing_files=set())
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    repos = [AttributedRepo(
        full_name="acme/dusty", url="", clone_url="",
        default_branch="main", archived=True,
        pushed_at="2024-01-01T00:00:00Z",  # >2 years ago
        reasons=["owned_by_org"], confidence_score=0.8,
    )]
    out = await scan_repo_hygiene(gh, repos, archived_active_days=180, now=now)
    assert out == []


# ── Workflow risk analyzer (pure-function rules) ──────────────────────


class TestWorkflowAnalyzerSelfHosted:
    def test_basic_self_hosted(self):
        wf = """
name: build
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hi
"""
        risks = analyze_workflow_content("acme/x", ".github/workflows/build.yml", wf)
        assert any(r.rule_id == "self_hosted_runner" for r in risks)

    def test_self_hosted_in_matrix_array(self):
        wf = "jobs:\n  j:\n    runs-on: [self-hosted, linux]\n"
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert any(r.rule_id == "self_hosted_runner" for r in risks)

    def test_github_hosted_no_finding(self):
        wf = "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n"
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "self_hosted_runner" for r in risks)


class TestWorkflowAnalyzerPrTarget:
    def test_pr_target_with_head_sha_checkout(self):
        wf = """
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        rules = {r.rule_id for r in risks}
        assert "pull_request_target" in rules

    def test_pr_target_alone_is_safe(self):
        # pull_request_target without checking out the head ref is a
        # legitimate triage pattern — must not fire.
        wf = """
on:
  pull_request_target:
    types: [labeled]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "label added"
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "pull_request_target" for r in risks)

    def test_plain_pull_request_no_finding(self):
        wf = """
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "pull_request_target" for r in risks)


class TestWorkflowAnalyzerUnpinned:
    def test_third_party_tag_flagged(self):
        wf = """
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v44
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        unpinned = [r for r in risks if r.rule_id == "unpinned_action"]
        assert len(unpinned) == 1
        assert "tj-actions/changed-files@v44" in unpinned[0].evidence

    def test_third_party_branch_flagged(self):
        wf = "jobs:\n  j:\n    steps:\n      - uses: someuser/action@main\n"
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert any(r.rule_id == "unpinned_action" for r in risks)

    def test_actions_org_exempt(self):
        wf = """
jobs:
  j:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
      - uses: github/codeql-action/init@v3
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "unpinned_action" for r in risks)

    def test_sha_pinned_action_not_flagged(self):
        wf = ("jobs:\n  j:\n    steps:\n      "
              "- uses: tj-actions/changed-files@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n")
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "unpinned_action" for r in risks)

    def test_multiple_unpinned_aggregated_into_one_risk(self):
        wf = """
jobs:
  j:
    steps:
      - uses: foo/a@v1
      - uses: bar/b@main
      - uses: baz/c@latest
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        unpinned = [r for r in risks if r.rule_id == "unpinned_action"]
        assert len(unpinned) == 1
        # All three refs must appear in the evidence string.
        for ref in ("foo/a@v1", "bar/b@main", "baz/c@latest"):
            assert ref in unpinned[0].evidence

    def test_local_and_docker_refs_skipped(self):
        wf = """
jobs:
  j:
    steps:
      - uses: ./.github/actions/local
      - uses: docker://alpine:3.18
"""
        risks = analyze_workflow_content("acme/x", "wf.yml", wf)
        assert not any(r.rule_id == "unpinned_action" for r in risks)


# ── scan_workflow_risks (stubbed GitHub client) ───────────────────────


class _StubGHWorkflows:
    """GitHubClient stand-in that serves a pre-built workflows directory."""

    def __init__(
        self,
        *,
        listings: dict[tuple[str, str, str], list[dict]],
        files: dict[tuple[str, str, str], str],
    ):
        self._listings = listings
        self._files = files

    async def list_directory(self, owner, repo, path, ref=None):
        return list(self._listings.get((owner, repo, path), []))

    async def get_raw_file(self, owner, repo, path, *, ref=None):
        return self._files.get((owner, repo, path))


@pytest.mark.asyncio
async def test_scan_workflow_risks_emits_findings_per_workflow():
    listings = {
        ("acme", "x", ".github/workflows"): [
            {"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
            {"name": "release.yml", "path": ".github/workflows/release.yml", "type": "file"},
            # Non-yaml file in the dir — must be ignored.
            {"name": "README.md", "path": ".github/workflows/README.md", "type": "file"},
        ],
    }
    files = {
        ("acme", "x", ".github/workflows/ci.yml"): (
            "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: tj-actions/changed-files@v44\n"
        ),
        ("acme", "x", ".github/workflows/release.yml"): (
            "jobs:\n  j:\n    runs-on: self-hosted\n    steps: []\n"
        ),
    }
    gh = _StubGHWorkflows(listings=listings, files=files)
    repos = [AttributedRepo(
        full_name="acme/x", url="", clone_url="",
        default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
    )]

    risks = await scan_workflow_risks(gh, repos)

    by_rule = {(r.workflow_path, r.rule_id) for r in risks}
    assert (".github/workflows/ci.yml", "unpinned_action") in by_rule
    assert (".github/workflows/release.yml", "self_hosted_runner") in by_rule


@pytest.mark.asyncio
async def test_scan_workflow_risks_skips_forks_and_archived():
    listings = {
        ("acme", "fork", ".github/workflows"): [
            {"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
        ],
        ("acme", "old", ".github/workflows"): [
            {"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
        ],
    }
    files = {
        ("acme", "fork", ".github/workflows/ci.yml"): "jobs:\n  j:\n    runs-on: self-hosted\n",
        ("acme", "old", ".github/workflows/ci.yml"): "jobs:\n  j:\n    runs-on: self-hosted\n",
    }
    gh = _StubGHWorkflows(listings=listings, files=files)
    repos = [
        AttributedRepo(
            full_name="acme/fork", url="", clone_url="",
            is_fork=True, reasons=["owned_by_org"], confidence_score=0.8,
        ),
        AttributedRepo(
            full_name="acme/old", url="", clone_url="",
            archived=True, reasons=["owned_by_org"], confidence_score=0.8,
        ),
    ]
    risks = await scan_workflow_risks(gh, repos)
    assert risks == []


@pytest.mark.asyncio
async def test_scan_workflow_risks_no_workflows_dir_is_clean():
    gh = _StubGHWorkflows(listings={}, files={})
    repos = [AttributedRepo(
        full_name="acme/x", url="", clone_url="",
        default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
    )]
    risks = await scan_workflow_risks(gh, repos)
    assert risks == []

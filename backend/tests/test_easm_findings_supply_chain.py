"""Tests for the supply-chain & repo-hygiene Finding emission paths in
``services.easm._import_github_npm_assets``.

Covers:
1. npm CVEs from OSV become one Finding per advisory on the npm_package asset.
2. npm package hygiene (deprecated, unmaintained) becomes Findings on the
   npm_package asset.
3. Repo hygiene (branch protection, SECURITY.md, archived w/ activity) becomes
   Findings on the code_repo asset.
4. Re-running with the same DiscoveryResult is idempotent (refresh, not
   duplicate).
"""
from __future__ import annotations

import pytest

from models.models import Asset, Finding, Scan
from services.easm import _import_github_npm_assets


@pytest.fixture
def easm_scan(db_session, test_org):
    scan = Scan(
        org_id=test_org.id,
        filename="easm-supply-chain",
        scan_name="EASM supply-chain test",
        scan_type="easm_full",
        source_type="easm",
        status="running",
        raw_metadata={"domain": "acme.example"},
    )
    db_session.add(scan)
    db_session.flush()
    return scan


def _build_result() -> dict:
    """A DiscoveryResult-shaped dict with one repo, one package, and one of
    each new vuln type."""
    return {
        "attributed_assets": {
            "github_orgs": [{"login": "acme", "url": "https://github.com/acme",
                              "is_verified_domain": False, "confidence_score": 0.85,
                              "reasons": ["org_blog_match"]}],
            "github_users": [],
            "github_repos": [{
                "full_name": "acme/widget",
                "url": "https://github.com/acme/widget",
                "clone_url": "https://github.com/acme/widget.git",
                "default_branch": "main",
                "owner_login": "acme", "owner_type": "Organization",
                "is_fork": False, "archived": False,
                "stars": 5, "language": "TypeScript",
                "pushed_at": "2026-04-01T00:00:00Z",
                "confidence_score": 0.8,
                "reasons": ["owned_by_org"],
            }],
            "npm_packages": [{
                "name": "acme-utils",
                "version": "1.2.0",
                "maintainers": ["dev <dev@acme.example>"],
                "repository_url": "https://github.com/acme/widget",
                "homepage": "https://acme.example",
                "last_published": "2022-01-01T00:00:00Z",
                "deprecated": True,
                "deprecated_message": "use acme-utils-v2 instead",
                "confidence_score": 0.7,
                "reasons": ["npm_maintainer"],
            }],
        },
        "vulnerabilities": {
            "exposed_files": [],
            "dependency_cves": [{
                "package": "acme-utils",
                "installed_version": "1.2.0",
                "cve": "GHSA-test-aaaa-bbbb",
                "severity": "high",
                "advisory_url": "https://github.com/advisories/GHSA-test-aaaa-bbbb",
                "fix_available": True,
                "fixed_version": "1.3.0",
                "summary": "Prototype pollution in acme-utils",
                "aliases": ["CVE-2025-99999"],
                "unmaintained": False,
            }],
            "package_hygiene": [
                {"package": "acme-utils", "version": "1.2.0",
                 "rule_id": "deprecated", "severity": "medium",
                 "detail": "use acme-utils-v2 instead"},
                {"package": "acme-utils", "version": "1.2.0",
                 "rule_id": "unmaintained", "severity": "low",
                 "detail": "latest version published 1500 days ago (threshold: 730)"},
            ],
            "repo_hygiene": [
                {"repo": "acme/widget", "rule_id": "no_branch_protection",
                 "severity": "medium",
                 "detail": "default branch 'main' has no protection rules",
                 "evidence": "branches/main.protected=false"},
                {"repo": "acme/widget", "rule_id": "missing_security_md",
                 "severity": "low",
                 "detail": "no security policy file found"},
            ],
            "workflow_risks": [
                {"repo": "acme/widget",
                 "workflow_path": ".github/workflows/ci.yml",
                 "rule_id": "unpinned_action", "severity": "medium",
                 "detail": "1 third-party action reference(s) pinned to a tag",
                 "evidence": "tj-actions/changed-files@v44"},
                {"repo": "acme/widget",
                 "workflow_path": ".github/workflows/release.yml",
                 "rule_id": "self_hosted_runner", "severity": "high",
                 "detail": "Workflow uses `self-hosted` runners.",
                 "evidence": ""},
            ],
        },
    }


def test_imports_dependency_cve_as_finding(db_session, easm_scan):
    asset_count, finding_count, _aids, _fids = _import_github_npm_assets(
        db_session, easm_scan, _build_result(), "acme.example",
    )
    db_session.flush()

    assert asset_count >= 3  # org, repo, npm_package
    # 1 cve + 2 npm hygiene + 2 repo hygiene + 2 workflow risks
    assert finding_count >= 7

    findings = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).all()
    cves = [f for f in findings if f.plugin_id.startswith("EASM-NPM-CVE-")]
    assert len(cves) == 1
    cve = cves[0]
    assert cve.plugin_id == "EASM-NPM-CVE-GHSA-test-aaaa-bbbb"
    assert cve.plugin_family == "EASM: Supply Chain"
    assert cve.severity == 3  # high
    assert "1.3.0" in (cve.solution or "")
    assert "acme-utils" in cve.plugin_name


def test_imports_package_hygiene_as_findings(db_session, easm_scan):
    _import_github_npm_assets(db_session, easm_scan, _build_result(), "acme.example")
    db_session.flush()

    findings = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).all()
    pids = {f.plugin_id for f in findings}
    assert "EASM-NPM-HYGIENE-DEPRECATED" in pids
    assert "EASM-NPM-HYGIENE-UNMAINTAINED" in pids

    deprecated = next(f for f in findings if f.plugin_id == "EASM-NPM-HYGIENE-DEPRECATED")
    npm_asset = db_session.query(Asset).filter(Asset.id == deprecated.asset_id).one()
    assert npm_asset.asset_type == "npm_package"


def test_imports_repo_hygiene_as_findings(db_session, easm_scan):
    _import_github_npm_assets(db_session, easm_scan, _build_result(), "acme.example")
    db_session.flush()

    findings = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).all()
    pids = {f.plugin_id for f in findings}
    assert "EASM-REPO-HYGIENE-NO_BRANCH_PROTECTION" in pids
    assert "EASM-REPO-HYGIENE-MISSING_SECURITY_MD" in pids

    bp = next(f for f in findings if f.plugin_id == "EASM-REPO-HYGIENE-NO_BRANCH_PROTECTION")
    repo_asset = db_session.query(Asset).filter(Asset.id == bp.asset_id).one()
    assert repo_asset.asset_type == "code_repo"
    assert bp.plugin_family == "EASM: Repo Hygiene"


def test_imports_workflow_risks_as_findings(db_session, easm_scan):
    _import_github_npm_assets(db_session, easm_scan, _build_result(), "acme.example")
    db_session.flush()

    findings = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).all()
    pids = {f.plugin_id for f in findings}
    # plugin_id encodes both rule and workflow basename, so two workflow
    # risks on different files coexist as distinct findings.
    assert "EASM-WORKFLOW-UNPINNED_ACTION-CI" in pids
    assert "EASM-WORKFLOW-SELF_HOSTED_RUNNER-RELEASE" in pids

    self_hosted = next(
        f for f in findings
        if f.plugin_id == "EASM-WORKFLOW-SELF_HOSTED_RUNNER-RELEASE"
    )
    repo_asset = db_session.query(Asset).filter(Asset.id == self_hosted.asset_id).one()
    assert repo_asset.asset_type == "code_repo"
    assert self_hosted.plugin_family == "EASM: CI/CD"
    assert self_hosted.severity == 3  # high


def test_reimport_is_idempotent(db_session, easm_scan):
    """Running the same DiscoveryResult twice must not duplicate findings —
    the (asset_id, plugin_id) keying refreshes the existing row."""
    _import_github_npm_assets(db_session, easm_scan, _build_result(), "acme.example")
    db_session.flush()
    first_count = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).count()

    _import_github_npm_assets(db_session, easm_scan, _build_result(), "acme.example")
    db_session.flush()
    second_count = db_session.query(Finding).filter(Finding.scan_id == easm_scan.id).count()

    assert first_count == second_count
    assert first_count >= 7

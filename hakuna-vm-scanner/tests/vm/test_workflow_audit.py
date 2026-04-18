"""Tests for .github/workflows audit."""

import os
import textwrap

import pytest

from scanner.vm.code_repo.workflow_audit import audit_workflows


def _write_workflow(repo_path, name, content):
    wdir = os.path.join(repo_path, ".github", "workflows")
    os.makedirs(wdir, exist_ok=True)
    path = os.path.join(wdir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


class TestPullRequestTarget:
    def test_bare_pull_request_target_flagged(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            name: ci
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hello
        """))
        risks = audit_workflows(str(tmp_path), "acme/ci")
        prts = [r for r in risks if r["rule_id"] == "pull_request_target"]
        assert len(prts) == 1
        assert prts[0]["severity"] == "medium"

    def test_pwn_request_pattern_is_high_severity(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            name: ci
            on: pull_request_target
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                    with:
                      ref: ${{ github.event.pull_request.head.sha }}
                  - run: npm test
        """))
        risks = audit_workflows(str(tmp_path), "acme/ci")
        prts = [r for r in risks if r["rule_id"] == "pull_request_target"]
        assert prts[0]["severity"] == "high"

    def test_plain_pull_request_not_flagged(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            on: pull_request
            jobs:
              b: {runs-on: ubuntu-latest, steps: [{run: echo hi}]}
        """))
        risks = audit_workflows(str(tmp_path), "acme/ci")
        assert not any(r["rule_id"] == "pull_request_target" for r in risks)


class TestUnpinnedActions:
    def test_third_party_tag_flagged(self, tmp_path):
        _write_workflow(tmp_path, "deploy.yml", textwrap.dedent("""\
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - uses: shady-org/evil-action@v1
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        unpinned = [r for r in risks if r["rule_id"] == "unpinned_action"]
        assert len(unpinned) == 1
        assert unpinned[0]["severity"] == "medium"

    def test_trusted_owner_tag_not_flagged(self, tmp_path):
        _write_workflow(tmp_path, "deploy.yml", textwrap.dedent("""\
            on: push
            jobs:
              d:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - uses: docker/build-push-action@v5
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert not any(r["rule_id"] == "unpinned_action" for r in risks)

    def test_sha_pin_not_flagged(self, tmp_path):
        sha = "a" * 40
        _write_workflow(tmp_path, "deploy.yml", textwrap.dedent(f"""\
            on: push
            jobs:
              d:
                runs-on: ubuntu-latest
                steps:
                  - uses: third-party/action@{sha}
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert not any(r["rule_id"] == "unpinned_action" for r in risks)


class TestSelfHosted:
    def test_self_hosted_string_flagged(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            on: push
            jobs:
              b:
                runs-on: self-hosted
                steps: [{run: true}]
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert any(r["rule_id"] == "self_hosted_runner" for r in risks)

    def test_self_hosted_label_list_flagged(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            on: push
            jobs:
              b:
                runs-on: [self-hosted, linux]
                steps: [{run: true}]
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert any(r["rule_id"] == "self_hosted_runner" for r in risks)

    def test_ubuntu_runner_not_flagged(self, tmp_path):
        _write_workflow(tmp_path, "ci.yml", textwrap.dedent("""\
            on: push
            jobs:
              b:
                runs-on: ubuntu-latest
                steps: [{run: true}]
        """))
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert not any(r["rule_id"] == "self_hosted_runner" for r in risks)


class TestEdgeCases:
    def test_no_workflows_dir(self, tmp_path):
        assert audit_workflows(str(tmp_path), "acme/empty") == []

    def test_malformed_yaml_emits_parse_error(self, tmp_path):
        _write_workflow(tmp_path, "bad.yml", "::: not yaml :::\n    [")
        risks = audit_workflows(str(tmp_path), "acme/x")
        assert any(r["rule_id"] == "parse_error" for r in risks)

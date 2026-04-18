"""GitHub Actions workflow audit.

Parses every .yml/.yaml file under .github/workflows and flags:

  1. pull_request_target: dangerous when combined with `checkout` of the PR ref
     (classic "pwn_request" anti-pattern — an attacker's PR runs with secrets).
  2. unpinned third-party actions: `uses: some/action@main` or `@v1` (mutable
     tag) is vulnerable to upstream compromise. `@<full-sha>` is the only safe form.
  3. self-hosted runners: `runs-on: self-hosted` or labels that include it.
     Not inherently bad, but surfaces asset ownership questions.

Returns a list of workflow_risks dicts matching the shape in
hakuna-scanner/app/ingest/github_npm/models.WorkflowRisk.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import yaml

logger = logging.getLogger(__name__)


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# GitHub-owned + trusted first-party actions. These are allowed to use tags.
TRUSTED_ACTION_OWNERS: set[str] = {
    "actions", "github", "docker", "aws-actions", "azure", "google-github-actions",
}


def audit_workflows(repo_path: str, repo_full_name: str) -> list[dict[str, Any]]:
    """Walk .github/workflows and produce risk entries."""
    workflows_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []

    risks: list[dict[str, Any]] = []
    for entry in sorted(os.listdir(workflows_dir)):
        if not entry.endswith((".yml", ".yaml")):
            continue
        abs_path = os.path.join(workflows_dir, entry)
        rel_path = os.path.join(".github", "workflows", entry)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                doc = yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            risks.append(_risk(repo_full_name, rel_path, "parse_error", "low",
                               f"could not parse workflow: {e}"))
            continue

        if not isinstance(doc, dict):
            continue

        risks.extend(_audit_one(doc, repo_full_name, rel_path))

    return risks


def _audit_one(doc: dict, repo: str, path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    # 1. pull_request_target detection
    on = doc.get("on") or doc.get(True)  # PyYAML parses `on:` sometimes as True key
    if _triggers_pull_request_target(on):
        # Higher severity if any step checks out the PR head
        pwn_request = _has_pr_head_checkout(doc)
        severity = "high" if pwn_request else "medium"
        detail = (
            "workflow is triggered by pull_request_target. This event runs with repo "
            "secrets even for PRs from forks. "
            + ("Combined with a checkout of the PR head ref, this is the pwn_request "
               "anti-pattern — attacker code runs with secrets." if pwn_request else
               "Audit any step that references `github.event.pull_request.head.*`.")
        )
        out.append(_risk(repo, path, "pull_request_target", severity, detail))

    # 2. Unpinned third-party actions + 3. self-hosted runners
    jobs = doc.get("jobs") or {}
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            # self-hosted check
            runs_on = job.get("runs-on")
            if _is_self_hosted(runs_on):
                out.append(_risk(
                    repo, path, "self_hosted_runner", "medium",
                    f"job '{job_name}' uses a self-hosted runner ({runs_on!r}). "
                    "Self-hosted runners on public repos can be hijacked by malicious PRs.",
                    evidence=str(runs_on),
                ))

            for step in (job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if not uses or not isinstance(uses, str):
                    continue
                unpinned_reason = _unpinned_reason(uses)
                if unpinned_reason:
                    out.append(_risk(
                        repo, path, "unpinned_action",
                        "medium" if "third-party" in unpinned_reason else "low",
                        f"job '{job_name}' step uses '{uses}' — {unpinned_reason}. "
                        "Pin to a full commit SHA (e.g. `actions/checkout@<sha>`) to prevent "
                        "supply-chain compromise via a moved tag.",
                        evidence=uses,
                    ))

    return out


def _triggers_pull_request_target(on: Any) -> bool:
    if on is None:
        return False
    if isinstance(on, str):
        return on == "pull_request_target"
    if isinstance(on, list):
        return "pull_request_target" in on
    if isinstance(on, dict):
        return "pull_request_target" in on
    return False


def _has_pr_head_checkout(doc: dict) -> bool:
    """Heuristic: any step with `uses: actions/checkout*` that sets
    `ref: ${{ github.event.pull_request.head.* }}`."""
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in (job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses") or ""
            if "actions/checkout" not in uses:
                continue
            with_ = step.get("with") or {}
            ref = str(with_.get("ref") or "")
            if "pull_request.head" in ref:
                return True
    return False


def _is_self_hosted(runs_on: Any) -> bool:
    if runs_on is None:
        return False
    if isinstance(runs_on, str):
        return runs_on == "self-hosted" or runs_on.startswith("self-hosted-")
    if isinstance(runs_on, list):
        return any(isinstance(x, str) and (x == "self-hosted" or x.startswith("self-hosted-"))
                   for x in runs_on)
    return False


def _unpinned_reason(uses: str) -> str | None:
    """Return a human explanation if `uses` isn't pinned to a full SHA."""
    if uses.startswith("./") or uses.startswith("docker://"):
        return None  # local actions or docker refs — different threat model
    if "@" not in uses:
        return "no ref specified (implicit floating default)"
    name, _, ref = uses.rpartition("@")
    owner = name.split("/", 1)[0]
    if _SHA_RE.match(ref):
        return None
    is_trusted = owner in TRUSTED_ACTION_OWNERS
    if is_trusted:
        # Trusted owners with a tag ref are acceptable (lower severity).
        return None
    return f"third-party action pinned to mutable ref '{ref}'"


def _risk(
    repo: str, workflow_path: str, rule_id: str, severity: str, detail: str,
    *, evidence: str = "",
) -> dict[str, Any]:
    return {
        "repo": repo,
        "workflow_path": workflow_path,
        "rule_id": rule_id,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
    }

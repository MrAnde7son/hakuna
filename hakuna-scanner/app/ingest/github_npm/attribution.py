"""Attribution logic — decides which discovered artifacts actually belong
to the target domain, and produces a confidence_score in [0, 1].

The user's pro-tip rule is encoded here: attribute a repo only if
    - it belongs to a confirmed org, OR
    - its package.json contains the domain, OR
    - its top contributor has the corporate email.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Iterable

from app.ingest.github_npm.models import (
    REASON_CONTRIBUTOR_EMAIL,
    REASON_KEYWORD_MATCH,
    REASON_NPM_MAINTAINER_MATCH,
    REASON_ORG_BLOG_MATCH,
    REASON_OWNED_BY_ATTRIBUTED_ORG,
    REASON_PACKAGE_JSON_MATCH,
    REASON_USER_EMAIL_MATCH,
    REASON_VERIFIED_DOMAIN,
    SCORE_TABLE,
    AttributedOrg,
    AttributedRepo,
    AttributedUser,
)

logger = logging.getLogger(__name__)

# Domains that are not useful attribution signals — if the target is one of
# these, we should skip attribution entirely because everything would match.
NOISY_DOMAINS: set[str] = {
    "github.com", "gmail.com", "googlemail.com", "outlook.com",
    "hotmail.com", "yahoo.com", "protonmail.com", "icloud.com",
}


EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9._-]+)")


def domain_matches(value: str | None, target: str) -> bool:
    """True if value contains the target domain as an exact host / email
    suffix. Handles subdomains (blog.example.com counts for example.com)."""
    if not value:
        return False
    value = value.lower().strip()
    target = target.lower().strip()
    # Strip scheme + path for URL-like values
    for scheme in ("https://", "http://"):
        if value.startswith(scheme):
            value = value[len(scheme):]
    value = value.split("/", 1)[0]
    value = value.split("@", 1)[-1]  # email local-part irrelevant
    return value == target or value.endswith("." + target)


def top_level_confidence(reasons: Iterable[str]) -> float:
    """Compute the max confidence across a set of reasons, with a small
    bonus for multiple independent corroborating reasons (capped at 1.0)."""
    scores = [SCORE_TABLE.get(r, 0.0) for r in reasons]
    if not scores:
        return 0.0
    base = max(scores)
    # Each additional corroborating reason adds 0.05, capped at 1.0.
    bonus = 0.05 * max(0, len(scores) - 1)
    return round(min(1.0, base + bonus), 3)


def score_org(
    org_payload: dict,
    target_domain: str,
    verified_domains: list[str] | None = None,
) -> AttributedOrg | None:
    """Score a GitHub org payload. Returns None if it doesn't match at all."""
    reasons: list[str] = []
    login = org_payload.get("login") or ""
    blog = org_payload.get("blog") or ""
    email = org_payload.get("email") or ""

    if verified_domains:
        for vd in verified_domains:
            if domain_matches(vd, target_domain):
                reasons.append(REASON_VERIFIED_DOMAIN)
                break

    if domain_matches(blog, target_domain) or domain_matches(email, target_domain):
        reasons.append(REASON_ORG_BLOG_MATCH)

    if not reasons:
        return None

    return AttributedOrg(
        login=login,
        url=org_payload.get("html_url") or f"https://github.com/{login}",
        domain_match=target_domain,
        is_verified_domain=REASON_VERIFIED_DOMAIN in reasons,
        email=email or None,
        blog=blog or None,
        reasons=reasons,
        confidence_score=top_level_confidence(reasons),
    )


def score_user(user_payload: dict, target_domain: str) -> AttributedUser | None:
    email = user_payload.get("email") or ""
    if not domain_matches(email, target_domain):
        return None
    reasons = [REASON_USER_EMAIL_MATCH]
    login = user_payload.get("login") or ""
    return AttributedUser(
        login=login,
        url=user_payload.get("html_url") or f"https://github.com/{login}",
        email=email,
        reasons=reasons,
        confidence_score=top_level_confidence(reasons),
    )


def score_repo(
    repo_payload: dict,
    target_domain: str,
    *,
    owner_is_attributed_org: bool = False,
    package_json_raw: str | None = None,
    top_contributor_email: str | None = None,
    from_keyword_search: bool = False,
) -> AttributedRepo | None:
    """Score a repo against the target. Encodes the user's filter rule:

        ONLY attribute if owner is attributed, OR package.json matches, OR
        top contributor email matches. Bare keyword matches yield the lowest
        possible score and are not promoted unless one of the above also fires.
    """
    reasons: list[str] = []

    if owner_is_attributed_org:
        reasons.append(REASON_OWNED_BY_ATTRIBUTED_ORG)

    if package_json_raw and _package_json_references_domain(package_json_raw, target_domain):
        reasons.append(REASON_PACKAGE_JSON_MATCH)

    if top_contributor_email and domain_matches(top_contributor_email, target_domain):
        reasons.append(REASON_CONTRIBUTOR_EMAIL)

    if from_keyword_search and not reasons:
        # Keyword-only hit — return it but at the noise floor so the caller
        # can decide whether to filter (default threshold 0.3 drops these).
        reasons.append(REASON_KEYWORD_MATCH)

    if not reasons:
        return None

    owner = repo_payload.get("owner") or {}
    full_name = repo_payload.get("full_name") or ""
    return AttributedRepo(
        full_name=full_name,
        url=repo_payload.get("html_url") or f"https://github.com/{full_name}",
        clone_url=repo_payload.get("clone_url") or f"https://github.com/{full_name}.git",
        default_branch=repo_payload.get("default_branch") or "main",
        owner_login=owner.get("login") or "",
        owner_type=owner.get("type") or "",
        is_fork=bool(repo_payload.get("fork")),
        archived=bool(repo_payload.get("archived")),
        pushed_at=repo_payload.get("pushed_at"),
        stars=int(repo_payload.get("stargazers_count") or 0),
        language=repo_payload.get("language"),
        reasons=reasons,
        confidence_score=top_level_confidence(reasons),
    )


def _package_json_references_domain(raw: str, target_domain: str) -> bool:
    """True if a package.json string references the target domain in any of
    the fields where attribution is meaningful (homepage, repository, bugs,
    author, contributors) — NOT just anywhere in the file, which would
    false-positive on dependency URLs."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return False

    def _check(value) -> bool:
        if isinstance(value, str):
            return domain_matches(value, target_domain) or target_domain.lower() in value.lower()
        if isinstance(value, dict):
            return any(_check(v) for v in value.values())
        if isinstance(value, list):
            return any(_check(v) for v in value)
        return False

    relevant_fields = ("homepage", "repository", "bugs", "author", "contributors")
    for field in relevant_fields:
        if field in data and _check(data[field]):
            return True
    return False


def is_noisy_target(target_domain: str) -> bool:
    """Refuse to attribute against well-known public email/hosting domains
    where matches are meaningless (millions of false positives)."""
    return target_domain.lower().strip() in NOISY_DOMAINS


def emails_from_git_log(log_entries: Iterable[dict]) -> list[str]:
    """Extract distinct author emails from a list of commit API responses."""
    out: list[str] = []
    seen: set[str] = set()
    for c in log_entries:
        commit = c.get("commit") or {}
        author = commit.get("author") or {}
        email = (author.get("email") or "").lower()
        if email and email not in seen and "@" in email:
            seen.add(email)
            out.append(email)
    return out


def filter_above_threshold(items: list, threshold: float) -> list:
    """Filter any list of dataclass instances with a .confidence_score field."""
    return [i for i in items if getattr(i, "confidence_score", 0.0) >= threshold]

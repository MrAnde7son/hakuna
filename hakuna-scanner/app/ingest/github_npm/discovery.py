"""Phase 1 — attribution & discovery.

Functions here take a target domain and produce candidate artifacts
(orgs, users, npm packages, repos). They do NOT score or filter —
that's attribution.py's job.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator

from app.ingest.github_npm.attribution import (
    domain_matches,
    score_org,
    score_repo,
    score_user,
    top_level_confidence,
)
from app.ingest.github_npm.clients import GitHubClient, NpmClient, OsvClient
from app.ingest.github_npm.models import (
    REASON_CONTRIBUTOR_EMAIL,
    REASON_NPM_MAINTAINER_MATCH,
    REASON_PACKAGE_JSON_MATCH,
    SCORE_TABLE,
    AttributedNpmPackage,
    AttributedOrg,
    AttributedRepo,
    AttributedUser,
    DependencyCVE,
    ExposedFile,
    PackageHygiene,
    RepoHygiene,
    WorkflowRisk,
)

logger = logging.getLogger(__name__)

# Subdomain labels that carry no org-identity signal and should be stripped
# when deriving a candidate GitHub org login from a domain name.
_COMMON_SUBDOMAIN_PREFIXES: frozenset[str] = frozenset({
    "www", "mail", "smtp", "ftp", "dev", "staging", "app", "api",
    "blog", "docs", "support", "status", "secure", "cdn",
})


def _derive_login_hints_from_domain(domain: str) -> list[str]:
    """Return candidate GitHub org login names derived from a domain.

    Strips well-known subdomain prefixes then returns the leftmost label
    before the TLD as the most likely org slug:

        tenable.com         → ["tenable"]
        www.tenable.com     → ["tenable"]
        rapid7.com          → ["rapid7"]
        app.company.co.uk   → ["company"]
    """
    parts = domain.lower().strip().split(".")
    while len(parts) > 2 and parts[0] in _COMMON_SUBDOMAIN_PREFIXES:
        parts = parts[1:]
    hint = parts[0] if len(parts) >= 2 else ""
    return [hint] if hint else []


# ── GitHub orgs ───────────────────────────────────────────────────────


async def find_orgs_by_domain(
    gh: GitHubClient, target_domain: str, *, candidate_logins: list[str] | None = None,
) -> list[AttributedOrg]:
    """Find GitHub Orgs whose blog/email matches target_domain.

    GitHub has no "find org by domain" API. Strategy:
      1. Derive candidate logins from the domain itself (e.g. tenable.com →
         "tenable") and merge with any caller-supplied hints, then fetch each
         org's full profile directly — this is cheap and catches the common
         case where the org slug matches the company name.
      2. Fall back to a user search with `type:org`. GitHub's search only
         supports `in:email` and `in:name` for orgs (not `in:blog`/website),
         so this catches orgs that list their corporate email on their profile.
    """
    out: list[AttributedOrg] = []
    seen: set[str] = set()

    async def _evaluate(login: str):
        if login in seen:
            return
        seen.add(login)
        payload = await gh.get_org(login)
        if not payload:
            return
        org = score_org(payload, target_domain)
        if org:
            out.append(org)

    # Merge caller-supplied hints with auto-derived ones, then do direct
    # lookups. These are cheap single-org GETs and catch the common case
    # where the org slug matches the company/domain name.
    all_hints = list(candidate_logins or []) + _derive_login_hints_from_domain(target_domain)
    if all_hints:
        await asyncio.gather(*(_evaluate(c) for c in all_hints))

    # Then search — limited to first 100 to keep cost bounded.
    # Note: GitHub's user search does not support `in:blog`, so we use
    # `in:email,name` to surface orgs with the domain in their email or
    # display name.
    query = f"{target_domain} in:email,name type:org"
    count = 0
    async for hit in gh.search_users(query, per_page=100):
        if hit.get("type") != "Organization":
            continue
        await _evaluate(hit.get("login") or "")
        count += 1
        if count >= 100:
            break

    return out


# ── GitHub users ──────────────────────────────────────────────────────


async def find_users_by_domain(
    gh: GitHubClient, target_domain: str, *, max_results: int = 200,
) -> list[AttributedUser]:
    """Find GitHub users whose public email is @target_domain.

    The search/users endpoint matches on *@target_domain but also returns
    noise (name/bio matches). We re-fetch each hit's /users/:login to
    confirm the email field, since search results don't include it.
    """
    out: list[AttributedUser] = []
    query = f'"{target_domain}" in:email type:user'
    seen: set[str] = set()
    count = 0

    async def _confirm(login: str):
        if login in seen:
            return
        seen.add(login)
        payload = await gh.get_user(login)
        if not payload:
            return
        user = score_user(payload, target_domain)
        if user:
            out.append(user)

    batch: list[str] = []
    async for hit in gh.search_users(query, per_page=100):
        login = hit.get("login") or ""
        if login:
            batch.append(login)
            count += 1
        if len(batch) >= 10:
            await asyncio.gather(*(_confirm(c) for c in batch))
            batch.clear()
        if count >= max_results:
            break
    if batch:
        await asyncio.gather(*(_confirm(c) for c in batch))

    return out


# ── npm discovery ─────────────────────────────────────────────────────


async def find_npm_packages_by_domain(
    npm: NpmClient, target_domain: str, *, max_packages: int = 250,
) -> list[AttributedNpmPackage]:
    """Find npm packages where any maintainer's email ends in @target_domain."""
    hits = await npm.search_by_maintainer(target_domain, size=max_packages)
    out: list[AttributedNpmPackage] = []

    async def _hydrate(entry: dict):
        pkg = entry.get("package") or {}
        name = pkg.get("name")
        if not name:
            return
        full = await npm.get_package(name)
        if not full:
            return
        maintainers_raw = full.get("maintainers") or []
        matched_maintainers: list[str] = []
        for m in maintainers_raw:
            if not isinstance(m, dict):
                continue
            email = (m.get("email") or "").lower()
            if domain_matches(email, target_domain):
                matched_maintainers.append(f"{m.get('name', '')} <{email}>")

        if not matched_maintainers:
            return

        repo_url: str | None = None
        repo_field = full.get("repository")
        if isinstance(repo_field, dict):
            repo_url = repo_field.get("url")
        elif isinstance(repo_field, str):
            repo_url = repo_field

        latest = (full.get("dist-tags") or {}).get("latest")
        last_published = None
        time_map = full.get("time") or {}
        if latest and isinstance(time_map, dict):
            last_published = time_map.get(latest)

        # `deprecated` lives on the per-version manifest, not the packument
        # root. Pull from `versions[latest]` so we surface what `npm install`
        # would warn on.
        deprecated_msg = None
        versions_map = full.get("versions") or {}
        if latest and isinstance(versions_map, dict):
            ver_manifest = versions_map.get(latest) or {}
            raw = ver_manifest.get("deprecated")
            if isinstance(raw, str) and raw.strip():
                deprecated_msg = raw.strip()

        reasons = [REASON_NPM_MAINTAINER_MATCH]
        out.append(AttributedNpmPackage(
            name=name,
            version=latest,
            maintainers=matched_maintainers,
            repository_url=_normalize_git_url(repo_url),
            homepage=full.get("homepage"),
            last_published=last_published,
            deprecated=bool(deprecated_msg),
            deprecated_message=deprecated_msg,
            reasons=reasons,
            confidence_score=top_level_confidence(reasons),
        ))

    # Concurrency cap — npm is gentle but we don't want to hammer.
    sem = asyncio.Semaphore(10)

    async def _wrap(entry: dict):
        async with sem:
            await _hydrate(entry)

    await asyncio.gather(*(_wrap(e) for e in hits))
    return out


def _normalize_git_url(url: str | None) -> str | None:
    """Normalize various git URL forms to a canonical HTTPS URL."""
    if not url:
        return None
    url = url.strip()
    # "git+https://github.com/foo/bar.git" → "https://github.com/foo/bar"
    if url.startswith("git+"):
        url = url[4:]
    if url.startswith("git://"):
        url = "https://" + url[len("git://"):]
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:"):]
    if url.endswith(".git"):
        url = url[: -4]
    return url


def extract_github_slug(url: str | None) -> tuple[str, str] | None:
    """From "https://github.com/owner/repo(.git)?" → ("owner", "repo")."""
    if not url:
        return None
    m = re.match(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    if not m:
        return None
    return m.group(1), m.group(2)


# ── Org → repos ───────────────────────────────────────────────────────


async def repos_from_orgs(
    gh: GitHubClient,
    orgs: list[AttributedOrg],
    target_domain: str,
    *,
    max_repos_per_org: int = 100,
) -> list[AttributedRepo]:
    out: list[AttributedRepo] = []

    async def _process_org(org: AttributedOrg):
        count = 0
        async for repo in gh.list_org_repos(org.login):
            scored = score_repo(repo, target_domain, owner_is_attributed_org=True)
            if scored:
                out.append(scored)
            count += 1
            if count >= max_repos_per_org:
                break

    await asyncio.gather(*(_process_org(o) for o in orgs))
    return out


# ── User → repos (Shadow IT candidates) ───────────────────────────────


async def repos_from_users(
    gh: GitHubClient,
    users: list[AttributedUser],
    target_domain: str,
    *,
    max_repos_per_user: int = 30,
) -> list[AttributedRepo]:
    """User-owned repos are inherently lower-confidence (Shadow IT). We
    still return them but with the contributor-email reason only."""
    out: list[AttributedRepo] = []

    async def _process_user(user: AttributedUser):
        count = 0
        async for repo in gh.list_user_repos(user.login):
            owner = repo.get("owner") or {}
            full_name = repo.get("full_name") or ""
            repo_obj = AttributedRepo(
                full_name=full_name,
                url=repo.get("html_url") or f"https://github.com/{full_name}",
                clone_url=repo.get("clone_url") or f"https://github.com/{full_name}.git",
                default_branch=repo.get("default_branch") or "main",
                owner_login=owner.get("login") or user.login,
                owner_type=owner.get("type") or "User",
                is_fork=bool(repo.get("fork")),
                archived=bool(repo.get("archived")),
                pushed_at=repo.get("pushed_at"),
                stars=int(repo.get("stargazers_count") or 0),
                language=repo.get("language"),
                reasons=[REASON_CONTRIBUTOR_EMAIL],
                confidence_score=SCORE_TABLE[REASON_CONTRIBUTOR_EMAIL],
            )
            out.append(repo_obj)
            count += 1
            if count >= max_repos_per_user:
                break

    await asyncio.gather(*(_process_user(u) for u in users))
    return out


# ── Repos from npm package → repository.url ───────────────────────────


def repos_from_npm_packages(packages: list[AttributedNpmPackage], target_domain: str) -> list[AttributedRepo]:
    """Derive GitHub repo references from npm package.repository.url.

    We don't re-fetch GitHub metadata here — that's the caller's job if it
    wants full repo info. Returning the slug is enough to hand off to the
    VM scanner (which will clone by URL anyway).
    """
    out: list[AttributedRepo] = []
    seen: set[str] = set()
    for pkg in packages:
        slug = extract_github_slug(pkg.repository_url)
        if not slug:
            continue
        full_name = f"{slug[0]}/{slug[1]}"
        if full_name in seen:
            continue
        seen.add(full_name)
        out.append(AttributedRepo(
            full_name=full_name,
            url=f"https://github.com/{full_name}",
            clone_url=f"https://github.com/{full_name}.git",
            owner_login=slug[0],
            owner_type="",
            reasons=[REASON_PACKAGE_JSON_MATCH],
            confidence_score=SCORE_TABLE[REASON_PACKAGE_JSON_MATCH],
        ))
    return out


# ── Keyword search (last-ditch, lowest confidence) ────────────────────


async def repos_from_keyword_search(
    gh: GitHubClient,
    target_domain: str,
    *,
    max_results: int = 50,
    attributed_org_logins: set[str] | None = None,
) -> list[AttributedRepo]:
    """Run a GitHub code search for the domain string and return candidate
    repos. Applies the user's filter rule:

        Keep a repo from keyword search ONLY if at least one of:
          - it belongs to an already-attributed org, OR
          - its package.json references the domain, OR
          - its top contributor has @domain.

    We check package.json + top contributor inline for each hit.
    """
    attributed_org_logins = attributed_org_logins or set()
    out: list[AttributedRepo] = []
    seen: set[str] = set()

    async def _evaluate(item: dict):
        repo = item.get("repository") or {}
        full_name = repo.get("full_name") or ""
        if not full_name or full_name in seen:
            return
        seen.add(full_name)
        owner = (repo.get("owner") or {}).get("login") or ""

        owner_is_attributed = owner in attributed_org_logins

        # Fetch package.json (best effort)
        pkg_raw = None
        if "/" in full_name:
            o, r = full_name.split("/", 1)
            pkg_raw = await gh.get_file(o, r, "package.json")

        # Fetch top contributor email (best effort)
        top_email = None
        if "/" in full_name:
            o, r = full_name.split("/", 1)
            contribs = await gh.list_repo_contributors(o, r, per_page=1)
            if contribs:
                top_login = contribs[0].get("login")
                if top_login:
                    top_user = await gh.get_user(top_login)
                    top_email = (top_user or {}).get("email")

        scored = score_repo(
            repo,
            target_domain,
            owner_is_attributed_org=owner_is_attributed,
            package_json_raw=pkg_raw,
            top_contributor_email=top_email,
            from_keyword_search=True,
        )
        if scored:
            out.append(scored)

    query = f'"{target_domain}"'
    count = 0
    sem = asyncio.Semaphore(5)
    pending: list[asyncio.Task] = []
    async for item in gh.search_code(query, per_page=100):

        async def _wrap(it=item):
            async with sem:
                await _evaluate(it)

        pending.append(asyncio.create_task(_wrap()))
        count += 1
        if count >= max_results:
            break
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    return out


# ── Exposed secret files (path-only existence probes) ─────────────────


# Paths that shouldn't exist in a public repo. Checked via HEAD on
# raw.githubusercontent.com — no rate-limiting, no token, no content pulled.
# `rule_id` is the stable identifier used by downstream reporting.
COMMON_SECRET_FILE_PATHS: list[tuple[str, str, str, str]] = [
    # (path, rule_id, severity, detail)
    # Dotenv variants — the most common accidental leak.
    (".env", "dotenv", "high", "application env file committed to public repo"),
    (".env.local", "dotenv", "high", "local env file committed to public repo"),
    (".env.development", "dotenv", "high", "dev env file committed to public repo"),
    (".env.dev", "dotenv", "high", "dev env file committed to public repo"),
    (".env.production", "dotenv", "critical", "production env file committed to public repo"),
    (".env.prod", "dotenv", "critical", "production env file committed to public repo"),
    (".env.staging", "dotenv", "high", "staging env file committed to public repo"),
    (".env.backup", "dotenv", "high", "env backup committed to public repo"),

    # Package-manager creds.
    (".npmrc", "npmrc", "high", "may contain npm _authToken"),
    (".pypirc", "pypirc", "high", "may contain PyPI upload credentials"),
    (".netrc", "netrc", "high", "may contain HTTP basic-auth credentials"),
    (".git-credentials", "git-credentials", "critical", "plaintext git credentials"),

    # Cloud / platform creds.
    (".aws/credentials", "aws-credentials", "critical", "AWS access keys"),
    (".aws/config", "aws-config", "medium", "AWS profile configuration (may leak account/region)"),
    ("credentials.json", "credentials-json", "high", "generic credentials file"),
    ("service-account.json", "gcp-service-account", "critical", "GCP service account key"),
    ("service_account.json", "gcp-service-account", "critical", "GCP service account key"),
    ("firebase-adminsdk.json", "firebase-admin", "critical", "Firebase admin SDK key"),
    ("gcloud-service-key.json", "gcp-service-account", "critical", "GCP service account key"),
    ("client_secret.json", "oauth-client-secret", "high", "OAuth client secret"),

    # SSH / signing keys.
    ("id_rsa", "ssh-private-key", "critical", "SSH private key"),
    ("id_ed25519", "ssh-private-key", "critical", "SSH private key"),
    ("id_ecdsa", "ssh-private-key", "critical", "SSH private key"),
    (".ssh/id_rsa", "ssh-private-key", "critical", "SSH private key"),
    (".ssh/id_ed25519", "ssh-private-key", "critical", "SSH private key"),

    # Docker creds.
    (".dockercfg", "docker-creds", "high", "Docker registry credentials"),
    (".docker/config.json", "docker-creds", "high", "Docker registry credentials"),

    # Infra state.
    ("terraform.tfstate", "tfstate", "critical", "Terraform state (often contains secrets inline)"),
    ("terraform.tfstate.backup", "tfstate", "critical", "Terraform state backup"),
    ("terraform.tfvars", "tfvars", "high", "Terraform variables (may contain secrets)"),
    ("secrets.tfvars", "tfvars", "critical", "Terraform secret variables"),

    # Framework-specific configs that commonly hold credentials.
    ("config/database.yml", "rails-database-yml", "high", "Rails DB config (may contain credentials)"),
    ("config/secrets.yml", "rails-secrets-yml", "critical", "Rails secrets file"),
    ("config/master.key", "rails-master-key", "critical", "Rails master key"),
    ("wp-config.php", "wp-config", "high", "WordPress config with DB credentials"),
    ("appsettings.Development.json", "dotnet-appsettings", "medium", ".NET dev settings (may contain secrets)"),
    ("appsettings.Production.json", "dotnet-appsettings", "high", ".NET production settings"),
    ("web.config", "dotnet-web-config", "medium", ".NET web.config (may contain connection strings)"),

    # Generic secrets bundles.
    ("secrets.yml", "secrets-yml", "high", "generic secrets YAML"),
    ("secrets.yaml", "secrets-yml", "high", "generic secrets YAML"),
    ("secret.yml", "secrets-yml", "high", "generic secret YAML"),

    # Local artifacts that sometimes contain session tokens.
    (".vscode/sftp.json", "sftp-json", "high", "VSCode SFTP config (often with creds)"),
]


async def scan_exposed_secret_files(
    gh: GitHubClient,
    repos: list[AttributedRepo],
    *,
    paths: list[tuple[str, str, str, str]] | None = None,
    concurrency: int = 20,
) -> list[ExposedFile]:
    """HEAD a list of known-bad paths on every repo and record hits.

    Uses raw.githubusercontent.com, which has no API rate limit — so this
    scales with repos * paths without burning the GitHub API budget.
    Archived/fork repos are skipped (noise, not real exposures).
    """
    path_specs = paths if paths is not None else COMMON_SECRET_FILE_PATHS
    out: list[ExposedFile] = []
    sem = asyncio.Semaphore(concurrency)

    async def _probe(repo: AttributedRepo, path: str, rule_id: str, severity: str, detail: str):
        if "/" not in repo.full_name:
            return
        owner, name = repo.full_name.split("/", 1)
        ref = repo.default_branch or "HEAD"
        async with sem:
            exists = await gh.raw_file_exists(owner, name, path, ref=ref)
        if exists:
            out.append(ExposedFile(
                repo=repo.full_name,
                path=path,
                url=f"https://github.com/{repo.full_name}/blob/{ref}/{path}",
                rule_id=rule_id,
                severity=severity,
                detail=detail,
            ))

    tasks: list[asyncio.Task] = []
    for repo in repos:
        if repo.archived or repo.is_fork:
            continue
        for path, rule_id, severity, detail in path_specs:
            tasks.append(asyncio.create_task(
                _probe(repo, path, rule_id, severity, detail),
            ))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return out


# ── Reverse-attribution (unauth-friendly) ─────────────────────────────


async def enrich_repos_with_package_json(
    gh: GitHubClient,
    repos: list[AttributedRepo],
    target_domain: str,
    *,
    concurrency: int = 10,
) -> None:
    """Fetch package.json for each repo via raw URL and add the
    package-json-match reason if it references the target domain.

    Works fully unauthenticated (raw.githubusercontent.com has no API rate
    limit), so we can corroborate org/user repos even when code search is
    disabled. Mutates `repos` in place.
    """
    from app.ingest.github_npm.attribution import (
        _package_json_references_domain,
        top_level_confidence,
    )

    sem = asyncio.Semaphore(concurrency)

    async def _check(repo: AttributedRepo):
        if REASON_PACKAGE_JSON_MATCH in repo.reasons:
            return
        if "/" not in repo.full_name:
            return
        owner, name = repo.full_name.split("/", 1)
        ref = repo.default_branch or "HEAD"
        async with sem:
            raw = await gh.get_raw_file(owner, name, "package.json", ref=ref)
        if not raw:
            return
        if _package_json_references_domain(raw, target_domain):
            repo.reasons = list({*repo.reasons, REASON_PACKAGE_JSON_MATCH})
            repo.confidence_score = top_level_confidence(repo.reasons)

    await asyncio.gather(*(_check(r) for r in repos), return_exceptions=True)


# ── npm dependency CVEs (OSV.dev) ─────────────────────────────────────


# OSV severity strings vary by source DB; normalize to our four-bucket scale.
_OSV_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "low",
}


def _normalize_osv_severity(vuln: dict) -> str:
    """Pick the best severity string from an OSV vulnerability record.

    Prefers `database_specific.severity` (set by GHSA / PyPA / etc.), falls
    back to parsing the CVSS base score from `severity[].score`, then to
    "medium" as a safe default.
    """
    db_spec = vuln.get("database_specific") or {}
    raw = (db_spec.get("severity") or "").upper()
    if raw in _OSV_SEVERITY_MAP:
        return _OSV_SEVERITY_MAP[raw]

    # Fallback: parse CVSS base score from the severity array.
    for sev in vuln.get("severity") or []:
        score_str = sev.get("score") or ""
        # Format examples: "CVSS:3.1/AV:N/.../A:H" (vector) or "9.8" (numeric).
        if score_str.replace(".", "", 1).isdigit():
            try:
                score = float(score_str)
            except ValueError:
                continue
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
    return "medium"


def _earliest_fixed_version(vuln: dict, ecosystem: str = "npm") -> str | None:
    """Walk OSV `affected[].ranges[].events` for the earliest `fixed` event.

    OSV uses event ranges of the form `[{introduced: "0"}, {fixed: "1.2.3"}]`.
    We don't try to compare versions semantically — picking *any* fixed
    version is enough to tell the user "an upgrade exists." If multiple
    `fixed` events appear, we just take the first.
    """
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for ev in rng.get("events") or []:
                fixed = ev.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def _osv_advisory_url(vuln: dict) -> str | None:
    """Pick the canonical advisory URL — prefer GHSA, then OSV's own page."""
    refs = vuln.get("references") or []
    for ref in refs:
        url = ref.get("url") or ""
        if "github.com/advisories/GHSA-" in url:
            return url
    vid = vuln.get("id") or ""
    if vid:
        return f"https://osv.dev/vulnerability/{vid}"
    return None


def _osv_primary_id(vuln: dict) -> str | None:
    """Prefer the GHSA id (more stable & widely indexed) over the OSV id."""
    vid = vuln.get("id") or ""
    if vid.startswith("GHSA-"):
        return vid
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("GHSA-"):
            return alias
    # Fall back to first CVE alias, then the OSV id itself.
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return vid or None


async def scan_npm_dependency_cves(
    osv: OsvClient,
    packages: list[AttributedNpmPackage],
    *,
    concurrency: int = 10,
) -> list[DependencyCVE]:
    """One OSV query per package@version → DependencyCVE per advisory.

    Skips packages with no resolved version (we'd otherwise get every
    historical advisory back, which is just noise).
    """
    out: list[DependencyCVE] = []
    sem = asyncio.Semaphore(concurrency)

    async def _scan(pkg: AttributedNpmPackage) -> None:
        if not pkg.version:
            return
        async with sem:
            vulns = await osv.query(pkg.name, pkg.version, ecosystem="npm")
        for v in vulns:
            primary = _osv_primary_id(v)
            severity = _normalize_osv_severity(v)
            fixed = _earliest_fixed_version(v)
            cve_alias = next(
                (a for a in (v.get("aliases") or []) if isinstance(a, str) and a.startswith("CVE-")),
                None,
            )
            out.append(DependencyCVE(
                package=pkg.name,
                installed_version=pkg.version,
                cve=primary,
                severity=severity,
                advisory_url=_osv_advisory_url(v),
                fix_available=bool(fixed),
                fixed_version=fixed,
                summary=v.get("summary") or v.get("details") or None,
                aliases=[a for a in (v.get("aliases") or []) if isinstance(a, str)],
                unmaintained=False,
            ))

    await asyncio.gather(*(_scan(p) for p in packages), return_exceptions=True)
    return out


# ── npm package hygiene (deprecated, unmaintained) ────────────────────


def scan_npm_package_hygiene(
    packages: list[AttributedNpmPackage],
    *,
    unmaintained_after_days: int = 730,
    now: datetime | None = None,
) -> list[PackageHygiene]:
    """Pure function — turns existing package metadata into hygiene findings.

    No network calls: `deprecated` is captured during attribution, and
    `last_published` lets us flag packages that haven't been touched in
    `unmaintained_after_days` (default 2 years).
    """
    out: list[PackageHygiene] = []
    cutoff = (now or datetime.now(timezone.utc))
    for pkg in packages:
        if pkg.deprecated:
            msg = pkg.deprecated_message or "package marked deprecated by maintainers"
            out.append(PackageHygiene(
                package=pkg.name,
                version=pkg.version,
                rule_id="deprecated",
                severity="medium",
                detail=msg[:500],  # cap — some maintainers paste long migration guides
            ))

        if pkg.last_published:
            published = _parse_iso8601(pkg.last_published)
            if published is None:
                continue
            age_days = (cutoff - published).days
            if age_days > unmaintained_after_days:
                out.append(PackageHygiene(
                    package=pkg.name,
                    version=pkg.version,
                    rule_id="unmaintained",
                    severity="low",
                    detail=(
                        f"latest version published {age_days} days ago "
                        f"(threshold: {unmaintained_after_days})"
                    ),
                ))
    return out


def _parse_iso8601(s: str) -> datetime | None:
    """Parse npm/GitHub-style ISO8601 timestamps into a tz-aware UTC datetime.

    npm uses `2023-04-12T14:22:01.123Z`; GitHub uses `2023-04-12T14:22:01Z`.
    Both are handled by stripping the trailing `Z` and forcing UTC.
    """
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


# ── Repo hygiene (branch protection, SECURITY.md, archived w/ activity) ──


# Conventional locations for a repo's security policy. We HEAD all three on
# raw.githubusercontent.com — no API budget cost — and only emit a finding
# if every one is missing.
_SECURITY_MD_PATHS: tuple[str, ...] = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
)


async def scan_repo_hygiene(
    gh: GitHubClient,
    repos: list[AttributedRepo],
    *,
    concurrency: int = 20,
    archived_active_days: int = 180,
    now: datetime | None = None,
) -> list[RepoHygiene]:
    """Three checks per public, non-fork repo:

    1. **no_branch_protection** — default branch has no protection rules.
       Uses GET /repos/{o}/{r}/branches/{b} which is public-readable and
       includes a `protected` bool, so we don't need admin scope.
    2. **missing_security_md** — none of SECURITY.md, .github/SECURITY.md,
       or docs/SECURITY.md exists. HEAD-only, no auth.
    3. **archived_with_recent_activity** — repo flagged archived but pushed
       in the last `archived_active_days` (default 180), suggesting either
       a mis-flag or an active fork-bait scenario.

    Forks are skipped on every check (they inherit upstream's protection
    state and noise drowns the signal).
    """
    out: list[RepoHygiene] = []
    sem = asyncio.Semaphore(concurrency)
    cutoff = (now or datetime.now(timezone.utc))

    async def _check(repo: AttributedRepo) -> None:
        if repo.is_fork:
            return
        full_name = repo.full_name
        if "/" not in full_name:
            return
        owner, name = full_name.split("/", 1)
        branch = repo.default_branch or "main"

        # (3) Archived-with-activity is a pure local check — no API call.
        if repo.archived and repo.pushed_at:
            pushed = _parse_iso8601(repo.pushed_at)
            if pushed and (cutoff - pushed).days <= archived_active_days:
                out.append(RepoHygiene(
                    repo=full_name,
                    rule_id="archived_with_recent_activity",
                    severity="low",
                    detail=(
                        f"archived repo last pushed {(cutoff - pushed).days} days ago — "
                        f"verify intent (archive freezes issues/PRs but the code stays public)"
                    ),
                ))

        # Skip remote checks on archived repos — they can't change, so a
        # finding is just noise.
        if repo.archived:
            return

        # (1) Branch protection — single REST call.
        async with sem:
            branch_data = await gh.get_branch(owner, name, branch)
        if isinstance(branch_data, dict) and branch_data.get("protected") is False:
            out.append(RepoHygiene(
                repo=full_name,
                rule_id="no_branch_protection",
                severity="medium",
                detail=(
                    f"default branch '{branch}' has no protection rules — "
                    f"force-push, history rewrite, and unreviewed merges are unrestricted"
                ),
                evidence=f"branches/{branch}.protected=false",
            ))

        # (2) SECURITY.md — three HEADs in parallel; emit only if all miss.
        sec_results = await asyncio.gather(*[
            gh.raw_file_exists(owner, name, p, ref=branch)
            for p in _SECURITY_MD_PATHS
        ], return_exceptions=True)
        any_present = any(r is True for r in sec_results)
        if not any_present:
            out.append(RepoHygiene(
                repo=full_name,
                rule_id="missing_security_md",
                severity="low",
                detail=(
                    "no security policy file found at SECURITY.md, "
                    ".github/SECURITY.md, or docs/SECURITY.md — researchers "
                    "have no documented disclosure channel"
                ),
            ))

    await asyncio.gather(*(_check(r) for r in repos), return_exceptions=True)
    return out


# ── GitHub Actions workflow risks ─────────────────────────────────────


# Action owners we consider trusted enough to allow tag/branch refs. GitHub
# itself runs these on managed infra and rotates them, so the
# unpinned-action class isn't actionable for them.
_TRUSTED_ACTION_OWNERS: frozenset[str] = frozenset({
    "actions", "github", "docker",
})

# Workflow yaml regexes — line-oriented and tolerant to formatting.
# We avoid a yaml parser deliberately: malformed yaml in real workflows is
# common, and we only care about a few specific tokens.
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s]+)", re.MULTILINE)
_PR_TARGET_RE = re.compile(r"\bpull_request_target\b")
_PR_HEAD_RE = re.compile(
    # Matches both `github.event.pull_request.head.*` and the rare bare
    # `pull_request.head.*` form some workflows use after destructuring.
    r"\bpull_request\.head\.(sha|ref)\b",
)
_SELF_HOSTED_RE = re.compile(
    r"runs-on:\s*\[?\s*['\"]?self-hosted",
    re.IGNORECASE,
)


def analyze_workflow_content(
    repo_full_name: str, workflow_path: str, content: str,
) -> list[WorkflowRisk]:
    """Run three checks on a single workflow yaml string.

    Returns at most one risk per (workflow, rule_id) — multiple unpinned
    action references in the same file collapse into a single finding with
    all matched refs in `evidence`. This keeps the finding list aggregable
    by workflow path on the backend side.
    """
    risks: list[WorkflowRisk] = []

    if _SELF_HOSTED_RE.search(content):
        risks.append(WorkflowRisk(
            repo=repo_full_name,
            workflow_path=workflow_path,
            rule_id="self_hosted_runner",
            severity="high",
            detail=(
                "Workflow uses `self-hosted` runners. Unless the repo is "
                "private and runners are isolated per-job, fork PRs can "
                "execute attacker code on the runner host."
            ),
        ))

    if _PR_TARGET_RE.search(content) and _PR_HEAD_RE.search(content):
        risks.append(WorkflowRisk(
            repo=repo_full_name,
            workflow_path=workflow_path,
            rule_id="pull_request_target",
            severity="high",
            detail=(
                "Workflow triggers on `pull_request_target` AND references "
                "`pull_request.head.{sha|ref}`. This pattern checks out "
                "untrusted fork code while running with the repo's secrets "
                "and write token — a well-known privilege-escalation route."
            ),
        ))

    unpinned: list[str] = []
    for match in _USES_RE.finditer(content):
        ref = match.group(1).strip()
        # Skip local (`./.github/actions/foo`) and docker:// refs entirely.
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref or "/" not in ref:
            continue
        action_path, _, version = ref.rpartition("@")
        owner = action_path.split("/", 1)[0].lower()
        if owner in _TRUSTED_ACTION_OWNERS:
            continue
        if _SHA40_RE.match(version):
            continue  # SHA-pinned → safe
        unpinned.append(ref)

    if unpinned:
        # Order-preserving dedup — same action can be `uses:`d in multiple
        # steps and we don't want to repeat it in evidence.
        seen: set[str] = set()
        unique = [r for r in unpinned if not (r in seen or seen.add(r))]
        evidence_refs = unique[:10]
        evidence = ", ".join(evidence_refs)
        if len(unique) > len(evidence_refs):
            evidence += f", …and {len(unique) - len(evidence_refs)} more"
        risks.append(WorkflowRisk(
            repo=repo_full_name,
            workflow_path=workflow_path,
            rule_id="unpinned_action",
            severity="medium",
            detail=(
                f"{len(unique)} third-party action reference(s) pinned to a "
                f"tag or branch instead of a full commit SHA. A compromised "
                f"upstream tag silently propagates to every build."
            ),
            evidence=evidence,
        ))

    return risks


async def scan_workflow_risks(
    gh: GitHubClient,
    repos: list[AttributedRepo],
    *,
    concurrency: int = 10,
    max_workflows_per_repo: int = 25,
) -> list[WorkflowRisk]:
    """For each public, non-fork, non-archived repo: list its workflow
    files via the contents API and run `analyze_workflow_content` on each.

    Cost per repo: 1 GitHub API call (contents listing) + N raw fetches
    (no API budget). Forks/archived are skipped — forks inherit upstream
    workflows and archived repos can't be remediated.
    """
    out: list[WorkflowRisk] = []
    sem = asyncio.Semaphore(concurrency)

    async def _process_repo(repo: AttributedRepo) -> None:
        if repo.is_fork or repo.archived:
            return
        if "/" not in repo.full_name:
            return
        owner, name = repo.full_name.split("/", 1)
        ref = repo.default_branch or None

        async with sem:
            entries = await gh.list_directory(owner, name, ".github/workflows", ref=ref)
        if not entries:
            return

        # Filter to .yml/.yaml files; cap so a pathological repo can't blow
        # our budget by checking in dozens of generated workflows.
        workflows = [
            e for e in entries
            if isinstance(e, dict)
            and (e.get("name") or "").lower().endswith((".yml", ".yaml"))
            and e.get("type") == "file"
        ][:max_workflows_per_repo]

        async def _fetch_and_analyze(entry: dict) -> None:
            path = entry.get("path") or ""
            if not path:
                return
            content = await gh.get_raw_file(owner, name, path, ref=ref or "HEAD")
            if not content:
                return
            out.extend(analyze_workflow_content(repo.full_name, path, content))

        await asyncio.gather(
            *(_fetch_and_analyze(w) for w in workflows),
            return_exceptions=True,
        )

    await asyncio.gather(*(_process_repo(r) for r in repos), return_exceptions=True)
    return out

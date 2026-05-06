"""Dataclasses for the GitHub/npm attribution engine.

These are the only types crossing between modules and the Celery result
payload. Keep them JSON-serializable (dataclasses.asdict works out of the
box on primitives + nested dataclasses).
"""

from dataclasses import asdict, dataclass, field
from typing import Any


# Attribution reasons — ordered by strength. The engine picks the strongest
# one for each asset and converts it to a confidence_score via SCORE_TABLE.
REASON_VERIFIED_DOMAIN = "verified_domain"           # GitHub Verified Domain match
REASON_ORG_BLOG_MATCH = "org_blog_match"             # org.blog/email matches domain
REASON_OWNED_BY_ATTRIBUTED_ORG = "owned_by_org"      # repo.owner is an attributed org
REASON_PACKAGE_JSON_MATCH = "package_json_match"     # repo's package.json references domain
REASON_NPM_MAINTAINER_MATCH = "npm_maintainer"       # npm package maintainer is @domain
REASON_CONTRIBUTOR_EMAIL = "contributor_email"       # top contributor has @domain email
REASON_USER_EMAIL_MATCH = "user_email"               # GitHub user public email is @domain
REASON_KEYWORD_MATCH = "keyword_match"               # bare mention in code/README

SCORE_TABLE: dict[str, float] = {
    REASON_VERIFIED_DOMAIN: 1.0,
    REASON_ORG_BLOG_MATCH: 0.85,
    REASON_OWNED_BY_ATTRIBUTED_ORG: 0.8,
    REASON_PACKAGE_JSON_MATCH: 0.75,
    REASON_NPM_MAINTAINER_MATCH: 0.7,
    REASON_CONTRIBUTOR_EMAIL: 0.55,
    REASON_USER_EMAIL_MATCH: 0.55,
    REASON_KEYWORD_MATCH: 0.2,
}


@dataclass
class AttributedOrg:
    login: str
    url: str
    domain_match: str | None = None        # which attribute matched (blog/email/verified)
    is_verified_domain: bool = False
    email: str | None = None
    blog: str | None = None
    reasons: list[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class AttributedUser:
    login: str
    url: str
    email: str | None = None
    reasons: list[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class AttributedRepo:
    full_name: str                          # "owner/repo"
    url: str
    clone_url: str
    default_branch: str = "main"
    owner_login: str = ""
    owner_type: str = ""                    # "Organization" | "User"
    is_fork: bool = False
    archived: bool = False
    pushed_at: str | None = None            # ISO8601
    stars: int = 0
    language: str | None = None
    package_json_urls: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class AttributedNpmPackage:
    name: str                               # "@scope/pkg" or "pkg"
    version: str | None = None
    maintainers: list[str] = field(default_factory=list)    # "user <email>" strings
    repository_url: str | None = None       # parsed from package.json
    homepage: str | None = None
    last_published: str | None = None
    deprecated: bool = False
    deprecated_message: str | None = None
    reasons: list[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class SecretFinding:
    """Secret-scan result (populated by hakuna-vm-scanner side, but we
    define the shape here so both scanners agree on the contract)."""
    detector: str
    verified: bool
    redacted: str
    source_ref: str                         # e.g. "github.com/o/r/blob/sha/file.js"
    repo: str | None = None
    validation_nuclei: dict[str, Any] | None = None


@dataclass
class WorkflowRisk:
    repo: str
    workflow_path: str                      # ".github/workflows/ci.yml"
    rule_id: str                            # "pull_request_target" | "unpinned_action" | "self_hosted_runner"
    severity: str                           # "low" | "medium" | "high"
    detail: str
    evidence: str = ""


@dataclass
class ExposedFile:
    """A well-known secret-bearing file that exists in a public repo.

    We only record *presence* at a known path — not content — so this is safe
    to emit without risking further leakage in logs/reports."""
    repo: str                               # "owner/repo"
    path: str                               # file path inside the repo
    url: str                                # direct raw URL for the analyst
    rule_id: str                            # stable identifier (e.g. "dotenv", "tfstate")
    severity: str = "medium"                # "low" | "medium" | "high" | "critical"
    detail: str = ""


@dataclass
class DependencyCVE:
    package: str
    installed_version: str | None
    cve: str | None                         # GHSA or CVE id (prefer GHSA)
    severity: str                           # "low" | "medium" | "high" | "critical"
    advisory_url: str | None = None
    fix_available: bool = False
    fixed_version: str | None = None        # earliest fixed version per OSV ranges
    summary: str | None = None
    aliases: list[str] = field(default_factory=list)
    unmaintained: bool = False


@dataclass
class PackageHygiene:
    """Non-CVE hygiene issues on an npm package — deprecated, unmaintained, etc."""
    package: str                            # "@scope/pkg" or "pkg"
    version: str | None
    rule_id: str                            # "deprecated" | "unmaintained"
    severity: str                           # "low" | "medium" | "high"
    detail: str = ""


@dataclass
class RepoHygiene:
    """Repository-level hygiene findings — branch protection, security policy, etc."""
    repo: str                               # "owner/repo"
    rule_id: str                            # stable id, e.g. "no_branch_protection"
    severity: str                           # "low" | "medium" | "high"
    detail: str = ""
    evidence: str = ""


@dataclass
class DiscoveryResult:
    """Unified engine output. JSON-serializable via asdict()."""
    target_domain: str
    mode: str
    attributed_assets: dict[str, list] = field(default_factory=lambda: {
        "github_orgs": [],
        "github_users": [],
        "github_repos": [],
        "npm_packages": [],
    })
    vulnerabilities: dict[str, list] = field(default_factory=lambda: {
        "secrets": [],
        "workflow_risks": [],
        "dependency_cves": [],
        "package_hygiene": [],
        "repo_hygiene": [],
        "exposed_files": [],
    })
    stats: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

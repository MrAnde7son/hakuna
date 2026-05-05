"""Tests for the EASM GitHub/npm attribution engine — pure functions only.

Network-dependent paths (clients, engine.run) are covered by integration
tests in staging, not here.
"""

import json

import pytest

from app.ingest.github_npm.attribution import (
    _package_json_references_domain,
    domain_matches,
    filter_above_threshold,
    is_noisy_target,
    score_org,
    score_repo,
    score_user,
    top_level_confidence,
)
from app.ingest.github_npm.discovery import (
    COMMON_SECRET_FILE_PATHS,
    _derive_login_hints_from_domain,
    _normalize_git_url,
    enrich_repos_with_package_json,
    extract_github_slug,
    scan_exposed_secret_files,
)
from app.ingest.github_npm.engine import EASMEngine
from app.ingest.github_npm.models import (
    REASON_KEYWORD_MATCH,
    REASON_OWNED_BY_ATTRIBUTED_ORG,
    REASON_PACKAGE_JSON_MATCH,
    REASON_VERIFIED_DOMAIN,
    SCORE_TABLE,
    AttributedRepo,
    DiscoveryResult,
    ExposedFile,
)


class TestDomainMatches:
    def test_exact_hostname(self):
        assert domain_matches("example.com", "example.com")

    def test_subdomain(self):
        assert domain_matches("blog.example.com", "example.com")

    def test_unrelated_domain(self):
        assert not domain_matches("other.com", "example.com")

    def test_email_form(self):
        assert domain_matches("alice@example.com", "example.com")

    def test_url_form(self):
        assert domain_matches("https://blog.example.com/post", "example.com")

    def test_suffix_trap(self):
        # "notexample.com" should NOT match "example.com" — endswith check
        # must include the leading dot.
        assert not domain_matches("notexample.com", "example.com")

    def test_none_input(self):
        assert not domain_matches(None, "example.com")


class TestTopLevelConfidence:
    def test_empty_returns_zero(self):
        assert top_level_confidence([]) == 0.0

    def test_single_reason_uses_table(self):
        assert top_level_confidence([REASON_VERIFIED_DOMAIN]) == 1.0

    def test_multiple_reasons_get_bonus(self):
        base = SCORE_TABLE[REASON_PACKAGE_JSON_MATCH]
        got = top_level_confidence([REASON_PACKAGE_JSON_MATCH, REASON_KEYWORD_MATCH])
        assert got > base
        assert got <= 1.0

    def test_bonus_caps_at_one(self):
        reasons = list(SCORE_TABLE.keys())
        assert top_level_confidence(reasons) == 1.0


class TestScoreOrg:
    def test_blog_match_attributes(self):
        org = score_org(
            {"login": "acme", "blog": "https://acme.example.com", "email": ""},
            "example.com",
        )
        assert org is not None
        assert org.login == "acme"
        assert org.confidence_score > 0.5

    def test_verified_domain_is_max(self):
        org = score_org(
            {"login": "acme", "blog": "", "email": ""},
            "example.com",
            verified_domains=["example.com"],
        )
        assert org is not None
        assert org.is_verified_domain
        assert org.confidence_score == 1.0

    def test_no_match_returns_none(self):
        assert score_org({"login": "acme", "blog": "other.com"}, "example.com") is None


class TestScoreUser:
    def test_user_with_matching_email(self):
        u = score_user({"login": "bob", "email": "bob@example.com"}, "example.com")
        assert u is not None
        assert u.login == "bob"

    def test_user_without_email(self):
        assert score_user({"login": "bob", "email": ""}, "example.com") is None

    def test_user_unrelated_email(self):
        assert score_user({"login": "bob", "email": "bob@other.com"}, "example.com") is None


class TestScoreRepo:
    """Encodes the user's filter rule explicitly."""

    def _repo(self, owner="acme"):
        return {
            "full_name": f"{owner}/widget",
            "html_url": f"https://github.com/{owner}/widget",
            "clone_url": f"https://github.com/{owner}/widget.git",
            "owner": {"login": owner, "type": "Organization"},
            "default_branch": "main",
        }

    def test_owned_by_attributed_org(self):
        r = score_repo(self._repo(), "example.com", owner_is_attributed_org=True)
        assert r is not None
        assert REASON_OWNED_BY_ATTRIBUTED_ORG in r.reasons

    def test_package_json_references_domain(self):
        pkg = json.dumps({"homepage": "https://example.com"})
        r = score_repo(self._repo(), "example.com", package_json_raw=pkg)
        assert r is not None
        assert REASON_PACKAGE_JSON_MATCH in r.reasons

    def test_contributor_email_match(self):
        r = score_repo(
            self._repo(),
            "example.com",
            top_contributor_email="alice@example.com",
        )
        assert r is not None

    def test_keyword_only_yields_noise_floor(self):
        r = score_repo(self._repo(), "example.com", from_keyword_search=True)
        assert r is not None
        assert r.reasons == [REASON_KEYWORD_MATCH]
        assert r.confidence_score < 0.3  # default filter drops this

    def test_no_reasons_returns_none(self):
        assert score_repo(self._repo(), "example.com") is None


class TestPackageJsonCheck:
    def test_homepage_field(self):
        raw = json.dumps({"homepage": "https://example.com/docs"})
        assert _package_json_references_domain(raw, "example.com")

    def test_dependency_url_does_not_match(self):
        # Ensure we don't false-positive on a dep URL that happens to mention
        # the target — we only check attribution-relevant fields.
        raw = json.dumps({
            "dependencies": {"random-lib": "https://example.com/tarball.tgz"},
            "homepage": "https://other.com",
        })
        assert not _package_json_references_domain(raw, "example.com")

    def test_malformed_json(self):
        assert not _package_json_references_domain("{not json", "example.com")


class TestNoisyTarget:
    def test_gmail_refused(self):
        assert is_noisy_target("gmail.com")

    def test_corp_domain_allowed(self):
        assert not is_noisy_target("acme.com")


class TestFilterAboveThreshold:
    def test_drops_below(self):
        items = [
            AttributedRepo(full_name="a/b", url="", clone_url="", confidence_score=0.2),
            AttributedRepo(full_name="c/d", url="", clone_url="", confidence_score=0.8),
        ]
        kept = filter_above_threshold(items, 0.3)
        assert len(kept) == 1
        assert kept[0].full_name == "c/d"


class TestDeriveLoginHintsFromDomain:
    def test_simple_two_part_domain(self):
        assert _derive_login_hints_from_domain("tenable.com") == ["tenable"]

    def test_strips_www_prefix(self):
        assert _derive_login_hints_from_domain("www.tenable.com") == ["tenable"]

    def test_strips_mail_prefix(self):
        assert _derive_login_hints_from_domain("mail.rapid7.com") == ["rapid7"]

    def test_strips_app_prefix(self):
        assert _derive_login_hints_from_domain("app.company.co.uk") == ["company"]

    def test_non_stripped_subdomain(self):
        # "sub" is not in the strip list — return it as-is (false-positive hints
        # are safely rejected by score_org if the blog/email doesn't match).
        assert _derive_login_hints_from_domain("sub.example.com") == ["sub"]

    def test_no_tld(self):
        assert _derive_login_hints_from_domain("localhost") == []

    def test_empty_string(self):
        assert _derive_login_hints_from_domain("") == []

    def test_preserves_hyphens_and_digits(self):
        assert _derive_login_hints_from_domain("palo-alto123.com") == ["palo-alto123"]


class TestGitUrlNormalization:
    def test_git_plus_https(self):
        assert _normalize_git_url("git+https://github.com/a/b.git") == "https://github.com/a/b"

    def test_ssh_form(self):
        assert _normalize_git_url("git@github.com:a/b.git") == "https://github.com/a/b"

    def test_strips_dot_git(self):
        assert _normalize_git_url("https://github.com/a/b.git") == "https://github.com/a/b"

    def test_none_input(self):
        assert _normalize_git_url(None) is None

    def test_extract_slug(self):
        assert extract_github_slug("https://github.com/owner/repo") == ("owner", "repo")
        assert extract_github_slug("https://github.com/owner/repo.git") == ("owner", "repo")
        assert extract_github_slug("https://gitlab.com/a/b") is None
        assert extract_github_slug(None) is None


class TestEngineDedup:
    def test_merges_duplicate_repos(self):
        a = AttributedRepo(
            full_name="acme/widget", url="", clone_url="",
            reasons=["owned_by_org"], confidence_score=0.8, stars=5,
        )
        b = AttributedRepo(
            full_name="acme/widget", url="", clone_url="",
            reasons=["package_json_match"], confidence_score=0.75, stars=10,
            language="Python",
        )
        merged = EASMEngine._dedupe_repos([a, b])
        assert len(merged) == 1
        entry = merged[0]
        assert "owned_by_org" in entry.reasons
        assert "package_json_match" in entry.reasons
        assert entry.stars == 10  # max of the two
        assert entry.language == "Python"
        # Confidence rises above either individual score due to corroboration
        # bonus (two reasons → +0.05).
        assert entry.confidence_score > 0.8


class TestCommonSecretPaths:
    def test_list_is_non_empty(self):
        assert len(COMMON_SECRET_FILE_PATHS) > 10

    def test_entries_are_well_formed(self):
        for entry in COMMON_SECRET_FILE_PATHS:
            assert len(entry) == 4
            path, rule_id, severity, detail = entry
            assert path and not path.startswith("/")
            assert rule_id
            assert severity in {"low", "medium", "high", "critical"}
            assert detail

    def test_covers_high_signal_paths(self):
        paths = {p for p, *_ in COMMON_SECRET_FILE_PATHS}
        # Representative high-signal paths must be covered. Any regression
        # here means we stopped flagging the most common public-repo leaks.
        for required in (".env", ".env.production", ".aws/credentials",
                         "terraform.tfstate", "id_rsa", ".npmrc"):
            assert required in paths, f"missing high-signal path: {required}"


class TestDiscoveryResultShape:
    def test_exposed_files_bucket_is_initialized(self):
        r = DiscoveryResult(target_domain="example.com", mode="discovery")
        assert r.vulnerabilities["exposed_files"] == []


class _StubClient:
    """Minimal stand-in for GitHubClient — only implements the two async
    methods exposed-file scanning touches."""

    def __init__(self, existing: set[tuple[str, str, str]], pkg_json: dict[tuple[str, str], str] | None = None):
        self._existing = existing  # {(owner, repo, path)}
        self._pkg_json = pkg_json or {}

    async def raw_file_exists(self, owner, repo, path, *, ref=None):
        return (owner, repo, path) in self._existing

    async def get_raw_file(self, owner, repo, path, *, ref=None):
        return self._pkg_json.get((owner, repo))


@pytest.mark.asyncio
async def test_scan_exposed_secret_files_returns_hits():
    repos = [
        AttributedRepo(
            full_name="acme/leaky", url="", clone_url="",
            default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
        ),
        AttributedRepo(
            full_name="acme/clean", url="", clone_url="",
            default_branch="main", reasons=["owned_by_org"], confidence_score=0.8,
        ),
    ]
    client = _StubClient(existing={
        ("acme", "leaky", ".env"),
        ("acme", "leaky", "terraform.tfstate"),
    })

    hits = await scan_exposed_secret_files(client, repos)

    repos_hit = {(h.repo, h.path) for h in hits}
    assert ("acme/leaky", ".env") in repos_hit
    assert ("acme/leaky", "terraform.tfstate") in repos_hit
    assert not any(h.repo == "acme/clean" for h in hits)
    assert all(h.url.startswith("https://github.com/") for h in hits)


@pytest.mark.asyncio
async def test_scan_exposed_secret_files_skips_archived_and_forks():
    repos = [
        AttributedRepo(
            full_name="acme/old", url="", clone_url="",
            archived=True, reasons=["owned_by_org"], confidence_score=0.8,
        ),
        AttributedRepo(
            full_name="acme/fork", url="", clone_url="",
            is_fork=True, reasons=["owned_by_org"], confidence_score=0.8,
        ),
    ]
    client = _StubClient(existing={
        ("acme", "old", ".env"),
        ("acme", "fork", ".env"),
    })

    hits = await scan_exposed_secret_files(client, repos)
    assert hits == []


@pytest.mark.asyncio
async def test_enrich_repos_upgrades_confidence_on_package_json_match():
    repo = AttributedRepo(
        full_name="acme/widget", url="", clone_url="",
        default_branch="main",
        owner_login="acme", owner_type="Organization",
        reasons=["contributor_email"], confidence_score=SCORE_TABLE["contributor_email"],
    )
    client = _StubClient(
        existing=set(),
        pkg_json={("acme", "widget"): json.dumps({"homepage": "https://example.com"})},
    )

    await enrich_repos_with_package_json(client, [repo], "example.com")

    assert REASON_PACKAGE_JSON_MATCH in repo.reasons
    assert repo.confidence_score > SCORE_TABLE["contributor_email"]


@pytest.mark.asyncio
async def test_enrich_repos_is_noop_when_package_json_missing():
    repo = AttributedRepo(
        full_name="acme/widget", url="", clone_url="",
        reasons=["contributor_email"], confidence_score=SCORE_TABLE["contributor_email"],
    )
    client = _StubClient(existing=set(), pkg_json={})

    await enrich_repos_with_package_json(client, [repo], "example.com")

    assert REASON_PACKAGE_JSON_MATCH not in repo.reasons


def test_exposed_file_dataclass():
    f = ExposedFile(
        repo="acme/leaky", path=".env",
        url="https://github.com/acme/leaky/blob/main/.env",
        rule_id="dotenv", severity="high", detail="env file committed",
    )
    assert f.severity == "high"
    assert f.rule_id == "dotenv"


@pytest.mark.asyncio
async def test_engine_refuses_noisy_target():
    engine = EASMEngine()
    from app.ingest.github_npm.engine import Mode

    result = await engine.run("gmail.com", mode=Mode.DISCOVERY)
    assert any("noisy" in e for e in result.errors)
    assert result.attributed_assets["github_orgs"] == []

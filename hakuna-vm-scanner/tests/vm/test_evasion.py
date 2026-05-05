"""Unit tests for scanner.vm.evasion — pure policy, no I/O."""

import random

import pytest

from scanner.vm.evasion import (
    EvasionConfig,
    EvasionPlan,
    apply_to_nuclei_cmd,
    decide_evasion,
    resolve_origin,
)


def _cfg(**overrides) -> EvasionConfig:
    base = dict(
        enabled=True,
        proxy_pool=("http://proxy-a.example:8080", "http://proxy-b.example:8080"),
        auto_on_cdn=True,
        auto_on_retry=True,
    )
    base.update(overrides)
    return EvasionConfig(**base)


# ── decide_evasion ───────────────────────────────────────────────


def test_disabled_config_returns_none_always():
    cfg = _cfg(enabled=False)
    assert decide_evasion(
        config=cfg, attempt=0, preflight_cdn="cloudflare", prior_status=None,
    ) is None
    assert decide_evasion(
        config=cfg, attempt=1, preflight_cdn=None, prior_status="blocked",
    ) is None


def test_first_attempt_no_cdn_no_optin_returns_none():
    plan = decide_evasion(
        config=_cfg(), attempt=0, preflight_cdn=None, prior_status=None,
    )
    assert plan is None


def test_first_attempt_with_cdn_triggers_evasion():
    plan = decide_evasion(
        config=_cfg(), attempt=0, preflight_cdn="cloudflare", prior_status=None,
        rng=random.Random(0),
    )
    assert plan is not None
    assert plan.label == "cdn-auto-cloudflare"
    assert plan.proxy_url in _cfg().proxy_pool
    assert plan.user_agent is not None
    assert any(name == "X-Forwarded-For" for name, _ in plan.extra_headers)


def test_first_attempt_with_cdn_disabled_no_evasion():
    plan = decide_evasion(
        config=_cfg(auto_on_cdn=False),
        attempt=0, preflight_cdn="cloudflare", prior_status=None,
    )
    assert plan is None


@pytest.mark.parametrize("status", ["blocked", "timeout", "cdn_blocked"])
def test_retry_after_retryable_status_triggers_evasion(status):
    plan = decide_evasion(
        config=_cfg(), attempt=1, preflight_cdn=None, prior_status=status,
        rng=random.Random(1),
    )
    assert plan is not None
    assert plan.label == f"retry-after-{status}"


@pytest.mark.parametrize("status", ["complete", "partial", "unreachable", "error", "skipped"])
def test_retry_after_non_retryable_status_no_evasion(status):
    plan = decide_evasion(
        config=_cfg(), attempt=1, preflight_cdn=None, prior_status=status,
    )
    assert plan is None


def test_retry_disabled_no_evasion_even_if_blocked():
    plan = decide_evasion(
        config=_cfg(auto_on_retry=False),
        attempt=1, preflight_cdn=None, prior_status="blocked",
    )
    assert plan is None


def test_optin_prefer_origin_triggers_evasion_first_attempt():
    plan = decide_evasion(
        config=_cfg(), attempt=0, preflight_cdn=None, prior_status=None,
        plan_flags={"prefer_origin": True}, target_host="example.com",
        rng=random.Random(2),
    )
    assert plan is not None
    assert plan.label == "optin-prefer-origin"
    assert plan.prefer_origin is True
    # prefer_origin path adds Host + X-Forwarded-Host carrying the
    # public hostname so origin-direct vhost routing works.
    header_names = {n for n, _ in plan.extra_headers}
    assert "Host" in header_names
    assert "X-Forwarded-Host" in header_names


def test_empty_proxy_pool_still_returns_plan_with_headers_only():
    cfg = _cfg(proxy_pool=())
    plan = decide_evasion(
        config=cfg, attempt=0, preflight_cdn="cloudflare", prior_status=None,
        rng=random.Random(3),
    )
    assert plan is not None
    assert plan.proxy_url is None
    # Headers + UA are still applied — they don't depend on a proxy pool.
    assert plan.user_agent is not None
    assert plan.extra_headers


def test_proxy_choice_is_from_configured_pool():
    cfg = _cfg(proxy_pool=("http://only.example:1080",))
    plan = decide_evasion(
        config=cfg, attempt=0, preflight_cdn="akamai", prior_status=None,
        rng=random.Random(4),
    )
    assert plan is not None
    assert plan.proxy_url == "http://only.example:1080"


def test_cdn_takes_precedence_label_over_optin_when_both_apply():
    """When both prefer_origin AND a CDN are detected on the first
    attempt, the retry-trigger logic prefers the CDN auto-label so the
    UI surfaces the *reason* the system intervened, not the user's
    opt-in. prefer_origin is still honoured (Host header present)."""
    plan = decide_evasion(
        config=_cfg(), attempt=0, preflight_cdn="cloudflare",
        prior_status=None, plan_flags={"prefer_origin": True},
        target_host="example.com", rng=random.Random(5),
    )
    assert plan is not None
    # We branch on retry > cdn > optin in the implementation; cdn wins
    # on first attempt over optin.
    assert plan.label.startswith("cdn-auto-")
    assert plan.prefer_origin is True


# ── apply_to_nuclei_cmd ──────────────────────────────────────────


def test_apply_does_not_mutate_input_cmd():
    base = ["/usr/local/bin/nuclei", "-target", "https://example.com", "-jsonl"]
    plan = EvasionPlan(
        label="t", proxy_url="http://p:1", user_agent="UA",
        extra_headers=[("X-Real-IP", "1.2.3.4")],
    )
    out = apply_to_nuclei_cmd(base, plan)
    assert base == ["/usr/local/bin/nuclei", "-target", "https://example.com", "-jsonl"]
    assert out is not base


def test_apply_injects_proxy_flag():
    out = apply_to_nuclei_cmd(
        ["nuclei"],
        EvasionPlan(label="t", proxy_url="socks5://127.0.0.1:9050"),
    )
    assert "-proxy" in out
    assert "socks5://127.0.0.1:9050" in out


def test_apply_omits_proxy_when_none():
    out = apply_to_nuclei_cmd(
        ["nuclei"],
        EvasionPlan(label="t", proxy_url=None, user_agent="UA"),
    )
    assert "-proxy" not in out


def test_apply_emits_one_dash_h_pair_per_header():
    plan = EvasionPlan(
        label="t",
        user_agent="MyUA",
        extra_headers=[("X-Real-IP", "1.2.3.4"), ("X-Forwarded-For", "1.2.3.4")],
    )
    out = apply_to_nuclei_cmd(["nuclei"], plan)
    h_indices = [i for i, v in enumerate(out) if v == "-H"]
    assert len(h_indices) == 3  # UA + 2 forwarded headers
    # Every -H is followed by a "Name: value" string
    for i in h_indices:
        assert ":" in out[i + 1]


def test_apply_credentials_appear_before_evasion_headers():
    """Credential -H flags are added before evasion runs (in the
    worker's command builder). When evasion appends its own -H pairs
    after, both are passed; Nuclei keeps both. We rely on order, not
    dedup — this test pins the contract that evasion appends, never
    prepends.
    """
    cred_cmd = ["nuclei", "-target", "x", "-H", "Authorization: Bearer abc"]
    plan = EvasionPlan(
        label="t", user_agent="UA",
        extra_headers=[("X-Real-IP", "9.9.9.9")],
    )
    out = apply_to_nuclei_cmd(cred_cmd, plan)
    auth_idx = out.index("Authorization: Bearer abc")
    ua_idx = out.index("User-Agent: UA")
    assert auth_idx < ua_idx


# ── resolve_origin stub ──────────────────────────────────────────


def test_resolve_origin_stub_returns_none():
    """Stub contract: returns None until origin-discovery ships. Pinned
    so a future change that flips the default without wiring the real
    resolver is caught here."""
    assert resolve_origin("https://example.com") is None


# ── EvasionConfig.from_env ───────────────────────────────────────


def test_from_env_defaults(monkeypatch):
    for k in (
        "HAKUNA_EVASION_ENABLED", "HAKUNA_PROXY_POOL",
        "HAKUNA_EVASION_AUTO_ON_CDN", "HAKUNA_EVASION_AUTO_ON_RETRY",
    ):
        monkeypatch.delenv(k, raising=False)
    cfg = EvasionConfig.from_env()
    assert cfg.enabled is True
    assert cfg.proxy_pool == ()
    assert cfg.auto_on_cdn is True
    assert cfg.auto_on_retry is True


def test_from_env_parses_proxy_pool(monkeypatch):
    monkeypatch.setenv(
        "HAKUNA_PROXY_POOL",
        "http://a.example:1, http://b.example:2 ,,http://c.example:3",
    )
    cfg = EvasionConfig.from_env()
    assert cfg.proxy_pool == (
        "http://a.example:1", "http://b.example:2", "http://c.example:3",
    )


def test_from_env_disabled(monkeypatch):
    monkeypatch.setenv("HAKUNA_EVASION_ENABLED", "false")
    cfg = EvasionConfig.from_env()
    assert cfg.enabled is False

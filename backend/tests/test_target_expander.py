"""Tests for services.target_expander."""
import pytest

from services.target_expander import expand_cidr_targets


def test_passes_through_single_ip():
    assert expand_cidr_targets(["192.168.1.5"]) == ["192.168.1.5"]


def test_passes_through_hostname_and_url():
    targets = ["example.com", "https://app.example.com/login"]
    assert expand_cidr_targets(targets) == targets


def test_expands_ipv4_cidr():
    # /30 = 2 usable hosts (.1, .2); network + broadcast are dropped by .hosts()
    result = expand_cidr_targets(["10.0.0.0/30"])
    assert result == ["10.0.0.1", "10.0.0.2"]


def test_expands_cidr_24():
    result = expand_cidr_targets(["192.168.1.0/24"])
    assert len(result) == 254
    assert result[0] == "192.168.1.1"
    assert result[-1] == "192.168.1.254"


def test_slash_32_passes_through_as_host():
    assert expand_cidr_targets(["192.168.1.5/32"]) == ["192.168.1.5"]


def test_mixed_list_preserves_order():
    result = expand_cidr_targets(["example.com", "10.0.0.0/30", "1.1.1.1"])
    assert result == ["example.com", "10.0.0.1", "10.0.0.2", "1.1.1.1"]


def test_raises_when_over_cap():
    with pytest.raises(ValueError, match="exceeds"):
        expand_cidr_targets(["10.0.0.0/20"], max_hosts=1024)


def test_invalid_cidr_passes_through_unchanged():
    # Unparseable `/`-bearing tokens (probably a typo) are left for the
    # downstream scanner to reject — we don't silently drop them.
    assert expand_cidr_targets(["not-a-cidr/whatever"]) == ["not-a-cidr/whatever"]


def test_strips_whitespace_and_skips_empty():
    assert expand_cidr_targets(["  1.1.1.1  ", "", "   "]) == ["1.1.1.1"]


# ── Routability classification ──────────────────────────────────────

from services.target_expander import (  # noqa: E402
    PRIVATE_TARGET_POLICY_ENV,
    find_unroutable_targets,
    private_target_policy,
    unroutable_target_message,
)


@pytest.mark.parametrize("target", [
    "192.168.1.5",
    "10.0.0.1",
    "172.16.4.4",
    "127.0.0.1",
    "169.254.1.1",
    "100.64.0.1",          # CGNAT — equally unreachable from the cloud
    "192.168.1.0/24",
    "10.0.0.0/8",
    "https://10.0.0.5:8443/admin",
    "http://192.168.1.10",
    "127.0.0.1:9000",
    "[fd00::1]",           # IPv6 unique-local
    "::1",
])
def test_flags_unroutable_targets(target):
    assert find_unroutable_targets([target]) == [target]


@pytest.mark.parametrize("target", [
    "8.8.8.8",
    "1.1.1.1",
    "8.8.8.0/24",
    "example.com",
    "https://app.example.com/login",
    "2606:4700::1111",
    "not-a-cidr/whatever",
])
def test_does_not_flag_routable_or_unclassifiable(target):
    assert find_unroutable_targets([target]) == []


def test_hostnames_are_never_flagged_even_when_they_resolve_privately():
    # The lab compose reaches targets by hostname over a shared Docker
    # network. Classifying those would need DNS, so they must pass through.
    assert find_unroutable_targets(["dvwa", "smb", "ldap"]) == []


def test_flags_preserve_order_and_dedupe():
    targets = ["10.0.0.1", "example.com", "192.168.1.0/24", "10.0.0.1", "8.8.8.8"]
    assert find_unroutable_targets(targets) == ["10.0.0.1", "192.168.1.0/24"]


def test_flagged_before_expansion_quotes_the_typed_subnet():
    # The whole point of classifying pre-expansion: the operator sees the /24
    # they typed, not 254 individual hosts.
    assert find_unroutable_targets(["192.168.1.0/24"]) == ["192.168.1.0/24"]


def test_mixed_list_flags_only_the_unroutable_entries():
    targets = ["example.com", "10.0.0.0/30", "1.1.1.1"]
    assert find_unroutable_targets(targets) == ["10.0.0.0/30"]


def test_empty_and_whitespace_tokens_are_skipped():
    assert find_unroutable_targets(["", "   ", "10.0.0.1"]) == ["10.0.0.1"]


# ── Policy resolution ───────────────────────────────────────────────

def test_policy_defaults_to_warn(monkeypatch):
    monkeypatch.delenv(PRIVATE_TARGET_POLICY_ENV, raising=False)
    assert private_target_policy() == "warn"


@pytest.mark.parametrize("value,expected", [
    ("allow", "allow"),
    ("block", "block"),
    ("warn", "warn"),
    ("BLOCK", "block"),
    ("  allow  ", "allow"),
])
def test_policy_reads_env(monkeypatch, value, expected):
    monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, value)
    assert private_target_policy() == expected


def test_unrecognised_policy_falls_back_to_default(monkeypatch):
    # A typo in an env var must not take the scan endpoint down.
    monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "yolo")
    assert private_target_policy() == "warn"


def test_policy_is_read_at_call_time(monkeypatch):
    monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "block")
    assert private_target_policy() == "block"
    monkeypatch.setenv(PRIVATE_TARGET_POLICY_ENV, "allow")
    assert private_target_policy() == "allow"


# ── Message ─────────────────────────────────────────────────────────

def test_message_truncates_long_lists():
    tokens = [f"10.0.0.{i}" for i in range(10)]
    msg = unroutable_target_message(tokens)
    assert "(+5 more)" in msg
    assert "10.0.0.5" not in msg


def test_message_names_the_env_var_and_differs_by_outcome():
    warn = unroutable_target_message(["10.0.0.1"])
    blocked = unroutable_target_message(["10.0.0.1"], blocked=True)
    assert warn.startswith("Warning:")
    assert blocked.startswith("Refusing:")
    assert PRIVATE_TARGET_POLICY_ENV in warn
    assert PRIVATE_TARGET_POLICY_ENV in blocked

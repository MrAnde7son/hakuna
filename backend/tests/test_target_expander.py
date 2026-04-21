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

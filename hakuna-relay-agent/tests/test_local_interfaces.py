"""Tests for local_interfaces enumeration used by the registration handshake."""

import socket
from collections import namedtuple

import pytest

from agent import local_interfaces


SNIC = namedtuple("snicaddr", ["family", "address", "netmask", "broadcast", "ptp"])


def _snic(address: str, netmask: str | None) -> SNIC:
    return SNIC(family=socket.AF_INET, address=address, netmask=netmask, broadcast=None, ptp=None)


def test_psutil_path_returns_directly_connected_cidrs(monkeypatch):
    fake = {
        "lo": [_snic("127.0.0.1", "255.0.0.0")],
        "en0": [_snic("192.168.1.42", "255.255.255.0")],
        "en1": [_snic("10.0.0.5", "255.255.0.0")],
    }

    class _StubPsutil:
        @staticmethod
        def net_if_addrs():
            return fake

    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: [])
    import sys
    monkeypatch.setitem(sys.modules, "psutil", _StubPsutil)

    cidrs = local_interfaces.enumerate_local_cidrs()
    assert "192.168.1.0/24" in cidrs
    assert "10.0.0.0/16" in cidrs
    # Loopback excluded
    assert all(not c.startswith("127.") for c in cidrs)


def test_psutil_path_drops_link_local_and_dedupes(monkeypatch):
    fake = {
        "en0": [_snic("169.254.1.1", "255.255.0.0"), _snic("192.168.5.10", "255.255.255.0")],
        "en1": [_snic("192.168.5.20", "255.255.255.0")],  # same subnet, must dedupe
    }

    class _StubPsutil:
        @staticmethod
        def net_if_addrs():
            return fake

    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: [])
    import sys
    monkeypatch.setitem(sys.modules, "psutil", _StubPsutil)

    cidrs = local_interfaces.enumerate_local_cidrs()
    assert cidrs == ["192.168.5.0/24"]


def test_falls_back_to_proc_net_route_when_no_psutil(monkeypatch):
    monkeypatch.setattr(local_interfaces, "_from_psutil", lambda: [])
    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: ["10.1.0.0/16"])
    cidrs = local_interfaces.enumerate_local_cidrs()
    assert cidrs == ["10.1.0.0/16"]


def test_returns_empty_when_no_sources(monkeypatch):
    monkeypatch.setattr(local_interfaces, "_from_psutil", lambda: [])
    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: [])
    assert local_interfaces.enumerate_local_cidrs() == []


def test_psutil_handles_missing_netmask(monkeypatch):
    fake = {
        "tun0": [_snic("10.99.0.1", None)],  # VPN interfaces sometimes lack a netmask
        "en0": [_snic("192.168.1.5", "255.255.255.0")],
    }

    class _StubPsutil:
        @staticmethod
        def net_if_addrs():
            return fake

    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: [])
    import sys
    monkeypatch.setitem(sys.modules, "psutil", _StubPsutil)

    cidrs = local_interfaces.enumerate_local_cidrs()
    assert cidrs == ["192.168.1.0/24"]


def test_psutil_exception_does_not_propagate(monkeypatch):
    class _BoomPsutil:
        @staticmethod
        def net_if_addrs():
            raise RuntimeError("denied")

    import sys
    monkeypatch.setitem(sys.modules, "psutil", _BoomPsutil)
    monkeypatch.setattr(local_interfaces, "_from_proc_net_route", lambda: [])
    # Should swallow and return [] rather than crash the handshake.
    assert local_interfaces.enumerate_local_cidrs() == []

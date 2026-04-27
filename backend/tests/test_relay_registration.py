"""Unit tests for the relay registration handler.

Exercises ``_apply_register_message`` in isolation — the WS receive-loop
wraps it in I/O but the logic that needs coverage is the parsing and
``RelayAgent.labels`` merge.
"""

from types import SimpleNamespace

import pytest

from routes.relay_routes import _apply_register_message


def _agent(version: str | None = None, labels: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(agent_version=version, labels=labels)


def test_register_persists_local_interfaces_into_labels():
    agent = _agent()
    _apply_register_message(agent, {
        "type": "register",
        "agent_version": "0.2.0",
        "local_interfaces": ["192.168.1.0/24", "10.0.0.0/16"],
    })
    assert agent.agent_version == "0.2.0"
    assert agent.labels == {"local_interfaces": ["192.168.1.0/24", "10.0.0.0/16"]}


def test_register_preserves_existing_labels():
    agent = _agent(labels={"site": "nyc-office", "tier": "edge"})
    _apply_register_message(agent, {
        "type": "register",
        "local_interfaces": ["172.16.0.0/24"],
    })
    assert agent.labels == {
        "site": "nyc-office",
        "tier": "edge",
        "local_interfaces": ["172.16.0.0/24"],
    }


def test_register_overwrites_stale_local_interfaces():
    agent = _agent(labels={"local_interfaces": ["10.10.0.0/24"], "site": "nyc"})
    _apply_register_message(agent, {
        "type": "register",
        "local_interfaces": ["192.168.99.0/24"],
    })
    assert agent.labels["local_interfaces"] == ["192.168.99.0/24"]
    assert agent.labels["site"] == "nyc"


def test_register_drops_non_string_cidrs():
    agent = _agent()
    _apply_register_message(agent, {
        "type": "register",
        "local_interfaces": ["192.168.1.0/24", None, 42, "", "10.0.0.0/8"],
    })
    assert agent.labels == {"local_interfaces": ["192.168.1.0/24", "10.0.0.0/8"]}


def test_register_ignores_missing_local_interfaces():
    agent = _agent(labels={"site": "remote"})
    _apply_register_message(agent, {"type": "register", "agent_version": "0.3.0"})
    # Labels untouched when local_interfaces field is absent.
    assert agent.labels == {"site": "remote"}
    assert agent.agent_version == "0.3.0"


def test_register_ignores_non_list_local_interfaces():
    agent = _agent()
    _apply_register_message(agent, {
        "type": "register",
        "local_interfaces": "192.168.1.0/24",  # malformed — must be list
    })
    assert agent.labels in (None, {})


def test_register_with_empty_list_clears_local_interfaces():
    agent = _agent(labels={"local_interfaces": ["10.0.0.0/8"], "site": "nyc"})
    _apply_register_message(agent, {
        "type": "register",
        "local_interfaces": [],
    })
    # Empty list must replace stale CIDRs — relay may have lost an interface.
    assert agent.labels["local_interfaces"] == []
    assert agent.labels["site"] == "nyc"


def test_register_ignores_non_string_agent_version():
    agent = _agent(version="0.1.0")
    _apply_register_message(agent, {
        "type": "register",
        "agent_version": 42,
        "local_interfaces": ["10.0.0.0/24"],
    })
    assert agent.agent_version == "0.1.0"

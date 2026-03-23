"""Tests for the run_agent workflow action node."""

import secrets
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization, Agent, AgentRun

    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    yield session, org
    session.close()


@pytest.fixture
def agent(db_session):
    from models.models import Agent

    session, org = db_session
    ag = Agent(
        org_id=org.id,
        name="Triage Agent",
        system_prompt="You are a triage agent.",
        tools=["query_findings"],
        model="claude-sonnet-4-6",
    )
    session.add(ag)
    session.flush()
    return ag


@pytest.fixture
def sample_items():
    return [
        {
            "finding_id": 1,
            "asset_id": 10,
            "asset_ip": "10.0.0.1",
            "severity": 4,
            "severity_label": "Critical",
            "plugin_name": "Apache Log4Shell",
        },
        {
            "finding_id": 2,
            "asset_id": 11,
            "asset_ip": "10.0.0.2",
            "severity": 3,
            "severity_label": "High",
            "plugin_name": "OpenSSL Heartbleed",
        },
    ]


def _make_fake_run(agent_id, output="Agent analysis complete."):
    run = MagicMock()
    run.id = 999
    run.agent_id = agent_id
    run.output = output
    run.status = "done"
    run.steps_used = 2
    return run


# ── _execute_action / run_agent ───────────────────────────────────────────────

class TestRunAgentAction:
    def _make_node(self, config):
        node = MagicMock()
        node.node_type = "action"
        node.node_subtype = "run_agent"
        node.config = config
        return node

    def test_runs_agent_and_returns_items(self, db_session, agent, sample_items):
        """Agent is invoked; original items flow downstream by default."""
        session, _ = db_session
        fake_run = _make_fake_run(agent.id)

        with patch("agents.agent_engine.run_agent", return_value=fake_run) as mock_run:
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": agent.id, "pass_items_downstream": True})
            result = _execute_action(session, node, sample_items)

        assert result["status"] == "success"
        assert result["output"]["affected"] == 1
        assert result["items"] == sample_items  # original items passed through
        mock_run.assert_called_once()

    def test_agent_input_contains_findings_context(self, db_session, agent, sample_items):
        """The string passed to run_agent contains finding names and asset IPs."""
        session, _ = db_session
        fake_run = _make_fake_run(agent.id)

        captured = {}
        def capture_run(ag, user_input, db):
            captured["input"] = user_input
            return fake_run

        with patch("agents.agent_engine.run_agent", side_effect=capture_run):
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": agent.id})
            _execute_action(session, node, sample_items)

        assert "Apache Log4Shell" in captured["input"]
        assert "10.0.0.1" in captured["input"]
        assert "Critical" in captured["input"]

    def test_custom_input_template_is_rendered(self, db_session, agent, sample_items):
        """{{count}} and {{assets}} placeholders are substituted in input_template."""
        session, _ = db_session
        fake_run = _make_fake_run(agent.id)

        captured = {}
        def capture_run(ag, user_input, db):
            captured["input"] = user_input
            return fake_run

        with patch("agents.agent_engine.run_agent", side_effect=capture_run):
            from services.workflow_engine import _execute_action

            node = self._make_node({
                "agent_id": agent.id,
                "input_template": "Triage {{count}} findings on {{assets}} assets.",
            })
            _execute_action(session, node, sample_items)

        assert "2 findings" in captured["input"] or "Triage 2" in captured["input"]

    def test_pass_items_downstream_false_returns_agent_output(self, db_session, agent, sample_items):
        """When pass_items_downstream=False, items are replaced with a synthetic agent output item."""
        session, _ = db_session
        fake_run = _make_fake_run(agent.id, output="Prioritize Log4Shell immediately.")

        with patch("agents.agent_engine.run_agent", return_value=fake_run):
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": agent.id, "pass_items_downstream": False})
            result = _execute_action(session, node, sample_items)

        assert len(result["items"]) == 1
        synthetic = result["items"][0]
        assert synthetic["agent_run_id"] == fake_run.id
        assert "Prioritize Log4Shell" in synthetic["agent_output"]
        assert synthetic["agent_name"] == agent.name

    def test_missing_agent_id_skips_gracefully(self, db_session, sample_items):
        """If agent_id is missing or invalid, the action skips without raising."""
        session, _ = db_session

        with patch("agents.agent_engine.run_agent") as mock_run:
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": None})
            result = _execute_action(session, node, sample_items)

        assert result["status"] == "success"
        assert result["output"]["affected"] == 0
        mock_run.assert_not_called()

    def test_unknown_agent_id_skips_gracefully(self, db_session, sample_items):
        """If agent_id points to a non-existent agent, the action skips without raising."""
        session, _ = db_session

        with patch("agents.agent_engine.run_agent") as mock_run:
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": 99999})
            result = _execute_action(session, node, sample_items)

        assert result["status"] == "success"
        assert result["output"]["affected"] == 0
        mock_run.assert_not_called()

    def test_large_item_list_is_capped_at_50(self, db_session, agent):
        """Context summary is capped at 50 items so we don't blow the token budget."""
        session, _ = db_session
        items = [
            {"finding_id": i, "asset_ip": f"10.0.{i}.1", "severity_label": "Medium", "plugin_name": f"Plugin {i}"}
            for i in range(100)
        ]
        fake_run = _make_fake_run(agent.id)
        captured = {}

        def capture_run(ag, user_input, db):
            captured["input"] = user_input
            return fake_run

        with patch("agents.agent_engine.run_agent", side_effect=capture_run):
            from services.workflow_engine import _execute_action

            node = self._make_node({"agent_id": agent.id})
            result = _execute_action(session, node, items)

        assert "50 more findings" in captured["input"]
        assert result["items"] == items  # all 100 items still flow downstream


# ── NODE_CATALOG ─────────────────────────────────────────────────────────────

class TestRunAgentCatalog:
    def test_run_agent_in_catalog(self):
        """run_agent node type is present in the actions catalog."""
        from services.workflow_engine import NODE_CATALOG

        subtypes = [n["subtype"] for n in NODE_CATALOG["actions"]]
        assert "run_agent" in subtypes

    def test_run_agent_has_agent_select_field(self):
        """run_agent config_schema exposes an agent_select field for the UI."""
        from services.workflow_engine import NODE_CATALOG

        node_def = next(n for n in NODE_CATALOG["actions"] if n["subtype"] == "run_agent")
        assert node_def["config_schema"]["agent_id"]["type"] == "agent_select"

    def test_run_agent_has_pass_items_toggle(self):
        """run_agent exposes the pass_items_downstream boolean toggle."""
        from services.workflow_engine import NODE_CATALOG

        node_def = next(n for n in NODE_CATALOG["actions"] if n["subtype"] == "run_agent")
        schema = node_def["config_schema"]["pass_items_downstream"]
        assert schema["type"] == "boolean"
        assert schema["default"] is True

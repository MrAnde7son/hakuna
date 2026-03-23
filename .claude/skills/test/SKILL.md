---
name: test
description: Run backend and/or frontend tests. Backend uses pytest with SQLite in-memory DB. Frontend uses Playwright smoke tests.
---

# Test

Runs the project's test suite. Backend unit/integration tests use pytest; frontend uses Playwright smoke tests.

## How to run

### Backend (pytest)

```bash
cd backend && source .venv/bin/activate && python -m pytest tests/ -v
```

Run a single file:
```bash
cd backend && source .venv/bin/activate && python -m pytest tests/test_workflow_run_agent.py -v
```

Run a single test:
```bash
cd backend && source .venv/bin/activate && python -m pytest tests/test_workflow_run_agent.py::TestRunAgentAction::test_runs_agent_and_returns_items -v
```

### Frontend (Playwright smoke tests)

```bash
cd frontend && npx playwright test tests/smoke.spec.js
```

## Backend test conventions

- Use SQLite in-memory DB (`sqlite:///:memory:`) — never a real DB
- Create the schema with `Base.metadata.create_all(bind=engine)`
- Mock external calls (LLM providers, HTTP, email) with `unittest.mock.patch`
- Use `@pytest.fixture(autouse=True)` to set required env vars (e.g. `INTEGRATION_SECRET_KEY`)
- Import app modules **inside** fixtures/tests, not at module level, to avoid import-time side effects
- One test class per unit under test; method names describe the scenario

## What to test for new workflow action nodes

When adding a new `node_subtype` to `workflow_engine._execute_action`, write tests covering:

1. **Happy path** — action runs and returns `{"status": "success", ...}`
2. **Items flow** — verify `result["items"]` is correct (passed through or transformed)
3. **Config rendering** — any template substitution or config field reads work correctly
4. **Missing/invalid config** — action skips gracefully without raising
5. **NODE_CATALOG presence** — new subtype appears in `NODE_CATALOG["actions"]`
6. **NODE_CATALOG schema** — all config_schema fields have the right types

See `tests/test_workflow_run_agent.py` as the reference implementation for the `run_agent` action.

## Current test files

| File | What it covers |
|------|----------------|
| `tests/test_workflow_run_agent.py` | `run_agent` workflow action — agent invocation, context building, item passthrough, graceful skip on missing agent |
| `tests/test_upsert_handler.py` | Finding/asset upsert deduplication and `user_edited_fields` protection |
| `tests/test_field_mapper.py` | Integration field mapping transforms |
| `tests/test_transports.py` | HTTP transport layer for integrations |
| `tests/test_credential_vault.py` | Credential encryption/decryption |

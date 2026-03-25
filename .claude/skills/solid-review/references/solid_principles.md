# SOLID Principles — Hakuna Codebase Reference

This document defines each SOLID principle with **real Hakuna examples** of adherence and violation, plus actionable refactoring guidance. Use it as the authoritative reference when reviewing code in this project.

---

## 1. Single Responsibility Principle (SRP)

> A module should have one, and only one, reason to change.

### What it means in Hakuna

Every service, route handler, and component should own exactly one concern. Route files handle HTTP. Services handle business logic. Parsers handle file format translation. When a module has multiple reasons to change, it's violating SRP.

### Adherence — Well-focused services

**`services/prioritizer.py`** (~450 lines)
Does one thing: compute priority scores. Contains `compute_priority_score()`, `compute_asset_risk_score()`, and supporting data tables (`PLUGIN_FAMILY_WEIGHTS`, `EXPLOIT_MATURITY_MULTIPLIERS`). All subordinate to the single concern of scoring.

**`services/dedup.py`** (~760 lines)
Solely responsible for deduplication: loading config, running cross-scan dedup, merge strategies. One reason to change: dedup logic evolves.

**`services/rule_engine.py`** (~1044 lines)
One responsibility: evaluate rule conditions against assets/findings. The `CONDITION_CATALOG`, operators, and `evaluate_rule()` all serve that concern. Reused by auto-tag, criticality rules, and campaigns — demonstrating reuse over duplication.

**`services/post_ingest.py`** (~294 lines)
Orchestrates the post-ingest pipeline via `finalize_scan()`. Delegates every step to dedicated services and handles only error isolation via `_step()`. Does NOT implement business logic itself — pure coordination.

### Violations to watch for

**`app.py`** (9,700+ lines, 161+ routes)
The primary SRP violation in the codebase. Contains inline business logic like `_ensure_sla_defaults()`, `_recalculate_sla_for_scan()`, `_apply_exception_to_findings()`, `_populate_temporal_fields()`, and `_parse_scan_date()`. These helper functions belong in dedicated service modules.

**Symptom**: `services/post_ingest.py` imports `from app import _apply_exception_to_findings` — a service depending on the application entrypoint is a clear sign that business logic leaked into `app.py`.

**`services/integrations.py`** (~742 lines)
Contains five structurally separate connectors (Jira, ServiceNow, Email, Slack, Teams) plus four AI provider testers. Each connector is a separate concern sharing one file.

### SRP review checklist

- [ ] Does this module have more than one reason to change?
- [ ] Does a route handler contain business logic beyond request/response translation?
- [ ] Does a service import from `app.py`?
- [ ] Could this file be split into independently-deployable modules?
- [ ] Is the module name accurately describing everything it does? If the name requires "and", it's doing too much.

### Refactoring patterns

| Smell | Fix |
|-------|-----|
| Business logic in route handler | Extract to `services/{domain}.py` |
| Helper functions in `app.py` | Move to `services/{concern}.py` |
| Multiple connectors in one file | One file per connector in `integrations/` |
| God class / god module | Facade pattern — thin orchestrator delegating to focused services |

---

## 2. Open/Closed Principle (OCP)

> Software entities should be open for extension, but closed for modification.

### What it means in Hakuna

Adding a new parser, integration, agent tool, or workflow node should NOT require modifying existing dispatch logic. Use registries, decorators, and polymorphism instead of `if/elif` chains.

### Adherence — Registry and decorator patterns

**Parser registry** (`parsers/base_parser.py` + `parsers/registry.py`)
`BaseParser(ABC)` defines `can_parse()` and `parse()` as abstract methods. `register_parser()` / `detect_parser()` / `init_parsers()` form a registry. Adding a new scanner: create `NewParser(BaseParser)`, call `register_parser(NewParser())`. Zero modification to existing code.

**Model registry** (`integrations/model_registry.py`)
The `@importable(...)` decorator lets any SQLAlchemy model opt into the integration builder without touching the registry. Models extend via decoration — the registry is closed to modification.

**Agent tools** (`agents/agent_tools.py`)
`@agent_tool(name, description, parameters)` decorator registers tools into `TOOL_REGISTRY`. New tools are added by decorating a function — no dispatch logic modified.

### Violations to watch for

**`services/integrations.py` `test_integration()`** (lines ~48–67)
```python
if provider == "jira":
    return _test_jira(cfg)
elif provider == "servicenow":
    return _test_servicenow(cfg)
elif provider == "email":
    return _test_email(cfg)
# ... 8 branches total
```
Every new integration requires editing this function.

**Fix**: Replace with a dispatch dict:
```python
_TESTERS = {"jira": _test_jira, "servicenow": _test_servicenow, ...}
def test_integration(provider, cfg):
    tester = _TESTERS.get(provider)
    if not tester:
        raise ValueError(f"Unknown provider: {provider}")
    return tester(cfg)
```

**`services/workflow_engine.py` `_execute_action()`** (lines ~1506–1680)
12+ `elif subtype ==` branches for node types (`assign_owner`, `add_tag`, `send_email`, `create_ticket`, etc.). Adding a workflow node requires modifying this function.

**Fix**: Command pattern or dispatch dict:
```python
_ACTION_HANDLERS = {
    "assign_owner": _handle_assign_owner,
    "add_tag": _handle_add_tag,
    ...
}
```

### OCP review checklist

- [ ] Does adding a new variant require modifying existing code?
- [ ] Are there `if/elif` chains dispatching on a type/provider/subtype string?
- [ ] Could a registry, dispatch dict, or decorator replace the branching?
- [ ] Does the module follow the existing registry patterns (parser registry, agent tool registry, model registry)?

---

## 3. Liskov Substitution Principle (LSP)

> Subtypes must be substitutable for their base types without altering program correctness.

### What it means in Hakuna

If code accepts a `BaseParser` or `BaseTransport`, any concrete implementation must fulfill that contract completely. No surprises, no `NotImplementedError` at runtime, no altered semantics.

### Adherence — Transport hierarchy

**`services/transports/base.py`** defines `BaseTransport` with `connect()`, `fetch_all()`, and `push()`.

Four concrete implementations all honor the interface:
- `ApiTransport(BaseTransport)` — HTTP-based
- `SqlTransport(BaseTransport)` — database queries
- `FileTransport(BaseTransport)` — filesystem
- `McpTransport(BaseTransport)` — MCP protocol

The run engine in `services/run_engine.py` selects the transport and calls `connect()`/`fetch_all()` without knowing which concrete type it has — substitution works cleanly.

### Adherence — Parser hierarchy

**`parsers/base_parser.py`** uses proper `ABC` + `@abstractmethod` on `can_parse()` and `parse()`. Subclasses cannot be instantiated without implementing the contract — the language enforces LSP.

### Violations to watch for

**`BaseTransport` uses `raise NotImplementedError` instead of `ABC`**
```python
class BaseTransport:
    async def connect(self, config, credentials) -> ConnectResult:
        raise NotImplementedError
```
A subclass that forgets to implement `push()` passes instantiation and only fails at runtime. Weaker than the parser hierarchy's ABC approach.

**Fix**: Use `ABC` + `@abstractmethod`:
```python
from abc import ABC, abstractmethod

class BaseTransport(ABC):
    @abstractmethod
    async def connect(self, config, credentials) -> ConnectResult: ...
```

### LSP review checklist

- [ ] Does the subclass implement ALL methods from the base class?
- [ ] Does any method raise `NotImplementedError` — indicating an incomplete contract?
- [ ] Can the subclass be used anywhere the base class is expected without behavioral surprises?
- [ ] Are base classes using `ABC` + `@abstractmethod` rather than `raise NotImplementedError`?
- [ ] Do overridden methods maintain the same pre/post conditions? (Same parameter types, same return type semantics, no additional exceptions)

---

## 4. Interface Segregation Principle (ISP)

> No client should be forced to depend on methods it does not use.

### What it means in Hakuna

Protocols/base classes should be narrow and role-specific. Consumers should import only what they need — not a kitchen-sink module.

### Adherence — Agent tool selection

**`agents/agent_tools.py`**
Each `@agent_tool` is a single-purpose function. Agents declare exactly which tool names they need (stored as a list in `Agent.tools` JSON column). No agent depends on the full 50+ tool catalog — they subscribe to only what they use.

**`integrations/schema.py`**
`NORMALIZED_SCHEMA` is split into `"asset"`, `"finding"`, and `"action"` sections. `get_schema(entity=None)` lets callers request only the slice they need.

### Violations to watch for

**`BaseTransport` forces `push()` on read-only transports**
`FileTransport` and `SqlTransport` are primarily pull/read transports. They inherit a `push()` method that either raises `NotImplementedError` or has a stub. Read-only and write-capable transports should be separated.

**Fix**: Split into role-specific protocols:
```python
from typing import Protocol

class ReadTransport(Protocol):
    async def connect(self, config, credentials) -> ConnectResult: ...
    async def fetch_all(self, config, credentials, params) -> AsyncIterator: ...

class WriteTransport(Protocol):
    async def push(self, config, credentials, payload) -> PushResult: ...

class FullTransport(ReadTransport, WriteTransport):
    """For transports that support both read and write."""
    ...
```

**`agents/agent_context.py`** (~298 lines)
Mixes three separate concerns: scratchpad I/O, structured handoff schemas, and LLM output compression. Any consumer that only needs `AgentHandoff` must import from a module that also contains filesystem-touching scratchpad code.

**Fix**: Split into `agent_scratchpad.py`, `agent_handoff.py`, `agent_compression.py`.

### ISP review checklist

- [ ] Does the base class/protocol include methods that some implementations don't need?
- [ ] Does importing a module force you to depend on unrelated functionality?
- [ ] Could the interface be split into smaller, role-specific protocols?
- [ ] Are consumers using only a subset of the imported module's exports?

---

## 5. Dependency Inversion Principle (DIP)

> High-level modules should not depend on low-level modules. Both should depend on abstractions.

### What it means in Hakuna

Services should not import from `app.py`. Route handlers should receive dependencies via `Depends()`, not instantiate them. Configuration should be injected, not hardcoded via `os.getenv()` inside business logic.

### Adherence — FastAPI `Depends()`

All routes inject dependencies via FastAPI's DI system:
```python
async def list_findings(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    org_ids: list = Depends(get_accessible_org_ids),
):
```
Route handlers don't create sessions or validate tokens — they declare what they need.

**`routes/vm_routes.py`** (~97 lines)
Exemplary thin route: takes `db` and `user` via `Depends()`, delegates entirely to `services/vm_scanner.py`. Zero business logic in the route.

**`agents/agent_engine.py` `_get_api_key()`**
Loads API keys from DB integration config or environment variables, in priority order. The agent engine doesn't hardcode credentials — it depends on abstractions.

### Violations to watch for

**`services/post_ingest.py` imports from `app.py`**
```python
from app import _apply_exception_to_findings
from app import _ensure_sla_defaults, _recalculate_sla_for_scan
from app import ENTITY_MODEL_MAP
```
A service module depending on the application entrypoint is an inverted dependency. `app.py` is high-level; `services/` is low-level.

**Fix**: Extract into dedicated service modules:
- `_ensure_sla_defaults`, `_recalculate_sla_for_scan` → `services/sla_engine.py`
- `_apply_exception_to_findings` → `services/exception_engine.py`
- `ENTITY_MODEL_MAP` → `models/registry.py`

**`services/workflow_engine.py` concrete imports**
```python
import services.integrations as integrations
import agents.agent_engine as agent_engine
```
Direct import of concrete implementations. When `_execute_action()` calls `integrations.create_jira_ticket()`, it's coupled to a concrete module, not an abstraction.

**Fix**: Inject via a registry or pass callables:
```python
class WorkflowEngine:
    def __init__(self, action_handlers: dict[str, Callable]):
        self._handlers = action_handlers
```

**`services/vm_scanner.py` hardcoded env lookup**
```python
VM_SCANNER_URL = os.getenv("VM_SCANNER_URL", "http://localhost:8002")
```
Business logic should receive config, not reach into the environment directly.

**Fix**: Accept URL as a parameter or inject via a config object.

### DIP review checklist

- [ ] Does any service import from `app.py`?
- [ ] Does the module call `os.getenv()` directly for business config?
- [ ] Are concrete implementations imported at module level where an abstraction would suffice?
- [ ] Are dependencies injected via `Depends()`, constructor, or parameter — not instantiated inline?
- [ ] Does the dependency graph flow downward? (routes → services → models, never services → app)

---

## Quick-Reference Decision Matrix

| You're adding... | Apply these principles | Follow this existing pattern |
|-------------------|----------------------|------------------------------|
| New scanner parser | OCP, LSP | `parsers/base_parser.py` + `registry.py` |
| New integration connector | OCP, SRP, ISP | `integrations/model_registry.py` `@importable` |
| New agent tool | OCP | `agents/agent_tools.py` `@agent_tool` |
| New workflow node type | OCP | Should use dispatch dict (current `elif` chain is a known violation) |
| New route handler | SRP, DIP | `routes/vm_routes.py` — thin route, inject via `Depends()` |
| New service module | SRP, DIP | `services/prioritizer.py` — single concern, no `app.py` imports |
| New transport | LSP, ISP | `transports/base.py` — but prefer `ABC` over `NotImplementedError` |
| Refactoring existing code | All five | Extract from `app.py`, split fat modules, replace `elif` chains |

---

## Severity Classification for Reviews

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Architectural violation causing circular deps or untestable code | Service importing from `app.py` |
| **High** | Long `if/elif` dispatch chains blocking extensibility | `test_integration()` provider branching |
| **Medium** | Fat interface forcing unused implementations | `BaseTransport.push()` on read-only transports |
| **Low** | Minor SRP concern — module doing slightly too much | Mixed utility functions in one file |
| **Info** | Suggestion for future improvement, not blocking | `NotImplementedError` instead of `ABC` |

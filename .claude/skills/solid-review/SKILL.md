---
name: solid-review
description: Review code for SOLID principle violations (SRP, OCP, LSP, ISP, DIP) with actionable refactoring guidance grounded in Hakuna's actual codebase patterns. Use when reviewing pull requests, refactoring services, adding new modules, or auditing architecture.
---

# SOLID Review

Principal-engineer-level SOLID principles review for the Hakuna codebase.

## When to use

- Reviewing PRs or code changes for architectural quality
- Before refactoring a service, route, or integration module
- When adding new parsers, transports, integrations, or workflow nodes
- Auditing a module that feels too large or tangled
- Teaching team members about SOLID through real codebase examples

## What it does

1. Reads the target files (from arguments, git diff, or specified paths)
2. Evaluates against all 5 SOLID principles using Hakuna-specific patterns
3. Classifies findings by severity (Critical → Info)
4. Provides concrete fixes using patterns already in the codebase
5. Outputs a summary table and overall SOLID health score

## Reference

The authoritative reference for all principles, with real Hakuna examples of adherence and violation, is in:

- `references/solid_principles.md` — Full guide with checklists, refactoring patterns, and decision matrix

## Existing patterns to recommend

| Pattern | Location | Principle |
|---------|----------|-----------|
| Parser registry + ABC | `parsers/base_parser.py`, `parsers/registry.py` | OCP, LSP |
| `@importable` decorator | `integrations/model_registry.py` | OCP |
| `@agent_tool` decorator | `agents/agent_tools.py` | OCP |
| FastAPI `Depends()` | All route files | DIP |
| Thin route → service delegation | `routes/vm_routes.py` | SRP, DIP |
| Pipeline orchestrator (no own logic) | `services/post_ingest.py` | SRP |
| Single-concern service | `services/prioritizer.py` | SRP |
| Transport hierarchy | `services/transports/` | LSP |
| Per-agent tool selection | `agents/agent_tools.py` | ISP |

## Usage

```
/solid-review                        # Review all uncommitted changes
/solid-review backend/services/      # Review a directory
/solid-review services/integrations.py  # Review a specific file
/solid-review SRP                    # Focus on Single Responsibility only
/solid-review OCP backend/services/workflow_engine.py  # Specific principle + file
```

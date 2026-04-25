# hakuna-audit-scanner

Credentialed protocol-audit ReAct agent. Open-source extraction of
Hakuna's audit pipeline. Runs LLM-driven SSH / WMI / LDAP / SMB / SNMP
audits against a single asset, dispatches read-only protocol queries
through `hakuna-relay-agent`, and returns structured findings.

## Status

Phase 1 skeleton — wired end-to-end for SSH only. The VM scanner
(`hakuna-vm-scanner`) is the architectural template; this package
mirrors its structure (asyncpg, standalone Celery, env-only config,
graceful no-LLM degradation).

What's in:

- `audit_engine.py` — ReAct loop, `@agent_tool` registry, multi-provider tool-use, **per-iteration event publishing**, **per-turn quota check + record**
- `audit_worker.py` — Celery task, asset/credential context fetch, wires publisher + quota + transport onto the run context
- `llm_provider.py` — multi-provider resolver (Anthropic → OpenAI → Vertex → Gemini → Groq → Ollama). All four adapters return `{content, stop_reason, usage: {input_tokens, output_tokens}}`.
- `publisher.py` — `RunPublisher` Protocol + `NullPublisher` + `RedisPublisher`. Engine publishes to `audit:run:{run_id}`; backend's SSE endpoint subscribes.
- `quota.py` — `QuotaProvider` Protocol + `NullQuotaProvider` + `InMemoryQuotaProvider`. Backend installs `SqlAlchemyQuotaProvider` via `set_provider(...)` at startup.
- `relay_client.py` — `RelayTransport` Protocol + `HttpRelayTransport` (default) + `NullRelayTransport`. Backend installs a WebSocket-broker adapter via `set_transport(...)` for multi-tenant relays.
- `tools/ssh_tools.py` — Linux audit palette (12 protocol tools), ported from `backend/agents/tools/ssh_tools.py`
- `tools/emit_finding.py` — shared finding-capture tool (no ORM dep)
- `tools/asset_profile.py` — `get_asset_profile` (asyncpg port; gracefully degrades when inventory tables are missing)
- `tools/cve_correlator.py` — `correlate_software_to_cves` (pluggable; `NullCveCorrelator` default; backend wires `SqlAlchemyCveCorrelator`)
- `tools/scratchpad.py` — `read_scratchpad` / `write_scratchpad` / `clear_scratchpad`
- `tools/clarification.py` — `request_clarification` (publishes a structured event; backend's approval flow listens)
- `mission_loader.py` + `templates/missions/*.yaml` — operator-editable mission prompts (replaces the backend's 3.7 k-line `agent_prompts.py`)
- `api.py` — FastAPI service (`POST /audit/scans/`, `GET /audit/scans/{id}`, mission validator)

Phase 2 ports:

- `tools/{wmi,ldap,smb,snmp,cloud}_tools.py` — same mechanical edit as `ssh_tools.py`
- True pause-and-resume on `request_clarification` (today the OSS run continues; backend approval flow needs `resume_audit_run` Celery task)

## Architecture (mirrors `hakuna-vm-scanner`)

```
                ┌─────────────────┐
                │ FastAPI         │   POST /audit/scans/
                │ (audit-api)     │   GET  /audit/scans/{id}
                └────────┬────────┘
                         │  Celery enqueue
                ┌────────▼────────┐
                │ Celery worker   │   audit_queue
                │ (audit-worker)  │
                └────┬──────┬─────┘
                     │      │
              asyncpg│      │httpx
                     │      │
            ┌────────▼─┐ ┌──▼────────────────┐
            │ Postgres │ │ hakuna-relay-agent │ ← ssh_query / wmi_query
            │ (shared) │ │  (HTTP /exec)      │   ldap_query / smb_query
            └──────────┘ └────────────────────┘
```

Findings flow back in the Celery result payload — same shape as the
VM scanner's nuclei findings — so backend ingest reuses the existing
import path.

## Quick start

```bash
cp .env.example .env
# Set ANTHROPIC_API_KEY (or OPENAI_API_KEY, or enable Ollama for local)
# Set HAKUNA_RELAY_URL pointing at a hakuna-relay-agent node
# Set DATABASE_URL pointing at the shared Postgres

docker compose up --build

# Trigger a run (async)
curl -X POST http://localhost:8001/audit/scans/ \
  -H 'content-type: application/json' \
  -d '{
        "asset_id": "00000000-0000-0000-0000-000000000001",
        "protocol": "ssh",
        "mission_key": "hardening_posture",
        "credentials": {"username": "auditor", "private_key": "..."}
      }'
# → {"job_id": "..."}

# Poll
curl http://localhost:8001/audit/scans/<job_id>
```

## Decoupling decisions (vs the backend monolith)

| Concern | Backend (`backend/agents/`) | This package |
|---|---|---|
| ORM | SQLAlchemy `models.models` | Raw asyncpg + plain dicts |
| LLM router | `core.llm_router` | `llm_provider.build_adapter` (copy of VM scanner) |
| Token quota | `core.token_quota` (raises 429 on Organization row) | `QuotaProvider` Protocol — `NullQuotaProvider` default, backend ships `SqlAlchemyQuotaProvider` |
| Run state | `AgentRun` rows + step writes mid-loop | In-memory + live Redis pub-sub events; Celery result has the full transcript |
| Credentials | `services.credential_manager` | Plaintext dict on `AuditContext`; resolved upstream |
| Relay | `services.relay_broker` (WebSocket fan-out) | `RelayTransport` Protocol — `HttpRelayTransport` default, backend installs a broker-adapter for multi-tenant |
| Streaming | `run_agent_streaming` SSE generator | `RunPublisher` Protocol — `NullPublisher` default, `RedisPublisher` writes `audit:run:{run_id}`; backend SSE endpoint subscribes |
| CVE correlation | `services.cve_correlator.correlate_asset` | `CveCorrelator` Protocol — `NullCveCorrelator` default, backend wires `SqlAlchemyCveCorrelator` |
| Mission prompts | `agents.agent_prompts.ENHANCED_PROMPTS` (3.7 k LOC dict) | YAML files under `templates/missions/` |
| UI Copilot tools | ~260 tools in `agents.agent_tools` (`query_findings`, `tag_assets`, `build_report`, ...) | Out of scope — stay in the backend, only power the chat copilot |

## How the backend integrates

Two integration paths — pick one per deployment.

### (a) In-process — recommended for the multi-tenant deployment

The backend imports `run_audit` directly. No Celery hop, no extra
broker, no HTTP — and the WebSocket relay broker stays where it is.
Backend wires its providers once at startup:

```python
# backend/services/audit_runner.py
from scanner.audit.audit_engine import run_audit
from scanner.audit.agent_context import AuditContext
from scanner.audit.publisher import RedisPublisher
from scanner.audit.quota import set_provider as set_quota_provider
from scanner.audit.relay_client import set_transport
from scanner.audit.tools.cve_correlator import set_correlator

# At backend boot:
set_quota_provider(SqlAlchemyQuotaProvider())          # uses core.token_quota
set_transport(RelayBrokerWsAdapter(get_relay_broker()))  # WebSocket fan-out
set_correlator(SqlAlchemyCveCorrelator())              # services.cve_correlator

# Per dispatch:
ctx = AuditContext(
    run_id=str(run.id), agent_id=run.agent_id, org_id=run.org_id,
    asset=asset_dict, target=target, target_port=port,
    relay_agent_id=run.relay_agent_id, credential_id=str(credential.id),
    credentials=credential_vault.decrypt(credential),
    protocol=run.protocol, mission_key=mission.key,
    publisher=RedisPublisher(REDIS_URL),
    db_pool=await get_audit_pool(),
)
result = await run_audit(ctx=ctx, adapter=adapter, ...)
write_agent_run_steps(db, run, result["steps"])
import_audit_findings(db, run, result["findings"])
```

### (b) Celery hop — recommended for OSS / standalone deployments

Backend dispatches to the audit-scanner's Celery worker; worker
returns findings in the result payload. Streaming flows through
the same Redis pub-sub channel.

```python
job = audit_celery.send_task(
    "scanner.audit.audit_worker.run_audit_scan",
    kwargs={
        "asset_id": str(asset.id),
        "protocol": run.protocol, "mission_key": mission.key,
        "credentials": credential_vault.decrypt(credential),
        "relay_agent_id": run.relay_agent_id,
        "credential_id": str(credential.id),
        "org_id": str(asset.org_id),
    },
    queue="audit_queue",
)
```

In path (a) the Celery worker is unused — the backend invokes the
engine directly. In path (b) the worker reads provider singletons
from its own process at boot; backend calls `set_*` in the worker's
startup module.

### Live step streaming (both paths)

Backend exposes:

```python
@router.get("/api/audits/runs/{run_id}/stream")
async def stream(run_id: str):
    async def gen():
        sub = redis.pubsub()
        sub.subscribe(f"audit:run:{run_id}")
        for msg in sub.listen():
            if msg["type"] == "message":
                yield f"data: {msg['data']}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")
```

The frontend agent-run viewer subscribes and renders `thinking`,
`tool_call`, `tool_result`, `text`, `finding`, and `run_end` events
exactly as it already does for the in-process streaming path.

## Phase-2 follow-ups

- **WMI / LDAP / SMB / SNMP / Cloud tool ports** — same mechanical
  edit as `ssh_tools.py`. Backend versions in `backend/agents/tools/`.
- **Pause-and-resume on `request_clarification`** — today the OSS run
  continues after publishing the `clarification` event. Backend
  approval flow needs a `resume_audit_run` Celery task that injects
  the user's reply as a tool_result block.
- **More YAML missions.** Phase 1 ships `ssh_hardening_posture.yaml`;
  migrate the rest from `agent_prompts.ENHANCED_PROMPTS`.
- **`agent_pipeline.py` and `copilot_*` stay in the backend** —
  Hakuna-specific orchestration + chat-copilot UX, not part of the
  audit scanner.

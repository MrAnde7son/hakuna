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

- `audit_engine.py` — ReAct loop, `@agent_tool` registry, multi-provider tool-use
- `audit_worker.py` — Celery task, asset/credential context fetch
- `llm_provider.py` — verbatim copy of the VM scanner's resolver (Anthropic → OpenAI → Vertex → Gemini → Groq → Ollama)
- `relay_client.py` — HTTP client to `hakuna-relay-agent`
- `tools/ssh_tools.py` — Linux audit palette (12 tools), ported from `backend/agents/tools/ssh_tools.py`
- `tools/emit_finding.py` — shared finding-capture tool
- `mission_loader.py` + `templates/missions/*.yaml` — operator-editable mission prompts (replaces the backend's 3.7 k-line `agent_prompts.py`)
- `api.py` — FastAPI service (`POST /audit/scans/`, `GET /audit/scans/{id}`, mission validator)

Phase 2 ports:

- `tools/{wmi,ldap,smb,snmp,cloud}_tools.py` — same mechanical edit as `ssh_tools.py`
- Streaming SSE for live step output
- WebSocket relay broker mode for Hakuna's multi-tenant deployment

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
| Token quota | `core.token_quota` | None — backend wraps with quota at the dispatch layer |
| Run state | `AgentRun` rows + step writes mid-loop | In-memory; returned in Celery result; backend writes after task completes |
| Credentials | `services.credential_manager` | Plaintext dict in `AuditContext`; resolved upstream |
| Relay | `services.relay_broker` (WebSocket fan-out) | HTTPS to a single relay node |
| Mission prompts | `agents.agent_prompts.ENHANCED_PROMPTS` (3.7 k LOC dict) | YAML files under `templates/missions/` |
| Copilot tools | 267 tools in `agents.agent_tools` | Out of scope — stay in the backend |

## How the backend integrates

`backend/services/audit_runner.py` becomes a thin Celery dispatcher:

```python
from celery import Celery
audit_celery = Celery(broker=os.environ["AUDIT_BROKER_URL"])

def kick_off_audit(db, run: AgentRun, asset, mission, credential):
    plaintext = credential_vault.decrypt(credential)
    job = audit_celery.send_task(
        "scanner.audit.audit_worker.run_audit_scan",
        kwargs={
            "asset_id": str(asset.id),
            "protocol": run.protocol,
            "mission_key": mission.key,
            "credentials": plaintext,
            "relay_agent_id": run.relay_agent_id,
            "credential_id": str(credential.id),
            "org_id": str(asset.org_id),
        },
        queue="audit_queue",
    )
    run.celery_task_id = job.id
    db.commit()
```

When the task completes, the existing ingest loop reads `findings`
out of the result payload and writes `Finding` rows — same path that
already handles `nuclei_worker` output.

## Limitations to discuss before merging

- **No mid-run streaming.** Backend's live "agent run viewer" reads
  from `AgentRun.steps`; with this design, steps land in one batch
  when the Celery task completes. Phase 2: add a Redis pub-sub channel
  the engine writes to per iteration, the backend subscribes.
- **One-relay HTTP transport only.** Hakuna's multi-tenant deployment
  needs the WebSocket broker; that path stays in the backend.
- **YAML missions are minimal.** Phase 1 ships one example
  (`ssh_hardening_posture.yaml`); the rest of the existing prompts
  need migrating from `agent_prompts.py`.
- **`agent_pipeline.py` and `copilot_*` are not ported** — they're
  Hakuna-specific orchestration / copilot UX that doesn't belong in
  OSS.

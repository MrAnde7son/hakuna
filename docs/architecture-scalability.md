# Architecture: Before & After (Scalability to 300 Customers)

---

## BEFORE — Current State

```mermaid
flowchart TD
    Browser(["🌐 Browser — React + Vite SPA"])

    subgraph Render["☁️ Render Free Tier — Single Dyno"]
        subgraph Proc["Single Process · Shared Thread Pool"]
            API["FastAPI / Uvicorn"]
            AS["⚠ APScheduler — in-process · lost on restart"]
        end
        DB[("⚠ SQLite — 1 writer · ephemeral")]
        CF["⚠ CVE Cache — JSON file · not shared"]
        API --- AS
        API <-->|"⚠ sync — blocks event loop"| DB
        API -.- CF
    end

    SC["🔍 Scanners — Nessus · Qualys · Rapid7 · Tenable · CrowdStrike · Wiz"]
    TI["🛡 Threat Intel — NVD · CISA KEV · MITRE · ExploitDB · GreyNoise"]
    NT["📣 Notifications — Jira · ServiceNow · Slack · Teams · SMTP"]
    LM["🤖 LLM APIs — Claude · OpenAI · Gemini · Groq"]

    Browser -->|"HTTP"| API
    AS -->|"⚠ competes with API threads"| SC
    API -->|"⚠ blocks HTTP response"| TI
    API -->|"⚠ blocks HTTP response"| NT
    API -->|"⚠ blocks HTTP response"| LM

    classDef problem fill:#3d1111,stroke:#cc2222,color:#ff9999
    class DB,CF,AS problem
```

### Key Problems

| Component | Problem |
|---|---|
| SQLite | 1 writer — lock contention with concurrent scan imports |
| APScheduler | In-process — 300 tenants × N integrations = thread pool exhaustion |
| Render Free | 15-min spin-down, ephemeral disk, data loss on restart |
| DB calls | Synchronous in async handlers — blocks event loop |
| No Redis | No cache, no rate limiting, no shared state |
| No queue | LLM calls and notifications block HTTP responses |
| No observability | Zero metrics, no error tracking |

---

## AFTER — Core Services

```mermaid
flowchart LR
    subgraph CL["Clients"]
        B["🌐 Browser"]
    end

    subgraph IN["Ingress"]
        CDN["CDN — Static assets"]
        LB["Load Balancer — HTTPS"]
    end

    subgraph AP["🚀 API Layer — stateless · auto-scalable"]
        A1["FastAPI Instance 1"]
        AN["FastAPI Instance N"]
    end

    subgraph RD["⚡ Redis HA — Sentinel"]
        RP["Primary — broker · cache · rate limits · locks"]
        RR["Replica — auto-failover"]
        RP -.->|replicate| RR
    end

    subgraph WK["⚙ Worker Layer — auto-scalable"]
        BT["Celery Beat — redbeat · singleton · distributed lock"]
        WS["sync worker — scanner polling · Redis lock per integration"]
        WI["import worker — scan parse · batch insert · idempotent"]
        WL["llm worker — AI enrichment · provider rate limits"]
        WN["notify worker — Jira · Slack · Email · tenacity backoff"]
    end

    subgraph DL["🗄 Data Layer"]
        PB["PgBouncer — connection pooler"]
        PG[("PostgreSQL Primary — Alembic · partitioned · WAL")]
        PR[("PostgreSQL Replica — dashboards · reports")]
        S3["☁ S3 / R2 — presigned URLs · browser uploads direct"]
        PB --> PG
        PG -.->|streaming replication| PR
    end

    B -->|static assets| CDN
    B -->|API calls| LB
    LB --> A1 & AN

    A1 & AN -->|"① issue presigned URL"| S3
    B -->|"② upload direct"| S3
    A1 & AN -->|"③ enqueue import job"| RD

    A1 & AN <-->|read · write| PB
    A1 & AN -->|heavy reads| PR
    A1 & AN <-->|cache · rate limit| RD

    BT -->|cron triggers + jitter| RD
    RD -->|sync queue| WS
    RD -->|import queue| WI
    RD -->|llm queue| WL
    RD -->|notify queue| WN

    WS & WI & WL & WN <-->|read · write| PB
    WI -->|read scan file| S3

    classDef new fill:#0d2137,stroke:#2277cc,color:#66aaff
    classDef data fill:#1e1133,stroke:#6622aa,color:#aa77ff
    classDef worker fill:#0d2211,stroke:#228844,color:#66cc88

    class CDN,S3 new
    class PB,PG,PR data
    class WS,WI,WL,WN,BT worker
```

## AFTER — Integrations & Observability

```mermaid
flowchart LR
    subgraph WK["⚙ Workers"]
        WS["sync worker"]
        WI["import worker"]
        WL["llm worker"]
        WN["notify worker"]
    end

    subgraph AP["🚀 API"]
        A1["FastAPI instances"]
    end

    subgraph SC["🔍 Scanners"]
        s1["Nessus · Qualys · Rapid7"]
        s2["Tenable SC · Tenable IO · CrowdStrike · Wiz"]
    end

    subgraph TI["🛡 Threat Intel"]
        t1["NVD API v2 · CISA KEV · MITRE ATT&CK"]
        t2["ExploitDB · GreyNoise · MSRC · CWE"]
    end

    subgraph LM["🤖 LLM Providers"]
        l1["Claude · OpenAI GPT · Gemini · Groq"]
    end

    subgraph NT["📣 Notifications"]
        n1["Jira · ServiceNow · Slack · Teams · SMTP"]
    end

    subgraph OB["📊 Observability"]
        SE["Sentry — errors · per-tenant context"]
        PM["Prometheus + Grafana — latency · queue depth · DB pool"]
        OT["OpenTelemetry + Jaeger — traces: API to queue to worker to DB"]
        LG["structlog — org_id · user_id · request_id on every line"]
    end

    WS -->|poll · circuit breaker| SC
    WL -->|enrich CVEs · circuit breaker| TI
    WL -->|AI calls · circuit breaker| LM
    WN -->|send · circuit breaker| NT

    AP -->|errors · metrics · traces| OB
    WK -->|errors · metrics · traces| OB

    classDef worker fill:#0d2211,stroke:#228844,color:#66cc88
    classDef obs fill:#1a1a2e,stroke:#5555aa,color:#9999ff

    class WS,WI,WL,WN worker
    class SE,PM,OT,LG obs
```

### What Changed

| Layer | Before | After |
|---|---|---|
| **API** | 1 process, sync DB calls | N stateless instances, async SQLAlchemy |
| **Scheduler** | APScheduler in-process | Celery Beat (redbeat) → Redis |
| **Jobs** | Blocking API threads | Isolated workers per queue type |
| **Database** | SQLite, 1 writer, ephemeral | PostgreSQL + Alembic + time partitioning |
| **Connections** | Unlimited, direct to DB | PgBouncer caps at safe limit |
| **Read queries** | Same DB for OLTP + dashboards | Read replica with explicit per-endpoint routing |
| **File uploads** | Routes through API memory | Presigned URLs — browser uploads direct to S3 |
| **Cache** | JSON file per-process | Redis HA, shared across all instances |
| **Task overlap** | Duplicate sync jobs possible | Redis lock per `integration_id` |
| **External calls** | No retry, no circuit breaker | `tenacity` backoff on all external APIs |
| **Notifications / LLM** | Blocks HTTP response | Async Celery workers |
| **Observability** | Audit log only | Sentry + Prometheus + OTel distributed traces |

---

## LOCAL DEVELOPMENT — Lightweight Mode

```mermaid
flowchart LR
    subgraph local["💻 Local Dev — docker compose up + uvicorn --reload"]
        B2["🌐 Browser — Vite dev server"]

        subgraph FP["FastAPI — single process"]
            API2["REST handlers"]
            EC["Celery ALWAYS_EAGER=true — tasks run inline · no workers needed"]
            API2 -.->|same code path| EC
        end

        subgraph DC["docker compose"]
            PG2[("PostgreSQL — direct connection · no PgBouncer · no replica")]
            RD2["Redis — single node · optional"]
            MN["MinIO — S3-compatible · presigned URLs identical to production"]
        end

        B2 -->|localhost:8000| API2
        B2 -->|"direct upload — localhost:9000"| MN
        API2 <--> PG2
        API2 <--> MN
        API2 -.->|optional| RD2
    end
```

**Skipped locally:** PgBouncer · read replica · Beat · Celery workers · Jaeger · Sentry

**Same application code** runs in both environments — `CELERY_TASK_ALWAYS_EAGER=true` is the only difference.

### docker-compose.dev.yml

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: hakuna
      POSTGRES_USER: hakuna
      POSTGRES_PASSWORD: hakuna
    ports: ["5432:5432"]
    volumes: ["pg_data:/var/lib/postgresql/data"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"

volumes:
  pg_data:
```

### .env.local

```bash
DATABASE_URL=postgresql+asyncpg://hakuna:hakuna@localhost:5432/hakuna
REDIS_URL=redis://localhost:6379/0
CELERY_TASK_ALWAYS_EAGER=true
CELERY_TASK_EAGER_PROPAGATES=true
S3_ENDPOINT_URL=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=hakuna-local
SENTRY_DSN=
OTEL_EXPORTER_OTLP_ENDPOINT=
ENV=development
```

### .env.production

```bash
DATABASE_URL=postgresql+asyncpg://hakuna:...@pgbouncer:5432/hakuna
DATABASE_REPLICA_URL=postgresql+asyncpg://hakuna:...@pg-replica:5432/hakuna
REDIS_URL=rediss://...upstash.io:6380
CELERY_TASK_ALWAYS_EAGER=false
S3_BUCKET=hakuna-prod
SENTRY_DSN=https://...@sentry.io/...
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
ENV=production
```

---

## Implementation Sequence

| Step | Change | Unlocks |
|---|---|---|
| **1** | `docker-compose.dev.yml` + env file split | Safe local dev baseline |
| **2** | PostgreSQL + Alembic | Concurrent writes, reliable storage |
| **3** | Async SQLAlchemy sessions | Event loop unblocked, real concurrency |
| **4** | Celery + Redis (`ALWAYS_EAGER` locally) | Background jobs, APScheduler removed |
| **5** | MinIO / S3 + presigned upload flow | Large scan files off API memory |
| **6** | PgBouncer in production | Connection stability at scale |
| **7** | `tenacity` circuit breakers | Resilient scanner + LLM integration |
| **8** | Per-tenant rate limiting via Redis | Noisy-neighbour protection |
| **9** | OpenTelemetry + Jaeger | Full traces: API → queue → worker → DB |
| **10** | Read replica + explicit per-endpoint routing | Dashboard query isolation |

# Architecture: Before & After (Scalability to 300 Customers)

---

## BEFORE — Current State

```mermaid
flowchart TD
    Browser(["🌐 Browser — React + Vite SPA"])

    subgraph Render["☁️ Render Free Tier — Single Dyno"]
        subgraph Proc["Single Process · Shared Thread Pool"]
            API["FastAPI / Uvicorn"]
            AS["⚠ APScheduler<br/>in-process · lost on restart"]
        end
        DB[("⚠ SQLite<br/>1 writer · ephemeral storage")]
        CF["⚠ CVE Cache<br/>JSON file · per-process · not shared"]
        API --- AS
        API <-->|"⚠ sync — blocks event loop"| DB
        API -.- CF
    end

    SC["🔍 Scanners<br/>Nessus · Qualys · Rapid7 · Tenable · CrowdStrike · Wiz"]
    TI["🛡 Threat Intel<br/>NVD · CISA KEV · MITRE · ExploitDB · GreyNoise"]
    NT["📣 Notifications<br/>Jira · ServiceNow · Slack · Teams · SMTP"]
    LM["🤖 LLM APIs<br/>Claude · OpenAI · Gemini · Groq"]

    Browser -->|"HTTP"| API
    AS -->|"⚠ competes with API threads"| SC
    API -->|"⚠ blocks HTTP response"| TI
    API -->|"⚠ blocks HTTP response"| NT
    API -->|"⚠ blocks HTTP response"| LM

    classDef problem fill:#3d1111,stroke:#cc2222,color:#ff9999
    classDef normal fill:#1e2433,stroke:#445577,color:#aabbcc
    class DB,CF,AS problem
    class API,Browser normal
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

## AFTER — Target Architecture

### Core Services

```mermaid
flowchart LR
    subgraph CL["Clients"]
        B["🌐 Browser<br/>React + Vite"]
    end

    subgraph IN["Ingress"]
        CDN["CDN<br/>Static assets<br/>Cloudflare"]
        LB["Load Balancer<br/>HTTPS · health checks"]
    end

    subgraph AP["🚀 API Layer — stateless · auto-scalable"]
        A1["FastAPI<br/>Instance 1"]
        AN["FastAPI<br/>Instance N"]
    end

    subgraph RD["⚡ Redis HA — Sentinel"]
        RP["Primary<br/>broker · cache<br/>rate limits · locks<br/>JWT denylist"]
        RR["Replica<br/>(auto-failover)"]
        RP -.->|replicate| RR
    end

    subgraph WK["⚙ Worker Layer — auto-scalable"]
        BT["Celery Beat<br/>redbeat · singleton<br/>distributed lock"]
        WS["sync worker<br/>scanner polling<br/>Redis lock / integration_id"]
        WI["import worker<br/>scan parse · batch insert<br/>checkpointed · idempotent"]
        WL["llm worker<br/>AI enrichment<br/>provider rate limits"]
        WN["notify worker<br/>Jira · Slack · Email<br/>tenacity backoff"]
    end

    subgraph DL["🗄 Data Layer"]
        PB["PgBouncer<br/>connection pooler<br/>transaction mode"]
        PG[("PostgreSQL Primary<br/>Alembic migrations<br/>time-partitioned findings<br/>WAL + PITR backups")]
        PR[("PostgreSQL Replica<br/>dashboards · reports<br/>explicit per-endpoint routing")]
        S3["☁ S3 / Cloudflare R2<br/>presigned URLs<br/>browser uploads direct<br/>zero API bandwidth"]
        PB --> PG
        PG -.->|streaming replication| PR
    end

    %% Ingress
    B -->|static assets| CDN
    B -->|API calls| LB
    LB --> A1 & AN

    %% Presigned upload — browser never goes through API
    A1 & AN -->|"① issue presigned URL"| S3
    B -->|"② upload direct"| S3
    A1 & AN -->|"③ enqueue import job"| RD

    %% API reads/writes
    A1 & AN <-->|read · write| PB
    A1 & AN -->|heavy reads| PR
    A1 & AN <-->|cache · rate limit| RD

    %% Worker dispatch
    BT -->|cron triggers + jitter| RD
    RD -->|sync queue| WS
    RD -->|import queue| WI
    RD -->|llm queue| WL
    RD -->|notify queue| WN

    %% Workers read/write
    WS & WI & WL & WN <-->|read · write| PB
    WI -->|read scan file| S3

    classDef new fill:#0d2137,stroke:#2277cc,color:#66aaff
    classDef data fill:#1e1133,stroke:#6622aa,color:#aa77ff
    classDef worker fill:#0d2211,stroke:#228844,color:#66cc88
    classDef ingress fill:#221a00,stroke:#997722,color:#ffcc66

    class CDN,S3 new
    class PB,PG,PR data
    class WS,WI,WL,WN,BT worker
    class CDN,LB ingress
```

### External Integrations & Observability

```mermaid
flowchart LR
    subgraph WK["⚙ Worker Layer"]
        WS["sync worker"]
        WI["import worker"]
        WL["llm worker"]
        WN["notify worker"]
    end

    subgraph AP["🚀 API Layer"]
        A1["FastAPI instances"]
    end

    subgraph SC["🔍 Scanners"]
        direction TB
        s1["Nessus · Qualys · Rapid7"]
        s2["Tenable SC · Tenable IO"]
        s3["CrowdStrike · Wiz"]
    end

    subgraph TI["🛡 Threat Intel"]
        direction TB
        t1["NVD API v2 · CISA KEV"]
        t2["MITRE ATT&CK · ExploitDB"]
        t3["GreyNoise · MSRC · CWE"]
    end

    subgraph LM["🤖 LLM Providers"]
        direction TB
        l1["Anthropic Claude · OpenAI GPT"]
        l2["Google Gemini · Groq"]
    end

    subgraph NT["📣 Notifications"]
        direction TB
        n1["Jira · ServiceNow"]
        n2["Slack · Teams · SMTP"]
    end

    subgraph OB["📊 Observability"]
        direction TB
        SE["Sentry<br/>errors · per-tenant context"]
        PM["Prometheus + Grafana<br/>latency · queue depth · DB pool"]
        OT["OpenTelemetry + Jaeger<br/>traces: API → queue → worker → DB"]
        LG["structlog<br/>org_id · user_id · request_id"]
    end

    WS -->|poll · circuit breaker| SC
    WL -->|enrich · circuit breaker| TI
    WL -->|AI calls · circuit breaker| LM
    WN -->|send · circuit breaker| NT

    AP -->|errors · metrics · traces| OB
    WK -->|errors · metrics · traces| OB

    classDef worker fill:#0d2211,stroke:#228844,color:#66cc88
    classDef obs fill:#1a1a2e,stroke:#5555aa,color:#9999ff
    class WS,WI,WL,WN worker
    class SE,PM,OT,LG obs
```

### What Changed from Before

| Layer | Before | After |
|---|---|---|
| **Frontend** | Render static (cold start) | CDN-served |
| **API** | 1 process, sync DB calls | N stateless instances, async SQLAlchemy |
| **Scheduler** | APScheduler in-process | Celery Beat (redbeat) → Redis |
| **Jobs** | Blocking API threads | Isolated workers per queue type |
| **Database** | SQLite, 1 writer, ephemeral | PostgreSQL + Alembic + time partitioning |
| **Read queries** | Same DB for OLTP + dashboards | Read replica with explicit per-endpoint routing |
| **Connections** | Unlimited, direct to DB | PgBouncer caps at safe limit |
| **File uploads** | Routes through API memory | Presigned URLs — browser uploads direct to S3 |
| **Cache** | JSON file per-process | Redis HA, shared across all instances |
| **Rate limiting** | None | Redis-backed per `org_id` |
| **Task overlap** | Duplicate sync jobs possible | Redis lock per `integration_id` |
| **External calls** | No retry, no circuit breaker | `tenacity` backoff on all external APIs |
| **Notifications / LLM** | Blocks HTTP response | Async Celery workers, never in request path |
| **Observability** | Audit log only | Sentry + Prometheus + OTel traces |
| **Tenant isolation** | App-level `org_id` filter | PostgreSQL RLS + app-level filter |

---

## LOCAL DEVELOPMENT — Lightweight Mode

```mermaid
flowchart LR
    subgraph local["💻 Local Dev — docker compose up + uvicorn --reload"]
        direction TB

        B2["🌐 Browser<br/>Vite dev server<br/>localhost:3000"]

        subgraph FP["FastAPI — single process"]
            API2["REST handlers"]
            EC["Celery ALWAYS_EAGER=true<br/>tasks run inline · synchronous<br/>no workers · no broker needed<br/>identical task code to production"]
            API2 -.->|same code path| EC
        end

        subgraph DC["docker compose services"]
            PG2[("PostgreSQL<br/>direct connection<br/>no PgBouncer · no replica")]
            RD2["Redis<br/>single node<br/>optional — only needed<br/>for lock/rate-limit testing"]
            MN["MinIO<br/>S3-compatible<br/>presigned URLs identical<br/>to production behavior"]
        end

        B2 -->|localhost:8000| API2
        B2 -->|"direct upload<br/>localhost:9000"| MN
        API2 <--> PG2
        API2 <--> MN
        API2 -.->|optional| RD2
    end

    note["❌ Skipped locally: PgBouncer · read replica · Beat · Workers · Jaeger<br/>✅ Same application code runs in both environments<br/>✅ MinIO presigned URLs behave identically to S3"]

    style local fill:#0d1f0d,stroke:#336633
    style note fill:#1f1f00,stroke:#666600,color:#cccc66
```

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
      - "9000:9000"   # S3 API endpoint
      - "9001:9001"   # MinIO browser console

volumes:
  pg_data:
```

### Environment Variables

**.env.local**
```bash
DATABASE_URL=postgresql+asyncpg://hakuna:hakuna@localhost:5432/hakuna

REDIS_URL=redis://localhost:6379/0

# Tasks run inline — no workers or broker needed locally
CELERY_TASK_ALWAYS_EAGER=true
CELERY_TASK_EAGER_PROPAGATES=true

# MinIO mimics S3 presigned URL flow exactly
S3_ENDPOINT_URL=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=hakuna-local

# Observability off locally
SENTRY_DSN=
OTEL_EXPORTER_OTLP_ENDPOINT=

ENV=development   # disables rate limiting middleware
```

**.env.production**
```bash
DATABASE_URL=postgresql+asyncpg://hakuna:...@pgbouncer:5432/hakuna
DATABASE_REPLICA_URL=postgresql+asyncpg://hakuna:...@pg-replica:5432/hakuna
REDIS_URL=rediss://...upstash.io:6380
CELERY_TASK_ALWAYS_EAGER=false
S3_ENDPOINT_URL=
S3_BUCKET=hakuna-prod
SENTRY_DSN=https://...@sentry.io/...
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
ENV=production
```

### Local vs. Production Matrix

| Component | Local | Production |
|---|---|---|
| PostgreSQL | Docker, direct connection | Managed + PgBouncer |
| Read replica | None — primary handles all | Explicit per-endpoint routing |
| Redis | Docker, single node (optional) | Managed HA with Sentinel |
| Celery | `ALWAYS_EAGER` — inline, synchronous | Workers + Beat (redbeat) |
| File uploads | MinIO presigned URLs | S3 / R2 presigned URLs |
| Migrations | `alembic upgrade head` on start | CI gate — must pass before deploy |
| Observability | Off | Sentry + OTel + Prometheus |
| Rate limiting | Disabled (`ENV=development`) | Redis-backed per `org_id` |

---

## Implementation Sequence

Each step ships independently and improves the system without requiring the next.

| Step | Change | Unlocks |
|---|---|---|
| **1** | `docker-compose.dev.yml` + env file split | Safe local dev baseline |
| **2** | PostgreSQL + Alembic migrations | Concurrent writes, reliable storage |
| **3** | Async SQLAlchemy sessions | Event loop unblocked, real concurrency |
| **4** | Celery + Redis (`ALWAYS_EAGER` locally) | Background jobs, APScheduler removed |
| **5** | MinIO / S3 + presigned upload flow | Large scan files off API memory |
| **6** | PgBouncer in production | Connection stability at scale |
| **7** | `tenacity` circuit breakers on external calls | Resilient scanner + LLM integration |
| **8** | Per-tenant rate limiting via Redis | Noisy-neighbour protection |
| **9** | OpenTelemetry + Jaeger | Full traces across API → queue → worker → DB |
| **10** | Read replica + explicit per-endpoint routing | Dashboard query isolation |

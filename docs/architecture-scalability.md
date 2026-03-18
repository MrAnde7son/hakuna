# Architecture: Before & After

---

## BEFORE — Current State

Single-process, single-file, single-dyno deployment on Render free tier.

```mermaid
flowchart TD
    Browser["🌐 Browser\nReact + Vite SPA\n(served from Render static)"]

    subgraph Render["☁️ Render Free Tier · Single Dyno"]
        direction TB

        subgraph Process["Single OS Process · Uvicorn 1 worker"]
            API["FastAPI\nREST API Handlers"]
            APSched["⚠️ APScheduler\nin-process scheduler\nlost on restart · no retry"]
            API -.-> APSched
        end

        SQLite[("⚠️ SQLite\nsingle file · 1 writer at a time\nephemeral · data loss on restart")]
        CVECache["⚠️ CVE Cache\nJSON file on disk\nper-process · not shared"]

        API <-->|"sync blocking calls\n⚠️ blocks event loop"| SQLite
        API --> CVECache
    end

    subgraph Scanners["🔍 Scanners  (pulled by APScheduler threads)"]
        direction LR
        Nessus["Nessus"]
        Qualys["Qualys"]
        Rapid7["Rapid7"]
        TenSC["Tenable SC"]
        TenIO["Tenable IO"]
        CS["CrowdStrike"]
        Wiz["Wiz"]
    end

    subgraph Intel["🛡️ Threat Intelligence  (called on-demand / ad-hoc)"]
        direction LR
        NVD["NVD API v2"]
        CISA["CISA KEV"]
        MITRE["MITRE ATT&CK"]
        EDBP["ExploitDB"]
        GN["GreyNoise"]
        MSRC["MSRC"]
        CWE["CWE"]
    end

    subgraph Notify["📣 Notifications  (synchronous in request path)"]
        direction LR
        Jira["Jira"]
        SN["ServiceNow"]
        Slack["Slack"]
        Teams["Teams"]
        Email["Email\nSMTP"]
    end

    subgraph LLM["🤖 AI / LLM  (blocking HTTP calls)"]
        direction LR
        Claude["Anthropic\nClaude"]
        GPT["OpenAI\nGPT"]
        Gemini["Google\nGemini"]
        Groq["Groq"]
    end

    Browser -->|"HTTP · same origin"| API
    APSched -->|"poll & import\n⚠️ competes with API threads"| Scanners
    API -->|"CVE enrichment\n⚠️ synchronous"| Intel
    API -->|"⚠️ blocks response"| Notify
    API -->|"⚠️ blocks response"| LLM

    classDef warning fill:#ffe0e0,stroke:#cc0000,color:#333
    classDef ok fill:#e8f5e9,stroke:#2e7d32,color:#333
    class SQLite,CVECache,APSched warning
```

### Key Problems

| Component | Problem |
|---|---|
| SQLite | 1 writer — lock contention at 10+ customers with concurrent imports |
| APScheduler | In-process — 300 customers × N integrations = thread pool exhaustion |
| Render Free | 15-min spin-down, no persistent disk, data loss on restart |
| DB calls | Sync in async handlers — blocks event loop under load |
| No Redis | No caching layer, no rate limiting, no shared state across instances |
| No queue | Notifications and LLM calls block the HTTP response |
| No observability | Zero metrics, no error tracking, blind to production issues |

---

## AFTER — Target State

Horizontally scalable API + decoupled worker layer + PostgreSQL with read replica.

```mermaid
flowchart TD
    subgraph Clients["👥 Clients"]
        Browser["🌐 Browser\nReact + Vite SPA"]
    end

    CDN["🌍 CDN\nStatic Assets\n(Cloudflare / Render CDN)"]
    LB["⚖️ Load Balancer\nHTTPS termination\nhealth checks"]

    subgraph AppLayer["🚀 API Layer  ·  horizontally scalable  ·  stateless"]
        direction LR
        API1["FastAPI\nInstance 1\nasync SQLAlchemy"]
        API2["FastAPI\nInstance 2\nasync SQLAlchemy"]
        APIN["FastAPI\nInstance N\nasync SQLAlchemy"]
    end

    subgraph WorkerLayer["⚙️ Worker Layer  ·  horizontally scalable"]
        direction TB
        Beat["Celery Beat\nScheduler\n(replaces APScheduler)\npersists to Redis"]
        W1["Celery Worker\nIntegration Sync\n(scanner polling)"]
        W2["Celery Worker\nScan Import\n(parse + batch insert)"]
        W3["Celery Worker\nAI / Enrichment\n(LLM + threat intel)"]
        W4["Celery Worker\nNotifications\n(Jira · Slack · Email)"]
    end

    subgraph CacheQueue["⚡ Cache & Message Broker"]
        Redis["Redis\n──────────────\nCelery broker + result backend\nAPI response cache\nRate limiting (per org_id)\nSession / JWT denylist"]
    end

    subgraph DataLayer["🗄️ Data Layer"]
        PGPrimary[("PostgreSQL Primary\n──────────────\nRow Level Security\nAlembic migrations\nWAL enabled\nPartitioned findings table")]
        PGReplica[("PostgreSQL\nRead Replica\n──────────────\nDashboards\nReports\nScan comparisons")]
        S3["☁️ Object Storage\nS3 / R2\n──────────────\nScan file uploads\nReport PDF exports\nAgent documents"]
    end

    subgraph Observability["📊 Observability"]
        direction LR
        Sentry["Sentry\nError tracking\nper-tenant context"]
        Prom["Prometheus\n+ Grafana\nAPI latency · queue depth\nDB pool · error rate"]
        Logs["Structured Logs\nstructlog\norg_id · user_id\nrequest_id in every line"]
    end

    subgraph Scanners["🔍 Scanners  (via Celery workers, not API process)"]
        direction LR
        Nessus2["Nessus"]
        Qualys2["Qualys"]
        Rapid72["Rapid7"]
        TenSC2["Tenable SC"]
        TenIO2["Tenable IO"]
        CS2["CrowdStrike"]
        Wiz2["Wiz"]
    end

    subgraph Intel["🛡️ Threat Intelligence  (async worker, cached in Redis)"]
        direction LR
        NVD2["NVD API v2"]
        CISA2["CISA KEV"]
        MITRE2["MITRE ATT&CK"]
        EDBP2["ExploitDB"]
        GN2["GreyNoise"]
        MSRC2["MSRC"]
        CWE2["CWE"]
    end

    subgraph Notify2["📣 Notifications  (async worker, never blocks API)"]
        direction LR
        Jira2["Jira"]
        SN2["ServiceNow"]
        Slack2["Slack"]
        Teams2["Teams"]
        Email2["Email SMTP"]
    end

    subgraph LLM2["🤖 AI / LLM  (async worker, rate-limited per org)"]
        direction LR
        Claude2["Anthropic\nClaude"]
        GPT2["OpenAI\nGPT"]
        Gemini2["Google\nGemini"]
        Groq2["Groq"]
    end

    %% Client routing
    Browser -->|"static assets"| CDN
    Browser -->|"API calls · HTTPS"| LB
    LB --> API1 & API2 & APIN

    %% API ↔ data
    API1 & API2 & APIN <-->|"async read/write"| PGPrimary
    API1 & API2 & APIN -->|"async read\nheavy queries"| PGReplica
    API1 & API2 & APIN <-->|"cache · rate limit\ncheck"| Redis

    %% API enqueues work
    API1 & API2 & APIN -->|"enqueue jobs\nnon-blocking"| Redis

    %% Worker dispatch
    Beat -->|"cron triggers"| Redis
    Redis -->|"dispatch"| W1 & W2 & W3 & W4

    %% Workers ↔ data
    W1 & W2 & W3 & W4 <-->|"read/write"| PGPrimary
    W2 -->|"store large files"| S3

    %% Workers ↔ external
    W1 -->|"poll & import"| Scanners
    W3 -->|"enrich CVEs"| Intel
    W3 -->|"AI features"| LLM2
    W4 -->|"send alerts"| Notify2

    %% Replication
    PGPrimary -->|"streaming replication"| PGReplica

    %% Observability
    AppLayer -->|"errors · traces"| Sentry
    WorkerLayer -->|"errors · traces"| Sentry
    AppLayer -->|"metrics"| Prom
    WorkerLayer -->|"metrics"| Prom
    AppLayer -->|"logs"| Logs
    WorkerLayer -->|"logs"| Logs

    classDef newComponent fill:#e3f2fd,stroke:#1565c0,color:#333
    classDef dataStore fill:#f3e5f5,stroke:#6a1b9a,color:#333
    classDef external fill:#e8f5e9,stroke:#2e7d32,color:#333
    class Redis,CDN,LB,Beat,S3 newComponent
    class PGPrimary,PGReplica dataStore
    class Observability external
```

### What Changed

| Layer | Before | After |
|---|---|---|
| **Frontend** | Render static (cold start) | CDN-served, instant globally |
| **API** | 1 process, 1 worker, sync DB | N stateless instances, async SQLAlchemy |
| **Scheduler** | APScheduler in-process | Celery Beat → Redis → Workers |
| **Jobs** | Blocking API threads | Isolated Celery workers per job type |
| **Database** | SQLite, 1 writer, ephemeral | PostgreSQL, RLS, Alembic, partitioned |
| **Read queries** | Same DB for OLTP + reports | Read replica for dashboards/reports |
| **Files** | SQLite / local disk | S3/R2 object storage |
| **Cache** | JSON file per-process | Redis, shared across all instances |
| **Rate limiting** | None | Redis-backed per `org_id` |
| **Notifications** | Blocks HTTP response | Async Celery worker |
| **LLM calls** | Blocks HTTP response | Async Celery worker, per-org queued |
| **Observability** | Audit log only | Sentry + Prometheus + structured logs |
| **Tenant isolation** | App-level `org_id` filter | PostgreSQL RLS enforced at DB layer |

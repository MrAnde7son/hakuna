# Hakuna — GCP Deployment Plan (Authoritative)

> **Single reference document.** This supersedes all previous deployment and scalability planning docs. Read this to know exactly what to build, why, and in what order.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Decisions](#architecture-decisions)
3. [Three-Tier Growth Path](#three-tier-growth-path)
4. [Component Details](#component-details)
   - [Cloud SQL Auth Proxy](#cloud-sql-auth-proxy)
   - [GCS Presigned Upload Flow](#gcs-presigned-upload-flow)
   - [Redis / Memorystore](#redis--memorystore)
   - [Celery Workers on Compute Engine](#celery-workers-on-compute-engine)
   - [Observability Stack](#observability-stack)
5. [Terraform Configuration](#terraform-configuration)
   - [providers.tf](#terraformproviderstf)
   - [network.tf](#terraformnetworktf)
   - [database.tf](#terraformdatabasetf)
   - [redis.tf](#terraformredistf)
   - [storage.tf](#terraformstoragetf)
   - [secrets.tf](#terraformsecretstf)
   - [iam.tf](#terraformiamtf)
   - [cloudrun\_api.tf](#terraformcloudrun_apitf)
   - [compute\_workers.tf](#terraformcompute_workerstf)
   - [scheduler.tf](#terraformschedulertf)
   - [loadbalancer.tf](#terraformloadbalancertf)
   - [artifact\_registry.tf](#terraformartifact_registrytf)
   - [monitoring.tf](#terraformmonitoringtf)
6. [Local Development](#local-development)
7. [Implementation Sequence](#implementation-sequence)
8. [What to Defer](#what-to-defer)

---

## Overview

**Product:** Hakuna — multi-tenant security vulnerability remediation SaaS platform
**Target:** 300 SMB/mid-market customers
**Primary region:** `me-west1` (Tel Aviv)
**Core principle:** Managed services everywhere. No Kubernetes. No self-hosted anything.

The architecture is built around three constraints:

1. **Operational simplicity** — every component must be manageable by a small team without dedicated DevOps.
2. **Cost efficiency** — right-sized resources at each growth tier, with a clear upgrade path.
3. **Correctness** — architectural choices are made for the right reasons (e.g., Celery workers on VMs because they are persistent daemons, not HTTP servers).

---

## Architecture Decisions

### Component Map

| Component | GCP Service | Rationale |
|---|---|---|
| React SPA | Cloud CDN + Cloud Storage | Zero ops, global edge caching |
| FastAPI API | Cloud Run (min 1, max 10) | Auto-scales, stateless, HTTP — perfect fit |
| Celery workers | Compute Engine VM (Docker Compose) | Persistent polling daemons — Cloud Run is HTTP-only and unsuitable |
| PostgreSQL | Cloud SQL PostgreSQL 16, Enterprise | Managed, PITR backups, Query Insights |
| Connection pooling | Cloud SQL Auth Proxy sidecar + SQLAlchemy | Free, handles IAM auth, no PgBouncer needed |
| Redis | Memorystore for Redis 7 | Managed, private IP, no ops |
| File storage | GCS + V4 presigned URLs | Browser uploads direct to GCS — API never handles bytes |
| Secrets | Secret Manager | Rotatable, audited, never in Terraform state |
| Observability | Cloud Logging + Cloud Trace + Sentry | Zero infra overhead |
| CI/CD | GitHub Actions | Keeps CI co-located with the codebase |
| IaC | Terraform with GCS backend | Standard, reproducible, reviewable |

### Key Architectural Choices

**Celery queue separation — 4 queues:**

| Queue | Worker | Purpose |
|---|---|---|
| `sync` | worker-sync | Scanner polling, external API calls |
| `import` | worker-import | Scan file parsing, batch DB inserts |
| `llm` | worker-llm | AI enrichment (OpenAI, Anthropic, etc.) |
| `notify` | worker-notify | Email, Slack, Jira notification dispatch |

**Other decisions carried forward:**

- **redbeat** for Celery Beat scheduler — Redis-backed distributed lock prevents duplicate Beat processes across restarts.
- **Circuit breakers via tenacity** — exponential backoff with jitter on ALL external API calls (scanners, LLMs, Jira, webhooks).
- **Presigned upload flow** — API issues V4 URL → browser uploads directly to GCS → API enqueues import job. API never proxies file bytes.
- **Per-tenant rate limiting** — Redis-backed counters keyed on `org_id`, TTL-based.
- **Read replica routing** — explicit per-endpoint. Dashboards and reports hit the replica. OLTP (writes, transactional reads) hit the primary.
- **Expand-contract migrations** — Alembic discipline: all migrations must be backward-compatible with the running previous version to enable zero-downtime deploys.
- **Task deduplication** — Redis lock per `integration_id` with a 3600s timeout prevents overlapping sync jobs for the same tenant integration.
- **gevent pool for LLM worker** — I/O-bound tasks benefit from high concurrency on a single vCPU. `celery worker -Q llm -P gevent -c 50`.
- **`CELERY_TASK_ALWAYS_EAGER=true` locally** — tasks execute inline in the calling process. Same task code path, no worker process needed for local development.

### Fixes Applied vs. Original GCP Plan

The following issues existed in the initial GCP deployment sketch and are corrected here:

1. **Workers moved to Compute Engine** — the original plan ran workers on Cloud Run. Celery workers are persistent long-running daemons that poll Redis; they do not serve HTTP. Cloud Run terminates containers with no inbound traffic. Workers must run on VMs.
2. **Cloud SQL IAM database authentication** — no database passwords, no password secrets in env vars. IAM auth is enforced via the Auth Proxy `--auto-iam-authn` flag.
3. **`roles/iam.serviceAccountTokenCreator` on the API service account** — required for GCS V4 signed URL generation. Without this role, `google.auth.exceptions.TransportError` is raised when calling `generate_signed_url()`.
4. **Cloud Scheduler Beat heartbeat added on day 1** — not deferred. Provides a safety net if the Beat container crashes and doesn't restart cleanly.
5. **LLM worker uses gevent pool** — the original plan used prefork (`-c 8`). LLM calls are network I/O, not CPU. gevent with `-c 50` gives 6× more concurrency on the same hardware.
6. **Celery Beat runs on the worker VM** — not on Cloud Run. Beat must maintain persistent schedule state in Redis; running it on Cloud Run would cause it to be killed during scale-to-zero.

---

## Three-Tier Growth Path

### Tier 1 — Start (0–50 customers) ~$370/mo

| Component | Spec | Est. Cost |
|---|---|---|
| Cloud Run API | min 1, max 5 instances · 1 vCPU / 512MB | ~$100/mo |
| Compute Engine | e2-standard-2 (2 vCPU, 8 GB) · all workers + Beat | ~$55/mo |
| Cloud SQL | db-custom-2-4096 · ZONAL (no HA) · 20 GB PD-SSD | ~$95/mo |
| Memorystore Redis | Basic tier · 1 GB | ~$52/mo |
| GCS | Scan file storage | ~$2/mo |
| Cloud CDN + Load Balancer | Global HTTPS LB + CDN | ~$22/mo |
| VPC Connector | min 2 × e2-micro instances | ~$16/mo |
| Sentry | Team plan | ~$26/mo |
| Artifact Registry + Secret Manager + Cloud Build | Supporting services | ~$5/mo |
| **Total** | | **~$373/mo (~$7.50/customer)** |

### Tier 2 — Growth (50–150 customers) ~$720/mo

Changes from Tier 1:

| Component | Change | New Cost |
|---|---|---|
| Cloud SQL | Upgrade to REGIONAL HA + add Read Replica | ~$253/mo (was $95) |
| Compute Engine | Upgrade to e2-standard-4 (4 vCPU, 16 GB) | ~$110/mo (was $55) |
| Memorystore Redis | Upgrade to Standard HA · 2 GB | ~$130/mo (was $52) |
| Cloud Run API | min 2, max 10 instances | ~$170/mo (was $100) |
| GCS | Growth in stored files | ~$5/mo |
| **Total** | | **~$724/mo (~$4.80/customer)** |

### Tier 3 — Scale (150–300 customers) ~$1,200/mo

Changes from Tier 2:

| Component | Change | New Cost |
|---|---|---|
| Cloud SQL | db-custom-4-8192 (4 vCPU, 8 GB) HA + larger replica | ~$380/mo |
| Compute Engine | 2× e2-standard-4 worker VMs | ~$220/mo |
| Memorystore Redis | Standard HA · 4 GB | ~$240/mo |
| Cloud Run API | max 20 instances | ~$280/mo |
| Cloud Armor WAF | DDoS + WAF rules | ~$50/mo |
| Sentry | Business plan | ~$80/mo |
| **Total** | | **~$1,195/mo (~$4.00/customer)** |

### Cost Optimization (apply when the system is stable)

| Optimization | Saving |
|---|---|
| Cloud SQL 1-year CUD | ~25% → save ~$60–95/mo |
| Compute Engine 1-year CUD | ~20% → save ~$11–22/mo |
| Cloud Run min-instance reservation | ~17% on idle instance cost |
| Skip read replica (Tier 1 → Tier 2) | Optional — only add when dashboards are measurably slow |

---

## Component Details

### Cloud SQL Auth Proxy

The Auth Proxy replaces PgBouncer. It runs as a sidecar container in Cloud Run (API) and as a container in the Docker Compose stack on the Compute Engine VM (workers).

**How it works:**

- Opens a local TCP listener (`localhost:5432` for primary, `localhost:5433` for replica).
- Application code connects to `localhost:5432` as if it were a plain Postgres server.
- The proxy handles TLS termination and IAM token refresh transparently.
- No database password is ever set. Authentication is handled via the service account identity.

**SQLAlchemy pool settings:**

```python
# Per Cloud Run instance (or per worker process)
engine = create_async_engine(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)
```

**Connection budget at Tier 1:**

- Up to 5 Cloud Run instances × 15 connections = 75
- 1 worker VM (5 processes) × 4 connections each = 20
- Total: ~95 connections — safely under `max_connections=200`

**Auth Proxy startup command (primary + replica):**

```
/cloud-sql-proxy \
  --auto-iam-authn \
  --port=5432 \
  PROJECT:REGION:INSTANCE_NAME \
  --port=5433 \
  PROJECT:REGION:REPLICA_INSTANCE_NAME
```

### GCS Presigned Upload Flow

The API never proxies file bytes. The flow is:

```
1. Frontend         → POST /api/scans/upload-url
                      Body: { filename, content_type }

2. API              → Returns V4 signed URL (15-minute TTL)
                      Requires: roles/iam.serviceAccountTokenCreator on self

3. Frontend         → PUT {signed_url}  (direct to GCS, no API involvement)
                      Headers: Content-Type matching what was signed

4. Frontend         → POST /api/scans/{id}/process
                      Body: { gcs_object_path }

5. API              → Enqueues task to import queue in Redis

6. worker-import    → Reads object from GCS, parses scan file,
                      batch-inserts vulnerabilities to PostgreSQL
```

**Why V4 signed URLs require `serviceAccountTokenCreator`:**

The GCS Python client library calls `signBlob()` on the service account's own key when running on GCP with a service account identity (as opposed to a JSON key file). This requires the service account to have `iam.serviceAccounts.signBlob` permission on itself, which is granted by `roles/iam.serviceAccountTokenCreator`.

### Redis / Memorystore

Redis serves multiple roles. All keys should be namespaced by purpose:

| Usage | Key Pattern | TTL |
|---|---|---|
| Celery broker | `celery` default namespace | Task-lifetime |
| redbeat schedule | `redbeat:` prefix | Persistent |
| Rate limiting | `ratelimit:{org_id}:{endpoint}` | Rolling window (60s) |
| Task deduplication | `lock:integration:{integration_id}` | 3600s |
| API response cache | `cache:{query_hash}` | 300s |
| JWT denylist | `denylist:jti:{jti}` | Token expiry TTL |

**Capacity planning:**

- Start: 1 GB Basic tier (no HA). Acceptable risk for early customers.
- Upgrade to Standard HA at 50+ tenants — Redis downtime affects all queues and all rate limiting simultaneously.

### Celery Workers on Compute Engine

All workers run as Docker Compose services on the Compute Engine VM. They share the same Docker image as the API (built from the same `Dockerfile`). The VM has no public IP — SSH access is via Identity-Aware Proxy (IAP).

**Docker Compose service definitions:**

```yaml
# docker-compose.workers.yml
services:
  worker-sync:
    image: REGION-docker.pkg.dev/PROJECT/hakuna/api:latest
    command: celery -A app.worker worker -Q sync -c 4 --loglevel=info
    env_file: .env.prod
    restart: unless-stopped

  worker-import:
    image: REGION-docker.pkg.dev/PROJECT/hakuna/api:latest
    command: celery -A app.worker worker -Q import -c 2 --loglevel=info
    env_file: .env.prod
    restart: unless-stopped

  worker-llm:
    image: REGION-docker.pkg.dev/PROJECT/hakuna/api:latest
    command: celery -A app.worker worker -Q llm -P gevent -c 50 --loglevel=info
    env_file: .env.prod
    restart: unless-stopped

  worker-notify:
    image: REGION-docker.pkg.dev/PROJECT/hakuna/api:latest
    command: celery -A app.worker worker -Q notify -c 4 --loglevel=info
    env_file: .env.prod
    restart: unless-stopped

  worker-beat:
    image: REGION-docker.pkg.dev/PROJECT/hakuna/api:latest
    command: celery -A app.worker beat --scheduler redbeat.RedBeatScheduler --loglevel=info
    env_file: .env.prod
    restart: unless-stopped

  cloud-sql-proxy:
    image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2
    command: >
      --auto-iam-authn
      --port=5432
      PROJECT:me-west1:hakuna-postgres
    restart: unless-stopped
```

**Worker concurrency rationale:**

| Worker | Pool | Concurrency | Reason |
|---|---|---|---|
| worker-sync | prefork | 4 | CPU + I/O mix, predictable memory |
| worker-import | prefork | 2 | Memory-heavy (large scan files) |
| worker-llm | gevent | 50 | Pure network I/O — greenlets are ideal |
| worker-notify | prefork | 4 | Mix of HTTP calls, low memory |

**Systemd unit (created by startup script):**

```ini
[Unit]
Description=Hakuna Workers
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/opt/hakuna
ExecStart=/usr/bin/docker compose -f docker-compose.workers.yml up
ExecStop=/usr/bin/docker compose -f docker-compose.workers.yml down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Observability Stack

**Errors — Sentry:**

```python
import sentry_sdk

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    environment=settings.ENV,
    traces_sample_rate=0.1,  # 10% of transactions
    profiles_sample_rate=0.1,
)

# Per-request: bind org_id to Sentry scope
with sentry_sdk.configure_scope() as scope:
    scope.set_tag("org_id", request.state.org_id)
```

**Logs — structlog → Cloud Logging:**

```python
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
```

On Cloud Run, stdout JSON is automatically ingested by Cloud Logging and parsed as structured log entries. On the Compute Engine VM, use the `gcplogs` Docker log driver or the Cloud Logging agent.

**Traces — OpenTelemetry → Cloud Trace:**

Use `opentelemetry-exporter-gcp-trace`, NOT the generic OTLP exporter. Cloud Trace does not accept plain OTLP HTTP/gRPC — it requires the GCP-specific exporter.

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(CloudTraceSpanExporter())
)
trace.set_tracer_provider(provider)
```

**Metrics — Cloud Monitoring:**

Cloud Monitoring auto-collects metrics for Cloud Run, Cloud SQL, and Memorystore with no instrumentation required. Add custom metrics for:

- Celery queue depth (emit from a lightweight metrics task or from Flower exporter)
- Per-tenant error rates (custom counter metric keyed on `org_id`)

**Alert policies (configured in `monitoring.tf`):**

| Alert | Threshold | Window |
|---|---|---|
| API p99 latency | > 2000ms | 5 minutes |
| Cloud SQL CPU utilization | > 80% | 10 minutes |
| Memorystore memory usage | > 80% | 5 minutes |
| Cloud Run instance count | > 8 (approaching limit) | 1 minute |
| Celery queue depth | > 500 tasks | 5 minutes |

---

## Terraform Configuration

All files live in a `terraform/` directory at the root of the repository. State is stored in a GCS bucket (`hakuna-tf-state`). Apply with `terraform apply -var="project_id=hakuna-prod"`.

### terraform/providers.tf

```hcl
terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "hakuna-tf-state"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "hakuna-prod"
}

variable "region" {
  description = "Primary GCP region"
  type        = string
  default     = "me-west1"
}

variable "environment" {
  description = "Deployment environment (production, staging)"
  type        = string
  default     = "production"
}

variable "app_domain" {
  description = "Primary application domain (e.g. app.hakuna.io)"
  type        = string
}
```

### terraform/network.tf

```hcl
# VPC
resource "google_compute_network" "hakuna" {
  name                    = "hakuna-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

# Primary subnet
resource "google_compute_subnetwork" "hakuna" {
  name          = "hakuna-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.hakuna.id
  project       = var.project_id

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private service connection for Cloud SQL
resource "google_compute_global_address" "private_service_range" {
  name          = "hakuna-private-service-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.hakuna.id
  project       = var.project_id
}

resource "google_service_networking_connection" "private_service_connection" {
  network                 = google_compute_network.hakuna.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]
}

# VPC Access Connector for Cloud Run → private VPC resources
resource "google_vpc_access_connector" "hakuna" {
  name          = "hakuna-connector"
  region        = var.region
  project       = var.project_id
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.hakuna.name

  min_instances = 2
  max_instances = 3
  machine_type  = "e2-micro"
}

# Cloud Router + NAT (for worker VM to reach internet: Docker Hub, scanner APIs)
resource "google_compute_router" "hakuna" {
  name    = "hakuna-router"
  region  = var.region
  network = google_compute_network.hakuna.id
  project = var.project_id
}

resource "google_compute_router_nat" "hakuna" {
  name                               = "hakuna-nat"
  router                             = google_compute_router.hakuna.name
  region                             = var.region
  project                            = var.project_id
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall: allow internal traffic within VPC
resource "google_compute_firewall" "allow_internal" {
  name    = "hakuna-allow-internal"
  network = google_compute_network.hakuna.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/20"]
  target_tags   = ["allow-internal"]
}

# Firewall: allow SSH from IAP (Identity-Aware Proxy)
resource "google_compute_firewall" "allow_ssh_iap" {
  name    = "hakuna-allow-ssh-iap"
  network = google_compute_network.hakuna.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP's fixed CIDR range
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-ssh-iap"]
}
```

### terraform/database.tf

```hcl
# Primary Cloud SQL instance
# Tier 1: ZONAL (single zone, no HA). Change availability_type to REGIONAL for Tier 2.
resource "google_sql_database_instance" "hakuna_postgres" {
  name             = "hakuna-postgres"
  database_version = "POSTGRES_16"
  region           = var.region
  project          = var.project_id

  deletion_protection = true

  settings {
    tier              = "db-custom-2-4096" # Tier 2: db-custom-2-7680; Tier 3: db-custom-4-8192
    edition           = "ENTERPRISE"
    availability_type = "ZONAL" # Change to REGIONAL for Tier 2 HA

    disk_size       = 20
    disk_type       = "PD_SSD"
    disk_autoresize = true

    ip_configuration {
      ipv4_enabled                                  = false # Private IP only
      private_network                               = google_compute_network.hakuna.id
      enable_private_path_for_google_cloud_services = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00" # 3 AM UTC
      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
      transaction_log_retention_days = 7
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = false
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "500" # Log queries slower than 500ms
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 4 # 4 AM UTC
      update_track = "stable"
    }
  }

  depends_on = [google_service_networking_connection.private_service_connection]
}

# Read replica
# Optional at Tier 1 — provision when dashboards become measurably slow.
resource "google_sql_database_instance" "hakuna_postgres_replica" {
  name                 = "hakuna-postgres-replica"
  database_version     = "POSTGRES_16"
  region               = var.region
  project              = var.project_id
  master_instance_name = google_sql_database_instance.hakuna_postgres.name

  deletion_protection = true

  replica_configuration {
    failover_target = false
  }

  settings {
    tier              = "db-custom-1-3840" # Tier 3: match primary size
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"

    disk_size       = 20
    disk_type       = "PD_SSD"
    disk_autoresize = true

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.hakuna.id
    }

    insights_config {
      query_insights_enabled = true
      query_string_length    = 1024
    }
  }

  depends_on = [google_sql_database_instance.hakuna_postgres]
}

# Application database
resource "google_sql_database" "hakuna" {
  name     = "hakuna"
  instance = google_sql_database_instance.hakuna_postgres.name
  project  = var.project_id
}

# IAM database users (no passwords — uses IAM authentication via Auth Proxy)
# The username must exactly match the service account email without the .gserviceaccount.com suffix
resource "google_sql_user" "hakuna_api" {
  name     = "hakuna-api@${var.project_id}.iam"
  instance = google_sql_database_instance.hakuna_postgres.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
  project  = var.project_id
}

resource "google_sql_user" "hakuna_worker" {
  name     = "hakuna-worker@${var.project_id}.iam"
  instance = google_sql_database_instance.hakuna_postgres.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
  project  = var.project_id
}
```

### terraform/redis.tf

```hcl
# Memorystore for Redis 7
# Tier 1: BASIC tier (no HA). Change tier to STANDARD_HA for Tier 2.
resource "google_redis_instance" "hakuna" {
  name           = "hakuna-redis"
  tier           = "BASIC"         # Change to STANDARD_HA for Tier 2
  memory_size_gb = 1               # Tier 2: 2; Tier 3: 4
  region         = var.region
  project        = var.project_id

  redis_version         = "REDIS_7_0"
  display_name          = "Hakuna Redis"
  reserved_ip_range     = "10.0.16.0/29"
  authorized_network    = google_compute_network.hakuna.id
  connect_mode          = "PRIVATE_SERVICE_ACCESS"

  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }

  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 4
        minutes = 0
      }
    }
  }

  depends_on = [google_service_networking_connection.private_service_connection]
}

output "redis_host" {
  value     = google_redis_instance.hakuna.host
  sensitive = false
}
```

### terraform/storage.tf

```hcl
# GCS bucket for scan file uploads
resource "google_storage_bucket" "scan_files" {
  name                        = "${var.project_id}-scan-files"
  location                    = var.region
  project                     = var.project_id
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true

  # Versioning disabled — scan files are immutable after upload
  versioning {
    enabled = false
  }

  # Lifecycle: move to Nearline after 30 days, delete after 90
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  # CORS required for browser direct upload via presigned URL
  cors {
    origin          = ["https://${var.app_domain}"]
    method          = ["PUT", "HEAD"]
    response_header = ["Content-Type", "Content-Length", "Authorization"]
    max_age_seconds = 3600
  }
}

# GCS bucket for frontend SPA static assets
resource "google_storage_bucket" "frontend_assets" {
  name                        = "${var.project_id}-frontend"
  location                    = var.region
  project                     = var.project_id
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true

  website {
    main_page_suffix = "index.html"
    not_found_page   = "index.html" # SPA — all 404s serve index.html
  }
}

# Allow public read on frontend bucket (static assets served via CDN)
resource "google_storage_bucket_iam_member" "frontend_public_read" {
  bucket = google_storage_bucket.frontend_assets.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

output "scan_files_bucket" {
  value = google_storage_bucket.scan_files.name
}

output "frontend_bucket" {
  value = google_storage_bucket.frontend_assets.name
}
```

### terraform/secrets.tf

```hcl
# Secret Manager secrets
# Note: No db-password secret — database authentication uses Cloud IAM, not passwords.

resource "google_secret_manager_secret" "redis_url" {
  secret_id = "redis-url"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "sentry_dsn" {
  secret_id = "sentry-dsn"
  project   = var.project_id

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "jwt-secret"
  project   = var.project_id

  replication {
    auto {}
  }
}

# Secret values must be populated manually or via a separate secure pipeline.
# Example (run once, outside Terraform):
#   echo -n "redis://10.0.16.X:6379/0" | \
#     gcloud secrets versions add redis-url --data-file=-
#
# Never put secret values in Terraform — they would be stored in plain text in state.
```

### terraform/iam.tf

```hcl
# API service account
resource "google_service_account" "hakuna_api" {
  account_id   = "hakuna-api"
  display_name = "Hakuna API Service Account"
  project      = var.project_id
}

# Worker service account
resource "google_service_account" "hakuna_worker" {
  account_id   = "hakuna-worker"
  display_name = "Hakuna Worker Service Account"
  project      = var.project_id
}

# --- API service account roles ---

resource "google_project_iam_member" "api_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

resource "google_project_iam_member" "api_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

resource "google_project_iam_member" "api_storage_admin" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

# CRITICAL: Required for GCS V4 signed URL generation.
# The API service account must be able to sign blobs using its own key.
# Without this, google.auth.exceptions.TransportError is raised at runtime.
resource "google_service_account_iam_member" "api_token_creator_self" {
  service_account_id = google_service_account.hakuna_api.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.hakuna_api.email}"
}

resource "google_project_iam_member" "api_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

resource "google_project_iam_member" "api_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

# IAM database auth — allows the service account identity to authenticate to Cloud SQL
resource "google_project_iam_member" "api_cloudsql_instance_user" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.hakuna_api.email}"
}

# --- Worker service account roles ---

resource "google_project_iam_member" "worker_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}

resource "google_project_iam_member" "worker_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}

# Workers read scan files from GCS — they do not write
resource "google_project_iam_member" "worker_storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}

resource "google_project_iam_member" "worker_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}

resource "google_project_iam_member" "worker_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}

resource "google_project_iam_member" "worker_cloudsql_instance_user" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:${google_service_account.hakuna_worker.email}"
}
```

### terraform/cloudrun\_api.tf

```hcl
resource "google_cloud_run_v2_service" "api" {
  name     = "hakuna-api"
  location = var.region
  project  = var.project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.hakuna_api.email

    scaling {
      min_instance_count = 1  # Tier 2: set to 2
      max_instance_count = 10 # Tier 1: can cap at 5
    }

    vpc_access {
      connector = google_vpc_access_connector.hakuna.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    # Faster cold starts — extra CPU during container startup
    annotations = {
      "run.googleapis.com/startup-cpu-boost" = "true"
    }

    containers {
      # --- Application container ---
      name  = "api"
      image = "${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest"

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle = true # Release CPU between requests (request-based billing)
        startup_cpu_boost = true
      }

      ports {
        container_port = 8000
      }

      env {
        name  = "ENV"
        value = "production"
      }

      env {
        name  = "CELERY_TASK_ALWAYS_EAGER"
        value = "false"
      }

      env {
        name  = "GCS_BUCKET"
        value = google_storage_bucket.scan_files.name
      }

      env {
        name  = "GCS_PROJECT"
        value = var.project_id
      }

      # IAM auth — no password in the connection string
      # Port 5432 = primary (via Auth Proxy sidecar)
      env {
        name  = "DATABASE_URL"
        value = "postgresql+asyncpg://hakuna-api@localhost:5432/hakuna"
      }

      # Port 5433 = read replica (via Auth Proxy sidecar)
      env {
        name  = "DATABASE_REPLICA_URL"
        value = "postgresql+asyncpg://hakuna-api@localhost:5433/hakuna"
      }

      env {
        name = "REDIS_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "SENTRY_DSN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.sentry_dsn.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 10
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        period_seconds    = 30
        failure_threshold = 3
      }
    }

    containers {
      # --- Cloud SQL Auth Proxy sidecar ---
      name  = "cloud-sql-proxy"
      image = "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2"

      args = [
        "--auto-iam-authn",
        "--port=5432",
        "${var.project_id}:${var.region}:hakuna-postgres",
        "--port=5433",
        "${var.project_id}:${var.region}:hakuna-postgres-replica",
      ]

      resources {
        limits = {
          cpu    = "0.5"
          memory = "256Mi"
        }
      }

      # Proxy must be ready before the application container starts
      depends_on = ["api"]
    }
  }

  depends_on = [
    google_project_iam_member.api_cloudsql_client,
    google_project_iam_member.api_secret_accessor,
    google_vpc_access_connector.hakuna,
  ]
}

output "api_url" {
  value = google_cloud_run_v2_service.api.uri
}
```

### terraform/compute\_workers.tf

```hcl
locals {
  worker_startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail

    # Install Docker
    apt-get update -qq
    apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Install Cloud SQL Auth Proxy
    curl -fsSL "https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.11.0/cloud-sql-proxy.linux.amd64" -o /usr/local/bin/cloud-sql-proxy
    chmod +x /usr/local/bin/cloud-sql-proxy

    # Create application directory
    mkdir -p /opt/hakuna

    # Authenticate Docker to Artifact Registry
    gcloud auth configure-docker ${var.region}-docker.pkg.dev --quiet

    # Write docker-compose file for workers
    cat > /opt/hakuna/docker-compose.workers.yml <<'COMPOSE'
    version: "3.9"
    services:
      cloud-sql-proxy:
        image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2
        command:
          - "--auto-iam-authn"
          - "--port=5432"
          - "${var.project_id}:${var.region}:hakuna-postgres"
        restart: unless-stopped
        network_mode: host

      worker-sync:
        image: ${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest
        command: celery -A app.worker worker -Q sync -c 4 --loglevel=info
        env_file: /opt/hakuna/.env.prod
        restart: unless-stopped
        depends_on: [cloud-sql-proxy]

      worker-import:
        image: ${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest
        command: celery -A app.worker worker -Q import -c 2 --loglevel=info
        env_file: /opt/hakuna/.env.prod
        restart: unless-stopped
        depends_on: [cloud-sql-proxy]

      worker-llm:
        image: ${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest
        command: celery -A app.worker worker -Q llm -P gevent -c 50 --loglevel=info
        env_file: /opt/hakuna/.env.prod
        restart: unless-stopped
        depends_on: [cloud-sql-proxy]

      worker-notify:
        image: ${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest
        command: celery -A app.worker worker -Q notify -c 4 --loglevel=info
        env_file: /opt/hakuna/.env.prod
        restart: unless-stopped
        depends_on: [cloud-sql-proxy]

      worker-beat:
        image: ${var.region}-docker.pkg.dev/${var.project_id}/hakuna/api:latest
        command: celery -A app.worker beat --scheduler redbeat.RedBeatScheduler --loglevel=info
        env_file: /opt/hakuna/.env.prod
        restart: unless-stopped
        depends_on: [cloud-sql-proxy]
    COMPOSE

    # Write systemd unit
    cat > /etc/systemd/system/hakuna-workers.service <<'UNIT'
    [Unit]
    Description=Hakuna Workers
    After=docker.service
    Requires=docker.service

    [Service]
    WorkingDirectory=/opt/hakuna
    ExecStart=/usr/bin/docker compose -f docker-compose.workers.yml up
    ExecStop=/usr/bin/docker compose -f docker-compose.workers.yml down
    Restart=always
    RestartSec=10
    StandardOutput=journal
    StandardError=journal

    [Install]
    WantedBy=multi-user.target
    UNIT

    systemctl daemon-reload
    systemctl enable hakuna-workers

    # Note: The service will not start until /opt/hakuna/.env.prod is populated.
    # Populate it via:
    #   gcloud compute ssh hakuna-workers --tunnel-through-iap -- \
    #     'sudo tee /opt/hakuna/.env.prod < local-env-file'
    # Then: sudo systemctl start hakuna-workers
  EOT
}

resource "google_compute_instance" "workers" {
  name         = "hakuna-workers"
  machine_type = "e2-standard-2" # Tier 2: upgrade to e2-standard-4
  zone         = "${var.region}-b"
  project      = var.project_id

  tags = ["allow-internal", "allow-ssh-iap"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 30
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = google_compute_network.hakuna.id
    subnetwork = google_compute_subnetwork.hakuna.id
    # No access_config block = no public IP
  }

  metadata = {
    startup-script = local.worker_startup_script
  }

  service_account {
    email  = google_service_account.hakuna_worker.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  lifecycle {
    ignore_changes = [metadata["startup-script"]] # Only run on initial creation
  }
}

output "workers_instance_name" {
  value = google_compute_instance.workers.name
}

output "workers_ssh_command" {
  value = "gcloud compute ssh ${google_compute_instance.workers.name} --tunnel-through-iap --zone=${google_compute_instance.workers.zone} --project=${var.project_id}"
}
```

### terraform/scheduler.tf

```hcl
# Cloud Scheduler: Beat heartbeat ping every 5 minutes
# Purpose: Detect if Celery Beat has crashed and is no longer processing schedules.
# Beat runs on the worker VM inside Docker — if the container exits and fails to restart,
# periodic tasks stop silently. This scheduler job provides an observable signal.
resource "google_cloud_scheduler_job" "beat_ping" {
  name             = "hakuna-beat-ping"
  description      = "Heartbeat check for Celery Beat scheduler"
  schedule         = "*/5 * * * *"
  time_zone        = "UTC"
  attempt_deadline = "30s"
  region           = var.region
  project          = var.project_id

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.api.uri}/_internal/beat-ping"

    headers = {
      "Content-Type" = "application/json"
    }

    body = base64encode(jsonencode({
      source = "cloud-scheduler"
    }))

    oidc_token {
      service_account_email = google_service_account.hakuna_api.email
      audience              = google_cloud_run_v2_service.api.uri
    }
  }
}

# Monitoring alert: fire if no Beat heartbeat received for 10 minutes
# This requires the API to emit a custom metric when it receives the beat-ping.
# Metric name: custom.googleapis.com/hakuna/beat_heartbeat
resource "google_monitoring_alert_policy" "beat_heartbeat_missing" {
  display_name = "Hakuna: Beat Heartbeat Missing"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "No beat heartbeat for 10 minutes"

    condition_absent {
      filter   = "metric.type=\"custom.googleapis.com/hakuna/beat_heartbeat\" resource.type=\"global\""
      duration = "600s" # 10 minutes

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  notification_channels = [] # Populate with your notification channel IDs
}
```

### terraform/loadbalancer.tf

```hcl
# Global external HTTPS load balancer
# URL routing: /api/* → Cloud Run, /* → GCS static bucket (with CDN)

# Static IP for the load balancer
resource "google_compute_global_address" "lb" {
  name    = "hakuna-lb-ip"
  project = var.project_id
}

# Managed SSL certificate
resource "google_compute_managed_ssl_certificate" "hakuna" {
  name    = "hakuna-ssl-cert"
  project = var.project_id

  managed {
    domains = [var.app_domain]
  }
}

# --- Backend: GCS static bucket (with CDN) ---

resource "google_compute_backend_bucket" "frontend" {
  name        = "hakuna-frontend-backend"
  description = "Frontend SPA static assets"
  bucket_name = google_storage_bucket.frontend_assets.name
  project     = var.project_id
  enable_cdn  = true

  cdn_policy {
    cache_mode        = "CACHE_ALL_STATIC"
    default_ttl       = 3600
    max_ttl           = 86400
    client_ttl        = 3600
    negative_caching  = true
    serve_while_stale = 86400
  }
}

# --- Backend: Cloud Run API ---

resource "google_compute_region_network_endpoint_group" "api" {
  name                  = "hakuna-api-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  project               = var.project_id

  cloud_run {
    service = google_cloud_run_v2_service.api.name
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "hakuna-api-backend"
  project               = var.project_id
  protocol              = "HTTPS"
  port_name             = "https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  enable_cdn            = false # Never cache API responses

  backend {
    group = google_compute_region_network_endpoint_group.api.id
  }

  log_config {
    enable      = true
    sample_rate = 0.1
  }
}

# --- URL map ---

resource "google_compute_url_map" "hakuna" {
  name            = "hakuna-url-map"
  project         = var.project_id
  default_service = google_compute_backend_bucket.frontend.id

  host_rule {
    hosts        = [var.app_domain]
    path_matcher = "all-paths"
  }

  path_matcher {
    name            = "all-paths"
    default_service = google_compute_backend_bucket.frontend.id

    path_rule {
      paths   = ["/api/*", "/api"]
      service = google_compute_backend_service.api.id
    }

    path_rule {
      paths   = ["/_internal/*"]
      service = google_compute_backend_service.api.id
    }
  }
}

# HTTP → HTTPS redirect
resource "google_compute_url_map" "https_redirect" {
  name    = "hakuna-https-redirect"
  project = var.project_id

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

# --- HTTPS proxy ---

resource "google_compute_target_https_proxy" "hakuna" {
  name             = "hakuna-https-proxy"
  project          = var.project_id
  url_map          = google_compute_url_map.hakuna.id
  ssl_certificates = [google_compute_managed_ssl_certificate.hakuna.id]
}

# --- HTTP proxy (for redirect) ---

resource "google_compute_target_http_proxy" "redirect" {
  name    = "hakuna-http-redirect-proxy"
  project = var.project_id
  url_map = google_compute_url_map.https_redirect.id
}

# --- Forwarding rules ---

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "hakuna-https-forwarding"
  project               = var.project_id
  target                = google_compute_target_https_proxy.hakuna.id
  port_range            = "443"
  ip_address            = google_compute_global_address.lb.address
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "hakuna-http-forwarding"
  project               = var.project_id
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.lb.address
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

output "load_balancer_ip" {
  value       = google_compute_global_address.lb.address
  description = "Point your DNS A record to this IP"
}
```

### terraform/artifact\_registry.tf

```hcl
resource "google_artifact_registry_repository" "hakuna" {
  location      = var.region
  repository_id = "hakuna"
  description   = "Hakuna Docker images"
  format        = "DOCKER"
  project       = var.project_id

  cleanup_policies {
    id     = "keep-last-10"
    action = "KEEP"

    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"

    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 days
    }
  }
}

output "docker_registry" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.hakuna.repository_id}"
}
```

### terraform/monitoring.tf

```hcl
# Notification channel — populate email before applying
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Hakuna Alerts Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = "alerts@example.com" # Replace with actual alert destination
  }
}

# 1. API p99 latency > 2000ms for 5 minutes
resource "google_monitoring_alert_policy" "api_latency" {
  display_name = "Hakuna: API p99 Latency High"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run p99 latency > 2s for 5 minutes"

    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"hakuna-api\" AND metric.type=\"run.googleapis.com/request_latencies\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2000

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_PERCENTILE_99"
        group_by_fields      = ["resource.labels.service_name"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}

# 2. Cloud SQL CPU > 80% for 10 minutes
resource "google_monitoring_alert_policy" "cloudsql_cpu" {
  display_name = "Hakuna: Cloud SQL CPU High"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Cloud SQL CPU utilization > 80% for 10 minutes"

    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\" AND resource.labels.database_id=\"${var.project_id}:hakuna-postgres\" AND metric.type=\"cloudsql.googleapis.com/database/cpu/utilization\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "3600s"
  }
}

# 3. Memorystore memory usage > 80%
resource "google_monitoring_alert_policy" "redis_memory" {
  display_name = "Hakuna: Redis Memory High"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Memorystore memory usage ratio > 80%"

    condition_threshold {
      filter          = "resource.type=\"redis_instance\" AND metric.type=\"redis.googleapis.com/stats/memory/usage_ratio\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}

# 4. Cloud Run instance count > 8 (approaching max limit of 10)
resource "google_monitoring_alert_policy" "api_instance_count" {
  display_name = "Hakuna: Cloud Run Approaching Max Instances"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run active instances > 8"

    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"hakuna-api\" AND metric.type=\"run.googleapis.com/container/instance_count\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 8

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.service_name"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}

# 5. Celery queue depth > 500 tasks
# Requires the application to emit a custom metric: custom.googleapis.com/hakuna/celery_queue_depth
# Emit from a lightweight monitoring task or a Prometheus-style exporter running on the worker VM.
resource "google_monitoring_alert_policy" "celery_queue_depth" {
  display_name = "Hakuna: Celery Queue Backlog High"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Celery queue depth > 500 tasks"

    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/hakuna/celery_queue_depth\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}

# Read replica lag > 30 seconds
resource "google_monitoring_alert_policy" "replica_lag" {
  display_name = "Hakuna: Read Replica Lag High"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Cloud SQL replica lag > 30 seconds"

    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\" AND resource.labels.database_id=\"${var.project_id}:hakuna-postgres-replica\" AND metric.type=\"cloudsql.googleapis.com/database/replication/replica_lag\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MAX"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}
```

---

## Local Development

Local development uses Docker Compose to replicate the production data layer (Postgres, Redis, object storage) with no cloud dependencies.

### docker-compose.dev.yml

```yaml
version: "3.9"
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: hakuna
      POSTGRES_PASSWORD: hakuna
      POSTGRES_DB: hakuna
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U hakuna"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru

  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001" # MinIO console
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  postgres_data:
  minio_data:
```

### .env.local

```dotenv
# Database
DATABASE_URL=postgresql+asyncpg://hakuna:hakuna@localhost:5432/hakuna
DATABASE_REPLICA_URL=postgresql+asyncpg://hakuna:hakuna@localhost:5432/hakuna

# Redis
REDIS_URL=redis://localhost:6379/0

# Celery — tasks run inline, no worker process needed
CELERY_TASK_ALWAYS_EAGER=true
CELERY_TASK_EAGER_PROPAGATES=true

# Object storage (MinIO, S3-compatible)
S3_ENDPOINT_URL=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=hakuna-local

# Observability — disabled locally
SENTRY_DSN=
OTEL_EXPORTER_OTLP_ENDPOINT=

# App
ENV=development
JWT_SECRET=dev-secret-not-for-production
```

### start-dev.sh

```bash
#!/bin/bash
set -euo pipefail

echo "Starting local development environment..."

# Start backing services
docker compose -f docker-compose.dev.yml up -d

# Wait for Postgres to be ready
echo "Waiting for Postgres..."
sleep 2

# Run migrations
alembic upgrade head

# Start API in background with hot reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &

# Start frontend dev server
cd frontend && npm run dev
```

---

## Implementation Sequence

The following table maps each architectural feature to the specific app code change and GCP service it depends on. Work in this order — each step builds on the previous one.

| Step | App Change | GCP Service / Notes |
|---|---|---|
| 1 | `docker-compose.dev.yml` + `.env.local` + `start-dev.sh` | Local only — no cloud needed |
| 2 | SQLAlchemy models + Alembic migrations | Cloud SQL (Terraform: `database.tf`) |
| 3 | Async SQLAlchemy sessions (`asyncpg`) + session factory with primary/replica routing | App code change — no new infra |
| 4 | Celery app + `CELERY_TASK_ALWAYS_EAGER=true` locally + task stubs for all 4 queues | Memorystore + Compute Engine workers (Terraform: `redis.tf`, `compute_workers.tf`) |
| 5 | GCS presigned upload endpoint (`POST /api/scans/upload-url`) + frontend upload client | Cloud Storage (Terraform: `storage.tf`) |
| 6 | Cloud SQL Auth Proxy connection string (no password) | Sidecar in Cloud Run + on worker VM (Terraform: `cloudrun_api.tf`, `compute_workers.tf`) |
| 7 | `tenacity` circuit breakers on all external API calls (scanners, LLMs, Jira) | App code change — no new infra |
| 8 | Per-tenant rate limiting middleware (Redis-backed, `ratelimit:{org_id}:{endpoint}`) | Uses existing Memorystore |
| 9 | OpenTelemetry SDK init + `opentelemetry-exporter-gcp-trace` | No new infra — Cloud Trace is auto-enabled |
| 10 | Read replica session routing — dashboards/reports use `DATABASE_REPLICA_URL` | Cloud SQL replica already provisioned in Terraform |

---

## What to Defer

These components are intentionally omitted from the initial build. Each has a clear trigger condition for when to add it.

| Component | Defer Until | Reason |
|---|---|---|
| Cloud SQL HA (REGIONAL) | 50+ tenants | $150/mo premium. Single-zone risk is acceptable for small customer count. Change `availability_type = "REGIONAL"` in `database.tf`. |
| Read replica | Dashboards are measurably slow (query time > 1s) | Adds ~$60/mo. Provision it, but don't route to it until needed. |
| Memorystore Standard HA | Redis downtime becomes a support incident | 2× the cost. Acceptable for early customers to experience brief Redis restarts. |
| Cloud Armor WAF | Security audit requirement or DDoS incident | $50+/mo plus rule maintenance. Add it in `loadbalancer.tf`. |
| 2nd worker VM | Queue depth consistently > 200 tasks | Monitor queue depth alert first. Add a second VM with the same Terraform resource. |
| Cloud SQL Enterprise Plus | Connection count approaches 200 or IAM auth latency becomes a concern | Upgrade is a single flag change in `database.tf`. |
| Multi-region | Data residency requirement or 500+ tenants | Major architectural jump. Requires active-passive or active-active topology design. |
| Flower (Celery monitoring UI) | Debugging worker queues in production becomes painful | Deploy as an additional Docker Compose service on the worker VM, behind IAP. |
| VPC Service Controls | Compliance requirement (SOC 2 Type II scope) | Complex to set up correctly — defer until audit requires it. |

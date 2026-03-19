# Migration Plan: Render Free → GCP Production

**Goal:** Move from SQLite + Render Free to a production-safe GCP setup that scales to 300 customers.
**Credits:** $22K GCP credits expiring Nov 2027 — infrastructure is free for ~20 months.

---

## Phase 1 — Infrastructure Move (This Week, ~3–4 days)

**Goal:** Fix the two production blockers (SQLite data loss, Render ephemerality) with **minimal app code changes**.

### What changes
| Layer | Before | After |
|---|---|---|
| Database | SQLite (ephemeral) | Cloud SQL PostgreSQL 16 (persistent, backups, PITR) |
| Hosting | Render Free (spin-down, data loss) | Cloud Run (always-on min 1, HTTPS, auto-scale) |
| Scheduler | APScheduler in-process | APScheduler in-process (unchanged for now) |
| File storage | Local disk | GCS bucket (set up now, used in Phase 2) |
| Redis | None | Memorystore Basic 1GB (set up now, used in Phase 2) |
| Secrets | Env vars | Secret Manager |

### What does NOT change
- All application code (no refactoring)
- APScheduler (stays in-process)
- Synchronous SQLAlchemy sessions (stays sync)
- No Celery yet

### App code changes required (minimal)

**1. Add asyncpg driver**
```bash
pip install asyncpg
# Add to requirements.txt: asyncpg>=0.29.0
```

**2. Update database.py — connection string only**
```python
# Before
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/nessus_remediation.db")

# After — no other changes needed
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/nessus_remediation.db")
# Cloud Run sets DATABASE_URL=postgresql+asyncpg://hakuna:<pass>@localhost:5432/hakuna
```

**3. Run Alembic setup (one-time)**
```bash
pip install alembic
alembic init alembic
# Configure alembic/env.py to use your models
alembic revision --autogenerate -m "initial_schema"
alembic upgrade head   # run against Cloud SQL
```

**4. Build and push Docker image**
```dockerfile
# Dockerfile (if not exists)
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```
```bash
gcloud auth configure-docker me-west1-docker.pkg.dev
docker build -t me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest .
docker push me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest
```

### Deployment steps

```bash
# 1. One-time GCP setup
gcloud projects create hakuna-prod
gcloud billing accounts link hakuna-prod --billing-account=<YOUR_BILLING_ACCOUNT>
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  storage.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  vpcaccess.googleapis.com \
  servicenetworking.googleapis.com \
  cloudtrace.googleapis.com \
  compute.googleapis.com \
  --project=hakuna-prod

# 2. Create GCS bucket for Terraform state
gsutil mb -p hakuna-prod -l me-west1 gs://hakuna-terraform-state

# 3. Push initial Docker image (Terraform needs it to exist)
docker build -t me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest ./backend
docker push me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest
# Note: Artifact Registry must exist first — bootstrap with gcloud or apply artifact_registry.tf separately

# 4. Apply Terraform
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply

# 5. Run database migrations
# Get Cloud SQL private IP from terraform output
# Connect via Cloud SQL Auth Proxy locally:
cloud-sql-proxy hakuna-prod:me-west1:hakuna-pg-primary --port=5432 &
DATABASE_URL=postgresql+asyncpg://hakuna:<password>@localhost:5432/hakuna \
  alembic upgrade head

# 6. Point your domain DNS to the Load Balancer IP
# terraform output load_balancer_ip
```

### Cost (Phase 1, me-west1)
| Service | Monthly |
|---|---|
| Cloud Run API (request-based, avg 1.5 instances) | ~$80 |
| Cloud SQL PostgreSQL (single zonal, 2vCPU/4GB) | ~$95 |
| Memorystore Redis Basic 1GB | ~$52 |
| GCS bucket | ~$2 |
| Load Balancer + CDN | ~$22 |
| VPC Connector | ~$16 |
| Secret Manager + Artifact Registry | ~$5 |
| **Total** | **~$272/mo** |

All covered by GCP credits (~81 months of runway at this cost).

---

## Phase 2 — Worker Layer (At 5+ paying customers, ~1 week)

**Goal:** Replace APScheduler with Celery for reliable background jobs. Unblock scanner integrations from competing with API threads.

### What changes
| Layer | Before (Phase 1) | After (Phase 2) |
|---|---|---|
| Scheduler | APScheduler in-process | Celery Beat (redbeat) on VM |
| Background jobs | Blocking API thread pool | 4 isolated Celery queues |
| Compute for workers | None (runs in API) | Compute Engine e2-standard-2 |
| Async DB | Sync SQLAlchemy | Async SQLAlchemy (asyncpg) |
| Redis | Set up, unused | Celery broker + redbeat store |

### App code changes

**1. Add Celery**
```bash
pip install celery[redis] redbeat gevent
```

**2. Create celery_app.py**
```python
from celery import Celery
import os

app = Celery('hakuna', broker=os.getenv('REDIS_URL'), backend=None)
app.conf.update(
    task_serializer='json',
    result_backend=None,          # no result storage = no Redis OOM
    task_ignore_result=True,
    task_always_eager=os.getenv('CELERY_TASK_ALWAYS_EAGER', 'false').lower() == 'true',
    task_eager_propagates=True,
    broker_connection_retry_on_startup=True,
)
CELERYBEAT_SCHEDULER = 'redbeat.RedBeatScheduler'
```

**3. Convert APScheduler jobs to Celery tasks**
```python
# Before (APScheduler)
scheduler.add_job(_run_integration_job, trigger, id=job_id)

# After (Celery task)
@celery_app.task(bind=True, queue='sync')
def run_integration_sync(self, integration_id: int):
    lock_key = f"lock:integration:{integration_id}"
    with redis_client.lock(lock_key, timeout=3600, blocking=False):
        ...  # same logic as before
```

**4. Migrate SQLAlchemy to async (do alongside Celery)**
```python
# Replace create_engine with create_async_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

engine = create_async_engine(os.getenv('DATABASE_URL'), pool_size=5, max_overflow=10)
```

### Infrastructure additions (Terraform)

Add `terraform/compute_workers.tf` — see [deployment-plan-gcp.md](deployment-plan-gcp.md) for full Terraform.

```bash
# docker-compose.workers.yml on the VM
# worker-sync, worker-import, worker-llm (gevent), worker-notify, worker-beat
# Cloud SQL Auth Proxy as a container alongside workers

terraform apply  # picks up new compute_workers.tf
```

### Phase 2 cost additions
| Service | Added Monthly |
|---|---|
| Compute Engine e2-standard-2 | +~$55 |
| **Phase 2 Total** | **~$327/mo** |

---

## Phase 3 — Scale Hardening (At 20+ customers, ongoing)

**Goal:** Production resilience, observability, and performance headroom for 150–300 customers.

### Changes, in priority order

#### 3a. Presigned upload flow (unblocks large scan files)
Large Nessus XML files (up to 2GB) currently route through the API — memory spikes.

App changes:
```python
# New endpoint: POST /api/scans/upload-url
# Returns V4 signed GCS URL, browser uploads direct
from google.cloud import storage
def generate_upload_url(filename: str, org_id: int) -> str:
    client = storage.Client()
    bucket = client.bucket(os.getenv('GCS_BUCKET'))
    blob = bucket.blob(f"uploads/{org_id}/{filename}")
    return blob.generate_signed_url(expiration=900, method='PUT', version='v4')
```

No Terraform changes — GCS bucket already exists.

#### 3b. Per-tenant rate limiting
```python
# middleware/rate_limit.py
from fastapi import Request
import redis.asyncio as aioredis

async def rate_limit_middleware(request: Request, call_next):
    org_id = request.state.org_id
    key = f"ratelimit:{org_id}:{request.url.path}"
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, 60)
    if count > 100:  # 100 req/min per org
        raise HTTPException(429, "Rate limit exceeded")
    return await call_next(request)
```

#### 3c. Circuit breakers on external calls
```bash
pip install tenacity
```
```python
from tenacity import retry, stop_after_attempt, wait_exponential, wait_random

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=30) + wait_random(0, 2),
    reraise=True,
)
async def call_nessus_api(...): ...
```

#### 3d. OpenTelemetry → Cloud Trace
```bash
pip install opentelemetry-sdk opentelemetry-exporter-gcp-trace opentelemetry-instrumentation-fastapi opentelemetry-instrumentation-sqlalchemy
```
```python
# main.py
from opentelemetry import trace
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
trace.set_tracer_provider(provider)
```

#### 3e. Infrastructure upgrades (Terraform flag changes only)

**Cloud SQL → HA:**
```hcl
# database.tf — change one line
availability_type = "REGIONAL"   # was "ZONAL"
```

**Add read replica:**
```hcl
# Uncomment the replica resource in database.tf
# Add DATABASE_REPLICA_URL to Cloud Run env vars
```

**Memorystore → Standard HA:**
```hcl
# redis.tf — change one line
tier = "STANDARD_HA"   # was "BASIC"
```

### Phase 3 cost additions
| Upgrade | Added Monthly |
|---|---|
| Cloud SQL HA (REGIONAL) | +~$100 |
| Cloud SQL Read Replica | +~$60 |
| Memorystore Standard HA | +~$80 |
| **Phase 3 Total** | **~$567/mo** |

---

## Full Cost Timeline

| Phase | Trigger | Monthly Cost | Per Customer |
|---|---|---|---|
| Phase 1 | Now | ~$272 | — |
| Phase 2 | 5+ paying customers | ~$327 | ~$65 (at 5) |
| Phase 3 | 20+ customers | ~$567 | ~$28 (at 20) |
| Tier 2 growth | 50+ customers | ~$724 | ~$14 (at 50) |
| Tier 3 scale | 150+ customers | ~$1,195 | ~$8 (at 150) |

All covered by $22K credits through Nov 2027.

---

## What to Skip Until You Need It

| Component | Skip Until |
|---|---|
| Cloud SQL HA | 20+ paying customers or first SLA commitment |
| Read replica | Dashboard queries measurably slow |
| Memorystore HA | Redis downtime has actually caused issues |
| Cloud Armor WAF | Security audit or enterprise customer requirement |
| 2nd worker VM | Worker queue depth consistently > 200 |
| Multi-region | Data residency requirement |
| Cloud SQL IAM auth | Phase 2 — replace password auth when you have time |

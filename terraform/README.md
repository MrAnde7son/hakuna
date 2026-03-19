# Terraform — Hakuna GCP Infrastructure (Phase 1)

Deploys the Phase 1 production infrastructure on GCP:
Cloud Run API + Cloud SQL PostgreSQL + Memorystore Redis + GCS + HTTPS Load Balancer + Scanner VM.

See [../docs/migration-plan.md](../docs/migration-plan.md) for the full phased migration plan.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Services Deployed](#services-deployed)
3. [Bootstrap (one-time)](#bootstrap-one-time-before-first-terraform-apply)
4. [Configuration](#configuration)
5. [First Deploy — End-to-End Checklist](#first-deploy--end-to-end-checklist)
6. [Run Database Migrations](#run-database-migrations)
7. [Deploy Frontend](#deploy-frontend)
8. [Verify Scanners](#verify-scanners)
9. [Day-2 Operations](#day-2-operations)
10. [Troubleshooting](#troubleshooting)
11. [File Structure](#file-structure)
12. [Costs](#costs-me-west1-phase-1)
13. [Phase 2 / Phase 3 Upgrade Paths](#phase-2--phase-3-upgrade-paths)

---

## Prerequisites

```bash
# Tools required
brew install terraform google-cloud-sdk

# Authenticate
gcloud auth login
gcloud auth application-default login
```

Also required:
- Docker (to build and push images)
- A registered domain with DNS management access

---

## Services Deployed

| Service | Where | Notes |
|---|---|---|
| FastAPI backend | Cloud Run | Auto-scales, HTTPS, Cloud SQL Auth Proxy sidecar |
| React frontend | GCS + Cloud CDN | Static SPA |
| hakuna-scanner (EASM) | Compute Engine VM `hakuna-scanners` | subfinder, dnsx, naabu, httpx, nmap — needs raw sockets |
| vm-scanner (Nuclei) | Same VM | Nuclei binary, needs Go toolchain |
| PostgreSQL | Cloud SQL | Single zonal Phase 1; `hakuna` + `hakuna_easm` databases |
| Redis | Memorystore | DB0=main API, DB1=vm-scanner, DB2=easm-scanner |

---

## Bootstrap (one-time, before first terraform apply)

These steps must be done manually once — they create resources that Terraform itself needs.

```bash
export PROJECT_ID=hakuna-prod
export REGION=me-west1

# 1. Create the GCP project
gcloud projects create $PROJECT_ID
gcloud config set project $PROJECT_ID

# 2. Link billing (required to enable APIs)
gcloud billing accounts list   # find your billing account ID
gcloud billing projects link $PROJECT_ID --billing-account=BILLING_ACCOUNT_ID

# 3. Enable required APIs
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
  iam.googleapis.com \
  iap.googleapis.com

# 4. Create GCS bucket for Terraform state
gsutil mb -p $PROJECT_ID -l $REGION gs://hakuna-terraform-state
gsutil versioning set on gs://hakuna-terraform-state

# 5. Create Artifact Registry first (needed to push Docker images)
cd terraform
terraform init
terraform apply -target=google_artifact_registry_repository.main

# 6. Build and push all Docker images
# (Cloud Run and the scanner VM both fail if images don't exist at apply time)
gcloud auth configure-docker $REGION-docker.pkg.dev
AR=$REGION-docker.pkg.dev/$PROJECT_ID/hakuna

# Main API
docker build -t $AR/api:latest ./backend
docker push $AR/api:latest

# EASM scanner
docker build -t $AR/hakuna-scanner:latest ./hakuna-scanner
docker push $AR/hakuna-scanner:latest

# VM scanner
docker build -t $AR/vm-scanner:latest ./hakuna-vm-scanner
docker push $AR/vm-scanner:latest
```

---

## Configuration

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
project_id = "hakuna-prod"
region     = "me-west1"
zone       = "me-west1-b"

# Your app domain — must have DNS pointing to the load balancer IP after first apply
app_domain = "app.yourdomain.com"

# Docker image — push this before running terraform apply
api_image = "me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest"

# Generate with: openssl rand -hex 32
jwt_secret = "replace-with-your-secret"

# Optional — leave empty to disable Sentry
sentry_dsn = ""

# Optional OSINT API keys for EASM scanner
# Scanner degrades gracefully without these — uses only passive/free sources
shodan_api_key    = ""
censys_api_id     = ""
censys_api_secret = ""
```

> `terraform.tfvars` is gitignored — never commit it.

Add to `.gitignore` if not already present:

```
terraform/terraform.tfvars
terraform/.terraform/
terraform/*.tfstate
terraform/*.tfstate.backup
terraform/.terraform.lock.hcl
```

---

## First Deploy — End-to-End Checklist

Run these steps in order on the very first deployment.

```bash
cd terraform

# Step 1 — Preview what will be created (~70 resources)
terraform plan

# Step 2 — Apply (~10–20 minutes; Cloud SQL is the slow part)
terraform apply

# Step 3 — Note the load balancer IP from outputs
terraform output load_balancer_ip
```

```bash
# Step 4 — Point DNS
# Create an A record: app.yourdomain.com → <load_balancer_ip>
# SSL cert provisioning starts automatically once DNS resolves (takes 10–20 min)
# Check cert status:
gcloud compute ssl-certificates describe hakuna-ssl-cert --global --format="get(managed.status)"
```

```bash
# Step 5 — Run main app database migrations (see section below)

# Step 6 — Run EASM scanner migrations (see section below)

# Step 7 — Deploy frontend (see section below)

# Step 8 — Verify health
curl https://app.yourdomain.com/api/health
```

---

## Run Database Migrations

Run after the first apply, and after every schema change.

### Main App Migrations

```bash
# Install Cloud SQL Auth Proxy (macOS)
curl -o cloud-sql-proxy https://storage.googleapis.com/cloud-sql-connectors/cloud-sql-proxy/v2.13.0/cloud-sql-proxy.darwin.amd64
chmod +x cloud-sql-proxy

# Get connection details
CONNECTION_NAME=$(terraform output -raw cloud_sql_connection_name)
DB_PASS=$(gcloud secrets versions access latest --secret=hakuna-db-password)

# Start proxy (background)
./cloud-sql-proxy $CONNECTION_NAME --port=5432 &

# Run migrations
DATABASE_URL="postgresql+asyncpg://hakuna:$DB_PASS@localhost:5432/hakuna" \
  alembic upgrade head

# Stop proxy
kill %1
```

### EASM Scanner Migrations

Run directly on the scanner VM (the EASM database is only accessible from within the VPC):

```bash
gcloud compute ssh hakuna-scanners --zone=me-west1-b --tunnel-through-iap \
  --command='cd /opt/hakuna-scanners && sudo docker compose exec easm-api alembic upgrade head'
```

---

## Deploy Frontend

```bash
cd frontend
npm run build

# Sync to GCS
gsutil -m rsync -r -d ./dist gs://$(cd ../terraform && terraform output -raw frontend_bucket)

# Invalidate CDN cache
gcloud compute url-maps invalidate-cdn-cache hakuna-url-map \
  --path "/*" \
  --global
```

---

## Verify Scanners

```bash
# SSH to scanner VM via IAP (no public IP needed)
gcloud compute ssh hakuna-scanners --zone=me-west1-b --tunnel-through-iap

# On the VM — check startup log (run once after first boot)
sudo tail -f /var/log/startup-script.log

# Check all containers are running (should show 7 containers)
cd /opt/hakuna-scanners
sudo docker compose ps

# View logs for a specific service
sudo docker compose logs -f easm-api
sudo docker compose logs -f vm-api
sudo docker compose logs -f easm-worker
sudo docker compose logs -f vm-worker
```

Expected containers: `cloud-sql-proxy`, `easm-api`, `easm-worker`, `easm-beat`, `vm-api`, `vm-worker`, `vm-beat`

---

## Day-2 Operations

### Update the API (after backend code changes)

```bash
export REGION=me-west1
export PROJECT_ID=hakuna-prod
AR=$REGION-docker.pkg.dev/$PROJECT_ID/hakuna

# Build and push
docker build -t $AR/api:latest ./backend
docker push $AR/api:latest

# Force immediate rollout (Cloud Run picks up new image on next deploy)
gcloud run deploy hakuna-api \
  --image=$AR/api:latest \
  --region=$REGION
```

### Update Scanner Images (after scanner code changes)

```bash
export REGION=me-west1
export PROJECT_ID=hakuna-prod
AR=$REGION-docker.pkg.dev/$PROJECT_ID/hakuna

# Build and push updated images
docker build -t $AR/hakuna-scanner:latest ./hakuna-scanner
docker push $AR/hakuna-scanner:latest

docker build -t $AR/vm-scanner:latest ./hakuna-vm-scanner
docker push $AR/vm-scanner:latest

# Pull and restart on the VM
gcloud compute ssh hakuna-scanners --zone=me-west1-b --tunnel-through-iap \
  --command='cd /opt/hakuna-scanners && sudo docker compose pull && sudo docker compose up -d'
```

### Update Frontend

```bash
cd frontend
npm run build
gsutil -m rsync -r -d ./dist gs://$(cd ../terraform && terraform output -raw frontend_bucket)
gcloud compute url-maps invalidate-cdn-cache hakuna-url-map --path "/*" --global
```

### Rotate Secrets

```bash
# Rotate JWT secret
NEW_SECRET=$(openssl rand -hex 32)
echo -n "$NEW_SECRET" | gcloud secrets versions add hakuna-jwt-secret --data-file=-

# Cloud Run picks up the new version on next instance restart.
# To force immediate rotation, redeploy:
gcloud run deploy hakuna-api --image=CURRENT_IMAGE --region=me-west1
```

### Scale Cloud Run

```bash
# Temporary manual scale (e.g., before a known traffic spike)
gcloud run services update hakuna-api \
  --min-instances=2 \
  --max-instances=10 \
  --region=me-west1

# Or update terraform.tfvars and re-apply for a permanent change
```

---

## Troubleshooting

### SSL cert stuck in PROVISIONING

DNS must resolve to the load balancer IP before provisioning starts.

```bash
# Check if DNS has propagated
dig +short app.yourdomain.com

# Check cert status
gcloud compute ssl-certificates describe hakuna-ssl-cert --global \
  --format="get(managed.status,managed.domainStatus)"
```

Provisioning can take up to 30 minutes after DNS resolves.

### Cloud Run fails to start

```bash
# View recent logs
gcloud run services logs read hakuna-api --region=me-west1 --limit=50

# Common causes:
# - Cloud SQL Auth Proxy sidecar not ready: check startup probe logs
# - Secret Manager access denied: verify API SA has secretmanager.secretAccessor
# - DATABASE_URL connection refused: proxy starts on 127.0.0.1:5432 — takes ~10s
```

### Scanner VM not starting containers

```bash
gcloud compute ssh hakuna-scanners --zone=me-west1-b --tunnel-through-iap

# Check startup script log
sudo tail -100 /var/log/startup-script.log

# Check systemd service
sudo systemctl status hakuna-scanners

# Manually restart
cd /opt/hakuna-scanners
sudo docker compose up -d

# Common causes:
# - Docker images not pushed before terraform apply: push images and re-run docker compose pull
# - Secret Manager permission denied: check scanner SA roles
# - Cloud SQL proxy not connecting: verify cloud SQL instance is running
```

### Database connection refused

```bash
# Verify Cloud SQL instance is running
gcloud sql instances describe hakuna-pg --format="get(state)"

# Check if VPC connector is ready
gcloud compute networks vpc-access connectors describe hakuna-connector \
  --region=me-west1 --format="get(state)"
```

### `terraform apply` fails on Cloud SQL

Cloud SQL provisioning can time out on slow days. Run again — Terraform is idempotent:

```bash
terraform apply
```

If `deletion_protection` blocks a destroy:

```bash
# Must disable deletion protection before destroy
terraform apply -var="deletion_protection=false"  # if you add this var
# Or manually in Cloud Console: SQL > Instance > Edit > uncheck deletion protection
```

### Check all outputs

```bash
terraform output
```

---

## File Structure

```
terraform/
├── providers.tf          # GCP provider, GCS backend, required versions
├── variables.tf          # Input variables with descriptions and defaults
├── network.tf            # VPC, subnet, private service connection, VPC connector, NAT, firewall
├── database.tf           # Cloud SQL PostgreSQL 16 (Phase 1: single zonal)
├── database_scanner.tf   # hakuna_easm database + hakuna_scanner user
├── redis.tf              # Memorystore Redis 7 (Phase 1: Basic tier)
├── storage.tf            # GCS buckets: scan files + frontend static assets
├── artifact_registry.tf  # Docker image registry
├── iam.tf                # API service account and IAM role bindings
├── iam_scanner.tf        # Scanner service account and IAM role bindings
├── secrets.tf            # Secret Manager: db password, redis URL, JWT secret, Sentry DSN
├── secrets_scanner.tf    # Secret Manager: scanner DB password, Shodan/Censys API keys
├── cloudrun_api.tf       # Cloud Run v2 service + Cloud SQL Auth Proxy sidecar
├── compute_scanners.tf   # Scanner VM with Docker Compose (EASM + Nuclei)
├── loadbalancer.tf       # Global HTTPS LB, Cloud CDN, URL routing, HTTP redirect
├── outputs.tf            # Key outputs: LB IP, connection names, next steps
└── terraform.tfvars      # Your values — gitignored, copy from .example
```

---

## Costs (me-west1, Phase 1)

| Resource | ~Monthly |
|---|---|
| Cloud Run API | ~$80 |
| Cloud SQL (single zonal, 2 databases) | ~$95 |
| Memorystore Redis Basic 1GB | ~$52 |
| Compute Engine e2-standard-4 (scanners) | ~$110 |
| Load Balancer + CDN | ~$22 |
| VPC Connector | ~$16 |
| GCS, Secrets, Registry | ~$7 |
| **Total** | **~$382/mo** |

Covered by GCP credits (~57 months of runway at this rate).

---

## Phase 2 / Phase 3 Upgrade Paths

### Phase 2 — Celery Workers (when async tasks are slow)

Uncomment in the following files:
- `iam.tf` — `google_service_account.worker` and its roles
- `database.tf` — read replica resource
- Add `compute_workers.tf` — Compute Engine VM with Docker Compose
- `cloudrun_api.tf` — change `CELERY_TASK_ALWAYS_EAGER` from `"true"` to `"false"`

### Phase 3 — High Availability (when uptime SLA matters)

- `database.tf` — change `availability_type = "ZONAL"` → `"REGIONAL"`
- `redis.tf` — change `tier = "BASIC"` → `"STANDARD_HA"`
- `cloudrun_api.tf` — uncomment read replica env var and proxy arg

See [../docs/migration-plan.md](../docs/migration-plan.md) for full Phase 2 and Phase 3 instructions.

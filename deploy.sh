#!/usr/bin/env bash
# deploy.sh — Build and deploy Hakuna to GCP
#
# Usage:
#   ./deploy.sh [options]
#
# Options:
#   --all           Run all steps (default if no flags given)
#   --api           Build & push API image, update Cloud Run
#   --scanners      Build & push scanner images (hakuna-scanner + vm-scanner)
#   --frontend      Build React app and sync to GCS
#   --infra         Run terraform apply (use for infra changes)
#   --migrate       Run standalone Python migration scripts via Cloud SQL Auth Proxy
#   --help          Show this help
#
# Examples:
#   ./deploy.sh                     # Deploy everything
#   ./deploy.sh --api --frontend    # Redeploy only API and frontend
#   ./deploy.sh --infra             # Apply infra changes only
#   ./deploy.sh --scanners          # Rebuild and push scanner images only

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
PROJECT_ID="hakuna-prod-2026"
REGION="me-west1"
ZONE="me-west1-b"
REGISTRY="${REGION}-docker.pkg.dev/${PROJECT_ID}/hakuna"

API_IMAGE="${REGISTRY}/api:latest"
SCANNER_IMAGE="${REGISTRY}/hakuna-scanner:latest"
VM_SCANNER_IMAGE="${REGISTRY}/vm-scanner:latest"

CLOUD_RUN_SERVICE="hakuna-api"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; }
step()    { echo -e "\n${BLUE}══════════════════════════════════════${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}══════════════════════════════════════${NC}"; }

# ── Parse flags ───────────────────────────────────────────────────────────────
DO_API=false
DO_SCANNERS=false
DO_FRONTEND=false
DO_INFRA=false
DO_MIGRATE=false

if [[ $# -eq 0 ]]; then
  DO_API=true; DO_SCANNERS=true; DO_FRONTEND=true
else
  for arg in "$@"; do
    case "$arg" in
      --all)       DO_API=true; DO_SCANNERS=true; DO_FRONTEND=true ;;
      --api)       DO_API=true ;;
      --scanners)  DO_SCANNERS=true ;;
      --frontend)  DO_FRONTEND=true ;;
      --infra)     DO_INFRA=true ;;
      --migrate)   DO_MIGRATE=true ;;
      --help|-h)
        sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
        exit 0 ;;
      *) error "Unknown option: $arg"; exit 1 ;;
    esac
  done
fi

# ── Prerequisite checks ───────────────────────────────────────────────────────
step "Checking prerequisites"

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    error "Required tool not found: $1"
    exit 1
  fi
}

check_cmd docker
check_cmd gcloud
check_cmd gsutil
$DO_INFRA   && check_cmd terraform
$DO_API     && check_cmd terraform
$DO_MIGRATE && check_cmd cloud-sql-proxy

# Verify gcloud is authenticated and project is set
ACTIVE_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
if [[ "$ACTIVE_PROJECT" != "$PROJECT_ID" ]]; then
  warn "Active gcloud project is '${ACTIVE_PROJECT}', switching to '${PROJECT_ID}'"
  gcloud config set project "$PROJECT_ID"
fi

# Configure Docker to use Artifact Registry
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
success "Prerequisites OK"

# ── Helper: get terraform output ──────────────────────────────────────────────
tf_output() {
  (cd "${SCRIPT_DIR}/terraform" && terraform output -raw "$1" 2>/dev/null)
}

# ── Step: Terraform ───────────────────────────────────────────────────────────
if $DO_INFRA; then
  step "Applying Terraform infrastructure"
  cd "${SCRIPT_DIR}/terraform"

  if [[ ! -f "terraform.tfvars" ]]; then
    error "terraform/terraform.tfvars not found. Copy terraform.tfvars.example and fill in your values."
    exit 1
  fi

  terraform init -upgrade -reconfigure
  terraform plan -out=tfplan
  echo ""
  read -r -p "Apply the plan above? [y/N] " confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    terraform apply tfplan
    success "Terraform applied"
  else
    warn "Terraform apply skipped"
  fi
  rm -f tfplan
  cd "${SCRIPT_DIR}"
fi

# ── Step: Build & push API image ──────────────────────────────────────────────
if $DO_API; then
  step "Building API Docker image"
  cd "${SCRIPT_DIR}"

  docker build \
    --platform linux/amd64 \
    -f Dockerfile.prod \
    -t "${API_IMAGE}" \
    .

  info "Pushing ${API_IMAGE}"
  docker push "${API_IMAGE}"
  success "API image pushed"

  # Update Cloud Run to use the new image
  step "Deploying API to Cloud Run"
  # Pull GOOGLE_CLIENT_ID from Secret Manager for Cloud Run
  GOOGLE_CLIENT_ID_VAL="${GOOGLE_CLIENT_ID:-$(gcloud secrets versions access latest --secret="google-oauth-client-id" 2>/dev/null || true)}"

  # Resolve scanner VM private IP from terraform so HAKUNA_SCANNER_URL stays in sync
  SCANNER_VM_IP=$(tf_output scanner_vm_ip 2>/dev/null || true)
  if [[ -n "$SCANNER_VM_IP" ]]; then
    HAKUNA_SCANNER_URL_VAL="http://${SCANNER_VM_IP}:8001"
    VM_SCANNER_URL_VAL="http://${SCANNER_VM_IP}:8002"
    info "Scanner VM IP: ${SCANNER_VM_IP}"
  else
    warn "Could not read scanner_vm_ip from terraform output — HAKUNA_SCANNER_URL will not be updated"
    HAKUNA_SCANNER_URL_VAL=""
    VM_SCANNER_URL_VAL=""
  fi

  ENV_VARS="GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID_VAL}"
  [[ -n "$HAKUNA_SCANNER_URL_VAL" ]] && ENV_VARS="${ENV_VARS},HAKUNA_SCANNER_URL=${HAKUNA_SCANNER_URL_VAL},VM_SCANNER_URL=${VM_SCANNER_URL_VAL}"

  gcloud run services update "${CLOUD_RUN_SERVICE}" \
    --image="${API_IMAGE}" \
    --region="${REGION}" \
    --update-env-vars="${ENV_VARS}" \
    --quiet

  success "Cloud Run service updated"
  CLOUD_RUN_URL=$(gcloud run services describe "${CLOUD_RUN_SERVICE}" \
    --region="${REGION}" --format="value(status.url)" 2>/dev/null || true)
  [[ -n "$CLOUD_RUN_URL" ]] && info "Cloud Run URL: ${CLOUD_RUN_URL}"
fi

# ── Step: Build & push scanner images ─────────────────────────────────────────
if $DO_SCANNERS; then
  step "Building hakuna-scanner (EASM) image"
  cd "${SCRIPT_DIR}"

  docker build \
    --platform linux/amd64 \
    -f hakuna-scanner/Dockerfile \
    -t "${SCANNER_IMAGE}" \
    hakuna-scanner/

  info "Pushing ${SCANNER_IMAGE}"
  docker push "${SCANNER_IMAGE}"
  success "hakuna-scanner image pushed"

  step "Building hakuna-vm-scanner (Nuclei) image"
  docker build \
    --platform linux/amd64 \
    -f hakuna-vm-scanner/Dockerfile \
    -t "${VM_SCANNER_IMAGE}" \
    hakuna-vm-scanner/

  info "Pushing ${VM_SCANNER_IMAGE}"
  docker push "${VM_SCANNER_IMAGE}"
  success "hakuna-vm-scanner image pushed"

  warn "Scanner images pushed. To pull and restart on the VM, run:"
  echo "  gcloud compute ssh hakuna-scanners --zone=${ZONE} --tunnel-through-iap \\"
  echo "    --command='cd /opt/hakuna-scanners && sudo docker compose pull && sudo docker compose up -d'"
fi

# ── Step: Frontend build & deploy to GCS ──────────────────────────────────────
if $DO_FRONTEND; then
  step "Building React frontend"
  cd "${SCRIPT_DIR}/frontend"

  # VITE_GOOGLE_CLIENT_ID must be set at build time (baked into the JS bundle)
  if [[ -z "${VITE_GOOGLE_CLIENT_ID:-}" ]]; then
    VITE_GOOGLE_CLIENT_ID=$(gcloud secrets versions access latest --secret="google-oauth-client-id" 2>/dev/null || true)
  fi
  export VITE_GOOGLE_CLIENT_ID

  npm ci --silent
  npm run build
  success "Frontend built → frontend/dist"

  # Resolve the frontend bucket name from terraform output, fallback to convention
  FRONTEND_BUCKET=$(tf_output frontend_bucket 2>/dev/null || true)
  if [[ -z "$FRONTEND_BUCKET" ]]; then
    # Terraform names it: hakuna-frontend-<project_id>
    FRONTEND_BUCKET="hakuna-frontend-${PROJECT_ID}"
    warn "Could not read bucket from terraform output, using convention: ${FRONTEND_BUCKET}"
  fi

  step "Uploading frontend to gs://${FRONTEND_BUCKET}"

  # Step 1: Upload all hashed assets (excluding index.html) with long-lived cache headers.
  # These files have content hashes in their names so they are safe to cache forever.
  # We do NOT use -d here to avoid deleting old assets while index.html may still reference them.
  gsutil -m -h "Cache-Control:public, max-age=31536000, immutable" \
    rsync -r -x "^index\.html$" ./dist "gs://${FRONTEND_BUCKET}"

  # Step 2: Invalidate CDN cache BEFORE uploading the new index.html, so that after
  # index.html is updated no user will receive the old index.html from CDN while
  # new assets are already live.
  step "Invalidating Cloud CDN cache"
  URL_MAP="hakuna-url-map"
  if gcloud compute url-maps describe "${URL_MAP}" --global &>/dev/null; then
    gcloud compute url-maps invalidate-cdn-cache "${URL_MAP}" \
      --path "/*" \
      --global \
      --quiet
    success "CDN cache invalidated"
  else
    warn "Could not find URL map '${URL_MAP}' to invalidate CDN. Clear cache manually if needed."
  fi

  # Step 3: Upload index.html last with no-cache headers so browsers always fetch the latest.
  gsutil -h "Cache-Control:no-cache, no-store, must-revalidate" \
    cp ./dist/index.html "gs://${FRONTEND_BUCKET}/index.html"

  success "Frontend deployed to GCS"

  # Step 4: Clean up old hashed assets that are no longer referenced by the new build.
  # This runs after index.html is live so any in-flight requests to old assets still work briefly.
  info "Removing stale assets from bucket..."
  gsutil -m rsync -r -d -x "^index\.html$" ./dist "gs://${FRONTEND_BUCKET}" 2>/dev/null || true

  cd "${SCRIPT_DIR}"
fi

# ── Step: Database migrations ─────────────────────────────────────────────────
if $DO_MIGRATE; then
  step "Running database migrations"
  cd "${SCRIPT_DIR}"

  # Get Cloud SQL connection name from terraform
  SQL_CONN=$(tf_output cloud_sql_connection_name 2>/dev/null || true)
  if [[ -z "$SQL_CONN" ]]; then
    error "Could not read cloud_sql_connection_name from terraform output."
    error "Make sure you've run terraform apply first, or set SQL_CONN manually."
    exit 1
  fi

  info "Starting Cloud SQL Auth Proxy for: ${SQL_CONN}"
  cloud-sql-proxy "${SQL_CONN}" --port=5432 --private-ip &
  PROXY_PID=$!
  trap "kill ${PROXY_PID} 2>/dev/null || true" EXIT
  sleep 3  # wait for proxy to be ready

  DB_PASS=$(gcloud secrets versions access latest --secret="hakuna-db-password")
  # Use psycopg2 (sync) driver — migration scripts use SQLAlchemy sync engine
  export DATABASE_URL="postgresql://hakuna:${DB_PASS}@localhost:5432/hakuna"

  cd "${SCRIPT_DIR}/backend"

  # Activate virtualenv if present
  if [[ -f ".venv/bin/activate" ]]; then
    source .venv/bin/activate
  fi

  # Run all migration scripts in order (idempotent — each checks before altering)
  MIGRATION_COUNT=0
  for migration in migrations/[0-9]*.py; do
    if [[ -f "$migration" ]]; then
      info "Applying: ${migration}"
      python "${migration}"
      MIGRATION_COUNT=$((MIGRATION_COUNT + 1))
    fi
  done

  success "Migrations applied (${MIGRATION_COUNT} scripts run)"

  kill "${PROXY_PID}" 2>/dev/null || true
  trap - EXIT
  cd "${SCRIPT_DIR}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deploy complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"

$DO_API       && echo "  API      → Cloud Run (${REGION})"
$DO_SCANNERS  && echo "  Scanners → Artifact Registry (pull on VM to activate)"
$DO_FRONTEND  && echo "  Frontend → GCS + CDN invalidated"
$DO_INFRA     && echo "  Infra    → Terraform applied"
$DO_MIGRATE   && echo "  Database → Migrations applied"

echo ""
echo "  Verify: curl https://app.hakunahq.com/api/health"
echo ""

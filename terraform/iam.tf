# ── Service Accounts ──────────────────────────────────────────────────────────

resource "google_service_account" "api" {
  account_id   = "hakuna-api"
  display_name = "Hakuna API (Cloud Run)"
  description  = "Service account for the FastAPI Cloud Run service"
}

# Audit-worker VM service account. Drives Protocol Audit LLM loops out of
# Cloud Run so the API doesn't serialize behind multi-minute agent runs.
resource "google_service_account" "audit_worker" {
  account_id   = "hakuna-audit-worker"
  display_name = "Hakuna Audit Worker (Compute Engine)"
  description  = "Service account for the Celery audit-worker VM (Protocol Audit agent runs)"
}

# ── API service account roles ─────────────────────────────────────────────────

resource "google_project_iam_member" "api_roles" {
  for_each = toset([
    "roles/cloudsql.client",              # connect via Auth Proxy
    "roles/secretmanager.secretAccessor", # read secrets at runtime
    "roles/storage.objectAdmin",          # generate presigned URLs + read/write objects
    "roles/cloudtrace.agent",             # write traces to Cloud Trace
    "roles/logging.logWriter",            # write structured logs
    "roles/monitoring.metricWriter",      # write custom metrics
    "roles/aiplatform.user",              # Vertex AI — invoke Gemini models (no API key needed)
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.api.email}"
}

# Required for generating GCS V4 signed URLs from Cloud Run.
# The service account must be able to sign blobs using its own key.
resource "google_service_account_iam_member" "api_token_creator" {
  service_account_id = google_service_account.api.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.api.email}"
}

# ── Audit-worker service account roles ───────────────────────────────────────
resource "google_project_iam_member" "audit_worker_roles" {
  for_each = toset([
    "roles/cloudsql.client",              # connect via Cloud SQL Auth Proxy
    "roles/secretmanager.secretAccessor", # pull DB password + JWT + INTEGRATION_SECRET_KEY + INTERNAL_SHARED_SECRET at startup
    "roles/artifactregistry.reader",      # pull the api Docker image (worker reuses it)
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/aiplatform.user", # Vertex AI (Gemini / Claude-on-Vertex) via ADC — agents pick a vertex provider
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.audit_worker.email}"
}

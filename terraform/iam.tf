# ── Service Accounts ──────────────────────────────────────────────────────────

resource "google_service_account" "api" {
  account_id   = "hakuna-api"
  display_name = "Hakuna API (Cloud Run)"
  description  = "Service account for the FastAPI Cloud Run service"
}

# Phase 2: uncomment when worker VM is added
# resource "google_service_account" "worker" {
#   account_id   = "hakuna-worker"
#   display_name = "Hakuna Workers (Compute Engine)"
#   description  = "Service account for Celery worker VM"
# }

# ── API service account roles ─────────────────────────────────────────────────

resource "google_project_iam_member" "api_roles" {
  for_each = toset([
    "roles/cloudsql.client",              # connect via Auth Proxy
    "roles/secretmanager.secretAccessor", # read secrets at runtime
    "roles/storage.objectAdmin",          # generate presigned URLs + read/write objects
    "roles/cloudtrace.agent",             # write traces to Cloud Trace
    "roles/logging.logWriter",            # write structured logs
    "roles/monitoring.metricWriter",      # write custom metrics
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

# ── Phase 2: Worker service account roles ─────────────────────────────────────
# Uncomment when adding compute_workers.tf in Phase 2.
#
# resource "google_project_iam_member" "worker_roles" {
#   for_each = toset([
#     "roles/cloudsql.client",
#     "roles/secretmanager.secretAccessor",
#     "roles/storage.objectViewer",   # workers read scan files, don't generate signed URLs
#     "roles/cloudtrace.agent",
#     "roles/logging.logWriter",
#     "roles/monitoring.metricWriter",
#   ])
#   project = var.project_id
#   role    = each.value
#   member  = "serviceAccount:${google_service_account.worker.email}"
# }

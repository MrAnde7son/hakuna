# ── Scanner VM service account ────────────────────────────────────────────────

resource "google_service_account" "scanner" {
  account_id   = "hakuna-scanner"
  display_name = "Hakuna Scanner VM"
  description  = "Service account for the scanner Compute Engine VM (EASM + Nuclei)"
}

resource "google_project_iam_member" "scanner_roles" {
  for_each = toset([
    "roles/cloudsql.client",              # connect via Cloud SQL Auth Proxy
    "roles/secretmanager.secretAccessor", # pull secrets at startup
    "roles/artifactregistry.reader",      # pull Docker images
    "roles/logging.logWriter",            # write logs to Cloud Logging
    "roles/monitoring.metricWriter",      # write metrics
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

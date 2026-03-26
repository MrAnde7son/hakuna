# ── Required GCP APIs ──────────────────────────────────────────────────────────
# APIs that must be enabled for Hakuna features to work.

resource "google_project_service" "aiplatform" {
  service            = "aiplatform.googleapis.com"
  disable_on_destroy = false
}

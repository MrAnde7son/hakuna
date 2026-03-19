# ── Artifact Registry — Docker Repository ────────────────────────────────────
# Bootstrap note: this must exist before pushing Docker images.
# Apply only this resource first if needed:
#   terraform apply -target=google_artifact_registry_repository.main

resource "google_artifact_registry_repository" "main" {
  location      = var.region
  repository_id = "hakuna"
  format        = "DOCKER"
  description   = "Hakuna application Docker images"

  cleanup_policies {
    id     = "keep-last-10"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
}

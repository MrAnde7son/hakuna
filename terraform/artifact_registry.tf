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

# ── Public repo — customer-pulled images (e.g. on-prem relay agent) ──────────
# Separate from the private `hakuna` repo so making this one publicly readable
# does not also expose the API / scanner images.
resource "google_artifact_registry_repository" "public" {
  location      = var.region
  repository_id = "hakuna-public"
  format        = "DOCKER"
  description   = "Hakuna customer-facing Docker images (relay agent, etc.) — publicly readable"

  cleanup_policies {
    id     = "keep-last-10"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
}

resource "google_artifact_registry_repository_iam_member" "public_reader" {
  location   = google_artifact_registry_repository.public.location
  repository = google_artifact_registry_repository.public.name
  role       = "roles/artifactregistry.reader"
  member     = "allUsers"
}

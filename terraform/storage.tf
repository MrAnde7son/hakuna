# ── GCS — Scan File Storage ───────────────────────────────────────────────────
# Set up now (Phase 1). Presigned URL upload flow added in Phase 3.
# Phase 1: scan files can still be uploaded through the API (existing behavior).
# Phase 3: switch to presigned URLs so browser uploads directly to GCS.

resource "google_storage_bucket" "scan_files" {
  name          = "hakuna-scan-files-${var.project_id}"
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true

  cors {
    origin          = ["https://${var.app_domain}"]
    method          = ["PUT", "GET", "HEAD"]
    response_header = ["Content-Type", "Content-Length", "Content-MD5"]
    max_age_seconds = 3600
  }

  lifecycle_rule {
    condition { age = 30 }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE" # cheaper storage for files older than 30 days
    }
  }

  lifecycle_rule {
    condition { age = 90 }
    action {
      type = "Delete" # auto-delete scan files after 90 days
    }
  }

  versioning {
    enabled = false # scan files are immutable — no versioning needed
  }
}

# ── GCS — Frontend Static Assets ─────────────────────────────────────────────
# Serves the React SPA. Cloud CDN fronts this bucket.

resource "google_storage_bucket" "frontend" {
  name          = "hakuna-frontend-${var.project_id}"
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true

  website {
    main_page_suffix = "index.html"
    not_found_page   = "index.html" # SPA: all 404s → index.html for client-side routing
  }
}

# Public read access — required for Cloud CDN backend bucket to serve objects.
# Requires org policy exemption: iam.allowedPolicyMemberDomains must allow allUsers
# for project hakuna-prod-2026 (GCP Console → IAM → Org Policies → project override).
resource "google_storage_bucket_iam_member" "frontend_public" {
  bucket = google_storage_bucket.frontend.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

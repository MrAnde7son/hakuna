variable "project_id" {
  type        = string
  description = "GCP project ID"
  default     = "hakuna-prod"
}

variable "region" {
  type        = string
  description = "GCP region — me-west1 is Tel Aviv (closest to your users)"
  default     = "me-west1"
}

variable "zone" {
  type        = string
  description = "GCP zone for zonal resources (Cloud SQL Phase 1, worker VM)"
  default     = "me-west1-b"
}

variable "environment" {
  type        = string
  description = "Deployment environment label"
  default     = "production"
}

variable "app_domain" {
  type        = string
  description = "Primary domain for the app (e.g. app.yourdomain.com). Used for managed SSL cert."
}

variable "api_image" {
  type        = string
  description = "Full Docker image path for the API. Push before applying."
  # e.g. me-west1-docker.pkg.dev/hakuna-prod/hakuna/api:latest
}

variable "sentry_dsn" {
  type        = string
  description = "Sentry DSN for error tracking. Leave empty to disable."
  default     = ""
  sensitive   = true
}

variable "jwt_secret" {
  type        = string
  description = "JWT signing secret. Generate with: openssl rand -hex 32"
  sensitive   = true
}

variable "cloud_run_min_instances" {
  type        = number
  description = "Minimum Cloud Run instances (1 = no cold starts for paying customers)"
  default     = 1
}

variable "cloud_run_max_instances" {
  type        = number
  description = "Maximum Cloud Run instances"
  default     = 5
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine type. Phase 1: db-custom-2-4096. Phase 2+: db-custom-2-7680 or larger."
  default     = "db-custom-2-4096"
}

variable "scanner_machine_type" {
  type        = string
  description = "Compute Engine machine type for the scanner VM. e2-standard-4 handles both EASM and Nuclei scanners."
  default     = "e2-standard-4"
}

# ── Optional OSINT API keys (scanner degrades gracefully without them) ─────────

variable "shodan_api_key" {
  type        = string
  description = "Shodan API key for hakuna-scanner. Leave empty to disable."
  default     = ""
  sensitive   = true
}

variable "censys_api_id" {
  type        = string
  description = "Censys API ID for hakuna-scanner. Leave empty to disable."
  default     = ""
  sensitive   = true
}

variable "censys_api_secret" {
  type        = string
  description = "Censys API secret for hakuna-scanner. Leave empty to disable."
  default     = ""
  sensitive   = true
}

# ── Brevo (email) ──────────────────────────────────────────────────────────────

variable "brevo_smtp_pass" {
  type        = string
  description = "Brevo SMTP API key — used for password reset emails and workflow alert emails."
  sensitive   = true
}

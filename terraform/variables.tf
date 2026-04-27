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

variable "posthog_api_key" {
  type        = string
  description = "PostHog project API key (phc_...) — shared by backend (POSTHOG_API_KEY) and frontend build (VITE_POSTHOG_KEY). Leave empty to disable product analytics."
  default     = ""
  sensitive   = true
}

variable "posthog_host" {
  type        = string
  description = "PostHog API host. Defaults to US cloud; set to https://eu.i.posthog.com for EU cloud or a self-hosted URL."
  default     = "https://us.i.posthog.com"
}

variable "jwt_secret" {
  type        = string
  description = "JWT signing secret. Generate with: openssl rand -hex 32"
  sensitive   = true

  validation {
    condition     = length(var.jwt_secret) >= 32
    error_message = "jwt_secret must be at least 32 characters — backend rejects shorter values at startup (core/auth.py)."
  }
}

variable "cloud_run_min_instances" {
  type        = number
  description = "Minimum Cloud Run instances (1 = no cold starts for paying customers)"
  default     = 1
}

variable "cloud_run_max_instances" {
  type        = number
  description = "Maximum Cloud Run instances. Bumped from 5 → 12 so concurrent scan uploads (200 MB each × 2 Gi per instance) don't OOM the service under beta load."
  default     = 12
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine type. Phase 1: db-custom-2-4096. Phase 2+: db-custom-2-7680 or larger."
  default     = "db-custom-2-4096"
}

variable "db_availability_type" {
  type        = string
  description = "Cloud SQL availability type. ZONAL = Phase 1 (~$95/mo, no HA). REGIONAL = HA auto-failover (~$195/mo). Flip to REGIONAL when ready for Phase 3."
  default     = "ZONAL"

  validation {
    condition     = contains(["REGIONAL", "ZONAL"], var.db_availability_type)
    error_message = "db_availability_type must be REGIONAL or ZONAL."
  }
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

variable "integration_secret_key" {
  type        = string
  description = "AES-256 key for encrypting integration credentials. Generate with: openssl rand -hex 32. Must be stable — changing it invalidates all stored credentials."
  sensitive   = true

  validation {
    condition     = length(var.integration_secret_key) == 64 && can(regex("^[0-9a-fA-F]+$", var.integration_secret_key))
    error_message = "integration_secret_key must be exactly 64 hex characters (32 bytes) — services/credential_vault.py rejects anything else."
  }
}

variable "internal_shared_secret" {
  type        = string
  description = "Shared secret for /internal/relay/dispatch — audit-worker presents it in X-Internal-Token. Generate with: openssl rand -hex 32."
  sensitive   = true

  validation {
    condition     = length(var.internal_shared_secret) >= 32
    error_message = "internal_shared_secret must be at least 32 characters."
  }
}

variable "audit_worker_machine_type" {
  type        = string
  description = "Machine type for the audit-worker VM. e2-small is enough — the worker drives LLM API calls, not CPU-heavy scans."
  default     = "e2-small"
}

# ── Stripe billing ────────────────────────────────────────────────────────────

variable "stripe_secret_key" {
  type        = string
  description = "Stripe secret key (sk_live_... or sk_test_...)"
  sensitive   = true
}

variable "stripe_publishable_key" {
  type        = string
  description = "Stripe publishable key (pk_live_... or pk_test_...)"
}

variable "stripe_webhook_secret" {
  type        = string
  description = "Stripe webhook signing secret (whsec_...)"
  sensitive   = true
}

variable "stripe_price_id_monthly" {
  type        = string
  description = "Stripe Price ID for the monthly Pro plan"
}

variable "stripe_price_id_annual" {
  type        = string
  description = "Stripe Price ID for the annual Pro plan"
}

# ── COGS ──────────────────────────────────────────────────────────────────────

variable "billing_export_ready" {
  type        = bool
  description = "Set to true after GCP Billing Export has started writing to the billing_export dataset (~4h after enabling in Console). Gates creation of v_infra_cost_daily and v_cogs_per_org_daily, whose wildcard table reference fails to validate before any export table exists."
  default     = false
}

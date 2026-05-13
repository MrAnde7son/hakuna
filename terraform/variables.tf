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
  description = "Maximum Cloud Run instances. Pinned to 1 because the relay broker (services/relay_broker.py) keeps WebSocket state in process memory — with >1 replica, audit-worker dispatch can land on an instance that doesn't hold the relay's WS and fails with 'relay agent ... is not connected'. Lift this once the broker is backed by Redis (see /internal/relay/dispatch routing). Tradeoff: concurrent 200 MB scan uploads share one instance's 2 Gi and can OOM under beta load."
  default     = 1
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

# WAF / rate-limit evasion for the VM scanner. The proxy pool is the
# highest-leverage piece — without it the feature still rotates UAs
# and forges X-Forwarded-* headers, but those alone don't bypass an
# IP-based rate limit. Set via terraform.tfvars (gitignored) or
# `-var "vm_scanner_proxy_pool=..."` at apply time. The two boolean
# triggers exist so ops can quickly disable the auto-fire branches
# without redeploying code.
variable "vm_scanner_proxy_pool" {
  type        = string
  description = "Comma-separated list of forward-proxy URLs (http://user:pw@host:port or socks5://host:port) the VM scanner rotates through when a CDN/WAF is detected or after a blocked/timeout retry. Empty disables proxy rotation; UA + forwarded-header tricks still fire."
  default     = ""
  sensitive   = true
}

variable "vm_scanner_evasion_enabled" {
  type        = string
  description = "Master kill switch for VM scanner evasion. Set to \"false\" to fall back to the pre-evasion shape (CDN short-circuit, no retry)."
  default     = "true"
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

# ── Lab VM (intentionally vulnerable test targets) ────────────────────────────

variable "lab_enabled" {
  type        = bool
  description = "Bring up the lab VM hosting docker-compose.lab.yml (DVWA, SMB, LDAP, SSH, SNMP, LocalStack, webapp, mysql, mongo, tomcat, etc.). Reachable from scanner + audit-worker VMs by internal IP. Off by default — flip on for E2E test passes, off when done. The lab is INTENTIONALLY VULNERABLE; do not leave it running."
  default     = false
}

variable "lab_machine_type" {
  type        = string
  description = "Machine type for the lab VM. e2-standard-4 (4 vCPU / 16 GB) handles all twelve services concurrently."
  default     = "e2-standard-4"
}

variable "lab_public_ip" {
  type        = bool
  description = "Give the lab VM a static external IP. Required for DNS-public access (lab.hakunahq.com). Firewall still scopes ingress to lab_allowed_source_ranges + scanner/audit-worker SAs — DNS publication does NOT mean the lab is reachable by arbitrary internet hosts."
  default     = false
}

variable "lab_allowed_source_ranges" {
  type        = list(string)
  description = "CIDRs allowed to reach the lab VM in addition to the scanner + audit-worker SAs. Use for your laptop / office IPs. Each entry should be a /32 if it's a single host. NEVER add 0.0.0.0/0 here — the lab is intentionally vulnerable."
  default     = []

  validation {
    condition     = !contains(var.lab_allowed_source_ranges, "0.0.0.0/0")
    error_message = "Refusing to allow 0.0.0.0/0 — the lab VM hosts intentionally-vulnerable services and would be compromised within minutes if exposed to the open internet."
  }
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

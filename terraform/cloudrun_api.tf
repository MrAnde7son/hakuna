# ── Cloud Run v2 — FastAPI API Service ───────────────────────────────────────

resource "google_cloud_run_v2_service" "api" {
  name     = "hakuna-api"
  location = var.region

  # Only accept traffic from the load balancer — not directly from the internet
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    timeout = "300s" # match LB backend timeout — allows large Nessus scans to fully process

    scaling {
      min_instance_count = var.cloud_run_min_instances # 1 = no cold starts
      max_instance_count = var.cloud_run_max_instances
    }

    # Faster startup for the first request when an instance spins up
    annotations = {
      "run.googleapis.com/startup-cpu-boost" = "true"
    }

    # Route all outbound traffic through the VPC connector so Cloud Run can reach
    # Cloud SQL private IP and Memorystore
    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY" # only VPC traffic goes through connector
    }

    service_account = google_service_account.api.email

    # ── Main application container ──────────────────────────────────────────

    containers {
      name  = "api"
      image = var.api_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi" # 2Gi required: SSVC sync loads a 240MB zip into memory for extraction
        }
        # CPU must stay allocated after response so FastAPI background tasks (threat intel syncs,
        # SSVC/ExploitDB/MSRC downloads) run at full speed. With cpu_idle=true, CPU is throttled
        # after the HTTP response is sent, causing multi-minute background syncs to stall.
        cpu_idle          = false
        startup_cpu_boost = true
      }

      # The Auth Proxy sidecar must be ready before the API starts
      depends_on = ["cloud-sql-proxy"]

      # ── Environment variables ─────────────────────────────────────────────

      env {
        name  = "ENV"
        value = "production"
      }

      # Read by core.auth / services.credential_vault to fail-fast when
      # JWT_SECRET or INTEGRATION_SECRET_KEY is missing.
      env {
        name  = "ENVIRONMENT"
        value = "production"
      }

      # Database URL (with password) from Secret Manager
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      # Phase 3: uncomment when read replica is added (database.tf replica resource)
      # env {
      #   name  = "DATABASE_REPLICA_URL"
      #   value = "postgresql+asyncpg://hakuna@localhost:5433/hakuna"
      # }

      # Redis from Secret Manager
      env {
        name = "REDIS_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_url.secret_id
            version = "latest"
          }
        }
      }

      # Phase 1: tasks run eagerly (inline, no workers needed).
      # Phase 2: change to "false" once Celery worker VM is running.
      env {
        name  = "CELERY_TASK_ALWAYS_EAGER"
        value = "true"
      }

      env {
        name  = "CELERY_TASK_EAGER_PROPAGATES"
        value = "true"
      }

      # JWT secret from Secret Manager
      env {
        name = "JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }

      # GCS bucket for scan file storage
      env {
        name  = "GCS_BUCKET"
        value = google_storage_bucket.scan_files.name
      }

      # Sentry error tracking
      env {
        name = "SENTRY_DSN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.sentry_dsn.secret_id
            version = "latest"
          }
        }
      }

      # Cloud Trace — Cloud Run automatically injects PROJECT_ID
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      # CORS — set to your app domain
      env {
        name  = "CORS_ORIGINS"
        value = "https://${var.app_domain}"
      }

      # Brevo — transactional email (password resets + workflow alert fallback)
      env {
        name = "BREVO_SMTP_PASS"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.brevo_smtp_pass.secret_id
            version = "latest"
          }
        }
      }

      # AES-256 key for encrypting integration credentials
      env {
        name = "INTEGRATION_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.integration_secret_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "BREVO_SMTP_USER"
        value = "a58580001@smtp-brevo.com"
      }

      env {
        name  = "BREVO_FROM_ADDRESS"
        value = "itamar@hakunahq.com"
      }

      env {
        name  = "APP_URL"
        value = "https://${var.app_domain}"
      }

      # Base URL headless Chromium navigates to when rendering scheduled
      # report PDFs. Same origin as the SPA — GCS/CDN serves the static app,
      # the load balancer forwards /api/* back to this Cloud Run service.
      env {
        name  = "FRONTEND_BASE_URL"
        value = "https://${var.app_domain}"
      }

      # Playwright Chromium location inside the image (pinned in Dockerfile.prod).
      env {
        name  = "PLAYWRIGHT_BROWSERS_PATH"
        value = "/ms-playwright"
      }

      # ── Stripe billing ──────────────────────────────────────────────────

      env {
        name = "STRIPE_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.stripe_secret_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "STRIPE_PUBLISHABLE_KEY"
        value = var.stripe_publishable_key
      }

      env {
        name = "STRIPE_WEBHOOK_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.stripe_webhook_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "STRIPE_PRICE_ID_MONTHLY"
        value = var.stripe_price_id_monthly
      }

      env {
        name  = "STRIPE_PRICE_ID_ANNUAL"
        value = var.stripe_price_id_annual
      }

      # Scanner services — reachable via private VPC IP (no public internet)
      env {
        name  = "HAKUNA_SCANNER_URL"
        value = "http://${google_compute_instance.scanners.network_interface[0].network_ip}:8001"
      }

      env {
        name  = "VM_SCANNER_URL"
        value = "http://${google_compute_instance.scanners.network_interface[0].network_ip}:8002"
      }

      # Health check
      liveness_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        initial_delay_seconds = 30
        period_seconds        = 30
        failure_threshold     = 3
      }

      startup_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        initial_delay_seconds = 10
        period_seconds        = 5
        failure_threshold     = 12 # 60s total startup time
      }
    }

    # ── Cloud SQL Auth Proxy sidecar ──────────────────────────────────────────
    # Handles TLS and IAM authentication to Cloud SQL.
    # Listens on localhost:5432 so the API connects with no extra config.

    containers {
      name  = "cloud-sql-proxy"
      image = "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2"

      args = [
        # Primary instance on port 5432
        "--structured-logs",
        "--port=5432",
        "--address=0.0.0.0", # listen on all interfaces so Cloud Run TCP health probe can reach it
        "--private-ip",      # connect via private IP (requires VPC connector)
        "${var.project_id}:${var.region}:${google_sql_database_instance.primary.name}",
        # Phase 3: add replica on port 5433 when replica is uncommented in database.tf
        # "--port=5433",
        # "${var.project_id}:${var.region}:hakuna-pg-replica",
      ]

      resources {
        limits = {
          cpu    = "0.5"
          memory = "256Mi"
        }
        cpu_idle = true
      }

      # Proxy is healthy when it can accept connections
      startup_probe {
        tcp_socket { port = 5432 }
        initial_delay_seconds = 10
        period_seconds        = 10
        failure_threshold     = 12 # 120s total startup time
      }
    }
  }

  depends_on = [
    google_vpc_access_connector.main,
    google_sql_database_instance.primary,
    google_redis_instance.main,
    google_secret_manager_secret_version.database_url,
    google_secret_manager_secret_version.redis_url,
    google_secret_manager_secret_version.jwt_secret,
    google_secret_manager_secret_version.sentry_dsn,
    google_secret_manager_secret_version.brevo_smtp_pass,
    google_secret_manager_secret_version.integration_secret_key,
    google_secret_manager_secret_version.stripe_secret_key,
    google_secret_manager_secret_version.stripe_webhook_secret,
    google_project_iam_member.api_roles,
  ]
}

# ── Allow load balancer to invoke Cloud Run ───────────────────────────────────
# Requires org policy exemption: iam.allowedPolicyMemberDomains must allow allUsers
# for project hakuna-prod-2026 (GCP Console → IAM → Org Policies → project override).

resource "google_cloud_run_v2_service_iam_member" "allow_unauthenticated" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

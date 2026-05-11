# ── Cloud Run v2 — Background Scheduler Service ──────────────────────────────
#
# Runs the same backend image as hakuna-api but with HAKUNA_ROLE=scheduler so
# app._deferred_startup owns every APScheduler (workflow, agent, integration,
# easm, audit, report, vm reaper/poll, replan, intel, etc.). Splitting these
# off the user-facing API service keeps the FastAPI event loop free of
# background CPU/IO bursts that previously starved /api/health and tripped
# Cloud Run's liveness probe under scan load.
#
# - Internal-only ingress: no load-balancer attachment, no public traffic.
#   Cloud Run still probes /api/health on the container itself.
# - min=max=1: schedulers can't be sharded today (advisory lock in app.py
#   protects against duplicates during deploys but the steady-state is 1).
# - Reuses the api service account so DB / Secret Manager / GCS / BQ IAM
#   bindings carry over without a second set of grants. Separate SA is a
#   future cleanup.
#
# Env vars are kept in sync with cloudrun_api.tf by hand. If you add a secret
# or integration there, mirror it here — otherwise the scheduler runs blind.

resource "google_cloud_run_v2_service" "scheduler" {
  name     = "hakuna-scheduler"
  location = var.region

  # No public traffic. Cloud Run still routes internal probes.
  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  labels = {
    hakuna_service = "scheduler"
    environment    = var.environment
  }

  template {
    timeout = "300s"

    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    annotations = {
      "run.googleapis.com/startup-cpu-boost" = "true"
    }

    vpc_access {
      connector = google_vpc_access_connector.main.id
      egress    = "PRIVATE_RANGES_ONLY"
    }

    service_account = google_service_account.api.email

    containers {
      name  = "api"
      image = var.api_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
        # Scheduler work runs on intervals — cpu_idle=false keeps CPU
        # allocated between requests so cron jobs fire on time.
        cpu_idle          = false
        startup_cpu_boost = true
      }

      depends_on = ["cloud-sql-proxy"]

      # ── Role marker ───────────────────────────────────────────────────────
      env {
        name  = "HAKUNA_ROLE"
        value = "scheduler"
      }

      env {
        name  = "ENV"
        value = "production"
      }

      env {
        name  = "ENVIRONMENT"
        value = "production"
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "REDIS_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.redis_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "CELERY_TASK_ALWAYS_EAGER"
        value = "false"
      }

      env {
        name  = "CELERY_TASK_EAGER_PROPAGATES"
        value = "false"
      }

      env {
        name  = "AUDIT_CELERY_BROKER_URL"
        value = "redis://${google_redis_instance.main.host}:${google_redis_instance.main.port}/3"
      }

      env {
        name  = "AUDIT_CELERY_RESULT_BACKEND"
        value = "redis://${google_redis_instance.main.host}:${google_redis_instance.main.port}/3"
      }

      env {
        name = "INTERNAL_SHARED_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.internal_shared_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "GCS_BUCKET"
        value = google_storage_bucket.scan_files.name
      }

      env {
        name = "SENTRY_DSN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.sentry_dsn.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "POSTHOG_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.posthog_api_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "POSTHOG_HOST"
        value = var.posthog_host
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      env {
        name  = "COGS_BQ_DATASET"
        value = google_bigquery_dataset.cogs.dataset_id
      }
      env {
        name  = "COGS_BQ_TABLE"
        value = google_bigquery_table.llm_usage.table_id
      }

      env {
        name  = "CORS_ORIGINS"
        value = "https://${var.app_domain}"
      }

      env {
        name = "BREVO_SMTP_PASS"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.brevo_smtp_pass.secret_id
            version = "latest"
          }
        }
      }

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

      env {
        name  = "FRONTEND_BASE_URL"
        value = "https://${var.app_domain}"
      }

      env {
        name  = "PLAYWRIGHT_BROWSERS_PATH"
        value = "/ms-playwright"
      }

      # Stripe — not strictly needed by schedulers today but mirror the API
      # service so a scheduled job that touches billing doesn't NPE.
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

      env {
        name  = "HAKUNA_SCANNER_URL"
        value = "http://${google_compute_instance.scanners.network_interface[0].network_ip}:8001"
      }

      env {
        name  = "VM_SCANNER_URL"
        value = "http://${google_compute_instance.scanners.network_interface[0].network_ip}:8002"
      }

      # Same probe config as hakuna-api — generous timeouts so a heavy
      # scheduler tick can't kill-restart the container in a loop.
      liveness_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        initial_delay_seconds = 30
        period_seconds        = 60
        timeout_seconds       = 10
        failure_threshold     = 5
      }

      startup_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        initial_delay_seconds = 10
        period_seconds        = 5
        timeout_seconds       = 5
        failure_threshold     = 12
      }
    }

    containers {
      name  = "cloud-sql-proxy"
      image = "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2"

      args = [
        "--structured-logs",
        "--port=5432",
        "--address=0.0.0.0",
        "--private-ip",
        "${var.project_id}:${var.region}:${google_sql_database_instance.primary.name}",
      ]

      resources {
        limits = {
          cpu    = "0.5"
          memory = "256Mi"
        }
        cpu_idle = true
      }

      startup_probe {
        tcp_socket { port = 5432 }
        initial_delay_seconds = 10
        period_seconds        = 10
        failure_threshold     = 12
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
    google_secret_manager_secret_version.posthog_api_key,
    google_secret_manager_secret_version.brevo_smtp_pass,
    google_secret_manager_secret_version.integration_secret_key,
    google_secret_manager_secret_version.internal_shared_secret,
    google_secret_manager_secret_version.stripe_secret_key,
    google_secret_manager_secret_version.stripe_webhook_secret,
    google_project_iam_member.api_roles,
  ]
}

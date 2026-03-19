# ── Cloud SQL PostgreSQL 16 ───────────────────────────────────────────────────
# Phase 1: single zonal (no HA). To upgrade to HA in Phase 3:
#   change availability_type = "REGIONAL"
# That triggers a brief failover (~60s) and doubles the instance cost.

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "primary" {
  name             = "hakuna-pg-primary"
  database_version = "POSTGRES_16"
  region           = var.region

  # Ensure private networking is ready before creating the instance
  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier    = var.db_tier
    edition = "ENTERPRISE"

    # Phase 1: ZONAL (single zone, no HA, ~$95/mo)
    # Phase 3: change to "REGIONAL" for HA auto-failover (~$195/mo)
    availability_type = "ZONAL"

    disk_size       = 20   # GB, auto-grows
    disk_type       = "PD_SSD"
    disk_autoresize = true

    ip_configuration {
      ipv4_enabled    = false                           # no public IP
      private_network = google_compute_network.main.id
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00" # 3 AM UTC
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 14
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 4 # 4 AM UTC
      update_track = "stable"
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000" # log queries slower than 1s
    }

    insights_config {
      query_insights_enabled  = true
      query_plans_per_minute  = 5
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = true
    }
  }

  deletion_protection = true
}

# ── Database and user ─────────────────────────────────────────────────────────

resource "google_sql_database" "hakuna" {
  name     = "hakuna"
  instance = google_sql_database_instance.primary.name
}

resource "google_sql_user" "app" {
  name     = "hakuna"
  instance = google_sql_database_instance.primary.name
  password = random_password.db_password.result
}

# ── Read replica ──────────────────────────────────────────────────────────────
# Phase 1: commented out. Uncomment in Phase 3 when dashboards become slow.
# Cost: ~$60/mo additional.
#
# resource "google_sql_database_instance" "replica" {
#   name                 = "hakuna-pg-replica"
#   master_instance_name = google_sql_database_instance.primary.name
#   database_version     = "POSTGRES_16"
#   region               = var.region
#
#   replica_configuration {
#     failover_target = false
#   }
#
#   settings {
#     tier              = "db-custom-1-3840"
#     availability_type = "ZONAL"
#
#     ip_configuration {
#       ipv4_enabled    = false
#       private_network = google_compute_network.main.id
#     }
#
#     insights_config {
#       query_insights_enabled = true
#     }
#   }
# }

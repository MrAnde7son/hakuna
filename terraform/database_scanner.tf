# ── Scanner database on the same Cloud SQL instance ───────────────────────────
# hakuna-scanner (EASM) has its own PostgreSQL schema — separate database
# on the same Cloud SQL instance (no extra cost beyond storage).
# vm-scanner uses the main 'hakuna' database (no extra DB needed).

resource "random_password" "scanner_db_password" {
  length  = 32
  special = false
}

resource "google_sql_database" "hakuna_easm" {
  name     = "hakuna_easm"
  instance = google_sql_database_instance.primary.name
}

resource "google_sql_user" "scanner" {
  name     = "hakuna_scanner"
  instance = google_sql_database_instance.primary.name
  password = random_password.scanner_db_password.result
}

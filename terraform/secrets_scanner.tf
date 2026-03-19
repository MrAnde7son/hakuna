# ── Scanner secrets ───────────────────────────────────────────────────────────

resource "google_secret_manager_secret" "scanner_db_password" {
  secret_id = "hakuna-scanner-db-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "scanner_db_password" {
  secret      = google_secret_manager_secret.scanner_db_password.id
  secret_data = random_password.scanner_db_password.result
}

# ── Optional OSINT API keys for hakuna-scanner ────────────────────────────────
# The scanner degrades gracefully without these (uses only passive sources).
# Add values via: gcloud secrets versions add hakuna-shodan-api-key --data-file=-
# Then update Cloud Run / VM env accordingly.

resource "google_secret_manager_secret" "shodan_api_key" {
  secret_id = "hakuna-shodan-api-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "shodan_api_key" {
  count       = var.shodan_api_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.shodan_api_key.id
  secret_data = var.shodan_api_key
}

resource "google_secret_manager_secret" "censys_api_id" {
  secret_id = "hakuna-censys-api-id"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "censys_api_id" {
  count       = var.censys_api_id != "" ? 1 : 0
  secret      = google_secret_manager_secret.censys_api_id.id
  secret_data = var.censys_api_id
}

resource "google_secret_manager_secret" "censys_api_secret" {
  secret_id = "hakuna-censys-api-secret"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "censys_api_secret" {
  count       = var.censys_api_secret != "" ? 1 : 0
  secret      = google_secret_manager_secret.censys_api_secret.id
  secret_data = var.censys_api_secret
}

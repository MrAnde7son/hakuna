# ── Memorystore for Redis 7 ───────────────────────────────────────────────────
# Phase 1: BASIC tier (no HA, no failover) — set up now, used in Phase 2.
# Phase 3: change tier = "STANDARD_HA" for auto-failover (~2× cost, ~$104/mo).

resource "google_redis_instance" "main" {
  name           = "hakuna-redis"
  tier           = "BASIC" # Phase 3: change to "STANDARD_HA"
  memory_size_gb = 1
  region         = var.region

  authorized_network = google_compute_network.main.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_version = "REDIS_7_0"

  redis_configs = {
    maxmemory-policy = "allkeys-lru" # evict least-recently-used keys when full
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

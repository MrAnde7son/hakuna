# ── Scanner VM — runs both hakuna-scanner (EASM) and vm-scanner (Nuclei) ──────
#
# Both services need system-level tools that Cloud Run can't provide:
#   hakuna-scanner: nmap, libpcap, subfinder, dnsx, naabu, httpx, tlsx, etc.
#   vm-scanner:     Nuclei binary, Go compiler, template cache
#
# One e2-standard-8 VM (8 vCPU, 32GB) hosts all scanner containers via Docker Compose.
# The Cloud SQL Auth Proxy runs as a container alongside them.
#
# Redis instances (Memorystore):
#   hakuna-redis         — main API (DB 0) + EASM scanner (DB 2)
#   hakuna-redis-vm-scanner — vm-scanner Celery broker (DB 0)

locals {
  ar_base = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

# Static internal IP for the scanner VM. Without this, the IP is ephemeral and
# changes whenever the instance stops/starts (e.g. a machine_type change via
# terraform apply). The main hakuna-api Cloud Run service has
# `ignore_changes = [env]` on its lifecycle (cloudrun_api.tf), so a changed IP
# silently leaves HAKUNA_SCANNER_URL / VM_SCANNER_URL pointing at nothing
# until `deploy.sh` re-pushes env vars — observed 2026-05-25 after upsizing
# the scanner VM from e2-standard-4 to e2-standard-8.
resource "google_compute_address" "scanner_internal" {
  name         = "hakuna-scanner-internal"
  region       = var.region
  subnetwork   = google_compute_subnetwork.main.id
  address_type = "INTERNAL"
}

resource "google_compute_instance" "scanners" {
  name         = "hakuna-scanners"
  # Sized for ~5 concurrent users running scans. The previous e2-standard-4
  # (4 vCPU / 16GB) ran out of memory under 2 parallel EASM scans + vm-worker
  # --concurrency=16: pthread_create / fork returned EAGAIN ("can't start new
  # thread", "[Errno 11] Resource temporarily unavailable") from inside the
  # easm-worker container. Doubling the box keeps both worker pools at their
  # current concurrency without re-engineering the colocation.
  machine_type = "e2-standard-8" # 8 vCPU, 32GB — handles both scanners + workers
  zone         = var.zone

  tags = ["allow-iap-ssh"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50 # GB — Docker images + Nuclei templates + scan data
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    network_ip = google_compute_address.scanner_internal.address
    # No access_config block = no public IP. Outbound internet via Cloud NAT.
  }

  service_account {
    email  = google_service_account.scanner.email
    scopes = ["cloud-platform"] # full access, restricted by IAM roles on the SA
  }

  metadata = {
    # Non-sensitive runtime values — startup script reads these via metadata API.
    # Secrets are fetched from Secret Manager inside the startup script.
    sql-connection-name = google_sql_database_instance.primary.connection_name
    redis-host             = google_redis_instance.main.host
    redis-port             = tostring(google_redis_instance.main.port)
    vm-scanner-redis-host  = google_redis_instance.vm_scanner.host
    vm-scanner-redis-port  = tostring(google_redis_instance.vm_scanner.port)
    ar-base                = local.ar_base
    project-id             = var.project_id
    region                 = var.region
  }

  metadata_startup_script = <<-STARTUP
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/startup-script.log 2>&1
    echo "=== Hakuna Scanner VM startup: $(date) ==="

    # ── Install Docker ──────────────────────────────────────────────────────
    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates curl gnupg netcat-openbsd
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    echo "Docker installed."

    # ── Read instance metadata ──────────────────────────────────────────────
    META="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
    H="Metadata-Flavor: Google"
    SQL_CONN=$(curl -sf -H "$H" "$META/sql-connection-name")
    REDIS_HOST=$(curl -sf -H "$H" "$META/redis-host")
    REDIS_PORT=$(curl -sf -H "$H" "$META/redis-port")
    VM_REDIS_HOST=$(curl -sf -H "$H" "$META/vm-scanner-redis-host")
    VM_REDIS_PORT=$(curl -sf -H "$H" "$META/vm-scanner-redis-port")
    AR_BASE=$(curl -sf -H "$H" "$META/ar-base")
    PROJECT_ID=$(curl -sf -H "$H" "$META/project-id")
    REGION=$(curl -sf -H "$H" "$META/region")
    echo "Metadata loaded. SQL: $SQL_CONN  Redis: $REDIS_HOST:$REDIS_PORT  VM Redis: $VM_REDIS_HOST:$VM_REDIS_PORT"

    # ── Configure Artifact Registry auth ───────────────────────────────────
    gcloud auth configure-docker "$${REGION}-docker.pkg.dev" --quiet
    echo "Artifact Registry auth configured."

    # ── Fetch secrets from Secret Manager ──────────────────────────────────
    DB_PASS=$(gcloud secrets versions access latest \
      --secret=hakuna-db-password --project="$${PROJECT_ID}")
    SCANNER_DB_PASS=$(gcloud secrets versions access latest \
      --secret=hakuna-scanner-db-password --project="$${PROJECT_ID}")
    echo "Secrets fetched."

    # ── Write docker-compose.yml ────────────────────────────────────────────
    mkdir -p /opt/hakuna-scanners
    # Shared volume for EASM httpx screenshots — worker writes, api reads.
    mkdir -p /opt/hakuna-scanners/screenshots
    cd /opt/hakuna-scanners

    cat > docker-compose.yml << COMPOSE
    services:

      # ── Cloud SQL Auth Proxy ─────────────────────────────────────────────
      # All scanner services connect to PostgreSQL via this proxy.
      # Listens on port 5432 within the Docker network.
      cloud-sql-proxy:
        image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2
        command:
          - "--structured-logs"
          - "--port=5432"
          - "--address=0.0.0.0"
          - "--private-ip"
          - "--health-check"
          - "$${SQL_CONN}"
        restart: always
        healthcheck:
          test: ["CMD", "/cloud-sql-proxy", "wait", "--max", "5s"]
          interval: 10s
          timeout: 5s
          retries: 10

      # ── hakuna-scanner (EASM) — Redis DB 2, hakuna_easm database ─────────
      # easm-worker writes httpx screenshots to /data/screenshots and
      # easm-api serves them via /api/v1/orgs/.../assets/.../screenshot.
      # Both containers bind-mount the same host dir so the API can see
      # files written by the worker.
      easm-api:
        image: $${AR_BASE}/hakuna-scanner:latest
        command: sh -c "PYTHONPATH=/app alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8001"
        ports:
          - "8001:8001"
        environment:
          DATABASE_URL: "postgresql+asyncpg://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          DATABASE_URL_SYNC: "postgresql://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          REDIS_URL: "redis://$${REDIS_HOST}:$${REDIS_PORT}/2"
          CELERY_CONCURRENCY: "4"
          SCAN_TIMEOUT_SECONDS: "600"
          NAABU_PORTS: "80,443,8080,8443,8888,9000,9443,3000,5000"
          SUBFINDER_SOURCES: "all"
          ORG_SCAN_STAGGER_SECONDS: "30"
        volumes:
          - /opt/hakuna-scanners/screenshots:/data/screenshots
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always

      easm-worker:
        image: $${AR_BASE}/hakuna-scanner:latest
        command: celery -A app.celery_app worker --loglevel=info --concurrency=4
        environment:
          DATABASE_URL: "postgresql+asyncpg://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          DATABASE_URL_SYNC: "postgresql://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          REDIS_URL: "redis://$${REDIS_HOST}:$${REDIS_PORT}/2"
          CELERY_CONCURRENCY: "4"
          SCAN_TIMEOUT_SECONDS: "600"
          NAABU_PORTS: "80,443,8080,8443,8888,9000,9443,3000,5000"
        volumes:
          - /opt/hakuna-scanners/screenshots:/data/screenshots
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always

      easm-beat:
        image: $${AR_BASE}/hakuna-scanner:latest
        command: celery -A app.celery_app beat --loglevel=info
        environment:
          DATABASE_URL: "postgresql+asyncpg://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          DATABASE_URL_SYNC: "postgresql://hakuna_scanner:$${SCANNER_DB_PASS}@cloud-sql-proxy:5432/hakuna_easm"
          REDIS_URL: "redis://$${REDIS_HOST}:$${REDIS_PORT}/2"
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always

      # ── vm-scanner (Nuclei) — dedicated Redis instance, main hakuna database ─
      vm-api:
        image: $${AR_BASE}/vm-scanner:latest
        command: uvicorn scanner.vm.api:create_app --factory --host 0.0.0.0 --port 8002
        ports:
          - "8002:8002"
        environment:
          DATABASE_URL: "postgresql://hakuna:$${DB_PASS}@cloud-sql-proxy:5432/hakuna"
          CELERY_BROKER_URL: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          CELERY_RESULT_BACKEND: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          PYTHONPATH: "/app"
          TEMPLATES_DIR: "/app/templates"
          NUCLEI_BIN: "/usr/local/bin/nuclei"
          NUCLEI_TIMEOUT: "30"
          NUCLEI_RATE_LIMIT: "150"
          SCAN_TIMEOUT_SECONDS: "600"
          GOOGLE_CLOUD_PROJECT: "$${PROJECT_ID}"
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always

      vm-worker:
        image: $${AR_BASE}/vm-scanner:latest
        # Concurrency raised from 4 -> 16: Nuclei runs are network-bound (each
        # task spends most of its 600s wall-clock waiting on HTTP), and on prod
        # ~100% of tasks ride the SCAN_TIMEOUT_SECONDS cap. With 4 workers a
        # short burst of dispatch is enough to back the queue up past the
        # 20-min orphan threshold; 16 fits comfortably on the e2-standard-8
        # (8 vCPU / 32GB) alongside easm-worker for IO-bound work.
        command: celery -A scanner.vm.celery_app:celery_app worker --loglevel=info --concurrency=16 -Q vm_queue
        environment:
          DATABASE_URL: "postgresql://hakuna:$${DB_PASS}@cloud-sql-proxy:5432/hakuna"
          CELERY_BROKER_URL: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          CELERY_RESULT_BACKEND: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          PYTHONPATH: "/app"
          TEMPLATES_DIR: "/app/templates"
          NUCLEI_BIN: "/usr/local/bin/nuclei"
          NUCLEI_RATE_LIMIT: "150"
          # Vertex AI / Gemini — agent_worker resolves the LLM provider
          # from env + integration_configs. On GCE the scanner SA's ADC
          # satisfies auth; only the project id has to be passed in.
          GOOGLE_CLOUD_PROJECT: "$${PROJECT_ID}"
          # WAF / rate-limit evasion — see scanner/vm/evasion.py. The
          # proxy pool is the only piece with a real cost (paid bandwidth,
          # provider rate caps); the header-only branch is free. With pool
          # empty, evasion still applies UA + forwarded-header tricks on
          # CDN-detected targets and on retry after a stall.
          HAKUNA_EVASION_ENABLED: "${var.vm_scanner_evasion_enabled}"
          HAKUNA_PROXY_POOL: "${var.vm_scanner_proxy_pool}"
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always

      vm-beat:
        image: $${AR_BASE}/vm-scanner:latest
        command: celery -A scanner.vm.celery_app:celery_app beat --loglevel=info
        environment:
          DATABASE_URL: "postgresql://hakuna:$${DB_PASS}@cloud-sql-proxy:5432/hakuna"
          CELERY_BROKER_URL: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          CELERY_RESULT_BACKEND: "redis://$${VM_REDIS_HOST}:$${VM_REDIS_PORT}/0"
          PYTHONPATH: "/app"
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always
    COMPOSE

    echo "docker-compose.yml written."

    # ── Pull all images ─────────────────────────────────────────────────────
    cd /opt/hakuna-scanners
    docker compose pull || echo "Image pull failed — images may not exist yet. Service will retry."

    # ── Daily docker prune (prevents disk fill from old image layers) ──────
    cat > /etc/systemd/system/docker-prune.service << 'PRUNE_SERVICE'
    [Unit]
    Description=Prune unused Docker images, containers, networks
    Requires=docker.service
    After=docker.service

    [Service]
    Type=oneshot
    ExecStart=/usr/bin/docker system prune -af --filter "until=168h"
    PRUNE_SERVICE

    cat > /etc/systemd/system/docker-prune.timer << 'PRUNE_TIMER'
    [Unit]
    Description=Run docker-prune daily

    [Timer]
    OnCalendar=daily
    Persistent=true

    [Install]
    WantedBy=timers.target
    PRUNE_TIMER

    # ── Create systemd service ──────────────────────────────────────────────
    cat > /etc/systemd/system/hakuna-scanners.service << SERVICE
    [Unit]
    Description=Hakuna Scanner Services (EASM + VM Scanner)
    After=docker.service network-online.target
    Requires=docker.service

    [Service]
    Type=simple
    WorkingDirectory=/opt/hakuna-scanners
    ExecStartPre=/usr/bin/docker compose pull
    ExecStart=/usr/bin/docker compose up --remove-orphans
    ExecStop=/usr/bin/docker compose down
    Restart=on-failure
    RestartSec=30

    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now docker-prune.timer
    systemctl enable hakuna-scanners
    systemctl start hakuna-scanners

    echo "=== Scanner VM startup complete: $(date) ==="
  STARTUP

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_sql_database_instance.primary,
    google_redis_instance.main,
    google_redis_instance.vm_scanner,
    google_secret_manager_secret_version.db_password,
    google_secret_manager_secret_version.scanner_db_password,
    google_project_iam_member.scanner_roles,
  ]
}

# ── Audit-worker VM — runs the Protocol Audit Celery worker ──────────────────
#
# Reuses the api Docker image (services.celery_app + services.audit_worker live
# in the backend tree). Splitting Compute makes audit runs decoupled from the
# Cloud Run request path — a 10-minute agent loop no longer holds an API
# instance hostage.
#
# Sizing: e2-small (2 vCPU burst, 2 GB) is enough — the worker is mostly
# blocked on LLM API calls, not CPU. Concurrency=4 means up to 4 simultaneous
# audit runs across all tenants. Bump machine_type and AUDIT_WORKER_CONCURRENCY
# together if the audit queue starts backing up.
#
# Redis: uses DB 3 on the main hakuna-redis instance. DB 0 is the API,
# DB 2 is the EASM scanner — DB 3 keeps audits queue-isolated without paying
# for a third Memorystore.
#
# Relay callback: worker sets HAKUNA_PROCESS_ROLE=worker, which flips
# services/relay_broker.py to RemoteRelayBroker. It calls back to the API at
# https://${app_domain}/internal/relay/dispatch using INTERNAL_SHARED_SECRET
# as X-Internal-Token. The API enforces the token in core/auth.py.

resource "google_compute_instance" "audit_worker" {
  name         = "hakuna-audit-worker"
  machine_type = var.audit_worker_machine_type
  zone         = var.zone

  tags = ["allow-iap-ssh"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 40 # GB — api image (~2GB pulled) plus headroom for old layers between prune cycles
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    # No access_config = no public IP. Outbound via Cloud NAT.
  }

  service_account {
    email  = google_service_account.audit_worker.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    sql-connection-name = google_sql_database_instance.primary.connection_name
    redis-host          = google_redis_instance.main.host
    redis-port          = tostring(google_redis_instance.main.port)
    ar-base             = local.ar_base
    api-image           = var.api_image
    project-id          = var.project_id
    region              = var.region
    app-domain          = var.app_domain
  }

  metadata_startup_script = <<-STARTUP
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/startup-script.log 2>&1
    echo "=== Audit-worker VM startup: $(date) ==="

    # ── Install Docker ──────────────────────────────────────────────────────
    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker

    # ── Read instance metadata ──────────────────────────────────────────────
    META="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
    H="Metadata-Flavor: Google"
    SQL_CONN=$(curl -sf -H "$H" "$META/sql-connection-name")
    REDIS_HOST=$(curl -sf -H "$H" "$META/redis-host")
    REDIS_PORT=$(curl -sf -H "$H" "$META/redis-port")
    AR_BASE=$(curl -sf -H "$H" "$META/ar-base")
    API_IMAGE=$(curl -sf -H "$H" "$META/api-image")
    PROJECT_ID=$(curl -sf -H "$H" "$META/project-id")
    REGION=$(curl -sf -H "$H" "$META/region")
    APP_DOMAIN=$(curl -sf -H "$H" "$META/app-domain")

    # ── Configure Artifact Registry auth ───────────────────────────────────
    gcloud auth configure-docker "$${REGION}-docker.pkg.dev" --quiet

    # ── Fetch secrets from Secret Manager ──────────────────────────────────
    DB_PASS=$(gcloud secrets versions access latest \
      --secret=hakuna-db-password --project="$${PROJECT_ID}")
    JWT_SECRET=$(gcloud secrets versions access latest \
      --secret=hakuna-jwt-secret --project="$${PROJECT_ID}")
    INTEGRATION_SECRET_KEY=$(gcloud secrets versions access latest \
      --secret=hakuna-integration-secret-key --project="$${PROJECT_ID}")
    INTERNAL_SHARED_SECRET=$(gcloud secrets versions access latest \
      --secret=hakuna-internal-shared-secret --project="$${PROJECT_ID}")
    SENTRY_DSN=$(gcloud secrets versions access latest \
      --secret=hakuna-sentry-dsn --project="$${PROJECT_ID}" 2>/dev/null || echo "")

    # ── Write docker-compose.yml ────────────────────────────────────────────
    mkdir -p /opt/hakuna-audit-worker
    cd /opt/hakuna-audit-worker

    cat > docker-compose.yml << COMPOSE
    services:
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

      audit-worker:
        image: $${API_IMAGE}
        # services.celery_app reads AUDIT_CELERY_BROKER_URL; queue name "audits"
        # matches services/audit_runner._dispatch_background_run.
        command: celery -A services.celery_app:celery_app worker --loglevel=info --concurrency=4 -Q audits
        environment:
          PYTHONPATH: "/app"
          # Worker reaches Postgres through the proxy sibling service.
          DATABASE_URL: "postgresql://hakuna:$${DB_PASS}@cloud-sql-proxy:5432/hakuna"
          # DB 3 to avoid clashing with API (/0) and EASM scanner (/2).
          AUDIT_CELERY_BROKER_URL: "redis://$${REDIS_HOST}:$${REDIS_PORT}/3"
          AUDIT_CELERY_RESULT_BACKEND: "redis://$${REDIS_HOST}:$${REDIS_PORT}/3"
          AUDIT_WORKER_CONCURRENCY: "4"
          # Flip relay_broker to RemoteRelayBroker — relay dispatch tunnels
          # through the API which owns the websocket.
          HAKUNA_PROCESS_ROLE: "worker"
          HAKUNA_BACKEND_URL: "https://$${APP_DOMAIN}"
          INTERNAL_SHARED_SECRET: "$${INTERNAL_SHARED_SECRET}"
          ENVIRONMENT: "production"
          JWT_SECRET: "$${JWT_SECRET}"
          INTEGRATION_SECRET_KEY: "$${INTEGRATION_SECRET_KEY}"
          # Vertex AI via Application Default Credentials (no API key needed —
          # the audit_worker SA has roles/aiplatform.user).
          GOOGLE_CLOUD_PROJECT: "$${PROJECT_ID}"
          SENTRY_DSN: "$${SENTRY_DSN}"
        depends_on:
          cloud-sql-proxy:
            condition: service_healthy
        restart: always
    COMPOSE

    docker compose pull || echo "Image pull failed — service will retry."

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
    cat > /etc/systemd/system/hakuna-audit-worker.service << SERVICE
    [Unit]
    Description=Hakuna Audit Worker (Celery)
    After=docker.service network-online.target
    Requires=docker.service

    [Service]
    Type=simple
    WorkingDirectory=/opt/hakuna-audit-worker
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
    systemctl enable hakuna-audit-worker
    systemctl start hakuna-audit-worker

    echo "=== Audit-worker VM startup complete: $(date) ==="
  STARTUP

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_sql_database_instance.primary,
    google_redis_instance.main,
    google_secret_manager_secret_version.db_password,
    google_secret_manager_secret_version.jwt_secret,
    google_secret_manager_secret_version.integration_secret_key,
    google_secret_manager_secret_version.internal_shared_secret,
    google_project_iam_member.audit_worker_roles,
  ]
}

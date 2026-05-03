# ── Cloud Scanner VM — Hakuna-managed relay agent for public assets ─────────
#
# Runs the hakuna-relay-agent container in HAKUNA_RELAY_MODE=cloud. The
# container holds one WebSocket per org (one per relay_type='cloud_scanner'
# row) and dispatches audits for internet-reachable assets without needing
# a customer deployment. Customers can still register their own on-prem
# relays for private/segregated networks — _pick_relay routes private
# assets to those, public assets to this one.
#
# Auth: shares INTERNAL_SHARED_SECRET with the API and audit-worker (same
# trust boundary). The cloud relay polls /internal/relay/cloud-relay/registrations
# every minute and opens new WebSockets as orgs are created.
#
# Sizing: e2-small. The cloud relay is mostly idle; spikes are short
# protocol probes (Nuclei-equivalent dial+banner) against public IPs.

resource "google_service_account" "cloud_scanner" {
  account_id   = "hakuna-cloud-scanner"
  display_name = "Hakuna Cloud Scanner (Compute Engine)"
  description  = "Runs the multi-tenant relay agent for public-asset audits"
}

resource "google_project_iam_member" "cloud_scanner_roles" {
  for_each = toset([
    "roles/secretmanager.secretAccessor", # read INTERNAL_SHARED_SECRET
    "roles/artifactregistry.reader",      # pull relay-agent image
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.cloud_scanner.email}"
}

variable "cloud_scanner_machine_type" {
  type        = string
  description = "Machine type for the cloud-scanner VM. e2-small is enough — the relay is mostly idle plus short network probes."
  default     = "e2-small"
}

resource "google_compute_instance" "cloud_scanner" {
  name         = "hakuna-cloud-scanner"
  machine_type = var.cloud_scanner_machine_type
  zone         = var.zone

  tags = ["allow-iap-ssh"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    # Public IP so probes can reach internet targets without going through
    # Cloud NAT egress quota. (NAT works too but we want predictable source
    # IP for customer allowlisting later.)
    access_config {}
  }

  service_account {
    email  = google_service_account.cloud_scanner.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    ar-base    = local.ar_base
    project-id = var.project_id
    region     = var.region
    app-domain = var.app_domain
  }

  metadata_startup_script = <<-STARTUP
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/startup-script.log 2>&1
    echo "=== Cloud-scanner VM startup: $(date) ==="

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
    AR_BASE=$(curl -sf -H "$H" "$META/ar-base")
    PROJECT_ID=$(curl -sf -H "$H" "$META/project-id")
    REGION=$(curl -sf -H "$H" "$META/region")
    APP_DOMAIN=$(curl -sf -H "$H" "$META/app-domain")

    # ── Configure Artifact Registry auth ───────────────────────────────────
    gcloud auth configure-docker "$${REGION}-docker.pkg.dev" --quiet

    # ── Fetch shared secret from Secret Manager ────────────────────────────
    INTERNAL_SHARED_SECRET=$(gcloud secrets versions access latest \
      --secret=hakuna-internal-shared-secret --project="$${PROJECT_ID}")

    RELAY_IMAGE="$${REGION}-docker.pkg.dev/$${PROJECT_ID}/hakuna-public/relay-agent:latest"

    # ── Write docker-compose.yml ────────────────────────────────────────────
    mkdir -p /opt/hakuna-cloud-scanner
    cd /opt/hakuna-cloud-scanner

    cat > docker-compose.yml << COMPOSE
    services:
      cloud-scanner:
        image: $${RELAY_IMAGE}
        environment:
          HAKUNA_RELAY_MODE: "cloud"
          HAKUNA_BACKEND_URL: "https://$${APP_DOMAIN}"
          INTERNAL_SHARED_SECRET: "$${INTERNAL_SHARED_SECRET}"
          HAKUNA_LOG_LEVEL: "INFO"
          HAKUNA_REGISTRATION_REFRESH_S: "60"
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

    # ── systemd service ─────────────────────────────────────────────────────
    cat > /etc/systemd/system/hakuna-cloud-scanner.service << SERVICE
    [Unit]
    Description=Hakuna Cloud Scanner (multi-tenant relay agent)
    After=docker.service network-online.target
    Requires=docker.service

    [Service]
    Type=simple
    WorkingDirectory=/opt/hakuna-cloud-scanner
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
    systemctl enable hakuna-cloud-scanner
    systemctl start hakuna-cloud-scanner

    echo "=== Cloud-scanner VM startup complete: $(date) ==="
  STARTUP

  depends_on = [
    google_secret_manager_secret_version.internal_shared_secret,
    google_project_iam_member.cloud_scanner_roles,
    google_artifact_registry_repository.public,
  ]
}

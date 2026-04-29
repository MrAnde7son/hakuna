# ── Lab VM — intentionally vulnerable E2E test targets ──────────────────────
#
# Hosts docker-compose.lab.yml so the cloud scanner + audit-worker VMs can
# run end-to-end against the same surfaces documented for local dev (DVWA,
# SMB, LDAP, SSH, SNMP, LocalStack, webapp, nginx, redis, mysql, mongo,
# tomcat). Reached over the private VPC by internal IP — the scanners and
# audit-worker resolve `<lab-ip>:445`, `<lab-ip>:389`, `<lab-ip>:2222`, etc.
#
# SECURITY POSTURE
#   - The services here are deliberately weak. The VM has NO public IP, so
#     inbound from the internet is blocked at the network boundary.
#   - Ingress firewall scopes to the scanner SA + audit-worker SA (source
#     service-account match). No other SA in the project can reach lab ports.
#   - Egress firewall denies traffic from the lab SA to Cloud SQL and
#     Memorystore — if a chained vuln in the lab pops shell, the attacker
#     can't pivot to production datastores.
#   - The lab SA holds NO Secret Manager access. Lab creds are hardcoded.
#   - Opt-in: var.lab_enabled defaults to false. Flip true → apply → run
#     E2E pass → flip back to false → apply.
#
# LAB BUNDLE
#   archive_file builds /tmp/hakuna-lab-bundle.tar.gz from the source tree
#   at apply time. Uploaded to a private GCS bucket. Re-running `terraform
#   apply` after editing lab files re-uploads (etag/md5 change). The VM's
#   startup script pulls the latest object on boot.

# ── Bundle: tar the lab tree, upload to a private bucket ─────────────────────

locals {
  # Explicit allowlist. archive_file's `excludes` is too risky here — the
  # repo root contains `.env` and other secrets, and a missed exclude would
  # ship them to the bundle bucket.
  lab_files = {
    "docker-compose.lab.yml"            = "${path.module}/../docker-compose.lab.yml"
    "lab-seed/smb/public/aws-creds.txt" = "${path.module}/../lab-seed/smb/public/aws-creds.txt"
    "lab-seed/smb/public/README.txt"    = "${path.module}/../lab-seed/smb/public/README.txt"
    "lab-seed/mysql/init.sql"           = "${path.module}/../lab-seed/mysql/init.sql"
    "lab-seed/mongo/init.js"            = "${path.module}/../lab-seed/mongo/init.js"
    "lab-seed/localstack/seed.sh"       = "${path.module}/../lab-seed/localstack/seed.sh"
    "lab-webapp/Dockerfile"             = "${path.module}/../lab-webapp/Dockerfile"
    "lab-webapp/app.py"                 = "${path.module}/../lab-webapp/app.py"
    "lab-nginx/Dockerfile"              = "${path.module}/../lab-nginx/Dockerfile"
    "lab-nginx/nginx.conf"              = "${path.module}/../lab-nginx/nginx.conf"
    "lab-tomcat/Dockerfile"             = "${path.module}/../lab-tomcat/Dockerfile"
    "lab-tomcat/tomcat-users.xml"       = "${path.module}/../lab-tomcat/tomcat-users.xml"
    "lab-tomcat/vuln-index.jsp"         = "${path.module}/../lab-tomcat/vuln-index.jsp"
  }
}

data "archive_file" "lab_bundle" {
  type        = "zip"
  output_path = "${path.module}/.terraform/tmp/hakuna-lab-bundle.zip"

  dynamic "source" {
    for_each = local.lab_files
    content {
      filename = source.key
      content  = file(source.value)
    }
  }
}

resource "google_storage_bucket" "lab_bundle" {
  name          = "hakuna-lab-bundle-${var.project_id}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = false
  }

  lifecycle_rule {
    condition { age = 7 }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_object" "lab_bundle" {
  name   = "lab-bundle-${data.archive_file.lab_bundle.output_md5}.zip"
  bucket = google_storage_bucket.lab_bundle.name
  source = data.archive_file.lab_bundle.output_path
}

# ── Service account ──────────────────────────────────────────────────────────

resource "google_service_account" "lab" {
  account_id   = "hakuna-lab"
  display_name = "Hakuna Lab VM"
  description  = "Service account for the intentionally-vulnerable lab VM. No secret access — lab creds are hardcoded."
}

resource "google_project_iam_member" "lab_roles" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.lab.email}"
}

# Bucket-scoped read for the bundle. Avoids project-wide storage access.
resource "google_storage_bucket_iam_member" "lab_bundle_reader" {
  bucket = google_storage_bucket.lab_bundle.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.lab.email}"
}

# ── Firewall: ingress from scanner + audit-worker only ──────────────────────
#
# allow_internal (network.tf) opens TCP between any pair of VMs in 10.0.0.0/8
# at priority 1000 (default). We add a higher-priority deny that blocks all
# ingress to the lab SA, then a still-higher-priority allow for scanner +
# audit-worker SAs only. Net effect: inside the VPC, only the two scanner
# VMs can reach lab ports.

resource "google_compute_firewall" "lab_deny_ingress" {
  name        = "hakuna-lab-deny-ingress"
  network     = google_compute_network.main.name
  description = "Block all ingress to the lab VM unless a higher-priority allow rule matches."

  direction = "INGRESS"
  priority  = 900

  deny {
    protocol = "all"
  }

  source_ranges           = ["0.0.0.0/0"]
  target_service_accounts = [google_service_account.lab.email]
}

resource "google_compute_firewall" "lab_allow_scanners" {
  name        = "hakuna-lab-allow-scanners"
  network     = google_compute_network.main.name
  description = "Allow the EASM/VM scanner VM and the audit-worker VM to reach lab ports."

  direction = "INGRESS"
  priority  = 800

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_service_accounts = [
    google_service_account.scanner.email,
    google_service_account.audit_worker.email,
  ]
  target_service_accounts = [google_service_account.lab.email]
}

# IAP-tunnelled SSH for manual debugging. Reuses the project IAP CIDR.
resource "google_compute_firewall" "lab_allow_iap_ssh" {
  name        = "hakuna-lab-allow-iap-ssh"
  network     = google_compute_network.main.name
  description = "IAP tunnel SSH to the lab VM (no public IP needed)."

  direction = "INGRESS"
  priority  = 800

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges           = ["35.235.240.0/20"]
  target_service_accounts = [google_service_account.lab.email]
}

# ── Firewall: egress deny to production datastores ──────────────────────────
#
# Default egress in GCP is allow-all. If an attacker chains lab vulns into
# RCE on this VM, they could otherwise hit Cloud SQL / Memorystore on the
# same VPC. Block those /32s at higher priority than the default allow.

resource "google_compute_firewall" "lab_deny_egress_datastores" {
  name        = "hakuna-lab-deny-egress-datastores"
  network     = google_compute_network.main.name
  description = "Block lab VM from reaching Cloud SQL / Memorystore. Limits blast radius if a deliberate vuln is exploited."

  direction = "EGRESS"
  priority  = 900

  deny {
    protocol = "all"
  }

  destination_ranges = [
    "${google_sql_database_instance.primary.private_ip_address}/32",
    "${google_redis_instance.main.host}/32",
    "${google_redis_instance.vm_scanner.host}/32",
  ]
  target_service_accounts = [google_service_account.lab.email]
}

# ── Lab VM ────────────────────────────────────────────────────────────────────

resource "google_compute_instance" "lab" {
  count = var.lab_enabled ? 1 : 0

  name         = "hakuna-lab"
  machine_type = var.lab_machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id
    # No access_config = no public IP. Outbound (Docker pulls) via Cloud NAT.
  }

  service_account {
    email  = google_service_account.lab.email
    scopes = ["cloud-platform"] # gated by the narrow IAM bindings above
  }

  metadata = {
    bundle-bucket = google_storage_bucket.lab_bundle.name
    bundle-object = google_storage_bucket_object.lab_bundle.name
    bundle-md5    = data.archive_file.lab_bundle.output_md5
  }

  metadata_startup_script = <<-STARTUP
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/startup-script.log 2>&1
    echo "=== Hakuna Lab VM startup: $(date) ==="

    # ── Install Docker + unzip ──────────────────────────────────────────────
    apt-get update -y
    apt-get install -y apt-transport-https ca-certificates curl gnupg unzip
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker

    # ── Refresh script: pulls latest bundle from metadata and re-ups ───────
    # Called by the systemd unit's ExecStartPre — `systemctl restart hakuna-lab`
    # after `terraform apply` is enough to roll new lab files onto the VM.
    mkdir -p /opt/hakuna-lab
    cat > /opt/hakuna-lab/refresh.sh <<'REFRESH'
    #!/bin/bash
    set -euo pipefail
    META="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
    H="Metadata-Flavor: Google"
    BUNDLE_BUCKET=$(curl -sf -H "$H" "$META/bundle-bucket")
    BUNDLE_OBJECT=$(curl -sf -H "$H" "$META/bundle-object")
    echo "Refreshing bundle: gs://$${BUNDLE_BUCKET}/$${BUNDLE_OBJECT}"
    gsutil cp "gs://$${BUNDLE_BUCKET}/$${BUNDLE_OBJECT}" /tmp/lab-bundle.zip
    unzip -o /tmp/lab-bundle.zip -d /opt/hakuna-lab
    rm -f /tmp/lab-bundle.zip
    # Strip the `hakuna_default: external: true` reference (host-only network
    # used by the dev compose; not present in the cloud lab).
    sed -i 's/external: true/driver: bridge/' /opt/hakuna-lab/docker-compose.lab.yml
    # Strip the `127.0.0.1:` host-binding prefix on port mappings. On the dev
    # laptop loopback-only is the safe default; on the lab VM the scanner +
    # audit-worker reach services through the VM's private VPC IP, so we
    # need the host ports bound on 0.0.0.0. Network-level safety comes from
    # the firewall (lab_allow_scanners) which only admits the two scanner SAs.
    sed -i 's/"127\.0\.0\.1:/"/g' /opt/hakuna-lab/docker-compose.lab.yml
    REFRESH
    chmod +x /opt/hakuna-lab/refresh.sh

    # ── Compose env: satisfy interpolation for profiled services ───────────
    # The `relay` service (under `profiles: [relay]`) references
    # ${HAKUNA_AGENT_TOKEN:?...}. Compose evaluates env interpolation for
    # ALL services at parse time, even profiled ones, so the var must be set
    # even though we never start that service in the cloud. The other relay
    # vars use `:-` defaults and don't need to be set.
    cat > /opt/hakuna-lab/.env <<ENVFILE
    HAKUNA_AGENT_TOKEN=unused-relay-not-started-in-cloud-lab
    ENVFILE

    # ── First-time refresh + build + up ─────────────────────────────────────
    /opt/hakuna-lab/refresh.sh
    cd /opt/hakuna-lab
    docker compose -f docker-compose.lab.yml pull --ignore-pull-failures || true
    docker compose -f docker-compose.lab.yml build
    docker compose -f docker-compose.lab.yml up -d

    # ── systemd: re-fetch bundle on every restart ───────────────────────────
    cat > /etc/systemd/system/hakuna-lab.service <<SERVICE
    [Unit]
    Description=Hakuna Lab (intentionally vulnerable test targets)
    After=docker.service network-online.target
    Requires=docker.service

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    WorkingDirectory=/opt/hakuna-lab
    ExecStartPre=/opt/hakuna-lab/refresh.sh
    ExecStartPre=/usr/bin/docker compose -f docker-compose.lab.yml build
    ExecStart=/usr/bin/docker compose -f docker-compose.lab.yml up -d
    ExecStop=/usr/bin/docker compose -f docker-compose.lab.yml down

    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable hakuna-lab

    echo "=== Hakuna Lab VM startup complete: $(date) ==="
  STARTUP

  depends_on = [
    google_storage_bucket_object.lab_bundle,
    google_storage_bucket_iam_member.lab_bundle_reader,
    google_project_iam_member.lab_roles,
    google_compute_firewall.lab_deny_ingress,
    google_compute_firewall.lab_allow_scanners,
    google_compute_firewall.lab_deny_egress_datastores,
  ]
}

# ── VM scanner evasion proxy fleet ───────────────────────────────────────────
#
# Three e2-micro instances in three regions, each running tinyproxy on a
# fixed port. The scanner worker rotates through their public IPs as
# `HAKUNA_PROXY_POOL` to dodge IP-based rate limiting and CDN edge blocks.
#
# Access control: GCP firewall only — the proxy port is open exclusively
# to the scanner Cloud NAT egress IP (see `google_compute_address.nat` in
# network.tf). No proxy-level auth on purpose: open auth credentials on
# a public-port proxy get scraped from log/leaked configs within hours
# and the proxy becomes an open relay regardless. Firewall-level IP
# allowlisting is the actual access control here.
#
# Caveat — these IPs are GCP egress (AS15169). Cloudflare specifically
# blocks GCP ASN aggressively; this fleet helps against Akamai / Fastly /
# Vercel / CloudFront / Netlify, but Cloudflare-fronted targets may need
# a residential proxy added to the pool separately. The benefit is still
# IP diversity across regions for the non-Cloudflare edges.

variable "vm_proxy_regions" {
  type        = list(string)
  description = "GCP regions hosting the VM scanner's evasion proxy pool."
  default     = ["us-central1", "europe-west1", "asia-east1"]
}

variable "vm_proxy_port" {
  type        = number
  description = "Port the tinyproxy daemon listens on. Internal-only — IP-allowlisted to the scanner Cloud NAT egress."
  default     = 3128
}

# Dedicated VPC for the proxy fleet — auto-mode subnets give us a
# subnet per region with no explicit declaration. Kept separate from
# hakuna-vpc so the fleet can be torn down with a single
# `terraform destroy -target=google_compute_network.proxy` without
# touching scanner/audit/EASM networking.
resource "google_compute_network" "proxy" {
  name                    = "hakuna-proxy-vpc"
  auto_create_subnetworks = true
}

resource "google_compute_address" "vm_proxy" {
  for_each = toset(var.vm_proxy_regions)
  name     = "hakuna-proxy-${each.key}"
  region   = each.key
}

# GCP retired some legacy zones (e.g. europe-west1-a) so we can't
# hardcode "${region}-a" — that breaks region-by-region. Query the
# live zone list per region and pick whichever zone Google reports
# first. Stable across applies as long as the region's zone roster
# doesn't shift, and no map maintenance when a new region is added
# to var.vm_proxy_regions.
data "google_compute_zones" "vm_proxy" {
  for_each = toset(var.vm_proxy_regions)
  region   = each.key
  status   = "UP"
}

# Only the scanner Cloud NAT egress IP can reach the proxy port. No
# proxy-level auth — the firewall is the entire access control surface.
resource "google_compute_firewall" "proxy_allow_scanner" {
  name    = "hakuna-proxy-allow-scanner"
  network = google_compute_network.proxy.name

  allow {
    protocol = "tcp"
    ports    = [tostring(var.vm_proxy_port)]
  }

  source_ranges = ["${google_compute_address.nat.address}/32"]
  target_tags   = ["hakuna-evasion-proxy"]
}

# IAP SSH for ops access — same pattern as hakuna-vpc.
resource "google_compute_firewall" "proxy_allow_iap_ssh" {
  name    = "hakuna-proxy-allow-iap-ssh"
  network = google_compute_network.proxy.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["hakuna-evasion-proxy"]
}

resource "google_compute_instance" "vm_proxy" {
  for_each     = toset(var.vm_proxy_regions)
  name         = "hakuna-proxy-${each.key}"
  machine_type = "e2-micro"
  zone         = data.google_compute_zones.vm_proxy[each.key].names[0]

  tags = ["hakuna-evasion-proxy"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
    }
  }

  network_interface {
    network = google_compute_network.proxy.name
    access_config {
      nat_ip = google_compute_address.vm_proxy[each.key].address
    }
  }

  # Tinyproxy is in Debian main; configuration is dead-simple — listen
  # on the configured port, no Allow directives (access control is the
  # firewall above). The MaxClients value is generous for vulnerability
  # scan traffic; the scanner worker concurrency tops out around 50
  # parallel requests per asset.
  metadata_startup_script = <<-STARTUP
    #!/bin/bash
    set -euo pipefail
    exec > /var/log/proxy-startup.log 2>&1
    echo "=== Hakuna evasion proxy startup: $(date) ==="

    apt-get update -y
    apt-get install -y tinyproxy

    cat > /etc/tinyproxy/tinyproxy.conf <<EOF
    User tinyproxy
    Group tinyproxy
    Port ${var.vm_proxy_port}
    Listen 0.0.0.0
    Timeout 600
    LogFile "/var/log/tinyproxy/tinyproxy.log"
    LogLevel Info
    PidFile "/var/run/tinyproxy/tinyproxy.pid"
    MaxClients 100
    # No Allow directives — access control is the GCP firewall.
    ConnectPort 80
    ConnectPort 443
    ConnectPort 8080
    ConnectPort 8443
    EOF

    systemctl enable tinyproxy
    systemctl restart tinyproxy
    echo "=== Hakuna evasion proxy ready: $(date) ==="
  STARTUP
}

# Paste the value of this output into terraform.tfvars (or pass via
# `-var "vm_scanner_proxy_pool=..."`) to wire the proxies into the
# VM scanner. Recomputed on every apply so a region change here is
# one apply away from a live worker config.
output "vm_scanner_proxy_pool_value" {
  description = "Comma-separated proxy URLs for HAKUNA_PROXY_POOL. Paste into terraform.tfvars under vm_scanner_proxy_pool."
  value = join(",", [
    for region in var.vm_proxy_regions :
    "http://${google_compute_address.vm_proxy[region].address}:${var.vm_proxy_port}"
  ])
}

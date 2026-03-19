# ── VPC ──────────────────────────────────────────────────────────────────────

resource "google_compute_network" "main" {
  name                    = "hakuna-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "hakuna-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.main.id

  private_ip_google_access = true # allows private access to Google APIs without NAT
}

# ── Private service connection (required for Cloud SQL private IP) ────────────

resource "google_compute_global_address" "private_ip_range" {
  name          = "hakuna-private-ip-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  depends_on = [google_compute_global_address.private_ip_range]
}

# ── VPC Access Connector (Cloud Run → private VPC resources) ─────────────────
# Required for Cloud Run to reach Cloud SQL private IP and Memorystore.

resource "google_vpc_access_connector" "main" {
  name          = "hakuna-vpc-connector"
  region        = var.region
  network       = google_compute_network.main.name
  ip_cidr_range = "10.8.0.0/28"
  min_instances = 2 # GCP minimum
  max_instances = 3
  machine_type  = "e2-micro"

  depends_on = [google_compute_subnetwork.main]
}

# ── Cloud NAT (allows VM/Cloud Run to reach the internet for external APIs) ───

resource "google_compute_router" "main" {
  name    = "hakuna-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name                               = "hakuna-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# ── Firewall rules ────────────────────────────────────────────────────────────

# Allow internal traffic within the VPC
resource "google_compute_firewall" "allow_internal" {
  name    = "hakuna-allow-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
}

# Allow SSH via IAP (Identity-Aware Proxy) — no public IP needed on VMs
resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "hakuna-allow-iap-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP's IP range
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-iap-ssh"]
}

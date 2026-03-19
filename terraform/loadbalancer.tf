# ── Global HTTPS Load Balancer ────────────────────────────────────────────────
# Routes traffic:
#   /api/* and /openapi.json       → Cloud Run API
#   /*               → GCS frontend bucket (React SPA)
#
# Cloud CDN is enabled on the frontend backend to cache static assets globally.

# ── Static IP ─────────────────────────────────────────────────────────────────

resource "google_compute_global_address" "lb_ip" {
  name = "hakuna-lb-ip"
}

# ── SSL Certificate (managed by Google) ───────────────────────────────────────
# Google automatically provisions and renews the cert.
# DNS must point to lb_ip BEFORE applying (or cert provisioning will fail).

resource "google_compute_managed_ssl_certificate" "main" {
  name = "hakuna-ssl-${replace(var.app_domain, ".", "-")}"

  managed {
    domains = [var.app_domain]
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ── Backend: Cloud Run API ─────────────────────────────────────────────────────

resource "google_compute_region_network_endpoint_group" "api_neg" {
  name                  = "hakuna-api-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region

  cloud_run {
    service = google_cloud_run_v2_service.api.name
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "hakuna-api-backend"
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  # timeout_sec is not supported for Serverless NEG backends (Cloud Run)

  backend {
    group = google_compute_region_network_endpoint_group.api_neg.id
  }

  # No CDN for API responses
  enable_cdn = false

  log_config {
    enable      = true
    sample_rate = 0.1 # log 10% of requests — adjust up if debugging
  }
}

# ── Backend: GCS Frontend Bucket ──────────────────────────────────────────────

resource "google_compute_backend_bucket" "frontend" {
  name        = "hakuna-frontend-backend"
  bucket_name = google_storage_bucket.frontend.name
  enable_cdn  = true # Cloud CDN for static assets

  cdn_policy {
    cache_mode                   = "CACHE_ALL_STATIC"
    default_ttl                  = 3600    # 1 hour
    max_ttl                      = 86400   # 24 hours
    client_ttl                   = 3600
    serve_while_stale            = 86400   # serve stale content for up to 24h while revalidating
    signed_url_cache_max_age_sec = 0
  }
}

# ── URL Map ────────────────────────────────────────────────────────────────────

resource "google_compute_url_map" "main" {
  name            = "hakuna-url-map"
  default_service = google_compute_backend_bucket.frontend.id

  host_rule {
    hosts        = [var.app_domain]
    path_matcher = "paths"
  }

  path_matcher {
    name            = "paths"
    default_service = google_compute_backend_bucket.frontend.id

    # API traffic → Cloud Run
    route_rules {
      priority = 1
      match_rules { prefix_match = "/api/" }
      service = google_compute_backend_service.api.id
    }
    route_rules {
      priority = 2
      match_rules { full_path_match = "/api" }
      service = google_compute_backend_service.api.id
    }
    route_rules {
      priority = 3
      match_rules { full_path_match = "/openapi.json" }
      service = google_compute_backend_service.api.id
    }

    # Static asset directories → GCS directly (no rewrite)
    route_rules {
      priority = 10
      match_rules { prefix_match = "/assets/" }
      service = google_compute_backend_bucket.frontend.id
    }
    route_rules {
      priority = 11
      match_rules { prefix_match = "/locales/" }
      service = google_compute_backend_bucket.frontend.id
    }
    route_rules {
      priority = 12
      match_rules { prefix_match = "/logos/" }
      service = google_compute_backend_bucket.frontend.id
    }

    # SPA catch-all: rewrite all other paths to /index.html with 200 status.
    # This is the fix for the /threat-intel 404 — GCS served the HTML but with
    # 404 status; the regex+template rewrite here lets GCS serve index.html as
    # a normal 200 for all React Router routes.
    route_rules {
      priority = 999
      match_rules { path_template_match = "/**" }
      service = google_compute_backend_bucket.frontend.id
      route_action {
        url_rewrite { path_template_rewrite = "/index.html" }
      }
    }
  }
}

# ── HTTPS Proxy + Forwarding Rule ─────────────────────────────────────────────

resource "google_compute_target_https_proxy" "main" {
  name             = "hakuna-https-proxy"
  url_map          = google_compute_url_map.main.id
  ssl_certificates = [google_compute_managed_ssl_certificate.main.id]
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "hakuna-https-forwarding"
  target                = google_compute_target_https_proxy.main.id
  port_range            = "443"
  ip_address            = google_compute_global_address.lb_ip.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# ── HTTP → HTTPS redirect ──────────────────────────────────────────────────────

resource "google_compute_url_map" "http_redirect" {
  name = "hakuna-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "hakuna-http-proxy"
  url_map = google_compute_url_map.http_redirect.id
}

resource "google_compute_global_forwarding_rule" "http_redirect" {
  name                  = "hakuna-http-forwarding"
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.lb_ip.id
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

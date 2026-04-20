"""VM Scanner configuration — all values from environment variables."""

import os


DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://hakuna:hakuna@postgres:5432/hakuna",
)

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/1")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "/root/go/bin/nuclei")
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "30"))
NUCLEI_RATE_LIMIT = int(os.environ.get("NUCLEI_RATE_LIMIT", "150"))
NUCLEI_COMMUNITY_TEMPLATES = os.environ.get("NUCLEI_COMMUNITY_TEMPLATES", "/root/nuclei-templates")

TEMPLATES_DIR = os.environ.get(
    "TEMPLATES_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates"),
)

# DAST template sync — cloned into custom/dast/ by scanner.vm.scheduler.
# The router auto-includes everything under custom/dast/ when the asset has
# a web-serving port open, so these participate in regular VM scans without
# needing a separate scan profile.
DAST_TEMPLATES_REPO = os.environ.get(
    "DAST_TEMPLATES_REPO",
    "https://github.com/reewardius/nuclei-dast-templates.git",
)
DAST_TEMPLATES_DIR = os.path.join(TEMPLATES_DIR, "custom", "dast")

SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "600"))

# ── Content discovery (ffuf) ────────────────────────────────────
# On by default. Ops can disable globally by setting
# CONTENT_DISCOVERY_ENABLED=false — useful for deployments where
# customer targets have aggressive WAFs or strict rate limits and the
# extra request volume causes scan-time incidents. The backend still
# needs to pass enable_content_discovery=true per scan; this env var
# is the kill switch on the worker side.
CONTENT_DISCOVERY_ENABLED = os.environ.get(
    "CONTENT_DISCOVERY_ENABLED", "true"
).lower() in {"1", "true", "yes"}
FFUF_BIN = os.environ.get("FFUF_BIN", "/usr/local/bin/ffuf")

# Rate & duration budgets. The defaults are deliberately conservative:
# a 50 req/s cap keeps us below most WAF/rate-limit thresholds and a
# 10-minute per-asset ceiling stops one slow target from starving the
# queue. Tune up per deployment; never tune down for shared scanning.
CONTENT_DISCOVERY_RATE_LIMIT = int(
    os.environ.get("CONTENT_DISCOVERY_RATE_LIMIT", "50")
)
CONTENT_DISCOVERY_MAX_DURATION_S = int(
    os.environ.get("CONTENT_DISCOVERY_MAX_DURATION_S", "600")
)
CONTENT_DISCOVERY_THREADS = int(
    os.environ.get("CONTENT_DISCOVERY_THREADS", "25")
)

# Wordlists — bundled curated lists live alongside templates/. Callers
# may override via env; absolute paths only.
_CD_WORDLIST_DIR = os.path.join(TEMPLATES_DIR, "wordlists")
CONTENT_DISCOVERY_PATHS_WORDLIST = os.environ.get(
    "CONTENT_DISCOVERY_PATHS_WORDLIST",
    os.path.join(_CD_WORDLIST_DIR, "paths.txt"),
)
CONTENT_DISCOVERY_PARAMS_WORDLIST = os.environ.get(
    "CONTENT_DISCOVERY_PARAMS_WORDLIST",
    os.path.join(_CD_WORDLIST_DIR, "params.txt"),
)
CONTENT_DISCOVERY_EXPOSURES_RULES = os.environ.get(
    "CONTENT_DISCOVERY_EXPOSURES_RULES",
    os.path.join(_CD_WORDLIST_DIR, "exposures.json"),
)

# When a path returns this many status codes or fewer we treat them as
# "interesting" and feed them back as asset_endpoints. 404/501/502/503
# are always filtered at the ffuf layer. We additionally drop soft-404s
# by comparing response body size against the most-frequent size seen
# during the scan — a rough but effective baseline without calibration.
CONTENT_DISCOVERY_MATCH_CODES = os.environ.get(
    "CONTENT_DISCOVERY_MATCH_CODES", "200,201,202,204,301,302,307,401,403"
)

# When the backend supplies a precomputed adaptive scan plan with a target
# list (per-endpoint Nuclei targeting), cap the number of URLs we actually
# pass to Nuclei. Per-endpoint × DAST templates is multiplicative — without
# a cap a single misbehaving plan can spawn hours of work. The plan is
# expected to rank endpoints by value (auth_required, has_parameters,
# OpenAPI-known) and the cap keeps us honest even when the planner
# overshoots. 200 is a deliberate compromise: enough to cover the main
# attack surface of typical APIs without ballooning per-asset wall time.
NUCLEI_MAX_TARGETS_PER_ASSET = int(os.environ.get("NUCLEI_MAX_TARGETS_PER_ASSET", "200"))

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

SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "600"))

# Backend URL + bearer token for fetching per-org dedup rules.
# When unset, the VM scanner falls back to a bundled default findings rule.
BACKEND_URL = os.environ.get("HAKUNA_BACKEND_URL", "")
INTERNAL_TOKEN = os.environ.get("HAKUNA_INTERNAL_TOKEN", "")
DEDUP_RULE_CACHE_TTL = int(os.environ.get("DEDUP_RULE_CACHE_TTL", "30"))

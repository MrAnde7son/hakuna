from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hakuna:hakuna@postgres:5432/hakuna"
    database_url_sync: str = "postgresql://hakuna:hakuna@postgres:5432/hakuna"
    redis_url: str = "redis://redis:6379/0"

    celery_concurrency: int = 4
    scan_timeout_seconds: int = 600
    naabu_ports: str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,8888,9000,9443,3000,5000,27017"
    subfinder_sources: str = "all"
    uncover_sources: str = "shodan,censys,fofa"
    org_scan_stagger_seconds: int = 120
    nmap_timeout_seconds: int = 300
    nmap_max_rate: int = 100
    nmap_concurrency: int = 3
    puredns_wordlist: str = "/opt/hakuna/wordlists/subdomains.txt"
    katana_depth: int = 2
    katana_rate_limit: int = 50
    screenshot_dir: str = "/data/screenshots"

    # Per-tool thread/concurrency caps. Combined with parallel batch execution
    # (see ENRICHMENT_BATCH_CONCURRENCY below), a single stage runs up to
    # concurrency × threads connections — e.g. httpx = 4 × 50 = 200 sockets.
    subfinder_threads: int = 5
    dnsx_threads: int = 50
    naabu_rate: int = 2000
    httpx_threads: int = 50
    tlsx_threads: int = 30
    cdncheck_threads: int = 25
    puredns_threads: int = 10

    # Max concurrent tool invocations per stage. Each invocation is one batch
    # running in its own subprocess; this bounds CPU/network fan-out.
    enrichment_batch_concurrency: int = 4
    discovery_batch_concurrency: int = 4

    # Skip httpx screenshots on scans larger than this (headless Chromium is
    # the single biggest slowdown — ~1s per host — so large scans trade the
    # UX nicety for wall-time).
    screenshot_max_hosts: int = 500

    # JS fingerprinting: detect client-side libraries (jQuery, Moment.js, etc.)
    # by fetching HTML + JS files and matching version patterns.
    js_fingerprint_concurrency: int = 20
    js_fingerprint_connect_timeout: int = 10

    # Celery task safety limits (seconds)
    task_soft_time_limit: int = 1800   # 30 min soft limit
    task_time_limit: int = 2100        # 35 min hard kill

    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    fofa_email: str = ""
    fofa_key: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

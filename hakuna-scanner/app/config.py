from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hakuna:hakuna@postgres:5432/hakuna"
    database_url_sync: str = "postgresql://hakuna:hakuna@postgres:5432/hakuna"
    redis_url: str = "redis://redis:6379/0"

    celery_concurrency: int = 4
    scan_timeout_seconds: int = 600

    # When True, naabu probes the union of nmap's top-1000 TCP ports and the
    # `naabu_ports` specialty list below. When False, only `naabu_ports` is
    # probed (legacy fast-scan profile for large internal batches).
    naabu_use_top1000: bool = True

    # Per-host probe budget (seconds) for naabu when scanning the wide
    # top-1000 + specialty union. Top-1000 is ~16x more probes than the
    # legacy curated list, so the per-batch timeout needs to scale.
    naabu_per_host_seconds_top1000: float = 1.5

    # Specialty ports added on top of nmap top-1000. Keep this focused on
    # protocols/services that aren't in nmap's default top-1000 list —
    # OT/ICS, AI/LLM infra, vendor-specific cameras/DVRs, etc. Standard
    # ports (80/443/8080/8443/22/etc.) are already covered by top-1000.
    naabu_ports: str = (
        # ── Standard IT services (kept for legacy `use_top1000=False`) ──
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
        "1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,"
        "8888,9000,9443,3000,5000,27017,"
        # ── AI / LLM / ML infrastructure ──
        "8000,"   # vLLM, FastChat, Chroma, LangServe, generic FastAPI
        "11434,"  # Ollama
        "5001,"   # LocalAI, MLflow
        "3080,"   # LibreChat
        "8501,"   # Streamlit
        "7860,"   # Gradio / HuggingFace Spaces
        "4000,"   # LiteLLM proxy
        "9090,"   # Prometheus (also AI monitoring)
        "6333,"   # Qdrant vector DB
        "19530,"  # Milvus vector DB
        "8527,"   # Weaviate vector DB (gRPC)
        # ── IoT devices ──
        "554,"    # RTSP (cameras)
        "8554,"   # RTSP alternate
        "1883,"   # MQTT
        "8883,"   # MQTTS
        "5683,"   # CoAP (UDP, but probe TCP fallback)
        "1900,"   # UPnP/SSDP
        "9100,"   # Printer (RAW/JetDirect)
        "631,"    # IPP (CUPS)
        "161,"    # SNMP
        "49152,"  # UPnP alt
        "37777,"  # Dahua camera
        "34567,"  # XMEye / generic DVR
        # ── OT / ICS / SCADA ──
        "502,"    # Modbus TCP
        "102,"    # Siemens S7comm
        "44818,"  # EtherNet/IP (CIP)
        "47808,"  # BACnet (UDP, but probe TCP)
        "20000,"  # DNP3
        "4840,"   # OPC-UA
        "2404,"   # IEC 60870-5-104
        "1911,"   # Niagara Fox (Tridium)
        "789,"    # Red Lion Crimson
        "18245,"  # GE SRTP
        "2222"    # EtherNet/IP alt
    )
    # UDP ports for specialized protocols (requires nmap -sU) — top 50
    nmap_udp_ports: str = (
        "53,67,68,69,111,123,137,138,161,162,389,500,514,520,523,554,"
        "623,1194,1434,1604,1645,1646,1812,1813,1883,1900,2049,2123,"
        "3283,3478,4500,4789,5060,5353,5683,6343,6481,10161,11211,"
        "17185,27015,30718,33434,34555,47808,49152"
    )
    nmap_udp_timeout_seconds: int = 600
    subfinder_sources: str = "all"
    uncover_sources: str = "shodan,censys,fofa"
    org_scan_stagger_seconds: int = 120
    nmap_timeout_seconds: int = 300
    nmap_max_rate: int = 100
    nmap_concurrency: int = 3
    puredns_wordlist: str = "/opt/hakuna/wordlists/subdomains.txt"
    katana_depth: int = 3
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

    # Deep TLS audit (sslyze cipher enum + chain + OCSP + CAA). Each host
    # runs ~5 handshakes per TLS version, so per-host wall time is 10-30s.
    # Disabled by default — flip on per-deployment once you've sized workers.
    tls_deep_audit_enabled: bool = False
    tls_deep_audit_concurrency: int = 8
    tls_deep_audit_host_timeout: int = 60
    # Cap at this many hosts per scan to avoid runaway wall time on large
    # scans; the rest are skipped with a log message.
    tls_deep_audit_max_hosts: int = 500

    # JS fingerprinting: detect client-side libraries (jQuery, Moment.js, etc.)
    # by fetching HTML + JS files and matching version patterns.
    # Also covers meta tag extraction (generator tags, HTML artifacts).
    js_fingerprint_concurrency: int = 20
    js_fingerprint_connect_timeout: int = 10

    # Favicon hash fingerprinting: identify technologies by /favicon.ico mmh3 hash.
    favicon_fingerprint_concurrency: int = 20
    favicon_fingerprint_connect_timeout: int = 10

    # Default endpoint probing: detect technologies by probing known paths.
    # Lower concurrency than JS/favicon since each host gets ~30 probes.
    endpoint_probe_concurrency: int = 10
    endpoint_probe_connect_timeout: int = 8

    # Kiterunner: API endpoint brute-forcing
    kiterunner_concurrency: int = 10
    kiterunner_timeout: int = 600
    kiterunner_wordlist: str = "/opt/hakuna/wordlists/kiterunner-routes.kite"

    # Trufflehog: secrets scanning on JS bundles
    trufflehog_concurrency: int = 5
    trufflehog_timeout: int = 300
    trufflehog_only_verified: bool = False

    # LLM JS endpoint extraction
    llm_js_extraction_enabled: bool = True
    llm_js_extraction_max_files_per_asset: int = 5
    llm_js_extraction_min_file_size: int = 10000  # bytes
    llm_js_extraction_model: str = "claude-haiku-4-5-20251001"

    # ── API discovery enrichers (PR 3 of Adaptive Scan Plan) ──
    # OpenAPI / Swagger spec discovery: probe well-known paths, parse paths
    # × methods, persist as asset_endpoints with source="openapi". Specs
    # are the single highest-signal endpoint source — when available, every
    # endpoint comes with method + parameters + auth requirement, so the
    # planner can fuzz them precisely without crawling.
    openapi_discovery_enabled: bool = True
    openapi_discovery_concurrency: int = 10
    openapi_discovery_timeout: int = 8       # per-probe seconds
    openapi_discovery_max_spec_bytes: int = 5_000_000  # cap on spec size
    openapi_discovery_max_endpoints: int = 1000        # cap on endpoints stored per asset

    # GraphQL introspection: detect /graphql-style endpoints, attempt
    # introspection POST. Introspection-enabled in prod is itself a finding.
    graphql_introspection_enabled: bool = True
    graphql_introspection_timeout: int = 8
    graphql_introspection_concurrency: int = 10

    # Per-asset target list cap when planner uses -list mode (mirrors
    # NUCLEI_MAX_TARGETS_PER_ASSET on the VM scanner side — keep in sync).
    asset_endpoints_per_asset_cap: int = 200

    # ── JS intelligence quartet (PR 4 of Adaptive Scan Plan) ──
    # Retire.js — match downloaded JS files against a known-vuln library
    # repo (jsrepository.json from upstream retirejs/retire.js). Each hit
    # becomes a Finding with the CVE list. Deterministic; no LLM cost.
    retirejs_enabled: bool = True

    # Source map exploitation — when JS files leak .map files, parse them
    # to recover original sources. The recovered sources are fed back into
    # endpoint extraction and secret scanning to amplify those passes
    # rather than being a separate sink. Hard caps prevent a malicious
    # server from serving a 1GB sourcemap and OOMing the worker.
    sourcemap_extraction_enabled: bool = True
    sourcemap_max_bytes: int = 5_000_000
    sourcemap_max_per_asset: int = 30
    sourcemap_concurrency: int = 10
    sourcemap_timeout: int = 10

    # Secret/token scanning in JS — entropy + pattern based. Stores SHA-256
    # + first/last 4 chars in evidence — never the raw secret.
    js_secret_scanning_enabled: bool = True
    js_secret_min_entropy: float = 4.0  # Shannon bits/char floor for "high-entropy" pattern

    # LLM deep JS analysis — beyond endpoint extraction: identify auth flow,
    # role logic, hidden admin routes. Cost-gated: criticality >= min OR
    # is_internet_facing. Cached by content_hash for refresh_days.
    llm_js_deep_analysis_enabled: bool = False  # off by default — explicit opt-in
    llm_js_deep_min_criticality: int = 5
    llm_js_deep_refresh_days: int = 7

    # Scanner registry — feature flag for the registry-driven orchestration.
    # When False, enrichment.py uses its hardcoded step_groups literal.
    # When True, step_groups are built from the SCANNER_REGISTRY at runtime.
    # Default False until parity is verified in production.
    use_scanner_registry: bool = False

    # Continuous CT monitoring (CertStream websocket consumer).
    # When enabled, a long-lived worker streams certificate transparency
    # events and upserts new hostnames matching any active target_domain.
    # Opt-in — requires outbound websocket connection to CertStream.
    certstream_enabled: bool = False
    certstream_url: str = "wss://certstream.calidog.io/"
    certstream_reconnect_delay: int = 30

    # Celery task safety limits (seconds)
    task_soft_time_limit: int = 1800   # 30 min soft limit
    task_time_limit: int = 2100        # 35 min hard kill

    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    fofa_email: str = ""
    fofa_key: str = ""
    otx_api_key: str = ""

    # Cloud-provider IP-range matching (app.ingest.cloud_ranges). The
    # refresh task (app.tasks.cloud_ranges) writes per-provider JSON files
    # here once a day; the matcher loads them lazily on first lookup.
    # Falls back to a bundled seed when the directory is empty.
    cloud_ranges_dir: str = "/data/cloud_ranges"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

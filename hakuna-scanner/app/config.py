from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hakuna:hakuna@postgres:5432/hakuna"
    database_url_sync: str = "postgresql://hakuna:hakuna@postgres:5432/hakuna"
    redis_url: str = "redis://redis:6379/0"

    celery_concurrency: int = 4
    scan_timeout_seconds: int = 600
    naabu_ports: str = (
        # ── Standard IT services ──
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
    # UDP ports for specialized protocols (requires nmap -sU)
    nmap_udp_ports: str = "161,47808,1900,5683,5353,1194,4500"
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

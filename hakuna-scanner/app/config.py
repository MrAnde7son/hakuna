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
    org_scan_stagger_seconds: int = 30
    nmap_timeout_seconds: int = 300
    nmap_max_rate: int = 100
    nmap_concurrency: int = 5
    puredns_wordlist: str = "/app/wordlists/subdomains.txt"
    katana_depth: int = 2
    katana_rate_limit: int = 50

    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    fofa_email: str = ""
    fofa_key: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

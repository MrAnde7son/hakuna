from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://hakuna:hakuna@postgres:5432/hakuna"
    database_url_sync: str = "postgresql://hakuna:hakuna@postgres:5432/hakuna"
    redis_url: str = "redis://redis:6379/0"

    celery_concurrency: int = 4
    scan_timeout_seconds: int = 600
    naabu_ports: str = "80,443,8080,8443,8888,9000,9443,3000,5000"
    subfinder_sources: str = "all"
    uncover_sources: str = "shodan,censys,fofa"
    org_scan_stagger_seconds: int = 30

    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    fofa_email: str = ""
    fofa_key: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

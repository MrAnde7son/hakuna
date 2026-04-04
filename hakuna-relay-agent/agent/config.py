"""Agent configuration — loads from env vars with optional YAML override."""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    # Required
    agent_token: str = ""
    cloud_url: str = ""

    # Optional
    log_level: str = "INFO"
    reconnect_max: int = 60          # max seconds between reconnect attempts
    heartbeat_interval: int = 30     # seconds between pings
    batch_size: int = 200            # records per WebSocket message
    request_timeout: int = 60        # HTTP timeout for on-prem calls
    verify_ssl: bool = False         # verify TLS for on-prem services

    # Local credentials (loaded from env)
    local_credentials: dict = field(default_factory=dict)


def load_config() -> AgentConfig:
    """Build config from environment variables + optional agent.yaml."""
    cfg = AgentConfig(
        agent_token=os.environ.get("HAKUNA_AGENT_TOKEN", ""),
        cloud_url=os.environ.get("HAKUNA_CLOUD_URL", ""),
        log_level=os.environ.get("HAKUNA_LOG_LEVEL", "INFO"),
        reconnect_max=int(os.environ.get("HAKUNA_RECONNECT_MAX", "60")),
        heartbeat_interval=int(os.environ.get("HAKUNA_HEARTBEAT_INTERVAL", "30")),
        batch_size=int(os.environ.get("HAKUNA_BATCH_SIZE", "200")),
        request_timeout=int(os.environ.get("HAKUNA_REQUEST_TIMEOUT", "60")),
        verify_ssl=os.environ.get("HAKUNA_VERIFY_SSL", "false").lower() == "true",
    )

    # Try to load YAML override
    yaml_path = Path(os.environ.get("HAKUNA_CONFIG_FILE", "/etc/hakuna/agent.yaml"))
    if yaml_path.exists():
        try:
            import yaml
            with open(yaml_path) as f:
                overrides = yaml.safe_load(f) or {}
            for k, v in overrides.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
            logger.info("Loaded config overrides from %s", yaml_path)
        except Exception as e:
            logger.warning("Failed to load %s: %s", yaml_path, e)

    # Discover local credentials from env vars
    cfg.local_credentials = _discover_credentials()

    return cfg


def _discover_credentials() -> dict:
    """Scan env vars for on-prem product credentials.

    Convention: <PRODUCT>_BASE_URL, <PRODUCT>_USERNAME, etc.
    Returns a dict keyed by lowercase product name.
    """
    products = {}
    env = os.environ

    # Known product prefixes
    prefixes = [
        "JIRA", "SERVICENOW", "CROWDSTRIKE", "SPLUNK",
        "NESSUS", "QUALYS", "TENABLE_SC", "RAPID7",
    ]

    for prefix in prefixes:
        base_url = env.get(f"{prefix}_BASE_URL")
        if not base_url:
            continue

        product_key = prefix.lower()
        creds = {"instance_url": base_url}

        # Collect all env vars with this prefix
        for key, val in env.items():
            if key.startswith(f"{prefix}_") and key != f"{prefix}_BASE_URL":
                # Strip prefix: JIRA_USERNAME → username
                field_name = key[len(prefix) + 1:].lower()
                creds[field_name] = val

        # Infer auth type
        if "client_id" in creds and "client_secret" in creds:
            creds["_auth_type"] = "client_credentials"
        elif "api_key" in creds or "api_token" in creds:
            creds["_auth_type"] = "api_key"
        elif "token" in creds:
            creds["_auth_type"] = "bearer"
        elif "username" in creds and ("password" in creds or "api_token" in creds):
            creds["_auth_type"] = "basic"
        elif "pat" in creds:
            creds["_auth_type"] = "pat"

        products[product_key] = creds
        logger.info("Discovered local credentials for %s (%s)", product_key, base_url)

    return products

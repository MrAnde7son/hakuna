"""Vector.dev configuration generator.

Generates complete Vector YAML configs from integration settings and
built-in templates. Each generated config includes source → transform → sink
with HMAC-authenticated HTTP sink pointing to Hakuna's ingest endpoints.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "vector_templates"

# Available source templates
AVAILABLE_TEMPLATES = {
    "palo_alto_panos": {
        "display_name": "Palo Alto PAN-OS",
        "source_type": "syslog",
        "default_port": 6514,
        "description": "PAN-OS firewall traffic and threat logs via syslog",
    },
    "fortinet": {
        "display_name": "Fortinet FortiGate",
        "source_type": "syslog",
        "default_port": 6514,
        "description": "FortiGate firewall logs via syslog (key=value format)",
    },
    "cisco_asa": {
        "display_name": "Cisco ASA/Firepower",
        "source_type": "syslog",
        "default_port": 6514,
        "description": "Cisco ASA and Firepower syslog messages",
    },
    "linux_syslog": {
        "display_name": "Linux Syslog",
        "source_type": "syslog",
        "default_port": 6514,
        "description": "Generic Linux syslog (auth, system, application)",
    },
    "windows_event_log": {
        "display_name": "Windows Event Log",
        "source_type": "http",
        "default_port": 8088,
        "description": "Windows events forwarded via NXLog/Winlogbeat as JSON",
    },
    "aws_cloudtrail": {
        "display_name": "AWS CloudTrail",
        "source_type": "http",
        "default_port": 8088,
        "description": "AWS CloudTrail events via HTTP push or S3",
    },
}


def list_templates() -> list[dict]:
    """Return metadata for all available Vector source templates."""
    result = []
    for key, meta in AVAILABLE_TEMPLATES.items():
        result.append({"id": key, **meta})
    return result


def load_template(template_id: str) -> Optional[dict]:
    """Load a Vector template YAML file and return parsed dict."""
    path = _TEMPLATES_DIR / f"{template_id}.yaml"
    if not path.exists():
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def generate_config(
    integration_name: str,
    template_id: str,
    endpoint_id: str,
    token: str,
    hakuna_url: str = "http://localhost:8000",
    listen_port: Optional[int] = None,
    custom_vrl: Optional[str] = None,
) -> str:
    """Generate a complete Vector YAML configuration.

    Args:
        integration_name: Human-readable name for this source
        template_id: One of AVAILABLE_TEMPLATES keys, or "custom"
        endpoint_id: Hakuna IngestEndpoint ID
        token: Bearer token for the ingest endpoint
        hakuna_url: Base URL of the Hakuna backend
        listen_port: Override the default listen port
        custom_vrl: Optional custom VRL transform to append

    Returns:
        Complete Vector YAML config as a string.
    """
    safe_name = integration_name.lower().replace(" ", "_").replace("-", "_")[:32]

    # Load template or use generic
    template = load_template(template_id) if template_id != "custom" else None
    tmpl_meta = AVAILABLE_TEMPLATES.get(template_id, {})

    port = listen_port or tmpl_meta.get("default_port", 6514)
    source_type = tmpl_meta.get("source_type", "syslog")

    # Build source config
    if template and "source" in template:
        source_cfg = template["source"]
        # Apply port override
        if "address" in source_cfg:
            source_cfg["address"] = f"0.0.0.0:{port}"
    elif source_type == "syslog":
        source_cfg = {
            "type": "syslog",
            "mode": "tcp",
            "address": f"0.0.0.0:{port}",
        }
    else:
        source_cfg = {
            "type": "http_server",
            "address": f"0.0.0.0:{port}",
        }

    # Build VRL transform
    vrl_lines = []
    if template and template.get("transform_vrl"):
        vrl_lines.append(template["transform_vrl"].strip())
    else:
        vrl_lines.append(f'.source_system = "{safe_name}"')
        vrl_lines.append('.event_type = "generic"')
        vrl_lines.append('.severity = "info"')

    if custom_vrl:
        vrl_lines.append(custom_vrl.strip())

    # Always add timestamp normalization
    vrl_lines.append("")
    vrl_lines.append("# Ensure event_time is set")
    vrl_lines.append('.event_time = .event_time ?? .timestamp ?? to_string!(now())')

    vrl_transform = "\n".join(vrl_lines)

    # Build the full config
    config = {
        "sources": {
            f"hakuna_{safe_name}": source_cfg,
        },
        "transforms": {
            f"normalize_{safe_name}": {
                "type": "remap",
                "inputs": [f"hakuna_{safe_name}"],
                "source": vrl_transform,
            },
        },
        "sinks": {
            f"hakuna_ingest_{safe_name}": {
                "type": "http",
                "inputs": [f"normalize_{safe_name}"],
                "uri": f"{hakuna_url}/api/ingest/events/{endpoint_id}",
                "method": "post",
                "encoding": {"codec": "json"},
                "headers": {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                "batch": {
                    "max_events": 100,
                    "timeout_secs": 5,
                },
                "request": {
                    "retry_max_duration_secs": 30,
                },
            },
        },
    }

    return yaml.dump(config, default_flow_style=False, sort_keys=False)


def generate_install_script(
    endpoint_id: str,
    token: str,
    template_id: str = "linux_syslog",
    hakuna_url: str = "http://localhost:8000",
    listen_port: Optional[int] = None,
) -> str:
    """Generate a shell script to install and configure Vector."""
    port = listen_port or AVAILABLE_TEMPLATES.get(template_id, {}).get("default_port", 6514)

    return f"""#!/bin/bash
# Hakuna Vector Collector — Auto-generated install script
# Source template: {template_id}
# Endpoint: {endpoint_id}
#
# Run: curl -sSL <this-url> | sudo bash

set -euo pipefail

echo "=== Installing Vector.dev ==="
if ! command -v vector &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSfL https://sh.vector.dev | bash -s -- -y
fi

echo "=== Writing Vector config ==="
VECTOR_CONFIG_DIR="/etc/vector"
mkdir -p "$VECTOR_CONFIG_DIR"

cat > "$VECTOR_CONFIG_DIR/hakuna-{endpoint_id[:8]}.yaml" << 'VECTOR_CONFIG'
{generate_config(
    integration_name=template_id,
    template_id=template_id,
    endpoint_id=endpoint_id,
    token=token,
    hakuna_url=hakuna_url,
    listen_port=listen_port,
)}VECTOR_CONFIG

echo "=== Validating config ==="
vector validate "$VECTOR_CONFIG_DIR/hakuna-{endpoint_id[:8]}.yaml"

echo "=== Starting Vector ==="
if command -v systemctl &>/dev/null; then
    systemctl restart vector
    systemctl enable vector
else
    vector --config "$VECTOR_CONFIG_DIR/hakuna-{endpoint_id[:8]}.yaml" &
fi

echo "=== Done! Vector is listening on port {port} ==="
echo "Send syslog to: <this-host>:{port}"
"""

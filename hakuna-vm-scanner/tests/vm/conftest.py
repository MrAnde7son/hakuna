"""Shared fixtures for VM scanner tests."""

import os
import sys

import pytest

# Ensure scanner package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture
def templates_dir(tmp_path):
    """Create a temporary templates directory with routing_table.json."""
    import json

    routing_table = {
        "cpe_map": {
            "apache:http_server": ["apache", "http"],
            "nginx:nginx": ["nginx", "http"],
            "wordpress:wordpress": ["wordpress", "cms", "php"],
            "microsoft:iis": ["iis", "windows", "http"],
        },
        "tech_map": {
            "apache": ["apache", "http"],
            "nginx": ["nginx", "http"],
            "wordpress": ["wordpress", "cms", "php"],
            "node.js": ["nodejs", "http"],
        },
        "port_gates": {
            "web": {"ports": [80, 443, 8080, 8443], "tags": ["http", "ssl"]},
            "smb": {"ports": [445], "tags": ["smb"]},
            "db": {"ports": [3306, 5432, 6379, 27017], "tags": ["db"]},
        },
    }

    rt_path = tmp_path / "routing_table.json"
    rt_path.write_text(json.dumps(routing_table))

    # Create custom templates dir
    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()

    return tmp_path


@pytest.fixture
def sample_custom_template(templates_dir):
    """Create a sample custom template YAML in the temp templates dir."""
    template_content = """\
id: test-custom-check

info:
  name: Test Custom Check
  author: test
  severity: info
  tags: always,http
  metadata:
    source: custom
    verified: true

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
"""
    path = templates_dir / "custom" / "test-custom.yaml"
    path.write_text(template_content)
    return path

"""Tests for Vector config generation and template rendering."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import yaml

from services.vector_config import (
    generate_config,
    generate_install_script,
    list_templates,
    load_template,
    AVAILABLE_TEMPLATES,
)


# ── Template listing ───────────────────────────────────

def test_list_templates():
    templates = list_templates()
    assert len(templates) >= 6
    ids = [t["id"] for t in templates]
    assert "palo_alto_panos" in ids
    assert "fortinet" in ids
    assert "cisco_asa" in ids
    assert "linux_syslog" in ids
    assert "windows_event_log" in ids
    assert "aws_cloudtrail" in ids

    for t in templates:
        assert "display_name" in t
        assert "source_type" in t
        assert "description" in t


# ── Template loading ───────────────────────────────────

def test_load_template_exists():
    tmpl = load_template("linux_syslog")
    assert tmpl is not None
    assert "source" in tmpl
    assert "transform_vrl" in tmpl
    assert "sample_event" in tmpl


def test_load_template_not_found():
    tmpl = load_template("nonexistent_template_xyz")
    assert tmpl is None


def test_all_templates_valid_yaml():
    """Every template file must parse as valid YAML with required keys."""
    for template_id in AVAILABLE_TEMPLATES:
        tmpl = load_template(template_id)
        assert tmpl is not None, f"Template {template_id} not found"
        assert "source" in tmpl, f"Template {template_id} missing 'source'"
        assert "transform_vrl" in tmpl, f"Template {template_id} missing 'transform_vrl'"


# ── Config generation ──────────────────────────────────

def test_generate_config_basic():
    config_str = generate_config(
        integration_name="Test Firewall",
        template_id="palo_alto_panos",
        endpoint_id="ep-12345",
        token="hki_test_token_abc",
        hakuna_url="http://hakuna:8000",
    )
    # Must be valid YAML
    config = yaml.safe_load(config_str)
    assert "sources" in config
    assert "transforms" in config
    assert "sinks" in config

    # Check source
    source_key = list(config["sources"].keys())[0]
    assert "test_firewall" in source_key

    # Check sink points to our endpoint
    sink_key = list(config["sinks"].keys())[0]
    sink = config["sinks"][sink_key]
    assert "ep-12345" in sink["uri"]
    assert sink["headers"]["Authorization"] == "Bearer hki_test_token_abc"


def test_generate_config_custom_port():
    config_str = generate_config(
        integration_name="Custom Port Test",
        template_id="linux_syslog",
        endpoint_id="ep-99999",
        token="token",
        listen_port=12345,
    )
    config = yaml.safe_load(config_str)
    source = list(config["sources"].values())[0]
    assert "12345" in source["address"]


def test_generate_config_custom_vrl():
    config_str = generate_config(
        integration_name="VRL Test",
        template_id="linux_syslog",
        endpoint_id="ep-vrl",
        token="token",
        custom_vrl='.custom_field = "added"',
    )
    config = yaml.safe_load(config_str)
    transform = list(config["transforms"].values())[0]
    assert '.custom_field = "added"' in transform["source"]


def test_generate_config_custom_template():
    """Custom template (no file) should produce a generic config."""
    config_str = generate_config(
        integration_name="Custom Source",
        template_id="custom",
        endpoint_id="ep-custom",
        token="token",
    )
    config = yaml.safe_load(config_str)
    assert "sources" in config
    assert "sinks" in config


def test_generate_config_all_templates():
    """Every built-in template should produce valid YAML."""
    for template_id in AVAILABLE_TEMPLATES:
        config_str = generate_config(
            integration_name=f"Test {template_id}",
            template_id=template_id,
            endpoint_id=f"ep-{template_id}",
            token="test-token",
        )
        config = yaml.safe_load(config_str)
        assert "sources" in config, f"Template {template_id} config missing sources"
        assert "sinks" in config, f"Template {template_id} config missing sinks"


# ── Install script generation ──────────────────────────

def test_generate_install_script():
    script = generate_install_script(
        endpoint_id="ep-install-test",
        token="hki_install_token",
        template_id="linux_syslog",
        hakuna_url="https://hakuna.example.com",
    )
    assert "#!/bin/bash" in script
    assert "vector" in script.lower()
    assert "ep-install-test" in script
    assert "hakuna.example.com" in script


def test_install_script_custom_port():
    script = generate_install_script(
        endpoint_id="ep-port",
        token="token",
        listen_port=7777,
    )
    assert "7777" in script


# ── API endpoint tests ─────────────────────────────────

def test_vector_templates_endpoint(authed_client):
    resp = authed_client.get("/api/siem/vector-templates")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 6


def test_vector_config_endpoint(authed_client):
    # Create an ingest endpoint first
    ep_resp = authed_client.post("/api/siem/endpoints", json={
        "name": "Vector Config Test",
        "parser_type": "json",
    })
    ep_data = ep_resp.json()

    resp = authed_client.post("/api/siem/vector-config", json={
        "template_id": "linux_syslog",
        "endpoint_id": ep_data["id"],
        "token": ep_data["token"],
        "hakuna_url": "http://localhost:8000",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "config" in data
    # Verify the config is valid YAML
    config = yaml.safe_load(data["config"])
    assert "sources" in config


def test_vector_config_nonexistent_endpoint(authed_client):
    resp = authed_client.post("/api/siem/vector-config", json={
        "template_id": "linux_syslog",
        "endpoint_id": "nonexistent",
        "token": "fake",
    })
    assert resp.status_code == 404


def test_vector_install_script_endpoint(authed_client):
    ep_resp = authed_client.post("/api/siem/endpoints", json={
        "name": "Install Script Test",
        "parser_type": "json",
    })
    ep_data = ep_resp.json()

    resp = authed_client.post("/api/siem/vector-config/install-script", json={
        "template_id": "linux_syslog",
        "endpoint_id": ep_data["id"],
        "token": ep_data["token"],
    })
    assert resp.status_code == 200
    assert "#!/bin/bash" in resp.json()["script"]

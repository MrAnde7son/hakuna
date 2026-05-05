"""Asset type classification — categorize discovered assets by function.

Examines all available fingerprint signals (endpoint probes, favicon hashes,
banners, nmap service names, protocol probes, tech stack) and assigns an
asset_type label used for filtering, dashboarding, and risk contextualization.

Asset types:
  IT:               web_server, database, mail_server, vpn, ci_cd, container_registry
  AI Infrastructure: ai_inference, ai_gateway, ai_agent, vector_db
  IoT:              camera, printer, nas, router, smart_building, iot_gateway
  OT/ICS:           plc, scada, hmi, industrial_gateway
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ─── Classification Rules ────────────────────────────────────────────────────
# Priority-ordered: first match wins. More specific rules first.

_RULES: list[dict] = [
    # ── OT/ICS (highest priority — these are the most critical to flag) ──
    {"asset_type": "plc", "signals": {
        "service_names": {"modbus", "s7comm", "ethernet-ip", "dnp3"},
        "ports": {502, 102, 44818, 20000, 2404, 18245},
        "banners": [r"(?i)(simatic|modicon|controllogix|compactlogix|plc|wago|phoenix.contact|PFC[12]00)"],
        "tech_keywords": [r"(?i)(allen.bradley|rockwell|siemens\s+s7|schneider.*modicon)"],
    }},
    {"asset_type": "scada", "signals": {
        "banners": [r"(?i)(wincc|cimplicity|ifix|factorytalk|deltav|ovation|proficy|ignition)"],
        "tech_keywords": [r"(?i)(scada|wonderware|citect|vtscada|clearscada)"],
    }},
    {"asset_type": "hmi", "signals": {
        "banners": [r"(?i)(simatic\s*hmi|magelis|panel|weintek|pro-?face|c-?more)"],
        "tech_keywords": [r"(?i)(hmi|human.machine|panel.view)"],
    }},
    {"asset_type": "industrial_gateway", "signals": {
        "banners": [r"(?i)(moxa|nport|mgate|iologik|eds-|digi.connect|anybus|red.lion)"],
        "ports": {4001, 4002, 789},
        "tech_keywords": [r"(?i)(serial.server|protocol.converter|industrial.gateway)"],
    }},
    {"asset_type": "smart_building", "signals": {
        "service_names": {"bacnet", "fox"},
        "ports": {47808, 1911},
        "banners": [r"(?i)(niagara|tridium|jace|honeywell|johnson.controls|crestron|bacnet|lonworks)"],
    }},

    # ── IoT ──
    {"asset_type": "camera", "signals": {
        "service_names": {"rtsp"},
        "ports": {554, 8554, 37777, 34567},
        "banners": [r"(?i)(hikvision|dahua|axis|vivotek|hanwha|reolink|amcrest|foscam|flir|avigilon|dvr|nvr|ipcam)"],
        "tech_keywords": [r"(?i)(camera|webcam|surveillance|cctv|video.stream|rtsp)"],
    }},
    {"asset_type": "printer", "signals": {
        "service_names": {"ipp", "jetdirect", "printer"},
        "ports": {9100, 631, 515},
        "banners": [r"(?i)(laserjet|officejet|brother|epson|xerox|canon|lexmark|ricoh|konica|kyocera|samsung.*printer|pagewide|workcentre)"],
        "tech_keywords": [r"(?i)(printer|print.server|cups|ipp)"],
    }},
    {"asset_type": "nas", "signals": {
        "banners": [r"(?i)(qnap|qts|synology|diskstation|freenas|truenas|openmediavault|unraid|drobo|netgear.readynas)"],
        "tech_keywords": [r"(?i)(nas|network.attached.storage|file.server)"],
    }},
    {"asset_type": "router", "signals": {
        "banners": [r"(?i)(mikrotik|routeros|openwrt|ddwrt|edgeos|edgerouter|unifi|ubiquiti|netgear|tp.link|asus.rt|linksys|draytek|zyxel|fortios)"],
        "tech_keywords": [r"(?i)(router|gateway|firewall|access.point)"],
        "ports": {8291},  # MikroTik Winbox
    }},
    {"asset_type": "iot_gateway", "signals": {
        "service_names": {"mqtt"},
        "ports": {1883, 8883},
        "banners": [r"(?i)(mosquitto|emqx|hivemq|vernemq|rabbitmq.*mqtt|mqtt)"],
    }},

    # ── AI Infrastructure ──
    {"asset_type": "vector_db", "signals": {
        "ports": {6333, 19530},
        "banners": [r"(?i)(qdrant|weaviate|milvus|chroma|pinecone|vespa)"],
        "tech_keywords": [r"(?i)(vector.database|embedding.store|vector.search)"],
    }},
    {"asset_type": "ai_inference", "signals": {
        "ports": {11434, 7860, 8501},
        "banners": [r"(?i)(ollama|vllm|localai|fastchat|triton|torchserve|tensorflow.serving|gradio|streamlit)"],
        "tech_keywords": [r"(?i)(inference|llm|language.model|ml.model|model.serving|hugging.?face)"],
    }},
    # MCP servers are split out from ai_agent so the backend can promote
    # them into a distinct asset kind (mcp_server) — same model as ai_agent
    # but a different ecosystem, different tooling, and very different
    # remediation guidance. Must come BEFORE ai_agent (first match wins).
    {"asset_type": "mcp_server", "signals": {
        "banners": [r"(?i)(mcp[.\s_-]?server|model.context.protocol)"],
        "tech_keywords": [r"(?i)(mcp[.\s_-]?server|model.context.protocol)"],
    }},
    {"asset_type": "ai_agent", "signals": {
        "banners": [r"(?i)(flowise|langflow|langserve|dify|autogen|crewai)"],
        "tech_keywords": [r"(?i)(ai.agent|langchain|rag.pipeline|chain|agent.framework)"],
    }},
    {"asset_type": "ai_gateway", "signals": {
        "ports": {4000},
        "banners": [r"(?i)(litellm|portkey|ai.gateway|helicone)"],
        "tech_keywords": [r"(?i)(ai.gateway|llm.proxy|model.router)"],
    }},

    # ── Standard IT (lowest priority) ──
    {"asset_type": "ci_cd", "signals": {
        "banners": [r"(?i)(jenkins|gitlab|gitea|drone|argo|tekton|teamcity|bamboo|circleci|buildkite)"],
    }},
    {"asset_type": "vpn", "signals": {
        "banners": [r"(?i)(fortigate|globalprotect|pulse.secure|ivanti|anyconnect|wireguard|openvpn)"],
    }},
    {"asset_type": "database", "signals": {
        "service_names": {"mysql", "postgresql", "mongodb", "redis", "mssql", "oracle"},
        "ports": {3306, 5432, 27017, 6379, 1433, 1521},
    }},
    {"asset_type": "mail_server", "signals": {
        "service_names": {"smtp", "imap", "pop3"},
        "ports": {25, 110, 143, 993, 995},
        "banners": [r"(?i)(exchange|postfix|sendmail|exim|dovecot|outlook.web)"],
    }},
]


def classify_asset(
    open_ports: list[int] | None = None,
    service_names: list[str] | None = None,
    banners: list[str] | None = None,
    tech_stack: list[str] | None = None,
    endpoint_probe_results: list[dict] | None = None,
    protocol_probe_results: list[dict] | None = None,
) -> str | None:
    """Classify an asset into a type based on available fingerprint signals.

    Returns the asset_type string, or None if no classification matched
    (treated as a generic web_server).
    """
    port_set = set(open_ports or [])
    svc_set = {s.lower() for s in (service_names or [])}
    banner_text = " ".join(banners or [])
    tech_text = " ".join(tech_stack or [])

    # Check if endpoint probes already assigned an asset_type
    if endpoint_probe_results:
        for result in endpoint_probe_results:
            if result.get("asset_type"):
                return result["asset_type"]

    # Check if protocol probes already assigned an asset_type
    if protocol_probe_results:
        for result in protocol_probe_results:
            if result.get("asset_type"):
                return result["asset_type"]

    # Walk rules in priority order
    for rule in _RULES:
        signals = rule["signals"]
        score = 0

        # Port match
        if "ports" in signals and port_set & signals["ports"]:
            score += 2

        # Service name match
        if "service_names" in signals and svc_set & signals["service_names"]:
            score += 3

        # Banner regex match
        if "banners" in signals:
            for pattern in signals["banners"]:
                if banner_text and re.search(pattern, banner_text):
                    score += 3
                    break

        # Tech/keyword match
        if "tech_keywords" in signals:
            for pattern in signals["tech_keywords"]:
                if tech_text and re.search(pattern, tech_text):
                    score += 2
                    break

        if score >= 2:
            return rule["asset_type"]

    return None


def classify_from_nmap_banner(banner: str, service_name: str = "") -> str | None:
    """Quick classification from a single nmap banner + service name.

    Used during nmap result ingestion to tag assets immediately.
    """
    return classify_asset(
        service_names=[service_name] if service_name else None,
        banners=[banner] if banner else None,
    )

"""Hakuna normalized schema — canonical destination for all integration pulls."""

NORMALIZED_SCHEMA = {
    "asset": [
        {"name": "source_id", "type": "string", "required": True, "group": "asset", "description": "Original ID in the source tool"},
        {"name": "source_system", "type": "string", "required": True, "group": "asset", "description": "Source system identifier"},
        {"name": "hostname", "type": "string", "required": False, "group": "asset", "description": "Asset hostname"},
        {"name": "ip_address", "type": "string", "required": False, "group": "asset", "description": "IP address"},
        {"name": "fqdn", "type": "string", "required": False, "group": "asset", "description": "Fully qualified domain name"},
        {"name": "os", "type": "string", "required": False, "group": "asset", "description": "Operating system"},
        {"name": "os_version", "type": "string", "required": False, "group": "asset", "description": "OS version"},
        {"name": "environment", "type": "string", "required": False, "group": "asset", "description": "Environment tag",
         "enum_values": ["production", "staging", "dev"]},
        {"name": "tags", "type": "string[]", "required": False, "group": "asset", "description": "Tags"},
        {"name": "criticality", "type": "integer", "required": False, "group": "asset", "description": "Criticality rating 1-5"},
        {"name": "last_seen", "type": "datetime", "required": False, "group": "asset", "description": "Last seen timestamp"},
    ],
    "finding": [
        {"name": "source_id", "type": "string", "required": True, "group": "finding", "description": "Original ID in the source tool"},
        {"name": "source_system", "type": "string", "required": True, "group": "finding", "description": "Source system identifier"},
        {"name": "asset.hostname", "type": "string", "required": False, "group": "finding", "description": "Asset hostname (resolved via FK)"},
        {"name": "asset.ip_address", "type": "string", "required": False, "group": "finding", "description": "Asset IP address"},
        {"name": "cve_id", "type": "string", "required": False, "group": "finding", "description": "CVE identifier"},
        {"name": "plugin_id", "type": "string", "required": False, "group": "finding", "description": "Scanner plugin/check ID"},
        {"name": "title", "type": "string", "required": True, "group": "finding", "description": "Finding title"},
        {"name": "description", "type": "string", "required": False, "group": "finding", "description": "Detailed description"},
        {"name": "severity", "type": "enum", "required": True, "group": "finding", "description": "Severity level",
         "enum_values": ["critical", "high", "medium", "low", "info"]},
        {"name": "cvss_score", "type": "float", "required": False, "group": "finding", "description": "CVSS base score"},
        {"name": "cvss_vector", "type": "string", "required": False, "group": "finding", "description": "CVSS vector string"},
        {"name": "exploit_available", "type": "boolean", "required": False, "group": "finding", "description": "Whether a public exploit exists"},
        {"name": "solution", "type": "string", "required": False, "group": "finding", "description": "Recommended remediation"},
        {"name": "first_seen", "type": "datetime", "required": False, "group": "finding", "description": "First detection timestamp"},
        {"name": "last_seen", "type": "datetime", "required": False, "group": "finding", "description": "Last detection timestamp"},
        {"name": "status", "type": "enum", "required": False, "group": "finding", "description": "Finding status",
         "enum_values": ["open", "in_progress", "resolved", "accepted"]},
    ],
    "action": [
        {"name": "finding.cve_id", "type": "string", "required": False, "group": "action", "description": "CVE from the finding"},
        {"name": "finding.title", "type": "string", "required": False, "group": "action", "description": "Finding title"},
        {"name": "finding.severity", "type": "string", "required": False, "group": "action", "description": "Finding severity"},
        {"name": "finding.solution", "type": "string", "required": False, "group": "action", "description": "Remediation recommendation"},
        {"name": "finding.cvss_score", "type": "float", "required": False, "group": "action", "description": "CVSS score"},
        {"name": "asset.hostname", "type": "string", "required": False, "group": "action", "description": "Asset hostname"},
        {"name": "asset.ip_address", "type": "string", "required": False, "group": "action", "description": "Asset IP"},
        {"name": "asset.environment", "type": "string", "required": False, "group": "action", "description": "Asset environment"},
        {"name": "custom_payload", "type": "json", "required": False, "group": "action", "description": "Free-form JSON template with {{variable}} syntax"},
    ],
    "siem_event": [
        {"name": "event_time", "type": "datetime", "required": True, "group": "siem_event", "description": "Timestamp when the event occurred"},
        {"name": "source_system", "type": "string", "required": True, "group": "siem_event", "description": "Source system identifier (e.g. palo_alto, crowdstrike)"},
        {"name": "source_id", "type": "string", "required": False, "group": "siem_event", "description": "Original event ID in the source system"},
        {"name": "event_type", "type": "string", "required": True, "group": "siem_event", "description": "ECS event type (authentication, network, process, etc.)"},
        {"name": "event_category", "type": "string", "required": False, "group": "siem_event", "description": "ECS event category (threat, intrusion_detection, etc.)"},
        {"name": "severity", "type": "enum", "required": False, "group": "siem_event", "description": "Event severity level",
         "enum_values": ["info", "low", "medium", "high", "critical"]},
        {"name": "action", "type": "string", "required": False, "group": "siem_event", "description": "Action taken (allowed, denied, dropped)"},
        {"name": "outcome", "type": "string", "required": False, "group": "siem_event", "description": "Outcome (success, failure, unknown)"},
        {"name": "user_name", "type": "string", "required": False, "group": "siem_event", "description": "Username associated with the event"},
        {"name": "source_ip", "type": "string", "required": False, "group": "siem_event", "description": "Source IP address"},
        {"name": "dest_ip", "type": "string", "required": False, "group": "siem_event", "description": "Destination IP address"},
        {"name": "host_name", "type": "string", "required": False, "group": "siem_event", "description": "Hostname where the event occurred"},
        {"name": "message", "type": "string", "required": False, "group": "siem_event", "description": "Human-readable event message"},
        {"name": "raw", "type": "json", "required": False, "group": "siem_event", "description": "Original event payload"},
        {"name": "normalized", "type": "json", "required": False, "group": "siem_event", "description": "ECS-normalized fields"},
    ],
}


def get_schema(entity=None):
    """Return the normalized schema, optionally filtered by entity type."""
    if entity and entity in NORMALIZED_SCHEMA:
        return NORMALIZED_SCHEMA[entity]
    return NORMALIZED_SCHEMA

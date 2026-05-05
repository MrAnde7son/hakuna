"""Service-fingerprint → audit-protocol routing table.

Maps a discovered service fingerprint to the right backend audit so the
chain coordinator can dispatch port-aware audits. Without this routing,
SSH on port 2222 would never trigger an audit because the legacy
port-driven ``AUTO_TRIGGER_RULES`` only knows about port 22.

Source of fingerprints: ``Asset.easm_data["services"]`` — populated by
hakuna-scanner's naabu ``-sV`` (and banner_grab / protocol_probe) and
projected onto the backend Asset by ``services.easm._build_easm_data``.
When the scanner didn't fingerprint a port, ``WELL_KNOWN_PORTS`` lets the
coordinator fall back to a port-name guess so first-time discovery still
routes correctly. Once naabu re-runs with -sV, the fingerprint takes
over.

HTTP / HTTPS are deliberately omitted: they're handled by the Nuclei
worker (Pipeline B), which reads per-port URLs directly from
``asset_ports.http_url`` (see hakuna-vm-scanner/scanner/vm/nuclei_worker.py).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceAudit:
    """One service → audit dispatch mapping.

    ``protocol`` and ``mission`` map to ``services.audit_runner.AUDITS``
    keys. ``setting`` is the org-level enable flag — same set
    ``services.audit_auto_trigger.AUTO_AUDIT_SETTING_KEYS`` defines.
    ``requires_consent`` mirrors the OT family in ``AUTO_TRIGGER_RULES``:
    even with the org-level switch on, dispatch refuses without a fresh
    per-asset ``Asset.easm_data['ot_audit_consent']`` record.
    """
    protocol: str
    mission: str
    setting: str
    requires_consent: bool = False


# Service name (lowercase, IANA / nmap-services convention as emitted by
# naabu -sV) → audit dispatch.
SERVICE_TO_AUDIT: dict[str, ServiceAudit] = {
    # Mgmt protocols
    "ssh":              ServiceAudit("ssh",                  "exposure_audit", "auto_audit_credentialed"),
    "smb":              ServiceAudit("smb",                  "exposure_audit", "auto_audit_anon"),
    "microsoft-ds":     ServiceAudit("smb",                  "exposure_audit", "auto_audit_anon"),
    "netbios-ssn":      ServiceAudit("smb",                  "exposure_audit", "auto_audit_anon"),
    "snmp":             ServiceAudit("snmp",                 "exposure_audit", "auto_audit_anon"),
    "ldap":             ServiceAudit("ldap",                 "exposure_audit", "auto_audit_anon"),

    # Anon-protocol family
    "ftp":              ServiceAudit("exposed_anon_protocol", "triage", "auto_audit_anon_protocol"),
    "telnet":           ServiceAudit("exposed_anon_protocol", "triage", "auto_audit_anon_protocol"),
    "vnc":              ServiceAudit("exposed_anon_protocol", "triage", "auto_audit_anon_protocol"),
    "kerberos-sec":     ServiceAudit("exposed_anon_protocol", "triage", "auto_audit_anon_protocol"),
    "domain":           ServiceAudit("exposed_anon_protocol", "triage", "auto_audit_anon_protocol"),

    # Datastores
    "mysql":            ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "postgresql":       ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "mongodb":          ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "redis":            ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "elasticsearch":    ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "couchdb":          ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "memcached":        ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "etcd-client":      ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "kibana":           ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "ms-sql-s":         ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),
    "oracle-tns":       ServiceAudit("exposed_datastore", "triage", "auto_audit_datastore"),

    # IPMI
    "ipmi":             ServiceAudit("ipmi_bmc", "triage", "auto_audit_ipmi"),

    # OT — dispatch refuses without per-asset consent, see ServiceAudit.requires_consent.
    "modbus":           ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
    "iso-tsap":         ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
    "ethernetip":       ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
    "opcua":            ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
    "bacnet":           ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
    "iec104":           ServiceAudit("ot_protocol", "triage", "auto_audit_ot", requires_consent=True),
}


# Fallback when the scanner left no service fingerprint on a port. Once
# naabu's -sV (or banner_grab / protocol_probe) catches up, the
# fingerprint in ``easm_data['services']`` takes over.
WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "domain",
    88: "kerberos-sec",
    137: "netbios-ssn",
    139: "netbios-ssn",
    161: "snmp",
    389: "ldap",
    445: "microsoft-ds",
    623: "ipmi",
    1433: "ms-sql-s",
    1521: "oracle-tns",
    3306: "mysql",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    102: "iso-tsap",
    502: "modbus",
    2379: "etcd-client",
    2404: "iec104",
    4840: "opcua",
    44818: "ethernetip",
    47808: "bacnet",
}


def enumerate_service_audits(
    asset_easm_data: dict | None,
) -> list[tuple[int, str, ServiceAudit]]:
    """Yield every (port, service_name, ServiceAudit) routable on the asset.

    Reads ``easm_data['services']`` first (authoritative — naabu -sV
    populates the ``name`` field per port). For ports that have no
    fingerprint yet, falls back to ``WELL_KNOWN_PORTS`` so the
    coordinator can route on first discovery without waiting for a -sV
    re-scan. Ports that match no service get dropped — the legacy
    ``AUTO_TRIGGER_RULES`` already covers most port-driven cases for
    non-fingerprinted ports during initial discovery.
    """
    data = asset_easm_data or {}
    services = data.get("services") or {}
    seen_ports: set[int] = set()
    out: list[tuple[int, str, ServiceAudit]] = []

    if isinstance(services, dict):
        for port_str, svc in services.items():
            try:
                port = int(port_str)
            except (TypeError, ValueError):
                continue
            if not isinstance(svc, dict):
                continue
            name = (svc.get("name") or "").strip().lower()
            if not name:
                continue
            seen_ports.add(port)
            audit = SERVICE_TO_AUDIT.get(name)
            if audit is not None:
                out.append((port, name, audit))

    for raw in data.get("open_ports") or []:
        if isinstance(raw, dict):
            raw = raw.get("port") or raw.get("number")
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if port in seen_ports:
            continue
        name = WELL_KNOWN_PORTS.get(port)
        if name is None:
            continue
        audit = SERVICE_TO_AUDIT.get(name)
        if audit is not None:
            out.append((port, name, audit))

    return out

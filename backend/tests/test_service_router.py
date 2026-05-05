"""Tests for services/service_router — the service-fingerprint → audit
routing table consumed by chain_coordinator's
``service_fingerprint_audit`` pattern.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.service_router import (
    SERVICE_TO_AUDIT,
    WELL_KNOWN_PORTS,
    enumerate_service_audits,
)


class TestEnumerateServiceAudits:
    def test_empty_easm_data_returns_empty(self):
        assert enumerate_service_audits(None) == []
        assert enumerate_service_audits({}) == []

    def test_fingerprinted_ssh_on_nonstandard_port(self):
        # naabu -sV labels port 2222 as ssh — coordinator must route the SSH
        # audit and dispatch carries port=2222 so audit_target_port stamps
        # "host:2222" instead of the hardcoded port 22.
        easm = {"services": {"2222": {"name": "ssh", "product": "OpenSSH"}}}
        out = enumerate_service_audits(easm)
        assert len(out) == 1
        port, name, route = out[0]
        assert port == 2222
        assert name == "ssh"
        assert route.protocol == "ssh"
        assert route.mission == "exposure_audit"
        assert route.setting == "auto_audit_credentialed"

    def test_well_known_port_fallback_when_no_fingerprint(self):
        # naabu without -sV: open_ports has 22, services dict is empty.
        # The fallback table still routes SSH.
        easm = {"open_ports": [22, 80], "services": {}}
        out = enumerate_service_audits(easm)
        names = {n for _, n, _ in out}
        assert "ssh" in names
        # Port 80 (http) is intentionally not in SERVICE_TO_AUDIT — Nuclei
        # owns HTTP scanning. Make sure the fallback doesn't accidentally
        # route it to an audit.
        assert all(name != "http" for _, name, _ in out)

    def test_fingerprint_takes_precedence_over_fallback(self):
        # If services[port].name exists, the well-known fallback for that
        # port must not also produce a duplicate entry.
        easm = {
            "open_ports": [22],
            "services": {"22": {"name": "ssh"}},
        }
        out = enumerate_service_audits(easm)
        assert len(out) == 1

    def test_unknown_service_name_is_dropped(self):
        easm = {"services": {"9999": {"name": "totally-made-up-service"}}}
        assert enumerate_service_audits(easm) == []

    def test_unknown_port_with_no_fingerprint_is_dropped(self):
        easm = {"open_ports": [54321]}
        assert enumerate_service_audits(easm) == []

    def test_dict_form_open_ports_handled(self):
        # Some scanners write open_ports as [{port: 22}, ...] rather than
        # [22, ...]. Match the existing _open_ports tolerance.
        easm = {"open_ports": [{"port": 22}, {"number": 445}]}
        out = enumerate_service_audits(easm)
        ports = {p for p, _, _ in out}
        assert ports == {22, 445}

    def test_postgres_on_nonstandard_port_routes_to_datastore(self):
        easm = {"services": {"5433": {"name": "postgresql"}}}
        out = enumerate_service_audits(easm)
        assert len(out) == 1
        port, _, route = out[0]
        assert port == 5433
        assert route.protocol == "exposed_datastore"
        assert route.setting == "auto_audit_datastore"

    def test_modbus_carries_consent_flag(self):
        easm = {"services": {"502": {"name": "modbus"}}}
        out = enumerate_service_audits(easm)
        assert len(out) == 1
        _, _, route = out[0]
        assert route.requires_consent is True
        assert route.setting == "auto_audit_ot"


class TestRoutingTableInvariants:
    def test_every_service_setting_is_a_known_org_key(self):
        # Cross-check: every audit setting referenced must exist in the
        # central AUTO_AUDIT_SETTING_KEYS registry. Otherwise dispatch
        # gating silently treats it as "unknown protocol" and refuses.
        from services.audit_auto_trigger import AUTO_AUDIT_SETTING_KEYS

        for service, route in SERVICE_TO_AUDIT.items():
            assert route.setting in AUTO_AUDIT_SETTING_KEYS, (
                f"service '{service}' references unregistered setting "
                f"'{route.setting}' — add it to AUTO_AUDIT_SETTING_KEYS"
            )

    def test_well_known_port_table_resolves(self):
        # Every port in WELL_KNOWN_PORTS should map to a service that
        # exists in SERVICE_TO_AUDIT — otherwise the fallback is dead code.
        for port, service in WELL_KNOWN_PORTS.items():
            assert service in SERVICE_TO_AUDIT, (
                f"WELL_KNOWN_PORTS[{port}] = '{service}' is not in "
                "SERVICE_TO_AUDIT — drop the entry or add the service"
            )

    def test_http_not_in_audit_table(self):
        # HTTP/HTTPS are owned by the VM scanner (Nuclei) — including them
        # here would double-dispatch a web target.
        assert "http" not in SERVICE_TO_AUDIT
        assert "https" not in SERVICE_TO_AUDIT

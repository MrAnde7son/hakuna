"""Tests for services.audit_auto_trigger — the out-of-the-box wiring that
turns a scanner port_change event into an unauthenticated SMB / SNMP audit
run when the org has opted in."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from models.models import Asset, RelayAgent, Scan

# Side-effect import populates AUDITS so dispatch_audit_run can resolve
# protocol="smb" / "snmp". Mirrors test_audit_runner.py.
import agents.agent_tools  # noqa: F401


@pytest.fixture
def connected_relay(db_session, test_org):
    relay = RelayAgent(
        org_id=test_org.id,
        name="test-relay",
        token_hash="x",
        status="connected",
        last_seen_at=datetime.utcnow(),
    )
    db_session.add(relay)
    db_session.flush()
    return relay


@pytest.fixture
def linked_asset(db_session, test_org):
    """Asset with the scanner-side UUID stamped in easm_data so the bridge
    can map a scanner event back to it."""
    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(
        scan_id=scan.id, hostname="winhost-1", ip="10.0.0.5",
        os="Windows Server 2022",
        easm_data={"easm_asset_id": "scanner-uuid-1"},
    )
    db_session.add(asset)
    db_session.flush()
    return asset


def _port_change_event(
    scanner_asset_id: str,
    new_ports: list[int],
    hostname: str = "winhost-1",
    transport: str = "tcp",
):
    """Build a scanner port_change event. Phase 4.0 added the ``transport``
    field; defaults to TCP for the legacy SMB/datastore/anon-protocol tests."""
    return {
        "id": "evt-1",
        "asset_id": scanner_asset_id,
        "event_type": "port_change",
        "created_at": "2026-04-25T00:00:00+00:00",
        "payload": {
            "hostname": hostname,
            "transport": transport,
            "new_ports": new_ports,
            "removed_ports": [],
        },
    }


def test_disabled_when_org_setting_off(db_session, test_org, linked_asset, connected_relay):
    """Default behavior: settings.auto_audit_anon is unset → no dispatch."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    assert (test_org.settings or {}).get("auto_audit_anon") is None

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_smb_dispatched_on_445(db_session, test_org, linked_asset, connected_relay):
    """445 added → SMB null_session audit dispatched anonymously."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445, 80]),
        )

    assert n == 1

    scan = db_session.query(Scan).filter_by(scan_type="smb_audit").first()
    assert scan is not None
    md = scan.raw_metadata or {}
    assert md["protocol"] == "smb"
    assert md["mission"] == "null_session"
    assert md["credential_id"] is None
    assert md["relay_agent_id"] == connected_relay.id
    assert md["asset_ids"] == [linked_asset.id]


def test_snmp_dispatched_on_161(db_session, test_org, linked_asset, connected_relay):
    """SNMP rule declares ``transport='udp'``; the auto-trigger only fires
    when the scanner emits a UDP-tagged port_change event (Phase 4.0)."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [161], transport="udp"),
        )

    assert n == 1
    scan = db_session.query(Scan).filter_by(scan_type="snmp_audit").first()
    assert scan is not None
    assert scan.raw_metadata["protocol"] == "snmp"
    assert scan.raw_metadata["mission"] == "device_posture"
    assert scan.raw_metadata["credential_id"] is None


def test_snmp_does_not_fire_on_tcp_event_for_port_161(
    db_session, test_org, linked_asset, connected_relay,
):
    """Phase 4.0 transport filter: a TCP port_change for port 161 (which
    would be unusual but shouldn't crash) must NOT fire the SNMP audit —
    SNMP is declared transport='udp' on the rule."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [161], transport="tcp"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_smb_does_not_fire_on_udp_event_for_port_445(
    db_session, test_org, linked_asset, connected_relay,
):
    """Mirror of the SNMP case: SMB rule is TCP; a UDP-tagged event with
    port 445 must not fire it. Confirms the matcher is symmetric."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445], transport="udp"),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_legacy_event_without_transport_field_defaults_to_tcp(
    db_session, test_org, linked_asset, connected_relay,
):
    """Phase 4.0 backwards-compat: a port_change event with no ``transport``
    field (pre-4.0 scanner emit) must be treated as TCP — preserving the
    historical behavior where SMB on 445 would fire."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    legacy_event = {
        "id": "evt-legacy",
        "asset_id": "scanner-uuid-1",
        "event_type": "port_change",
        "created_at": "2026-04-25T00:00:00+00:00",
        "payload": {
            "hostname": "winhost-1",
            "new_ports": [445],
            "removed_ports": [],
            # No ``transport`` field — pre-Phase-4.0 scanner emit shape.
        },
    }
    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(db_session, test_org, legacy_event)

    assert n == 1


def test_no_match_for_unrelated_ports(db_session, test_org, linked_asset, connected_relay):
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [80, 443, 22]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_no_relay_skips_dispatch(db_session, test_org, linked_asset):
    """Without a connected relay there's no path to the target — skip
    cleanly instead of erroring."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_unknown_scanner_asset_id_no_op(db_session, test_org, linked_asset, connected_relay):
    """Scanner emits an event for an asset the backend hasn't ingested yet —
    silently skip rather than raise."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("unknown-uuid", [445]),
        )

    assert n == 0
    mock_dispatch.assert_not_called()


def test_cooldown_suppresses_repeat_within_24h(db_session, test_org, linked_asset, connected_relay):
    """A second port_change for the same protocol within the cooldown
    window must not produce a second audit run."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        first = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )
        second = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert first == 1
    assert second == 0
    smb_scans = db_session.query(Scan).filter_by(scan_type="smb_audit").count()
    assert smb_scans == 1


def test_cooldown_expired_allows_redispatch(db_session, test_org, linked_asset, connected_relay):
    """Past the 24h window the same (asset, protocol) is re-eligible."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    # Pre-stamp an old cooldown so the next call falls outside the window.
    stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    linked_asset.easm_data = {
        **(linked_asset.easm_data or {}),
        "_auto_audit_last": {"smb": stale},
    }
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445]),
        )

    assert n == 1


def test_445_and_139_collapse_to_single_smb_run(db_session, test_org, linked_asset, connected_relay):
    """Both 445 and 139 map to the smb null_session mission — one event
    that adds both ports must produce exactly one SMB audit, not two."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
        n = maybe_auto_trigger_anon_audits(
            db_session, test_org,
            _port_change_event("scanner-uuid-1", [445, 139]),
        )

    assert n == 1
    smb_scans = db_session.query(Scan).filter_by(scan_type="smb_audit").count()
    assert smb_scans == 1


def test_non_port_change_event_ignored(db_session, test_org, linked_asset, connected_relay):
    """Defense-in-depth: even if the bridge mistakenly forwards a
    non-port_change event, the trigger function must no-op."""
    from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

    test_org.settings = {"auto_audit_anon": True}
    db_session.flush()

    event = {
        "id": "evt-2",
        "asset_id": "scanner-uuid-1",
        "event_type": "tech_change",
        "payload": {"hostname": "winhost-1", "new_tech": {"nginx": "1.20"}},
    }

    with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
        n = maybe_auto_trigger_anon_audits(db_session, test_org, event)

    assert n == 0
    mock_dispatch.assert_not_called()


# ── AutoTriggerRule registry & per-rule gating ───────────────────────


def test_auto_trigger_rules_registry_seeded_with_smb_and_snmp():
    """The Phase 0 refactor must keep the existing SMB/SNMP behavior — both
    rules must be present in the registry, with the right port mappings,
    and gated by the existing ``auto_audit_anon`` setting key so today's
    customers don't experience a behavior change."""
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES

    by_protocol = {r.protocol: r for r in AUTO_TRIGGER_RULES}
    assert {"smb", "snmp"}.issubset(by_protocol.keys())

    smb = by_protocol["smb"]
    assert set(smb.ports) == {445, 139}
    assert smb.mission == "null_session"
    assert smb.enabled_setting_key == "auto_audit_anon"
    assert smb.requires_per_asset_consent is False

    snmp = by_protocol["snmp"]
    assert set(snmp.ports) == {161,}
    assert snmp.mission == "device_posture"
    assert snmp.transport == "udp"


def test_per_rule_setting_key_isolates_families(db_session, test_org, linked_asset, connected_relay):
    """A future family rule gated by e.g. ``auto_audit_datastore`` must NOT
    fire when only ``auto_audit_anon`` is enabled. Verifies the per-family
    gating refactor (each family gets its own switch) actually isolates."""
    from datetime import timedelta
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES, AutoTriggerRule

    fake_rule = AutoTriggerRule(
        protocol="smb",  # reuse existing protocol so dispatch resolves
        mission="null_session",
        ports=(8888,),  # not in any other rule
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_datastore",  # new family key
    )
    AUTO_TRIGGER_RULES.append(fake_rule)
    try:
        from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

        # Only the legacy switch on; the datastore-family rule must not fire.
        test_org.settings = {"auto_audit_anon": True}
        db_session.flush()

        with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
            n = maybe_auto_trigger_anon_audits(
                db_session, test_org,
                _port_change_event("scanner-uuid-1", [8888]),
            )

        assert n == 0
        mock_dispatch.assert_not_called()
    finally:
        AUTO_TRIGGER_RULES.remove(fake_rule)


def test_per_asset_consent_gate_blocks_dispatch_when_missing(
    db_session, test_org, linked_asset, connected_relay,
):
    """OT-class rules with ``requires_per_asset_consent=True`` must refuse
    to dispatch even when the org-level switch is on, unless the asset
    carries a fresh consent record."""
    from datetime import timedelta
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES, AutoTriggerRule

    consent_rule = AutoTriggerRule(
        protocol="smb",
        mission="null_session",
        ports=(9999,),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_ot",
        requires_per_asset_consent=True,
    )
    AUTO_TRIGGER_RULES.append(consent_rule)
    try:
        from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

        test_org.settings = {"auto_audit_ot": True}  # org switch ON
        # No consent on the asset.
        db_session.flush()

        with patch("services.audit_auto_trigger.dispatch_audit_run") as mock_dispatch:
            n = maybe_auto_trigger_anon_audits(
                db_session, test_org,
                _port_change_event("scanner-uuid-1", [9999]),
            )
        assert n == 0
        mock_dispatch.assert_not_called()
    finally:
        AUTO_TRIGGER_RULES.remove(consent_rule)


def test_per_asset_consent_gate_allows_dispatch_when_fresh(
    db_session, test_org, linked_asset, connected_relay,
):
    """With a fresh consent record the consent-gated rule fires normally."""
    from datetime import timedelta
    from services.audit_auto_trigger import AUTO_TRIGGER_RULES, AutoTriggerRule

    consent_rule = AutoTriggerRule(
        protocol="smb",
        mission="null_session",
        ports=(9999,),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_ot",
        requires_per_asset_consent=True,
    )
    AUTO_TRIGGER_RULES.append(consent_rule)
    try:
        from services.audit_auto_trigger import maybe_auto_trigger_anon_audits

        test_org.settings = {"auto_audit_ot": True}
        # Stamp a fresh consent record for protocol=smb.
        linked_asset.easm_data = {
            **(linked_asset.easm_data or {}),
            "ot_audit_consent": {
                "smb": {
                    "granted_by": 1,
                    "granted_at": datetime.now(timezone.utc).isoformat(),
                },
            },
        }
        db_session.flush()

        with patch("services.audit_runner._dispatch_background_run", return_value="task-1"):
            n = maybe_auto_trigger_anon_audits(
                db_session, test_org,
                _port_change_event("scanner-uuid-1", [9999]),
            )

        assert n == 1
    finally:
        AUTO_TRIGGER_RULES.remove(consent_rule)


# ── ProtocolAudit safety_class / capability predicates ────────────────


def test_smb_and_snmp_marked_anon_capable():
    """The Phase 0 refactor moved anon-capability from a hardcoded set in
    audit_runner to a per-audit ``safety_class`` field. SMB/SNMP must
    keep ``is_anonymous_capable() == True`` so today's no-credential
    dispatches keep working."""
    import agents.agent_tools  # noqa: F401
    from agents.audit_registry import get_audit

    assert get_audit("smb").is_anonymous_capable() is True
    assert get_audit("smb").safety_class == "anon_standard"
    assert get_audit("smb").auto_trigger_policy == "auto_org_opt_in"

    assert get_audit("snmp").is_anonymous_capable() is True
    assert get_audit("snmp").safety_class == "anon_standard"


def test_credentialed_audits_remain_credentialed():
    """WMI / LDAP / SSH must NOT be anon-capable — they require creds."""
    import agents.agent_tools  # noqa: F401
    from agents.audit_registry import get_audit

    for proto in ("wmi", "ldap", "ssh"):
        audit = get_audit(proto)
        assert audit.safety_class == "credentialed", (
            f"{proto} must default to credentialed safety_class"
        )
        assert audit.is_anonymous_capable() is False
        assert audit.requires_per_asset_consent() is False


def test_dispatch_rejects_credentialed_audit_without_cred(db_session, test_org):
    """Audit-runner now derives the cred requirement from the audit's
    ``safety_class``. A credentialed audit (WMI) without ``credential_id``
    must still raise the same error message."""
    import agents.agent_tools  # noqa: F401
    from services.audit_runner import dispatch_audit_run, AuditDispatchError

    scan = Scan(
        filename="placeholder", scan_type="manual", source_type="manual",
        org_id=test_org.id,
    )
    db_session.add(scan)
    db_session.flush()
    asset = Asset(scan_id=scan.id, hostname="winhost-2", ip="10.0.0.6")
    db_session.add(asset)
    db_session.flush()

    with pytest.raises(AuditDispatchError, match="credential_id is required"):
        dispatch_audit_run(
            db=db_session,
            org=test_org,
            protocol="wmi",
            mission="identity",
            asset_ids=[asset.id],
            relay_agent_id="relay-x",
            credential_id=None,
        )

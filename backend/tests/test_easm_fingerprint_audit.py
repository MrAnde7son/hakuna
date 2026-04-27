"""Tests for the Phase-2 EASM fingerprint family.

Three concerns covered:

  1. ``ProtocolAudit(protocol="easm_fingerprint", mode="fingerprint")`` is
     registered, has the right metadata, and carries no LLM tools/missions.
  2. ``audit_runner._validate_dispatch_inputs`` refuses to dispatch any
     fingerprint-mode audit — the registration is for UI/compliance only.
  3. ``cve_correlator._banner_components`` extracts the four high-signal
     banner shapes (SSH OpenSSH/Dropbear/libssh, PostgreSQL, MySQL with
     OS-suffix stripping, TR-069 RomPager) and skips the free-form ones
     (RDP no version, SMTP/IMAP/POP3 software, IPP, UPnP).
"""

from __future__ import annotations

import pytest

# Side-effect import to populate AUDITS — same pattern test_audit_runner uses.
import agents.agent_tools  # noqa: F401

from agents.audit_registry import get_audit, list_audits
from services.audit_runner import AuditDispatchError, _validate_dispatch_inputs
from services.cve_correlator import _banner_components


# ── Registration ─────────────────────────────────────────────────────────


def test_easm_fingerprint_registered():
    assert "easm_fingerprint" in list_audits()
    audit = get_audit("easm_fingerprint")
    assert audit.mode == "fingerprint"
    assert audit.safety_class == "anon_standard"
    assert audit.tool_names == []
    assert audit.missions == []
    # 14 ports across the 6 banner families.
    assert set(audit.required_ports) == {
        22, 25, 110, 143, 465, 587, 631,
        993, 995, 1900, 3306, 3389, 5432, 7547,
    }
    # Compliance auto-tagging targets.
    assert "cis_benchmarks" in audit.compliance_tags
    assert "nist_csf_pr_ds" in audit.compliance_tags


def test_easm_fingerprint_is_anonymous_capable():
    """Required so the dispatch credential check doesn't reject it before
    the mode guard fires (defense-in-depth)."""
    audit = get_audit("easm_fingerprint")
    assert audit.is_anonymous_capable() is True


# ── Dispatch guard ────────────────────────────────────────────────────────


def test_dispatch_refuses_fingerprint_mode():
    """``mode="fingerprint"`` audits are scanner-driven; dispatching one
    via the LLM pipeline is a programming error and must raise loudly."""
    with pytest.raises(AuditDispatchError) as exc:
        _validate_dispatch_inputs(
            protocol="easm_fingerprint",
            mission="triage",
            relay_agent_id="r1",
            credential_id=None,
            asset_ids=[1],
            targets=None,
        )
    assert "fingerprint-mode" in str(exc.value)
    assert "scanner-driven" in str(exc.value)


def test_dispatch_guard_fires_before_mission_resolution():
    """Even with a bogus mission name, the mode check must reject first.
    Otherwise we'd return a confusing 'unknown mission' error for what is
    really a 'this audit isn't dispatchable at all' situation."""
    with pytest.raises(AuditDispatchError, match="fingerprint-mode"):
        _validate_dispatch_inputs(
            protocol="easm_fingerprint",
            mission="this_mission_does_not_exist",
            relay_agent_id="r1",
            credential_id=None,
            asset_ids=[1],
            targets=None,
        )


# ── Banner → (component, version) extraction ─────────────────────────────


class TestBannerComponents:
    def test_ssh_openssh(self):
        out = _banner_components({"banner_findings": [{
            "protocol": "ssh", "port": 22,
            "banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
            "version": {"proto": "2.0", "software": "OpenSSH_8.4p1",
                        "comments": "Debian-5+deb11u1"},
        }]})
        assert out == [{
            "component": "openssh", "version": "8.4p1",
            "source_protocol": "ssh", "port": 22,
            "raw_banner": "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
        }]

    def test_ssh_dropbear(self):
        out = _banner_components({"banner_findings": [{
            "protocol": "ssh", "port": 22,
            "banner": "SSH-2.0-dropbear_2020.81",
            "version": {"proto": "2.0", "software": "dropbear_2020.81",
                        "comments": None},
        }]})
        assert len(out) == 1
        assert out[0]["component"] == "dropbear"
        assert out[0]["version"] == "2020.81"

    def test_ssh_libssh_dash_separator(self):
        """libssh banners use '-' rather than '_' between name and version."""
        out = _banner_components({"banner_findings": [{
            "protocol": "ssh", "port": 22,
            "version": {"software": "libssh-0.10.4"},
        }]})
        assert len(out) == 1
        assert out[0]["component"] == "libssh"
        assert out[0]["version"] == "0.10.4"

    def test_ssh_unknown_software_skipped(self):
        """Unrecognized SSH implementations don't get a CVE candidate seed —
        substring matching against ThreatCVE.affected_products would be noise."""
        out = _banner_components({"banner_findings": [{
            "protocol": "ssh", "port": 22,
            "version": {"software": "WeirdCustomBuild_1.2"},
        }]})
        assert out == []

    def test_postgresql(self):
        out = _banner_components({"banner_findings": [{
            "protocol": "postgresql", "port": 5432,
            "banner": "FATAL: role \"hakuna_probe\" does not exist",
            "version": {"server_version": "14.5", "sqlstate": "28000"},
        }]})
        assert out[0]["component"] == "postgresql"
        assert out[0]["version"] == "14.5"

    def test_mysql_strips_os_suffix(self):
        """MySQL banners include the OS/build suffix; the matcher needs
        just the semver portion to match against ThreatCVE rows."""
        out = _banner_components({"banner_findings": [{
            "protocol": "mysql", "port": 3306,
            "version": {"protocol_version": 10,
                        "server_version": "8.0.32-0ubuntu0.20.04.2"},
        }]})
        assert out[0]["component"] == "mysql"
        assert out[0]["version"] == "8.0.32"

    def test_mysql_two_part_version(self):
        out = _banner_components({"banner_findings": [{
            "protocol": "mysql", "port": 3306,
            "version": {"server_version": "5.7-log"},
        }]})
        assert out[0]["version"] == "5.7"

    def test_tr069_rompager(self):
        """RomPager is the high-value TR-069 banner (CVE-2014-9222 'Misfortune
        Cookie' and friends). Must be extracted from the Server header."""
        out = _banner_components({"banner_findings": [{
            "protocol": "tr069", "port": 7547,
            "banner": "RomPager/4.07 UPnP/1.0",
            "version": {"server": "RomPager/4.07 UPnP/1.0"},
        }]})
        assert out[0]["component"] == "rompager"
        assert out[0]["version"] == "4.07"

    def test_skips_rdp_no_version(self):
        out = _banner_components({"banner_findings": [{
            "protocol": "rdp", "port": 3389,
            "version": {"selected_protocol": "rdp"},
        }]})
        assert out == []

    def test_skips_smtp_imap_pop3(self):
        """Free-form mail banners aren't reliably mappable to (vendor, version);
        keeping them in the easm_data ride-along is fine but we don't seed
        CVE candidates from them."""
        out = _banner_components({"banner_findings": [
            {"protocol": "smtp", "port": 25,
             "version": {"software": "Postfix (Ubuntu)"}},
            {"protocol": "imap", "port": 143,
             "version": {"software": "Dovecot ready"}},
            {"protocol": "pop3", "port": 110,
             "version": {"software": "Dovecot ready"}},
        ]})
        assert out == []

    def test_skips_printer_and_upnp(self):
        out = _banner_components({"banner_findings": [
            {"protocol": "ipp", "port": 631,
             "version": {"make_and_model": "HP LaserJet"}},
            {"protocol": "upnp", "port": 1900,
             "version": {"manufacturer": "Sonos", "model": "Play:1"}},
        ]})
        assert out == []

    def test_handles_missing_easm_data(self):
        assert _banner_components(None) == []
        assert _banner_components({}) == []
        assert _banner_components({"banner_findings": None}) == []
        assert _banner_components({"banner_findings": []}) == []
        assert _banner_components({"other_key": "x"}) == []

    def test_handles_malformed_entries(self):
        """Defensive: bad entries shouldn't crash the correlator."""
        out = _banner_components({"banner_findings": [
            None, "not a dict", 42,
            {"protocol": "ssh"},  # missing version
            {"protocol": "ssh", "version": "not a dict"},
        ]})
        assert out == []

    def test_mixed_batch(self):
        """Realistic asset: some mappable, some not — only the mappable
        ones come back, in order."""
        out = _banner_components({"banner_findings": [
            {"protocol": "rdp", "port": 3389, "version": {}},  # skip
            {"protocol": "ssh", "port": 22,
             "version": {"software": "OpenSSH_9.0p1"}},        # keep
            {"protocol": "smtp", "port": 25,
             "version": {"software": "Exim 4.94"}},            # skip
            {"protocol": "postgresql", "port": 5432,
             "version": {"server_version": "13.8"}},           # keep
        ]})
        assert [(o["component"], o["version"]) for o in out] == [
            ("openssh", "9.0p1"),
            ("postgresql", "13.8"),
        ]

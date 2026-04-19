"""Tests for the rewritten _generate_attack_paths.

Goals:
- Entry is NO LONGER gated on internet_facing.
- A target is required (DC, high-criticality, internet-facing, or critical finding).
- Every row carries entry_reason, target_reason, score, score_breakdown.
- Steps include why_reachable + what_enables.
- Re-running is idempotent (stale un-narrated paths wiped).
- Narrated paths are preserved across re-runs.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import text

from models.models import (
    Asset,
    AssetRelationship,
    AttackPath,
    Finding,
)
from services.finding_correlator import (
    _build_entry_set,
    _build_target_set,
    _generate_attack_paths,
    _score_chain,
)


def _asset(db, scan, *, hostname, ip=None, criticality=5, internet_facing=False):
    a = Asset(
        scan_id=scan.id,
        hostname=hostname,
        ip=ip,
        asset_type="host",
        criticality=criticality,
        is_internet_facing=internet_facing,
    )
    db.add(a)
    db.flush()
    return a


def _finding(db, scan, asset, *, severity=4, plugin_name="RCE", exploit=False, port=None):
    f = Finding(
        scan_id=scan.id,
        asset_id=asset.id,
        plugin_id="99999",
        plugin_name=plugin_name,
        severity=severity,
        severity_label={4: "Critical", 3: "High", 2: "Medium"}.get(severity, "Info"),
        workflow_status="open",
        exploit_available=exploit,
        port=port,
    )
    db.add(f)
    db.flush()
    return f


def _edge(db, org, src, tgt, rel_type, confidence="high", properties=None):
    db.add(AssetRelationship(
        org_id=org.id,
        source_asset_id=src.id,
        target_asset_id=tgt.id,
        relationship_type=rel_type,
        confidence=confidence,
        weight=0.9,
        properties=properties or {},
    ))
    db.flush()


class TestEntryAndTargetSets:
    def test_non_internet_facing_asset_qualifies_as_entry(self, db_session, test_org, test_scan):
        a = _asset(db_session, test_scan, hostname="internal-1", internet_facing=False)
        _finding(db_session, test_scan, a, severity=4)
        db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :a"),
                           {"o": test_org.id, "a": a.id})
        db_session.flush()

        entries = _build_entry_set(db_session, test_org.id)
        assert any(e["asset_id"] == a.id for e in entries)
        entry = next(e for e in entries if e["asset_id"] == a.id)
        assert "critical_finding" in entry["reason"]
        assert "internet_facing" not in entry["reason"]

    def test_internet_facing_flag_added_to_reason(self, db_session, test_org, test_scan):
        a = _asset(db_session, test_scan, hostname="edge", internet_facing=True)
        _finding(db_session, test_scan, a, severity=3, exploit=True)
        db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :a"),
                           {"o": test_org.id, "a": a.id})
        db_session.flush()

        entries = _build_entry_set(db_session, test_org.id)
        entry = next(e for e in entries if e["asset_id"] == a.id)
        assert "high_finding" in entry["reason"]
        assert "internet_facing" in entry["reason"]
        assert "has_exploit" in entry["reason"]

    def test_dc_target_inferred_from_edges(self, db_session, test_org, test_scan):
        workstation = _asset(db_session, test_scan, hostname="ws1")
        dc = _asset(db_session, test_scan, hostname="dc1")
        _edge(db_session, test_org, workstation, dc, "member_of_domain")

        targets = _build_target_set(db_session, test_org.id)
        assert dc.id in targets
        assert targets[dc.id]["reason"] == "domain_controller"

    def test_high_criticality_target(self, db_session, test_org, test_scan):
        db_host = _asset(db_session, test_scan, hostname="db1", criticality=9)
        db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :a"),
                           {"o": test_org.id, "a": db_host.id})
        db_session.flush()

        targets = _build_target_set(db_session, test_org.id)
        assert db_host.id in targets
        assert targets[db_host.id]["reason"] == "high_criticality=9"


class TestScoreChain:
    def test_score_combines_severity_criticality_and_bonuses(self):
        entry = {"max_severity": 4, "is_internet_facing": True, "has_exploit": True}
        chain = [
            {"edge_type": "entry", "severity": 4},
            {"edge_type": "connects_to", "edge_confidence": "high", "severity": 3},
        ]
        target = {"reason": "domain_controller", "criticality": 10}
        score, breakdown = _score_chain(entry, chain, target)

        # base = 4*6 + 10*4 = 64
        # length_bonus = log1p(2)*5 ≈ 5.49
        # bonuses = 5 (exploit) + 5 (IF) + 5 (DC) = 15
        # conf = 1.0
        assert score > 60
        assert score <= 100
        assert breakdown["entry_severity"] == 4
        assert breakdown["target_criticality"] == 10
        assert any(b["label"] == "domain_controller_target" for b in breakdown["bonuses"])
        assert any(b["label"] == "exploit_available" for b in breakdown["bonuses"])

    def test_low_confidence_edges_scale_down_score(self):
        entry = {"max_severity": 3, "is_internet_facing": False, "has_exploit": False}
        chain = [
            {"edge_type": "entry", "severity": 3},
            {"edge_type": "connects_to", "edge_confidence": "low", "severity": 2},
            {"edge_type": "connects_to", "edge_confidence": "low", "severity": 2},
        ]
        target = {"reason": "high_criticality=8", "criticality": 8}
        score, breakdown = _score_chain(entry, chain, target)
        assert breakdown["confidence_factor"] == 0.25  # 0.5 * 0.5
        # Low confidence should significantly reduce the score vs. all-high.
        high_score, _ = _score_chain(
            entry,
            [
                {"edge_type": "entry", "severity": 3},
                {"edge_type": "connects_to", "edge_confidence": "high", "severity": 2},
                {"edge_type": "connects_to", "edge_confidence": "high", "severity": 2},
            ],
            target,
        )
        assert score < high_score


class TestGenerateAttackPaths:
    def _setup(self, db_session, test_org, test_scan, *, entry_if=False):
        """Seed an internal entry → connects_to → DC target scenario."""
        entry = _asset(db_session, test_scan, hostname="ws1", internet_facing=entry_if)
        dc = _asset(db_session, test_scan, hostname="dc1", criticality=10)
        _finding(db_session, test_scan, entry, severity=4, plugin_name="RCE")
        _finding(db_session, test_scan, dc, severity=3, plugin_name="SMB signing not required")
        # mark a member_of_domain edge → dc is target
        _edge(db_session, test_org, entry, dc, "member_of_domain", properties={"domain": "corp"})
        db_session.execute(text("UPDATE assets SET org_id = :o"), {"o": test_org.id})
        db_session.flush()
        return entry, dc

    def test_internal_entry_generates_path_to_dc(self, db_session, test_org, test_scan):
        entry, dc = self._setup(db_session, test_org, test_scan, entry_if=False)
        created = _generate_attack_paths(db_session, test_org.id)
        assert created >= 1

        path = db_session.query(AttackPath).first()
        assert path is not None
        assert path.entry_asset_id == entry.id
        assert path.target_asset_id == dc.id
        assert "critical_finding" in (path.entry_reason or "")
        assert path.target_reason == "domain_controller"
        assert (path.score or 0) > 0
        assert isinstance(path.score_breakdown, dict)
        assert path.score_breakdown.get("entry_severity") == 4

    def test_steps_contain_why_reachable_and_what_enables(self, db_session, test_org, test_scan):
        self._setup(db_session, test_org, test_scan)
        _generate_attack_paths(db_session, test_org.id)
        path = db_session.query(AttackPath).first()
        steps = path.steps
        assert len(steps) >= 2
        # Entry step
        assert steps[0]["edge_type"] == "entry"
        assert "Exploitable" in steps[0]["why_reachable"]
        assert "Critical" in steps[0]["what_enables"]
        # Hop step
        hop = steps[1]
        assert hop["edge_type"] == "member_of_domain"
        assert "domain" in hop["why_reachable"].lower()

    def test_rerun_idempotent_and_preserves_narrated(self, db_session, test_org, test_scan):
        self._setup(db_session, test_org, test_scan)
        _generate_attack_paths(db_session, test_org.id)
        first_count = db_session.query(AttackPath).count()
        assert first_count >= 1

        # Simulate a narrator having written to one row.
        p = db_session.query(AttackPath).first()
        p.narrative = "Preserved"
        db_session.flush()

        # Re-run should wipe un-narrated rows and re-insert fresh ones,
        # but the narrated row must survive.
        _generate_attack_paths(db_session, test_org.id)
        remaining = db_session.query(AttackPath).all()
        assert any(r.narrative == "Preserved" for r in remaining)

    def test_no_targets_means_no_paths(self, db_session, test_org, test_scan):
        a = _asset(db_session, test_scan, hostname="solo")
        _finding(db_session, test_scan, a, severity=3)
        db_session.execute(text("UPDATE assets SET org_id = :o WHERE id = :a"),
                           {"o": test_org.id, "a": a.id})
        db_session.flush()

        # No edges, asset is not internet-facing, criticality is default 5.
        # Still qualifies as target because severity=3 finding → actually it
        # needs severity ≥ 4 for 'has_critical_finding'. Crit=5 not high
        # enough. Not IF. So NOT a target.
        created = _generate_attack_paths(db_session, test_org.id)
        assert created == 0


class TestExtractFindingPort:
    def test_plain_numeric_string(self):
        from services.finding_correlator import _extract_finding_port
        assert _extract_finding_port("445") == 445

    def test_slash_protocol(self):
        from services.finding_correlator import _extract_finding_port
        assert _extract_finding_port("445/tcp") == 445
        assert _extract_finding_port("tcp/445") == 445

    def test_zero_returns_none(self):
        """Plugin findings that aren't port-specific use port '0' — treat
        as unknown, not as "actually port 0"."""
        from services.finding_correlator import _extract_finding_port
        assert _extract_finding_port("0") is None

    def test_empty_and_none(self):
        from services.finding_correlator import _extract_finding_port
        assert _extract_finding_port("") is None
        assert _extract_finding_port(None) is None

    def test_out_of_range(self):
        from services.finding_correlator import _extract_finding_port
        assert _extract_finding_port("70000") is None


class TestPortCorrelation:
    """Cover finding-port ↔ netconn-port matching in the BFS hop."""

    def _setup_chain(self, db_session, test_org, test_scan, *, remote_port, target_finding_port):
        entry = _asset(db_session, test_scan, hostname="srv1", internet_facing=True)
        target = _asset(db_session, test_scan, hostname="dc1", criticality=10)
        # Entry has an exploitable critical (needed to qualify as entry).
        _finding(db_session, test_scan, entry, severity=4, plugin_name="RCE")
        # Target has a finding on a specific port.
        _finding(
            db_session, test_scan, target,
            severity=3, plugin_name="SMB Signing not required",
            port=str(target_finding_port),
        )
        db_session.add(AssetRelationship(
            org_id=test_org.id,
            source_asset_id=entry.id,
            target_asset_id=target.id,
            relationship_type="connects_to",
            confidence="high",
            weight=0.9,
            properties={"remote_port": remote_port, "state": "ESTABLISHED"},
        ))
        db_session.execute(text("UPDATE assets SET org_id = :o"), {"o": test_org.id})
        db_session.flush()
        return entry, target

    def test_netconn_matches_finding_port_is_verified(self, db_session, test_org, test_scan):
        self._setup_chain(
            db_session, test_org, test_scan,
            remote_port=445, target_finding_port=445,
        )
        _generate_attack_paths(db_session, test_org.id)
        path = db_session.query(AttackPath).first()
        assert path is not None
        hop = path.steps[1]
        assert hop["pivot_quality"] == "exploit_path_verified"
        assert hop["exploit_path_verified"] is True
        assert "confirms" in hop["why_reachable"].lower()

    def test_port_mismatch_flags_explicitly(self, db_session, test_org, test_scan):
        self._setup_chain(
            db_session, test_org, test_scan,
            remote_port=3389, target_finding_port=445,
        )
        _generate_attack_paths(db_session, test_org.id)
        path = db_session.query(AttackPath).first()
        assert path is not None
        hop = path.steps[1]
        assert hop["pivot_quality"] == "port_mismatch"
        assert hop.get("exploit_path_verified") is False
        assert "not a proven" in hop["why_reachable"].lower()

    def test_finding_without_port_falls_back_to_service_exposed(self, db_session, test_org, test_scan):
        # Finding port is "0" (non-port-specific plugin) — we can't verify.
        self._setup_chain(
            db_session, test_org, test_scan,
            remote_port=445, target_finding_port=0,
        )
        _generate_attack_paths(db_session, test_org.id)
        path = db_session.query(AttackPath).first()
        assert path is not None
        hop = path.steps[1]
        # Port 445 is a known service — quality should drop to service_exposed
        # since we can't prove finding correlation.
        assert hop["pivot_quality"] == "service_exposed"

    def test_score_bonus_applied_for_verified_path(self, db_session, test_org, test_scan):
        self._setup_chain(
            db_session, test_org, test_scan,
            remote_port=445, target_finding_port=445,
        )
        _generate_attack_paths(db_session, test_org.id)
        path = db_session.query(AttackPath).first()
        bonuses = {b["label"]: b["value"] for b in path.score_breakdown.get("bonuses", [])}
        assert bonuses.get("exploit_path_verified") == 10

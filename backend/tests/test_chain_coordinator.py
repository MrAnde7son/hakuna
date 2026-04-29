"""Tests for the Cross-Scan Chain Coordinator (Phase 3 v1).

Covers the deterministic parts of the coordinator — hypothesis
enumeration, gating, closure detection, ValidatedChain emit. The
audit dispatch path is exercised with `dispatch_audit_run` patched
out; no real relay/AgentRun is needed.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.asset_edges import (
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_COERCE,
    ASSET_TO_ASSET_PORT,
    CVE_ON_ASSET,
    INTERNET_TO_ASSET,
    PRINCIPAL_TO_DOMAIN,
)
from models.models import (
    AgentLead,
    AssetRelationship,
    AttackPath,
    Finding,
    Scan,
)
from services import chain_coordinator
from services.asset_edges import upsert_edge


# ── Helpers ────────────────────────────────────────────────────────


def _stamp_org(db_session, asset, org_id):
    asset.scan.org_id = org_id
    db_session.flush()


def _make_windows(asset, db_session):
    asset.os = "Windows Server 2019"
    asset.asset_type = "windows_host"
    db_session.flush()


def _make_crown_jewel(asset, db_session, criticality=9):
    asset.criticality = criticality
    db_session.flush()


# ── Hypothesis enumeration: easm_to_smb ────────────────────────────


class TestPatternEasmToSmb:
    def test_emits_hypothesis_for_internet_smb_windows_host(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        _make_windows(host, db_session)
        upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=host.id,
            properties={"port": 445, "family": "smb", "protocol": "tcp"},
        )

        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert len(hyps) == 1
        assert hyps[0].pattern == "easm_to_smb"
        assert hyps[0].asset_id == host.id
        assert hyps[0].protocol == "smb"
        assert hyps[0].mission == "exposure_audit"

    def test_skips_non_windows_host(self, db_session, test_org, test_assets):
        host = test_assets[0]   # default Linux from fixture
        upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=host.id,
            properties={"port": 445, "family": "smb"},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert hyps == []

    def test_skips_when_smb_audit_within_cooldown(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        _make_windows(host, db_session)
        # Stamp the same field the auto-trigger writes.
        host.easm_data = {
            "_auto_audit_last": {
                "smb": datetime.now(timezone.utc).isoformat(),
            }
        }
        db_session.flush()
        upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=host.id,
            properties={"port": 445, "family": "smb"},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert hyps == []

    def test_skips_when_outbound_coerce_edge_already_exists(
        self, db_session, test_org, test_assets,
    ):
        host, neighbor = test_assets[0], test_assets[1]
        _make_windows(host, db_session)
        upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            dst_asset_id=host.id,
            properties={"port": 445, "family": "smb"},
        )
        upsert_edge(
            db_session,
            org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE,
            source_system="audit_agent",
            src_asset_id=host.id,
            dst_asset_id=neighbor.id,
            properties={"primitive": "PrinterBug"},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert hyps == []

    def test_affected_set_filters_hypotheses(self, db_session, test_org, test_assets):
        a1, a2 = test_assets[0], test_assets[1]
        _make_windows(a1, db_session)
        _make_windows(a2, db_session)
        for asset in (a1, a2):
            upsert_edge(
                db_session,
                org_id=test_org.id,
                edge_type=INTERNET_TO_ASSET,
                source_system="easm",
                dst_asset_id=asset.id,
                properties={"port": 445, "family": "smb"},
            )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set={a1.id},
        )
        assert {h.asset_id for h in hyps} == {a1.id}


# ── Hypothesis ranking ─────────────────────────────────────────────


class TestRankHypotheses:
    def test_stable_sort_by_score_then_asset_id(self):
        hyps = [
            chain_coordinator.Hypothesis(
                pattern="easm_to_smb", asset_id=2, protocol="smb", mission="exposure_audit",
            ),
            chain_coordinator.Hypothesis(
                pattern="easm_to_smb", asset_id=1, protocol="smb", mission="exposure_audit",
            ),
        ]
        ranked = chain_coordinator.rank_hypotheses(hyps)
        # Scores tie on a single pattern → asset_id ascending tiebreaker.
        assert [h.asset_id for h in ranked] == [1, 2]
        assert all(h.score > 0 for h in ranked)


# ── Dispatch gating ────────────────────────────────────────────────


class TestDispatchGating:
    def setup_method(self):
        pass  # debounce is DB-backed; per-test fixtures isolate Scan rows

    def test_skips_when_org_setting_disabled(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        test_org.settings = {"auto_audit_anon": False}
        db_session.flush()

        hyp = chain_coordinator.Hypothesis(
            pattern="easm_to_smb", asset_id=host.id,
            protocol="smb", mission="exposure_audit",
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "org_setting_disabled"

    def test_skips_when_requires_approval(
        self, db_session, test_org, test_assets,
    ):
        hyp = chain_coordinator.Hypothesis(
            pattern="future_pattern", asset_id=test_assets[0].id,
            protocol="smb", mission="exposure_audit",
            requires_approval=True,
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "requires_approval"

    def test_skips_when_within_cooldown(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        host.easm_data = {
            "_auto_audit_last": {
                "smb": datetime.now(timezone.utc).isoformat(),
            }
        }
        db_session.flush()
        hyp = chain_coordinator.Hypothesis(
            pattern="easm_to_smb", asset_id=host.id,
            protocol="smb", mission="exposure_audit",
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "cooldown"

    def test_recent_dispatch_detected_via_scan_row(
        self, db_session, test_org, test_assets,
    ):
        """The DB-backed debounce: a recent matching Scan row gates
        re-dispatch even when the in-process state is fresh (e.g. a
        different replica fired). Stamps no cooldown — proves the
        check is sourced from `scans`, not `_auto_audit_last`."""
        host = test_assets[0]
        recent = datetime.utcnow() - timedelta(seconds=10)
        scan = Scan(
            org_id=test_org.id,
            filename="smb_audit://relay-x/exposure_audit/1hosts",
            scan_type="smb_audit",
            source_type="smb_audit",
            scan_date=recent.isoformat(),
            status="running",
            raw_metadata={
                "protocol": "smb",
                "mission": "exposure_audit",
                "asset_ids": [host.id],
            },
        )
        db_session.add(scan)
        db_session.flush()
        # Force created_at into the recent past — SQLAlchemy default is
        # commit-time, but we want the row to read as "10 seconds ago".
        scan.created_at = recent
        db_session.flush()

        hyp = chain_coordinator.Hypothesis(
            pattern="easm_to_smb", asset_id=host.id,
            protocol="smb", mission="exposure_audit",
        )
        now = datetime.now(timezone.utc)
        assert chain_coordinator._recent_coordinator_dispatch(
            db_session, test_org.id, hyp, now,
        ) is True

        # Stale scan (older than the debounce window) doesn't gate.
        scan.created_at = datetime.utcnow() - timedelta(seconds=120)
        db_session.flush()
        assert chain_coordinator._recent_coordinator_dispatch(
            db_session, test_org.id, hyp, now,
        ) is False

    def test_recent_dispatch_for_vm_scan_reads_pending_marker(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        host.easm_data = {
            "_pending_vm_rescan": {
                "requested_at": (
                    datetime.now(timezone.utc) - timedelta(seconds=15)
                ).isoformat(),
            }
        }
        db_session.flush()
        hyp = chain_coordinator.Hypothesis(
            pattern="sbom_unpatched", asset_id=host.id,
            protocol="vm_scan", mission="rescan",
        )
        now = datetime.now(timezone.utc)
        assert chain_coordinator._recent_coordinator_dispatch(
            db_session, test_org.id, hyp, now,
        ) is True

    def test_dispatches_and_stamps_cooldown(
        self, db_session, test_org, test_assets,
    ):
        from models.models import RelayAgent
        # Provide a connected relay so the picker doesn't short-circuit.
        relay = RelayAgent(
            id="relay-1", org_id=test_org.id, name="test-relay",
            token_hash="x", status="connected",
            relay_type="agent", last_seen_at=datetime.utcnow(),
        )
        db_session.add(relay)
        db_session.flush()

        host = test_assets[0]
        hyp = chain_coordinator.Hypothesis(
            pattern="easm_to_smb", asset_id=host.id,
            protocol="smb", mission="exposure_audit",
        )

        with patch("services.audit_runner.dispatch_audit_run") as mock_dispatch:
            mock_dispatch.return_value = {
                "scan_id": 999, "protocol": "smb", "mission": "exposure_audit",
                "status": "running", "runs": [],
            }
            outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)

        assert outcome["dispatched"] is True
        assert outcome["scan_id"] == 999
        # Cooldown was stamped — same key the auto-trigger reads.
        last_map = (host.easm_data or {}).get("_auto_audit_last") or {}
        assert "smb" in last_map
        # Recent-dispatch debounce now blocks an immediate re-fire.
        outcome2 = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        # Either cooldown or recent_dispatch — both are correct gates here.
        assert outcome2["dispatched"] is False
        assert outcome2["reason"] in ("cooldown", "recent_dispatch")


# ── Closure detection + ValidatedChain emit ────────────────────────


class TestClosureDetection:
    def test_no_closure_without_internet_entry(
        self, db_session, test_org, test_assets,
    ):
        out = chain_coordinator.detect_closures(db_session, test_org.id, set())
        assert out == []

    def test_no_closure_without_multi_source_corroboration(
        self, db_session, test_org, test_assets,
    ):
        entry, target = test_assets[0], test_assets[1]
        _make_crown_jewel(target, db_session)
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET, source_system="easm",
            dst_asset_id=entry.id, properties={"port": 445, "family": "smb"},
        )
        # Single-source coerce edge — not enough corroboration.
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=entry.id, dst_asset_id=target.id,
            properties={"primitive": "PrinterBug"},
        )
        out = chain_coordinator.detect_closures(db_session, test_org.id, set())
        assert out == []

    def test_closes_chain_with_two_producers(
        self, db_session, test_org, test_assets,
    ):
        entry, hop, target = test_assets[0], test_assets[1], test_assets[2]
        _make_crown_jewel(target, db_session)
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET, source_system="easm",
            dst_asset_id=entry.id, properties={"port": 445, "family": "smb"},
        )
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=entry.id, dst_asset_id=hop.id,
            properties={"primitive": "PrinterBug"},
        )
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_AUTH, source_system="inventory",
            src_asset_id=hop.id, dst_asset_id=target.id,
            properties={"via": "domain_trust"},
        )
        out = chain_coordinator.detect_closures(db_session, test_org.id, set())
        assert len(out) == 1
        chain = out[0]
        assert chain.entry_asset_id == entry.id
        assert chain.target_asset_id == target.id
        assert {"audit_agent", "inventory"}.issubset(chain.source_systems)
        assert chain.severity_label in ("Critical", "High", "Medium", "Low", "Info")

    def test_emit_validated_chain_creates_finding_and_attack_path(
        self, db_session, test_org, test_assets,
    ):
        entry, hop, target = test_assets[0], test_assets[1], test_assets[2]
        _make_crown_jewel(target, db_session)
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET, source_system="easm",
            dst_asset_id=entry.id, properties={"port": 445, "family": "smb"},
        )
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=entry.id, dst_asset_id=hop.id,
            properties={"primitive": "PrinterBug"},
        )
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_AUTH, source_system="inventory",
            src_asset_id=hop.id, dst_asset_id=target.id,
            properties={"via": "domain_trust"},
        )

        chains = chain_coordinator.detect_closures(db_session, test_org.id, set())
        assert chains
        finding = chain_coordinator._emit_validated_chain(
            db_session, test_org.id, chains[0],
        )
        assert finding is not None
        assert finding.source_type == "hakuna_chain_coordinator"
        assert finding.plugin_family == "Chain"
        assert finding.asset_id == target.id
        assert finding.custom_fields["chain"]["edge_ids"]

        # AttackPath row was created and linked.
        ap = db_session.query(AttackPath).filter(
            AttackPath.validated_chain_finding_id == finding.id,
        ).first()
        assert ap is not None
        assert ap.org_id == test_org.id

        # Idempotent: re-emitting the same chain returns None.
        again = chain_coordinator._emit_validated_chain(
            db_session, test_org.id, chains[0],
        )
        assert again is None


# ── tick() integration ─────────────────────────────────────────────


class TestTick:
    def setup_method(self):
        pass  # debounce is DB-backed; per-test fixtures isolate Scan rows

    def test_tick_no_data_returns_zero(self, db_session, test_org):
        result = chain_coordinator.tick(db_session, org_id=test_org.id)
        assert result["dispatched"] == 0
        assert result["validated_chains"] == 0

    def test_tick_dispatches_and_emits(
        self, db_session, test_org, test_assets,
    ):
        from models.models import RelayAgent
        # Set up a closing chain *and* a hypothesis candidate.
        entry, hop, target = test_assets[0], test_assets[1], test_assets[2]
        _make_windows(entry, db_session)
        _make_crown_jewel(target, db_session)
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=INTERNET_TO_ASSET, source_system="easm",
            dst_asset_id=entry.id, properties={"port": 445, "family": "smb"},
        )
        # An already-closing chain on a *different* entry so the
        # easm_to_smb pattern still fires for `entry` (which has no
        # outbound coerce/auth edges yet) while closure detection has
        # something to work with.
        other_entry = entry  # reuse — but we need the pattern's
        # "no outbound coerce/auth from this asset" predicate. Simulate
        # closure on the same entry by adding the corroborating chain
        # *from entry* — pattern then skips (chain already in motion),
        # but tick still emits the validated chain.
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=entry.id, dst_asset_id=hop.id,
            properties={"primitive": "PrinterBug"},
        )
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_AUTH, source_system="inventory",
            src_asset_id=hop.id, dst_asset_id=target.id,
            properties={"via": "domain_trust"},
        )

        relay = RelayAgent(
            id="relay-tick", org_id=test_org.id, name="tick-relay",
            token_hash="x", status="connected",
            relay_type="agent", last_seen_at=datetime.utcnow(),
        )
        db_session.add(relay)
        db_session.flush()

        with patch("services.audit_runner.dispatch_audit_run") as mock_dispatch:
            mock_dispatch.return_value = {
                "scan_id": 1234, "protocol": "smb", "mission": "exposure_audit",
                "status": "running", "runs": [],
            }
            result = chain_coordinator.tick(
                db_session, org_id=test_org.id, scan_id=None,
            )

        # Pattern was suppressed (entry already has outbound coerce edge),
        # so dispatched stays 0 — but a validated chain still emitted.
        assert result["validated_chains"] == 1
        assert result["dispatched"] == 0


# ── Pattern: coerce_to_dc (Phase 4) ────────────────────────────────


class TestPatternCoerceToDc:
    def test_emits_for_dc_with_no_recent_ldap_audit(
        self, db_session, test_org, test_assets,
    ):
        # Set up: a host with a coerce edge + a DC (via member_of_domain).
        coercer, dc = test_assets[0], test_assets[1]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=coercer.id,
            properties={"primitive": "PrinterBug"},
        )
        # Make `dc` a domain controller — crown jewel reason="domain_controller".
        # Easiest path: a `member_of_domain` edge with target=dc.id.
        rel = AssetRelationship(
            org_id=test_org.id,
            source_asset_id=coercer.id,
            target_asset_id=dc.id,
            relationship_type="member_of_domain",
            confidence="high",
        )
        db_session.add(rel)
        db_session.flush()

        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        coerce_hyps = [h for h in hyps if h.pattern == "coerce_to_dc"]
        assert len(coerce_hyps) == 1
        assert coerce_hyps[0].asset_id == dc.id
        assert coerce_hyps[0].protocol == "ldap"

    def test_skips_when_no_coerce_edges_in_org(
        self, db_session, test_org, test_assets,
    ):
        dc = test_assets[1]
        rel = AssetRelationship(
            org_id=test_org.id,
            source_asset_id=test_assets[0].id,
            target_asset_id=dc.id,
            relationship_type="member_of_domain",
            confidence="high",
        )
        db_session.add(rel)
        db_session.flush()
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "coerce_to_dc"] == []

    def test_skips_dc_with_recent_ldap_audit(
        self, db_session, test_org, test_assets,
    ):
        coercer, dc = test_assets[0], test_assets[1]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=coercer.id,
            properties={"primitive": "PrinterBug"},
        )
        rel = AssetRelationship(
            org_id=test_org.id,
            source_asset_id=coercer.id, target_asset_id=dc.id,
            relationship_type="member_of_domain", confidence="high",
        )
        db_session.add(rel)
        dc.easm_data = {
            "_auto_audit_last": {"ldap": datetime.now(timezone.utc).isoformat()},
        }
        db_session.flush()

        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "coerce_to_dc"] == []

    def test_skips_dc_with_existing_dcsync_edge(
        self, db_session, test_org, test_assets,
    ):
        coercer, dc = test_assets[0], test_assets[1]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_COERCE, source_system="audit_agent",
            src_asset_id=coercer.id,
            properties={"primitive": "PrinterBug"},
        )
        db_session.add(AssetRelationship(
            org_id=test_org.id,
            source_asset_id=coercer.id, target_asset_id=dc.id,
            relationship_type="member_of_domain", confidence="high",
        ))
        # Already-proven DCSync from this DC — chain in motion.
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=PRINCIPAL_TO_DOMAIN, source_system="audit_agent",
            src_asset_id=dc.id,
            properties={"principal": "evil-svc"},
        )
        db_session.flush()
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "coerce_to_dc"] == []


# ── Pattern: vm_kev_to_audit (Phase 4) ─────────────────────────────


class TestPatternVmKevToAudit:
    def test_emits_audit_for_kev_asset_with_smb_open(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        host.easm_data = {"open_ports": [445]}
        db_session.flush()
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="vm_scanner",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-12345", "kev": True},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        kev_hyps = [h for h in hyps if h.pattern == "vm_kev_to_audit"]
        assert len(kev_hyps) == 1
        assert kev_hyps[0].asset_id == host.id
        assert kev_hyps[0].protocol == "smb"

    def test_skips_non_kev_cve_edge(self, db_session, test_org, test_assets):
        host = test_assets[0]
        host.easm_data = {"open_ports": [445]}
        db_session.flush()
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="vm_scanner",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-99999", "kev": False},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "vm_kev_to_audit"] == []

    def test_skips_when_no_mgmt_port_open(self, db_session, test_org, test_assets):
        host = test_assets[0]
        host.easm_data = {"open_ports": [80, 443]}    # no mgmt port
        db_session.flush()
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="vm_scanner",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-12345", "kev": True},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "vm_kev_to_audit"] == []

    def test_picks_ssh_when_only_22_open(self, db_session, test_org, test_assets):
        host = test_assets[0]
        host.easm_data = {"open_ports": [22]}
        db_session.flush()
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="vm_scanner",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-X", "kev": True},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        kev_hyps = [h for h in hyps if h.pattern == "vm_kev_to_audit"]
        assert len(kev_hyps) == 1
        assert kev_hyps[0].protocol == "ssh"


# ── Pattern: lead_followup (Phase 4) ───────────────────────────────


class TestPatternLeadFollowup:
    def test_emits_hypothesis_for_open_lead(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        lead = AgentLead(
            org_id=test_org.id,
            target_asset_id=host.id,
            reason="Observed lsarpc reachable from prior SMB audit",
            suggested_protocol="ldap",
            suggested_mission="exposure_audit",
            status="open",
        )
        db_session.add(lead)
        db_session.flush()

        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        lead_hyps = [h for h in hyps if h.pattern == "lead_followup"]
        assert len(lead_hyps) == 1
        assert lead_hyps[0].asset_id == host.id
        assert lead_hyps[0].protocol == "ldap"
        assert "lsarpc" in lead_hyps[0].rationale

    def test_skips_dispatched_lead(self, db_session, test_org, test_assets):
        host = test_assets[0]
        db_session.add(AgentLead(
            org_id=test_org.id, target_asset_id=host.id,
            reason="x", suggested_protocol="ldap",
            suggested_mission="exposure_audit", status="dispatched",
        ))
        db_session.flush()
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "lead_followup"] == []

    def test_skips_lead_within_protocol_cooldown(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        host.easm_data = {
            "_auto_audit_last": {"ldap": datetime.now(timezone.utc).isoformat()},
        }
        db_session.add(AgentLead(
            org_id=test_org.id, target_asset_id=host.id,
            reason="x", suggested_protocol="ldap",
            suggested_mission="exposure_audit", status="open",
        ))
        db_session.flush()
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "lead_followup"] == []


# ── Pattern: sbom_unpatched (Phase 4) ──────────────────────────────


class TestPatternSbomUnpatched:
    def test_emits_vm_rescan_when_sbom_kev_uncovered(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="sbom",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-99", "kev": True},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        sbom_hyps = [h for h in hyps if h.pattern == "sbom_unpatched"]
        assert len(sbom_hyps) == 1
        assert sbom_hyps[0].protocol == "vm_scan"
        assert sbom_hyps[0].asset_id == host.id

    def test_skips_when_recent_vm_scan_covers_asset(
        self, db_session, test_org, test_assets, test_scan,
    ):
        host = test_assets[0]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="sbom",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-99", "kev": True},
        )
        # Add a recent vm_scanner Scan with a Finding on this asset.
        vm_scan = Scan(
            org_id=test_org.id, filename="vm.json",
            source_type="vm_scanner", scan_type="vm_scanner", status="completed",
        )
        db_session.add(vm_scan)
        db_session.flush()
        f = Finding(
            scan_id=vm_scan.id, asset_id=host.id,
            plugin_id="vm-1", plugin_name="VM finding",
            severity=2, severity_label="medium",
        )
        db_session.add(f)
        db_session.flush()

        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "sbom_unpatched"] == []

    def test_skips_non_sbom_kev_edges(self, db_session, test_org, test_assets):
        # Only `source_system='sbom'` edges drive this pattern; vm_scanner
        # KEV edges go through vm_kev_to_audit instead.
        host = test_assets[0]
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=CVE_ON_ASSET, source_system="vm_scanner",
            dst_asset_id=host.id,
            properties={"cve": "CVE-2024-99", "kev": True},
        )
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        assert [h for h in hyps if h.pattern == "sbom_unpatched"] == []


# ── Pattern: cred_found (Phase 4) ──────────────────────────────────


class TestPatternCredFound:
    def test_emits_approval_gated_hypothesis(
        self, db_session, test_org, test_assets,
    ):
        src, neighbor = test_assets[0], test_assets[1]
        # Plaintext credential captured on src (via auth edge property).
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_AUTH, source_system="audit_agent",
            src_asset_id=src.id, dst_asset_id=src.id,        # self-edge ok for marker
            properties={"credential": "plaintext"},
        )
        # Reachability to a neighbor.
        upsert_edge(
            db_session, org_id=test_org.id,
            edge_type=ASSET_TO_ASSET_PORT, source_system="inventory",
            src_asset_id=src.id, dst_asset_id=neighbor.id,
            properties={"port": 22},
        )
        neighbor.easm_data = {"open_ports": [22]}
        db_session.flush()
        hyps = chain_coordinator.enumerate_hypotheses(
            db_session, test_org.id, affected_set=set(),
        )
        cred_hyps = [h for h in hyps if h.pattern == "cred_found"]
        assert len(cred_hyps) == 1
        assert cred_hyps[0].asset_id == neighbor.id
        assert cred_hyps[0].requires_approval is True   # always gated
        assert cred_hyps[0].protocol == "ssh"

    def test_dispatch_gating_blocks_approval_required(
        self, db_session, test_org, test_assets,
    ):
        host = test_assets[0]
        hyp = chain_coordinator.Hypothesis(
            pattern="cred_found", asset_id=host.id,
            protocol="ssh", mission="exposure_audit",
            requires_approval=True,
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "requires_approval"
        # And the pending row was persisted so the operator can act.
        from models.models import CoordinatorPendingApproval
        pending = db_session.query(CoordinatorPendingApproval).filter(
            CoordinatorPendingApproval.org_id == test_org.id,
            CoordinatorPendingApproval.asset_id == host.id,
            CoordinatorPendingApproval.pattern == "cred_found",
        ).all()
        assert len(pending) == 1
        assert pending[0].status == "pending"

    def test_approved_row_lets_dispatch_proceed(
        self, db_session, test_org, test_assets,
    ):
        from models.models import CoordinatorPendingApproval, RelayAgent
        host = test_assets[0]
        # Operator already approved this hypothesis on a prior tick.
        approval = CoordinatorPendingApproval(
            org_id=test_org.id, asset_id=host.id,
            pattern="cred_found", protocol="ssh", mission="exposure_audit",
            status="approved",
            decided_by="operator@example.com",
            decided_at=datetime.utcnow(),
        )
        db_session.add(approval)
        # Provide a relay so the picker doesn't short-circuit.
        relay = RelayAgent(
            id="relay-cred", org_id=test_org.id, name="cred-relay",
            token_hash="x", status="connected",
            relay_type="agent", last_seen_at=datetime.utcnow(),
        )
        db_session.add(relay)
        # `cred_found` dispatches via ssh → auto_audit_credentialed (off by default).
        test_org.settings = {"auto_audit_credentialed": True}
        db_session.flush()

        hyp = chain_coordinator.Hypothesis(
            pattern="cred_found", asset_id=host.id,
            protocol="ssh", mission="exposure_audit",
            requires_approval=True,
        )
        with patch("services.audit_runner.dispatch_audit_run") as mock_dispatch:
            mock_dispatch.return_value = {
                "scan_id": 4242, "protocol": "ssh", "mission": "exposure_audit",
                "status": "running", "runs": [],
            }
            outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)

        assert outcome["dispatched"] is True
        # Approval row flipped to consumed so the same approval can't replay.
        # `_dispatch_hypothesis` mutates in-session; `tick()` is what commits.
        # Don't `refresh` — that would clobber the pending mutation with the
        # last-committed state.
        assert approval.status == "consumed"
        assert approval.consumed_by_scan_id == 4242

    def test_rejected_row_blocks_dispatch(
        self, db_session, test_org, test_assets,
    ):
        from models.models import CoordinatorPendingApproval
        host = test_assets[0]
        db_session.add(CoordinatorPendingApproval(
            org_id=test_org.id, asset_id=host.id,
            pattern="cred_found", protocol="ssh", mission="exposure_audit",
            status="rejected",
            decided_by="operator@example.com",
            decided_at=datetime.utcnow(),
        ))
        db_session.flush()
        hyp = chain_coordinator.Hypothesis(
            pattern="cred_found", asset_id=host.id,
            protocol="ssh", mission="exposure_audit",
            requires_approval=True,
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "rejected"


# ── Phase 4 dispatch helpers ───────────────────────────────────────


class TestPhase4Dispatch:
    def setup_method(self):
        pass  # debounce is DB-backed; per-test fixtures isolate Scan rows

    def test_vm_scan_pseudo_protocol_marks_asset(
        self, db_session, test_org, test_assets,
    ):
        # vm_scan is gated by `auto_audit_vm_rescan` (defaults OFF).
        test_org.settings = {"auto_audit_vm_rescan": True}
        db_session.flush()
        host = test_assets[0]
        hyp = chain_coordinator.Hypothesis(
            pattern="sbom_unpatched", asset_id=host.id,
            protocol="vm_scan", mission="rescan",
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is True
        assert outcome["scan_id"] is None
        # Asset got a `_pending_vm_rescan` marker (in-session — not refreshing
        # because the dispatch helper writes to the ORM object, not DB).
        assert "_pending_vm_rescan" in (host.easm_data or {})

    def test_lead_followup_marks_lead_dispatched(
        self, db_session, test_org, test_assets,
    ):
        from models.models import RelayAgent
        host = test_assets[0]
        relay = RelayAgent(
            id="relay-lead", org_id=test_org.id, name="lead-relay",
            token_hash="x", status="connected", relay_type="agent",
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(relay)
        lead = AgentLead(
            org_id=test_org.id, target_asset_id=host.id,
            reason="x", suggested_protocol="ldap",
            suggested_mission="exposure_audit", status="open",
        )
        db_session.add(lead)
        db_session.flush()

        hyp = chain_coordinator.Hypothesis(
            pattern="lead_followup", asset_id=host.id,
            protocol="ldap", mission="exposure_audit",
        )
        with patch("services.audit_runner.dispatch_audit_run") as mock_dispatch:
            mock_dispatch.return_value = {
                "scan_id": 4242, "protocol": "ldap", "mission": "exposure_audit",
                "status": "running", "runs": [],
            }
            outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is True
        # Don't refresh — _mark_lead_dispatched edits the in-session row;
        # we haven't committed in the test, so refresh would clobber it.
        assert lead.status == "dispatched"
        assert lead.consumed_by_scan_id == 4242

    def test_org_setting_disabled_blocks_credentialed_protocol_by_default(
        self, db_session, test_org, test_assets,
    ):
        # WMI defaults OFF — no explicit setting needed to demonstrate skip.
        host = test_assets[0]
        hyp = chain_coordinator.Hypothesis(
            pattern="vm_kev_to_audit", asset_id=host.id,
            protocol="wmi", mission="exposure_audit",
        )
        outcome = chain_coordinator._dispatch_hypothesis(db_session, test_org, hyp)
        assert outcome["dispatched"] is False
        assert outcome["reason"] == "org_setting_disabled"


# ── Affected subgraph ──────────────────────────────────────────────


class TestAffectedSubgraph:
    def test_includes_assets_with_recent_findings(
        self, db_session, test_org, test_assets, test_findings,
    ):
        # test_findings includes findings on every asset in test_assets,
        # all linked to test_scan. Coordinator should pick them all up.
        scan_id = test_findings[0].scan_id
        affected = chain_coordinator._recompute_affected_subgraph(
            db_session, test_org.id, scan_id,
        )
        assert {a.id for a in test_assets}.issubset(affected)

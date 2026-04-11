"""
Unit tests for patch reliability signal collectors and the rollback hook.

Focuses on the pieces that had bugs during development:
* Ubuntu USN regression detector (revision grouping + regression keywords)
* MSRC CVRF Type=7 Known Issue parser (DB-free, fed synthetic CVRF)
* OS → patch-source mapping used by the rollback hook
* handle_finding_reopened safeguards (window, OS filter, fingerprint dedup)
* Scorer + weight wiring end-to-end
"""
from datetime import datetime, timedelta

import pytest

from models.threat_intel_models import (
    MSRCPatch,
    PatchAdvisory,
    PatchReliability,
    PatchReliabilitySignal,
)
from services import patch_reliability as rel
from services import patch_signal_collectors as coll


# ─── MSRC supersedence ─────────────────────────────────────────────────────

def test_msrc_supercedence_emits_signal_and_scores(db_session):
    # Two KBs: KB5000001 supersedes KB4999999
    db_session.add_all([
        MSRCPatch(cve_id="CVE-2024-0001", kb_id="KB4999999", product_id="p1",
                  product_name="Windows 10", supercedence=""),
        MSRCPatch(cve_id="CVE-2024-0001", kb_id="KB5000001", product_id="p1",
                  product_name="Windows 10", supercedence="4999999"),
    ])
    db_session.flush()

    result = coll.collect_msrc_supercedence(db_session)
    assert result["signals_added"] == 1

    # Signal landed on the old KB with the correct (English) spelling
    signal = db_session.query(PatchReliabilitySignal).filter_by(
        patch_source="msrc", patch_ref="KB4999999"
    ).first()
    assert signal is not None
    assert signal.signal_type == "supersedence"
    assert signal.signal_source == "msrc_supersedence"
    assert signal.weight == pytest.approx(-0.05)
    assert signal.detail["superseded_by"] == "KB5000001"

    # Reliability row was created; still 'stable' at 0.95 (supersedence is mild)
    r = db_session.query(PatchReliability).filter_by(
        patch_source="msrc", patch_ref="KB4999999"
    ).first()
    assert r is not None
    assert r.status == "stable"
    assert r.score == pytest.approx(0.95, abs=0.01)


def test_msrc_supercedence_handles_comma_separated(db_session):
    db_session.add(MSRCPatch(
        cve_id="CVE-2024-0002", kb_id="KB5000002", product_id="p",
        product_name="Windows", supercedence="4999998, 4999997",
    ))
    db_session.flush()

    coll.collect_msrc_supercedence(db_session)
    refs = {s.patch_ref for s in db_session.query(PatchReliabilitySignal).filter_by(
        signal_source="msrc_supersedence"
    ).all()}
    assert "KB4999998" in refs
    assert "KB4999997" in refs


def test_msrc_supercedence_is_idempotent(db_session):
    db_session.add(MSRCPatch(
        cve_id="CVE-2024-0003", kb_id="KB5000003", product_id="p",
        product_name="Windows", supercedence="4999996",
    ))
    db_session.flush()

    coll.collect_msrc_supercedence(db_session)
    coll.collect_msrc_supercedence(db_session)

    count = db_session.query(PatchReliabilitySignal).filter_by(
        patch_source="msrc", patch_ref="KB4999996", signal_source="msrc_supersedence"
    ).count()
    assert count == 1  # fingerprint dedup prevents stacking


# ─── Ubuntu USN regression ─────────────────────────────────────────────────

def test_ubuntu_usn_groups_followups(db_session):
    db_session.add_all([
        PatchAdvisory(source="ubuntu", source_advisory_id="USN-1001-1",
                      title="Kernel vulns", cve_ids=["CVE-1"]),
        PatchAdvisory(source="ubuntu", source_advisory_id="USN-1001-2",
                      title="Kernel (OEM) vulns", cve_ids=["CVE-1"]),
        PatchAdvisory(source="ubuntu", source_advisory_id="USN-1001-3",
                      title="Kernel (GCP) vulns", cve_ids=["CVE-1"]),
    ])
    db_session.flush()

    result = coll.collect_ubuntu_usn_regressions(db_session)
    assert result["signals_added"] == 2  # -2 and -3 both signal against -1

    signals = db_session.query(PatchReliabilitySignal).filter_by(
        patch_source="ubuntu", patch_ref="USN-1001-1"
    ).all()
    assert len(signals) == 2
    # No regression keywords → defaults to the milder known_issue signal
    assert {s.signal_type for s in signals} == {"known_issue"}

    # Score drops to known_issues status (0.85 - 2*0.15 = 0.55... wait that's 0.70)
    # Actually: 1.0 + 2 * -0.15 = 0.70, which is ≥0.50 so "known_issues"
    r = db_session.query(PatchReliability).filter_by(
        patch_source="ubuntu", patch_ref="USN-1001-1"
    ).first()
    assert r.status == "known_issues"
    assert r.score == pytest.approx(0.70, abs=0.05)


def test_ubuntu_usn_regression_keyword_upgrades_signal_type(db_session):
    db_session.add_all([
        PatchAdvisory(source="ubuntu", source_advisory_id="USN-2002-1",
                      title="Firefox vulns", description="Original advisory"),
        PatchAdvisory(source="ubuntu", source_advisory_id="USN-2002-2",
                      title="Firefox regression",
                      description="The previous update introduced a regression."),
    ])
    db_session.flush()

    coll.collect_ubuntu_usn_regressions(db_session)

    sig = db_session.query(PatchReliabilitySignal).filter_by(
        patch_ref="USN-2002-1", signal_source="usn_regression"
    ).first()
    assert sig.signal_type == "regression"
    assert sig.weight == pytest.approx(-0.25)


def test_ubuntu_usn_single_revision_no_signal(db_session):
    db_session.add(PatchAdvisory(
        source="ubuntu", source_advisory_id="USN-3003-1", title="No follow-ups",
    ))
    db_session.flush()

    result = coll.collect_ubuntu_usn_regressions(db_session)
    assert result["signals_added"] == 0


# ─── MSRC CVRF Known-Issue parser ──────────────────────────────────────────

def test_parse_cvrf_known_issues_emits_signal_against_fix_kb(db_session):
    """
    Synthetic CVRF doc with one Vulnerability that has a Type=2 Vendor Fix
    (KB5034111) and a Type=7 Known Issue (no explicit KB in the description,
    so it should attach to the fix KB).
    """
    cvrf = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-9999",
                "Remediations": [
                    {
                        "Type": 2,  # Vendor Fix
                        "Description": {"Value": "5034111"},
                        "URL": "https://support.microsoft.com/kb/5034111",
                        "ProductID": ["p1"],
                    },
                    {
                        "Type": 7,  # Known Issue
                        "Description": {"Value": "BSOD on domain controllers after install"},
                        "URL": "https://support.microsoft.com/help/5034111#known-issues",
                    },
                ],
            }
        ]
    }
    added = coll._parse_cvrf_known_issues(db_session, cvrf, doc_id="2024-Jan")
    db_session.commit()
    assert added == 1

    sig = db_session.query(PatchReliabilitySignal).filter_by(
        patch_source="msrc", patch_ref="KB5034111", signal_source="msrc_known_issues"
    ).first()
    assert sig is not None
    assert sig.signal_type == "known_issue"
    assert sig.detail["cve_id"] == "CVE-2024-9999"
    assert "BSOD" in sig.detail["title"]


def test_parse_cvrf_known_issues_extracts_kb_from_description(db_session):
    """If the Known Issue description already names a KB, use that over the fix KB."""
    cvrf = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-8888",
                "Remediations": [
                    {"Type": 2, "Description": {"Value": "5000100"}},
                    {
                        "Type": 7,
                        "Description": {"Value": "KB5000099 - Printer spooler fails"},
                    },
                ],
            }
        ]
    }
    coll._parse_cvrf_known_issues(db_session, cvrf, doc_id="2024-Feb")
    db_session.commit()

    # Should attach to KB5000099 (from the description), not KB5000100 (the fix)
    sig = db_session.query(PatchReliabilitySignal).filter_by(
        patch_ref="KB5000099", signal_source="msrc_known_issues"
    ).first()
    assert sig is not None


def test_parse_cvrf_known_issues_ignores_non_type7(db_session):
    cvrf = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-7777",
                "Remediations": [
                    {"Type": 2, "Description": {"Value": "5000200"}},
                    {"Type": 0, "Description": {"Value": "Workaround"}},  # should be ignored
                    {"Type": 1, "Description": {"Value": "Mitigation"}},  # should be ignored
                ],
            }
        ]
    }
    added = coll._parse_cvrf_known_issues(db_session, cvrf, doc_id="2024-Mar")
    assert added == 0


# ─── KB number extractor ───────────────────────────────────────────────────

def test_extract_kb_from_text():
    assert coll._extract_kb_from_text("KB5034111") == "KB5034111"
    assert coll._extract_kb_from_text("kb5034111 - issue") == "KB5034111"
    assert coll._extract_kb_from_text("KB 5034111 - issue") == "KB5034111"
    assert coll._extract_kb_from_text("see kb5034111") == "KB5034111"
    assert coll._extract_kb_from_text("no kb here") is None
    assert coll._extract_kb_from_text("") is None
    assert coll._extract_kb_from_text(None) is None


# ─── OS → source map ───────────────────────────────────────────────────────

@pytest.mark.parametrize("os_string, expected", [
    ("Microsoft Windows Server 2019", {"msrc"}),
    ("Windows 10 Pro", {"msrc"}),
    ("Ubuntu 22.04 LTS", {"ubuntu"}),
    ("Debian GNU/Linux 12", {"debian"}),
    ("Red Hat Enterprise Linux 9", {"rhel"}),
    ("RHEL 8", {"rhel"}),
    ("CentOS 7", {"rhel"}),
    ("Amazon Linux 2", {"amazon_linux"}),
    ("macOS 14.2", {"apple"}),
    ("Darwin 23.0", {"apple"}),
    ("FreeBSD 14", set()),   # unmapped OS — no rollback signals emitted
    (None, set()),
    ("", set()),
])
def test_sources_for_os(os_string, expected):
    assert rel.sources_for_os(os_string) == expected


# ─── Rollback hook safeguards ──────────────────────────────────────────────

def _seed_ubuntu_patch(db_session, usn_id, cve):
    db_session.add(PatchAdvisory(
        source="ubuntu", source_advisory_id=usn_id, title=f"{usn_id} test",
        cve_ids=[cve],
    ))
    db_session.flush()


def test_handle_finding_reopened_emits_signal_on_matching_os(db_session):
    _seed_ubuntu_patch(db_session, "USN-4004-1", "CVE-2024-4004")

    emitted = rel.handle_finding_reopened(
        db_session,
        finding_id=42,
        cves=["CVE-2024-4004"],
        asset_os="Ubuntu 22.04 LTS",
        asset_id=1,
        org_id=1,
        resolved_at=datetime.utcnow() - timedelta(hours=6),
    )
    db_session.commit()
    assert emitted == 1

    sig = db_session.query(PatchReliabilitySignal).filter_by(
        fingerprint="finding:42", patch_ref="USN-4004-1"
    ).first()
    assert sig is not None
    assert sig.signal_type == "rollback"
    assert sig.weight == pytest.approx(-0.20)


def test_handle_finding_reopened_respects_rollback_window(db_session):
    _seed_ubuntu_patch(db_session, "USN-4005-1", "CVE-2024-4005")

    emitted = rel.handle_finding_reopened(
        db_session,
        finding_id=43,
        cves=["CVE-2024-4005"],
        asset_os="Ubuntu 22.04",
        asset_id=1,
        org_id=1,
        resolved_at=datetime.utcnow() - timedelta(days=60),  # outside window
    )
    assert emitted == 0


def test_handle_finding_reopened_filters_by_os(db_session):
    """A Windows box reopening a finding must not penalize the Ubuntu USN patching the same CVE."""
    _seed_ubuntu_patch(db_session, "USN-4006-1", "CVE-2024-4006")

    emitted = rel.handle_finding_reopened(
        db_session,
        finding_id=44,
        cves=["CVE-2024-4006"],
        asset_os="Windows Server 2022",   # maps to msrc, not ubuntu
        asset_id=1,
        org_id=1,
        resolved_at=datetime.utcnow() - timedelta(hours=1),
    )
    assert emitted == 0


def test_handle_finding_reopened_fingerprint_dedupe(db_session):
    _seed_ubuntu_patch(db_session, "USN-4007-1", "CVE-2024-4007")

    args = dict(
        finding_id=45,
        cves=["CVE-2024-4007"],
        asset_os="Ubuntu 22.04",
        asset_id=1,
        org_id=1,
        resolved_at=datetime.utcnow() - timedelta(hours=1),
    )
    rel.handle_finding_reopened(db_session, **args)
    rel.handle_finding_reopened(db_session, **args)
    db_session.commit()

    count = db_session.query(PatchReliabilitySignal).filter_by(
        fingerprint="finding:45"
    ).count()
    assert count == 1  # same finding flapping twice → one signal

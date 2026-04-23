"""Tests for services.cve_correlator.

Validates the three things the correlator has to get right:
  1. Version-range matching — a CVE that applies to 1.18.0 is returned
     when InventorySoftware has nginx 1.18.0, and not when it has 1.25.0.
  2. KB mitigation — a candidate CVE that's covered by an installed KB
     comes back as `mitigated=true`.
  3. EOL detection — an EOL OS/package on ProductLifecycle surfaces in
     `eol_components`.
"""

from __future__ import annotations

import pytest

from models.models import Asset, InventoryPatch, InventorySoftware, Organization, Scan
from models.threat_intel_models import MSRCPatch, ProductLifecycle, ThreatCVE
from services.cve_correlator import correlate_asset


@pytest.fixture
def seeded(db_session):
    """Seed an org + scan + asset with known software and CVEs.

    Shape:
      - Asset: Windows host with nginx 1.18.0 (vulnerable), openssl 3.0.12
        (not-vulnerable), installed KB5034441.
      - ThreatCVE: three CVEs —
          * CVE-2024-1001 affects nginx < 1.20.0 (applies to 1.18.0)
          * CVE-2024-2002 affects nginx >= 1.24.0 (does NOT apply)
          * CVE-2024-3003 affects Windows Server 2019, fixed by KB5034441
            (applies but should be tagged mitigated)
      - MSRCPatch: CVE-2024-3003 → KB5034441
      - ProductLifecycle: Windows Server 2012 R2 EOL row — should NOT
        match a Windows Server 2019 asset (negative test).
    """
    org = Organization(name="Test", slug="t1")
    db_session.add(org)
    db_session.flush()

    scan = Scan(org_id=org.id, filename="x.nessus", status="completed")
    db_session.add(scan)
    db_session.flush()

    asset = Asset(
        scan_id=scan.id,
        hostname="win-test", ip="10.0.0.10",
        os="Windows Server 2019 Datacenter",
    )
    db_session.add(asset)
    db_session.flush()

    # Software inventory
    db_session.add_all([
        InventorySoftware(
            scan_id=scan.id, asset_id=asset.id,
            name="nginx", version="1.18.0", vendor="nginx",
        ),
        InventorySoftware(
            scan_id=scan.id, asset_id=asset.id,
            name="openssl", version="3.0.12", vendor="OpenSSL",
        ),
    ])

    # Installed patch
    db_session.add(InventoryPatch(
        scan_id=scan.id, asset_id=asset.id,
        kb_id="KB5034441", vuln_count=1,
        description="Security update", cves=[],
    ))

    # Threat intel — CVEs and version ranges
    db_session.add_all([
        ThreatCVE(
            cve_id="CVE-2024-1001",
            description="nginx RCE in 1.x versions",
            cvss3_score=9.1,
            in_kev=False,
            has_public_exploit=True,
            epss_percentile=0.85,
            affected_products=[
                {"vendor": "nginx", "product": "nginx",
                 "versionStartIncluding": "1.0.0",
                 "versionEndExcluding": "1.20.0"},
            ],
        ),
        ThreatCVE(
            cve_id="CVE-2024-2002",
            description="nginx info disclosure in newer builds",
            cvss3_score=5.0,
            affected_products=[
                {"vendor": "nginx", "product": "nginx",
                 "versionStartIncluding": "1.24.0"},
            ],
        ),
        ThreatCVE(
            cve_id="CVE-2024-3003",
            description="Windows Server 2019 LPE",
            cvss3_score=7.8,
            in_kev=True,
            affected_products=[
                {"vendor": "nginx", "product": "nginx",
                 "versionStartIncluding": "1.0.0",
                 "versionEndExcluding": "2.0.0"},
            ],
            msrc_kb_ids=["KB5034441"],
        ),
    ])

    # MSRC KB → CVE bridge
    db_session.add(MSRCPatch(
        cve_id="CVE-2024-3003",
        kb_id="KB5034441",
        product_name="Windows Server 2019",
    ))

    # EOL lifecycle — Windows Server 2012 R2 is EOL (should NOT match 2019)
    db_session.add(ProductLifecycle(
        product_name="Windows Server 2012 R2",
        slug="windows-server-2012-r2",
        cycle="2012 R2",
        eol="2023-10-10",
        is_eol=True,
    ))

    db_session.flush()
    return {"org": org, "scan": scan, "asset": asset}


def test_matches_vulnerable_version(db_session, seeded):
    """nginx 1.18.0 should match CVE-2024-1001 (range < 1.20.0)."""
    result = correlate_asset(db_session, seeded["asset"].id)
    cve_ids = {c["cve_id"] for c in result["candidate_cves"]}
    assert "CVE-2024-1001" in cve_ids


def test_skips_out_of_range_version(db_session, seeded):
    """nginx 1.18.0 should NOT match CVE-2024-2002 (range >= 1.24.0)."""
    result = correlate_asset(db_session, seeded["asset"].id)
    cve_ids = {c["cve_id"] for c in result["candidate_cves"]}
    assert "CVE-2024-2002" not in cve_ids


def test_tags_mitigated_by_installed_kb(db_session, seeded):
    """CVE-2024-3003 is in-range AND covered by KB5034441 (installed) → mitigated."""
    result = correlate_asset(db_session, seeded["asset"].id)
    found = next((c for c in result["candidate_cves"] if c["cve_id"] == "CVE-2024-3003"), None)
    assert found is not None, "CVE-2024-3003 should be a candidate"
    assert found["mitigated"] is True


def test_summary_counts(db_session, seeded):
    """Sanity-check the aggregate counts."""
    result = correlate_asset(db_session, seeded["asset"].id)
    # Two packages seeded; nginx has matches, openssl has none (no seeded CVE).
    assert result["software_scanned"] == 2
    assert result["components_with_cves"] == 1  # only nginx
    # Two candidates matched (1001 missing, 3003 mitigated). 2002 out of range.
    assert result["total_candidate_cves"] == 2
    assert result["missing_patch_cves"] == 1
    assert result["already_mitigated_cves"] == 1
    assert result["kev_candidates"] == 1  # only CVE-2024-3003
    assert result["installed_kb_count"] == 1


def test_sorting_puts_kev_first(db_session, seeded):
    """With CVE-2024-3003 (in_kev=true) vs CVE-2024-1001 (not) both candidates,
    the KEV one must sort first."""
    result = correlate_asset(db_session, seeded["asset"].id)
    assert result["candidate_cves"][0]["cve_id"] == "CVE-2024-3003"
    assert result["candidate_cves"][0]["in_kev"] is True


def test_eol_does_not_match_wrong_os(db_session, seeded):
    """ProductLifecycle for 'Windows Server 2012 R2' should NOT surface on a
    'Windows Server 2019' asset — substring match is directional."""
    result = correlate_asset(db_session, seeded["asset"].id)
    eol_names = {e["product_name"] for e in result.get("eol_components") or []}
    assert "Windows Server 2012 R2" not in eol_names


def test_eol_matches_when_os_in_product_name(db_session, seeded):
    """Add a ProductLifecycle whose product_name is a substring of asset.os,
    confirm it shows up."""
    db_session.add(ProductLifecycle(
        product_name="Windows Server 2019",
        slug="windows-server-2019",
        cycle="2019",
        eol="2029-01-09",
        is_eol=True,  # force the flag for test purposes
    ))
    db_session.flush()
    result = correlate_asset(db_session, seeded["asset"].id)
    eol_names = {e["product_name"] for e in result.get("eol_components") or []}
    assert "Windows Server 2019" in eol_names


def test_missing_asset_returns_error(db_session):
    result = correlate_asset(db_session, asset_id=999999)
    assert "error" in result


def test_software_cve_missions_wired_up():
    """Both WMI and SSH expose the `software_cve` mission with the upgraded
    prompt that calls `correlate_software_to_cves`, and the suggested budget
    was bumped to reflect the heavier correlator+triage flow."""
    from agents.tools import wmi_tools, ssh_tools  # noqa: F401 — registers audits
    from agents.audit_registry import AUDITS
    from agents.agent_prompts import ENHANCED_PROMPTS

    for proto in ("wmi", "ssh"):
        audit = AUDITS[proto]
        mission = audit.mission("software_cve")
        assert mission is not None, f"{proto} missing software_cve mission"
        assert mission.suggested_budget == 25, (
            f"{proto} software_cve budget should be 25 (was {mission.suggested_budget})"
        )
        prompt = ENHANCED_PROMPTS[mission.prompt_key]
        assert "correlate_software_to_cves" in prompt, (
            f"{proto} software_cve prompt doesn't reference the correlator"
        )
        assert "{preamble}" not in prompt, (
            f"{proto} software_cve preamble unresolved"
        )
        # The tool is available in the protocol's palette — so the agent
        # can actually call what the prompt tells it to call.
        assert "correlate_software_to_cves" in audit.tool_names, (
            f"{proto} tool_names missing correlator"
        )


def test_no_software_yields_zero_candidates(db_session):
    """Asset with no software inventory should return zero candidates, not crash."""
    org = Organization(name="X", slug="x1")
    db_session.add(org)
    db_session.flush()
    scan = Scan(org_id=org.id, filename="x.nessus", status="completed")
    db_session.add(scan)
    db_session.flush()
    asset = Asset(scan_id=scan.id, hostname="empty", ip="10.0.0.99")
    db_session.add(asset)
    db_session.flush()

    result = correlate_asset(db_session, asset.id)
    assert result["software_scanned"] == 0
    assert result["total_candidate_cves"] == 0
    assert result["candidate_cves"] == []

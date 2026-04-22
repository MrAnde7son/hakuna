"""Per-asset CVE correlator — joins installed-software + patch inventory
against the threat-intel catalog to produce a deterministic candidate CVE
list per host.

This is the *coverage* layer of the CVE story: for each `(name, version)`
tuple in an asset's InventorySoftware, it asks `downstream_impact.
_query_threat_intel_cves` (the same version-range matcher used elsewhere
in the app) which CVEs apply. It then cross-references `MSRCPatch` and
`InventoryPatch.cves` to tell the caller which candidate CVEs are already
mitigated by an installed KB vs still missing.

The reasoning layer — deciding which of the candidates are actually
exploitable given the host's config — lives in the ReAct audit agents.
They consume this tool's output as input to triage + narrative, not as
ground truth.

Why a service, not a tool: version-range correctness is the part we need
reproducible across runs. An LLM is the wrong place for set arithmetic
over a CVE database.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from models.models import Asset, InventoryPatch, InventorySoftware
from models.threat_intel_models import MSRCPatch, ProductLifecycle
from services.downstream_impact import _query_threat_intel_cves

logger = logging.getLogger(__name__)


# Ordering knobs used when sorting candidates for LLM consumption. KEV
# first (actively exploited), then EPSS percentile (predicted probability
# of exploitation), then CVSS3. Keeps the top-N cheap to reason about.
def _candidate_sort_key(c: dict) -> tuple:
    return (
        0 if c.get("in_kev") else 1,
        -(c.get("epss_percentile") or 0.0),
        -(c.get("cvss3_score") or 0.0),
    )


def correlate_asset(
    db: Session,
    asset_id: int,
    *,
    include_software: bool = True,
    include_patches: bool = True,
    include_eol: bool = True,
    top_n: int = 40,
) -> dict[str, Any]:
    """Run the full correlation pass for one asset.

    Returns a structured report with three sections:
      - `candidate_cves`: CVEs matched against the asset's InventorySoftware,
        each tagged with mitigation status (is there an installed KB that
        covers it?). Sorted by KEV → EPSS → CVSS, capped at `top_n`.
      - `installed_kbs`: the MSRCPatch-covered CVEs for KBs listed in
        InventoryPatch (these are the CVEs that patch *would have fixed*
        if the patch were missing — i.e. what's already mitigated).
      - `eol_components`: ProductLifecycle hits for components whose
        cycle is past end-of-life.

    `top_n` applies only to the LLM-facing candidate list. The totals
    reported alongside are the unfiltered counts so the agent can reason
    about coverage.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return {"error": f"asset {asset_id} not found"}

    result: dict[str, Any] = {
        "asset_id": asset_id,
        "asset_hostname": asset.hostname,
        "asset_ip": asset.ip,
        "asset_os": asset.os,
    }

    # ── Patches: what's already been applied on this host ──────────────
    #
    # InventoryPatch.kb_id is the KB number collected from WMI
    # (wmi_list_patches → Win32_QuickFixEngineering). MSRCPatch maps each
    # KB to the CVEs it fixes. The union across all installed KBs is the
    # asset's "mitigated CVE" set.
    mitigated_cves: set[str] = set()
    installed_kb_ids: list[str] = []
    if include_patches:
        patches = db.query(InventoryPatch).filter(InventoryPatch.asset_id == asset_id).all()
        installed_kb_ids = sorted({p.kb_id for p in patches if p.kb_id})
        if installed_kb_ids:
            # One IN query beats N per-KB queries. MSRC data is authoritative;
            # fall back to InventoryPatch.cves (parsed from description text)
            # for coverage when MSRC hasn't ingested a KB yet.
            msrc_rows = (
                db.query(MSRCPatch.cve_id, MSRCPatch.kb_id)
                .filter(MSRCPatch.kb_id.in_(installed_kb_ids))
                .all()
            )
            for cve_id, _ in msrc_rows:
                if cve_id:
                    mitigated_cves.add(cve_id)
        # Parsed-from-description fallback — InventoryPatch.cves is a JSON
        # list populated by the scanner. Less reliable than MSRC (depends on
        # patch description formatting) but covers KBs MSRC hasn't ingested.
        for p in patches:
            for cve in (p.cves or []):
                if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                    mitigated_cves.add(cve.upper())

    # ── Software: candidate CVEs from installed packages ───────────────
    candidates: list[dict] = []
    software_scanned = 0
    components_matched = 0
    if include_software:
        software = db.query(InventorySoftware).filter(InventorySoftware.asset_id == asset_id).all()
        # Dedup by (name, version) — the same package can appear twice
        # across scans and we don't want duplicate CVE rows.
        seen: set[tuple[str, str]] = set()
        # Tracks which CVE came from which component so the agent can
        # connect a finding back to the package that triggered it.
        for sw in software:
            name = (sw.name or "").strip()
            version = (sw.version or "").strip()
            if not name or not version:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            software_scanned += 1
            matches = _query_threat_intel_cves(db, name, version, exclude_cve_ids=[])
            if matches:
                components_matched += 1
            for m in matches:
                cve_id = m.get("cve_id")
                if not cve_id:
                    continue
                m["component"] = name
                m["component_vendor"] = sw.vendor
                m["component_version"] = version
                m["mitigated"] = cve_id.upper() in mitigated_cves
                candidates.append(m)

    # Dedup candidates by CVE id — the same CVE can match via multiple
    # components (e.g., two installed packages that share a bundled lib).
    # Keep the first match per CVE but surface all affected components.
    dedup: dict[str, dict] = {}
    for c in candidates:
        cve_id = c["cve_id"]
        if cve_id not in dedup:
            dedup[cve_id] = {**c, "matched_components": [c["component"]]}
        else:
            comps = dedup[cve_id]["matched_components"]
            if c["component"] not in comps:
                comps.append(c["component"])
    merged = list(dedup.values())
    merged.sort(key=_candidate_sort_key)

    # Slim each row for LLM consumption — drop fields that are redundant
    # once matched_components is present, cap description length.
    def _slim(c: dict) -> dict:
        return {
            "cve_id": c.get("cve_id"),
            "components": c.get("matched_components") or [c.get("component")],
            "cvss3": c.get("cvss3_score"),
            "severity": c.get("severity"),
            "in_kev": bool(c.get("in_kev")),
            "ransomware_linked": bool(c.get("ransomware_linked")),
            "has_public_exploit": bool(c.get("has_public_exploit")),
            "exploit_maturity": c.get("exploit_maturity_level"),
            "epss": c.get("epss_score"),
            "epss_percentile": c.get("epss_percentile"),
            "trending_in_news": bool(c.get("trending_in_news")),
            "mitigated": bool(c.get("mitigated")),
            "description": (c.get("description") or "")[:180],
        }

    total = len(merged)
    missing = [c for c in merged if not c.get("mitigated")]
    already_mitigated = total - len(missing)

    # Summary counts are authoritative; the sampled lists are for LLM reasoning.
    result.update({
        "software_scanned": software_scanned,
        "components_with_cves": components_matched,
        "total_candidate_cves": total,
        "missing_patch_cves": len(missing),
        "already_mitigated_cves": already_mitigated,
        "kev_candidates": sum(1 for c in merged if c.get("in_kev")),
        "ransomware_linked_candidates": sum(1 for c in merged if c.get("ransomware_linked")),
        "with_public_exploit": sum(1 for c in merged if c.get("has_public_exploit")),
        "installed_kb_count": len(installed_kb_ids),
        "installed_kb_ids_sample": installed_kb_ids[:20],
        "candidate_cves": [_slim(c) for c in merged[:top_n]],
        "candidate_cves_truncated": len(merged) > top_n,
    })

    # ── EOL components ─────────────────────────────────────────────────
    #
    # ProductLifecycle is keyed by endoflife.date slug (e.g. "nodejs",
    # "ubuntu") — not directly joinable to InventorySoftware.name. We do
    # a best-effort substring match: this is lossy but a good-enough first
    # pass, and the agent can reason about false positives.
    if include_eol:
        result["eol_components"] = _correlate_eol(db, asset)

    return result


def _correlate_eol(db: Session, asset: Asset) -> list[dict]:
    """Best-effort EOL matching. Tries asset.os first (highest-signal hit),
    then walks InventorySoftware names against ProductLifecycle.product_name
    and .slug via case-insensitive substring match.
    """
    hits: list[dict] = []
    seen_keys: set[tuple[str, str]] = set()

    def _add(cycle_row: ProductLifecycle, matched_via: str) -> None:
        key = (cycle_row.slug, cycle_row.cycle)
        if key in seen_keys:
            return
        seen_keys.add(key)
        hits.append({
            "product_name": cycle_row.product_name,
            "slug": cycle_row.slug,
            "cycle": cycle_row.cycle,
            "is_eol": bool(cycle_row.is_eol),
            "eol_date": cycle_row.eol,
            "support_end": cycle_row.support_end,
            "latest_version": cycle_row.latest_version,
            "lts": bool(cycle_row.lts),
            "matched_via": matched_via,
        })

    # OS match — the highest-signal hit. asset.os often looks like
    # "Windows Server 2012 R2" or "Ubuntu 18.04" or "CentOS 7".
    if asset.os:
        os_lower = asset.os.lower()
        # Pull only EOL cycles — we surface non-EOL for context only if
        # the OS explicitly matches a known cycle. Keep the query narrow.
        candidates = db.query(ProductLifecycle).filter(
            ProductLifecycle.is_eol.is_(True),
        ).limit(500).all()
        for row in candidates:
            name = (row.product_name or "").lower()
            slug = (row.slug or "").lower()
            if name and name in os_lower:
                _add(row, f"os:{asset.os}")
            elif slug and slug in os_lower:
                _add(row, f"os:{asset.os}")

    # Software match — noisier. Only flag rows that are actually EOL.
    software = db.query(InventorySoftware.name).filter(
        InventorySoftware.asset_id == asset.id,
    ).distinct().limit(200).all()
    sw_names = [(n[0] or "").lower() for n in software if n[0]]

    if sw_names:
        eol_rows = db.query(ProductLifecycle).filter(
            ProductLifecycle.is_eol.is_(True),
        ).limit(500).all()
        for row in eol_rows:
            pname = (row.product_name or "").lower()
            slug = (row.slug or "").lower()
            if not pname and not slug:
                continue
            for sw_name in sw_names:
                if pname and (pname in sw_name or sw_name in pname):
                    _add(row, f"software:{sw_name}")
                    break
                if slug and slug in sw_name:
                    _add(row, f"software:{sw_name}")
                    break

    return hits[:30]

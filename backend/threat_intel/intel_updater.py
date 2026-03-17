"""
Intel Updater — fetches fresh CVE data every 24 hours.

Sources:
  - NVD API v2 (nvd.nist.gov) — CVEs published/modified in the last 25 hours
  - CISA KEV    (cisa.gov)     — known-exploited CVEs → marked as "weaponized"

Updates intel.json in place (merge: new entries added, existing ones updated).
"""
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

INTEL_PATH = Path(__file__).parent.parent.parent / "intel.json"

NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD rate-limits unauthenticated requests — 2 000 ms between calls
NVD_SLEEP  = 2.0
NVD_PAGE   = 2000   # max results per page


def _get_json(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "hakuna/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _fetch_cisa_kev() -> set:
    """Return set of CVE IDs that CISA has flagged as known-exploited."""
    try:
        data = _get_json(CISA_KEV)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.warning(f"Could not fetch CISA KEV: {e}")
        return set()


def _nvd_exploit_maturity(cve_item: dict, kev_ids: set) -> str:
    cve_id = cve_item.get("id", "")
    if cve_id in kev_ids:
        return "weaponized"

    # Check NVD references for public exploit indicators
    refs = cve_item.get("references", [])
    tags_all = {tag for r in refs for tag in r.get("tags", [])}
    if "Exploit" in tags_all or "exploit" in tags_all:
        # Distinguish PoC vs functional
        if any("Vendor Advisory" in r.get("tags", []) for r in refs):
            return "functional"
        return "poc"

    return "unproven"


def _nvd_to_entry(cve_item: dict, kev_ids: set) -> dict:
    cve_id = cve_item.get("id", "")

    # CVSS scores
    metrics  = cve_item.get("metrics", {})
    cvss2_score = cvss3_score = cvss4_score = None

    for m in metrics.get("cvssMetricV2", []):
        cvss2_score = m.get("cvssData", {}).get("baseScore")
        break
    for m in metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []):
        cvss3_score = m.get("cvssData", {}).get("baseScore")
        break
    for m in metrics.get("cvssMetricV40", []):
        cvss4_score = m.get("cvssData", {}).get("baseScore")
        break

    # Description (English preferred)
    descs = cve_item.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    published = cve_item.get("published", "")

    entry: dict = {
        "id":               cve_id,
        "exploit_maturity": _nvd_exploit_maturity(cve_item, kev_ids),
        "zero_day":         False,
        "timeline":         {"discovery_date": published},
    }
    if description:
        entry["description"] = description
    if cvss2_score is not None:
        entry["cvss2"] = {"base_score": cvss2_score}
    if cvss3_score is not None:
        entry["cvss3"] = {"base_score": cvss3_score}
    if cvss4_score is not None:
        entry["cvss4"] = {"base_score": cvss4_score}

    return entry


def _fetch_nvd_recent(hours: int = 25) -> list:
    """Fetch CVEs published or modified within the last `hours` hours."""
    now    = datetime.now(timezone.utc)
    start  = now - timedelta(hours=hours)
    fmt    = "%Y-%m-%dT%H:%M:%S.000"

    params = (
        f"?pubStartDate={start.strftime(fmt)}"
        f"&pubEndDate={now.strftime(fmt)}"
        f"&resultsPerPage={NVD_PAGE}"
    )

    results = []
    start_idx = 0

    while True:
        url = NVD_API + params + f"&startIndex={start_idx}"
        try:
            data = _get_json(url)
        except Exception as e:
            logger.warning(f"NVD fetch failed at startIndex={start_idx}: {e}")
            break

        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            results.append(v.get("cve", {}))

        total = data.get("totalResults", 0)
        start_idx += len(vulns)
        if start_idx >= total or not vulns:
            break

        time.sleep(NVD_SLEEP)

    logger.info(f"Fetched {len(results)} CVEs from NVD (last {hours}h)")
    return results


def _load_existing() -> dict:
    """Load existing intel.json and return as {cve_id: entry} dict."""
    if not INTEL_PATH.exists():
        return {}
    try:
        with open(INTEL_PATH) as f:
            data = json.load(f)
        return {e["id"]: e for e in data.get("metadata", []) if "id" in e}
    except Exception as e:
        logger.warning(f"Could not load existing intel.json: {e}")
        return {}


def _save(entries_by_id: dict):
    """Write merged entries back to intel.json atomically."""
    payload = {"metadata": list(entries_by_id.values())}
    tmp = INTEL_PATH.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(payload, f, indent=4)
    tmp.replace(INTEL_PATH)
    logger.info(f"intel.json updated — {len(entries_by_id)} total entries")


def update_intel():
    """Main entry point: fetch, merge, save."""
    logger.info("Starting intel update…")
    try:
        kev_ids  = _fetch_cisa_kev()
        nvd_cves = _fetch_nvd_recent(hours=25)

        existing = _load_existing()

        new_count = updated_count = 0
        for cve_item in nvd_cves:
            cve_id = cve_item.get("id", "")
            if not cve_id:
                continue
            entry = _nvd_to_entry(cve_item, kev_ids)
            if cve_id in existing:
                existing[cve_id].update(entry)
                updated_count += 1
            else:
                existing[cve_id] = entry
                new_count += 1

        # Also promote any existing entries that are now in CISA KEV
        for cve_id, entry in existing.items():
            if cve_id in kev_ids and entry.get("exploit_maturity") != "weaponized":
                entry["exploit_maturity"] = "weaponized"
                updated_count += 1

        _save(existing)
        logger.info(f"Intel update done: {new_count} new, {updated_count} updated, {len(kev_ids)} KEV entries")
    except Exception:
        logger.exception("Intel update failed")

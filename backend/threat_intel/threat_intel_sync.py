import json
import ssl
import subprocess
import tempfile
import os
import urllib.request
import urllib.parse
import logging
from datetime import datetime
from typing import Optional, List, Dict

import hashlib
import re
import xml.etree.ElementTree as ET
from models.threat_intel_models import (
    ThreatCVE, ThreatGroup, TTP, ThreatGroupTTP, CisaAdvisory,
    CWEEntry, ExploitReference, SSVCDecision, MSRCPatch,
    PatchAdvisory, PatchAdvisoryPlatform,
)
from models.models import Finding

logger = logging.getLogger(__name__)

_MITRE_BUNDLE_CACHE = None  # module-level cache to avoid re-fetching the large STIX bundle
_SSL_CONTEXT = None          # cached SSL context
_USER_AGENT = "Mozilla/5.0 (compatible; Hakuna/1.0; +https://github.com/MrAnde7son/hakuna)"


def _get_ssl_context() -> ssl.SSLContext:
    """
    Build an SSL context using macOS system root certificates when the default
    Python cert store is missing (common with Python.org builds on macOS).
    Falls back to an unverified context only if the system keychain export also fails.
    """
    global _SSL_CONTEXT
    if _SSL_CONTEXT is not None:
        return _SSL_CONTEXT

    # Try standard context first
    try:
        ctx = ssl.create_default_context()
        # Quick test — if cafile is set it worked
        if ctx.cert_store_stats()["x509"] > 0:
            _SSL_CONTEXT = ctx
            return ctx
    except Exception:
        pass

    # Export macOS system root certs via `security` CLI
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            tmp_path = f.name
        subprocess.run(
            ["security", "export", "-t", "certs", "-f", "pemseq",
             "-k", "/System/Library/Keychains/SystemRootCertificates.keychain",
             "-o", tmp_path],
            check=True, capture_output=True, timeout=10,
        )
        ctx = ssl.create_default_context(cafile=tmp_path)
        os.unlink(tmp_path)
        logger.info("SSL context loaded from macOS system keychain")
        _SSL_CONTEXT = ctx
        return ctx
    except Exception as exc:
        logger.warning("macOS keychain SSL export failed (%s); falling back to unverified context", exc)

    # Last resort: disable verification (all targets are well-known public APIs)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _SSL_CONTEXT = ctx
    return ctx


def fetch_cisa_kev() -> list:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalog.
    Returns a list of vulnerability dicts on success, [] on failure.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "python-urllib/3.8", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10, context=_get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("fetch_cisa_kev failed: %s", exc)
        return []


def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs from api.first.org in chunks of 100.
    Returns a dict mapping cve_id -> {"epss": float, "percentile": float}.
    """
    results = {}
    chunk_size = 100

    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        cve_param = ",".join(chunk)
        url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": cve_param})
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "python-urllib/3.8", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("data", []):
                cve = item.get("cve", "")
                try:
                    results[cve] = {
                        "epss": float(item.get("epss", 0.0)),
                        "percentile": float(item.get("percentile", 0.0)),
                    }
                except (TypeError, ValueError):
                    pass
        except Exception as exc:
            logger.warning("fetch_epss_scores chunk %d failed: %s", i // chunk_size, exc)

    return results


def fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    """
    Fetch a single CVE from the NVD API v2.
    Returns a normalized dict or None on failure / rate-limiting.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode({"cveId": cve_id})
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "python-urllib/3.8", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=_get_ssl_context()) as resp:
                if resp.status == 429:
                    logger.warning("fetch_nvd_cve rate-limited for %s", cve_id)
                    return None
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            if http_err.code == 429:
                logger.warning("fetch_nvd_cve rate-limited (429) for %s", cve_id)
                return None
            raise

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_data = vulnerabilities[0].get("cve", {})

        # Description
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        # CVSS scores from NVD metrics
        metrics = cve_data.get("metrics", {})

        # CVSS v2
        cvss2_score = None
        for m in metrics.get("cvssMetricV2", []):
            cvss_data = m.get("cvssData", {})
            cvss2_score = cvss_data.get("baseScore")
            break

        # CVSS v3 (prefer 3.1 over 3.0)
        cvss3_score = None
        cvss3_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss3_score = cvss_data.get("baseScore")
                cvss3_vector = cvss_data.get("vectorString")
                break

        # CVSS v4
        cvss4_score = None
        cvss4_vector = None
        for m in metrics.get("cvssMetricV40", []):
            cvss_data = m.get("cvssData", {})
            cvss4_score = cvss_data.get("baseScore")
            cvss4_vector = cvss_data.get("vectorString")
            break

        # Affected products — capture full version range from NVD CPE data
        affected_products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        # Extract version from CPE string (part 5) if present
                        cpe_version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
                        prod = {
                            "vendor": parts[3],
                            "product": parts[4],
                            "cpe_version": cpe_version,
                        }
                        # Capture all four NVD version range fields
                        for field in ("versionStartIncluding", "versionStartExcluding",
                                      "versionEndIncluding", "versionEndExcluding"):
                            val = cpe_match.get(field, "")
                            if val:
                                prod[field] = val
                        # Keep backward compat: "versions" = best ceiling
                        prod["versions"] = (
                            cpe_match.get("versionEndIncluding")
                            or cpe_match.get("versionEndExcluding")
                            or cpe_version
                            or ""
                        )
                        affected_products.append(prod)

        # CWE IDs
        cwe_ids = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val and val != "NVD-CWE-Other" and val != "NVD-CWE-noinfo":
                    cwe_ids.append(val)

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss2_score": cvss2_score,
            "cvss3_score": cvss3_score,
            "cvss3_vector": cvss3_vector,
            "cvss4_score": cvss4_score,
            "cvss4_vector": cvss4_vector,
            "published_date": cve_data.get("published", ""),
            "modified_date": cve_data.get("lastModified", ""),
            "affected_products": affected_products,
            "cwe_ids": cwe_ids,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    except Exception as exc:
        logger.warning("fetch_nvd_cve failed for %s: %s", cve_id, exc)
        return None


def sync_kev_to_db(db) -> dict:
    """
    Fetch the CISA KEV catalog and upsert ThreatCVE records.
    Returns {"added": int, "updated": int, "total": int}.
    """
    entries = fetch_cisa_kev()
    added = 0
    updated = 0

    for entry in entries:
        cve_id = entry.get("cveID", "")
        if not cve_id:
            continue

        existing = db.query(ThreatCVE).filter(ThreatCVE.cve_id == cve_id).first()
        if existing:
            existing.in_kev = True
            existing.has_public_exploit = True
            existing.kev_date_added = entry.get("dateAdded", "")
            existing.kev_due_date = entry.get("dueDate", "")
            existing.kev_ransomware_use = entry.get("knownRansomwareCampaignUse", "")
            existing.kev_notes = entry.get("notes", "")
            existing.updated_at = datetime.utcnow()
            updated += 1
        else:
            record = ThreatCVE(
                cve_id=cve_id,
                description=entry.get("shortDescription", ""),
                in_kev=True,
                has_public_exploit=True,
                kev_date_added=entry.get("dateAdded", ""),
                kev_due_date=entry.get("dueDate", ""),
                kev_ransomware_use=entry.get("knownRansomwareCampaignUse", ""),
                kev_notes=entry.get("notes", ""),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(record)
            added += 1

    # Backfill: ensure all KEV CVEs have has_public_exploit=True
    db.query(ThreatCVE).filter(
        ThreatCVE.in_kev == True,
        ThreatCVE.has_public_exploit != True,
    ).update({"has_public_exploit": True, "updated_at": datetime.utcnow()})

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_kev_to_db commit failed: %s", exc)
        db.rollback()

    return {"added": added, "updated": updated, "total": len(entries)}


def sync_nvd_scores(db, batch_size: int = 50) -> dict:
    """
    Backfill CVSS scores from NVD for ThreatCVE records missing cvss3_score.
    Uses single-CVE lookups with a delay to respect NVD rate limits (~5 req/s without API key).
    Returns {"updated": int, "failed": int, "skipped": int}.
    """
    import time

    from sqlalchemy import or_
    records = (
        db.query(ThreatCVE)
        .filter(or_(
            ThreatCVE.cvss3_score.is_(None),
            ThreatCVE.cvss4_score.is_(None),
            ThreatCVE.cvss2_score.is_(None),
        ))
        .limit(batch_size)
        .all()
    )

    if not records:
        return {"updated": 0, "failed": 0, "skipped": 0}

    logger.info("NVD backfill: fetching CVSS for %d CVEs", len(records))
    updated = 0
    failed = 0

    for i, record in enumerate(records):
        if i > 0:
            time.sleep(0.35)  # ~3 req/s to stay under NVD rate limit

        nvd_data = fetch_nvd_cve(record.cve_id)
        if nvd_data is None:
            failed += 1
            continue

        if nvd_data.get("cvss2_score") is not None and not record.cvss2_score:
            record.cvss2_score = nvd_data["cvss2_score"]
        if nvd_data.get("cvss3_score") is not None and not record.cvss3_score:
            record.cvss3_score = nvd_data["cvss3_score"]
        if nvd_data.get("cvss3_vector") and not record.cvss3_vector:
            record.cvss3_vector = nvd_data["cvss3_vector"]
        if nvd_data.get("cvss4_score") is not None and not record.cvss4_score:
            record.cvss4_score = nvd_data["cvss4_score"]
        if nvd_data.get("cvss4_vector") and not record.cvss4_vector:
            record.cvss4_vector = nvd_data["cvss4_vector"]
        if nvd_data.get("description") and not record.description:
            record.description = nvd_data["description"]
        if nvd_data.get("affected_products"):
            record.affected_products = nvd_data["affected_products"]
        if nvd_data.get("cwe_ids") and not record.cwe_ids:
            record.cwe_ids = nvd_data["cwe_ids"]
        if nvd_data.get("published_date") and not record.published_date:
            record.published_date = nvd_data["published_date"]
        if nvd_data.get("nvd_url") and not record.nvd_url:
            record.nvd_url = nvd_data["nvd_url"]
        record.updated_at = datetime.utcnow()
        updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_nvd_scores commit failed: %s", exc)
        db.rollback()

    skipped = len(records) - updated - failed
    logger.info("NVD backfill done: %d updated, %d failed, %d skipped", updated, failed, skipped)
    return {"updated": updated, "failed": failed, "skipped": skipped}


def _fetch_nvd_cves_by_cpe(vendor: str, product: str, max_results: int = 200) -> List[dict]:
    """Query NVD API v2 for CVEs affecting a specific CPE vendor:product.

    Returns a list of normalized CVE dicts (same format as fetch_nvd_cve).
    Uses the cpeName parameter with a wildcard version to get all CVEs for
    any version of the product.
    """
    cpe_match = f"cpe:2.3:a:{vendor}:{product}"
    params = {"virtualMatchString": cpe_match, "resultsPerPage": str(min(max_results, 2000))}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30, context=_get_ssl_context()) as resp:
                if resp.status == 429:
                    logger.warning("NVD CPE query rate-limited for %s:%s", vendor, product)
                    return []
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as http_err:
            if http_err.code == 429:
                logger.warning("NVD CPE query rate-limited (429) for %s:%s", vendor, product)
                return []
            raise

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            metrics = cve_data.get("metrics", {})

            cvss2_score = None
            for m in metrics.get("cvssMetricV2", []):
                cvss2_score = m.get("cvssData", {}).get("baseScore")
                break

            cvss3_score = None
            cvss3_vector = None
            for key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss3_score = cvss_data.get("baseScore")
                    cvss3_vector = cvss_data.get("vectorString")
                    break

            cvss4_score = None
            cvss4_vector = None
            for m in metrics.get("cvssMetricV40", []):
                cvss_data = m.get("cvssData", {})
                cvss4_score = cvss_data.get("baseScore")
                cvss4_vector = cvss_data.get("vectorString")
                break

            affected_products = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_uri = cpe_match.get("criteria", "")
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            cpe_version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
                            prod = {
                                "vendor": parts[3],
                                "product": parts[4],
                                "cpe_version": cpe_version,
                            }
                            for field in ("versionStartIncluding", "versionStartExcluding",
                                          "versionEndIncluding", "versionEndExcluding"):
                                val = cpe_match.get(field, "")
                                if val:
                                    prod[field] = val
                            prod["versions"] = (
                                cpe_match.get("versionEndIncluding")
                                or cpe_match.get("versionEndExcluding")
                                or cpe_version
                                or ""
                            )
                            affected_products.append(prod)

            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val and val not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                        cwe_ids.append(val)

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss2_score": cvss2_score,
                "cvss3_score": cvss3_score,
                "cvss3_vector": cvss3_vector,
                "cvss4_score": cvss4_score,
                "cvss4_vector": cvss4_vector,
                "published_date": cve_data.get("published", ""),
                "modified_date": cve_data.get("lastModified", ""),
                "affected_products": affected_products,
                "cwe_ids": cwe_ids,
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        logger.info(
            "NVD CPE query for %s:%s returned %d CVEs (total_results=%s)",
            vendor, product, len(results), data.get("totalResults"),
        )
        return results

    except Exception as exc:
        logger.warning("NVD CPE query failed for %s:%s: %s", vendor, product, exc)
        return []


def sync_cves_for_cpes(db, cpe_list: Optional[List[str]] = None) -> dict:
    """Pull CVEs from NVD for CPE vendor:product pairs not yet covered in threat_cves.

    If cpe_list is None, collects CPEs from all EASM asset_ports in the DB.
    Only queries NVD for products that have zero matching CVEs in threat_cves,
    so repeated calls are cheap (no redundant API hits).

    Returns {"products_queried": int, "cves_added": int, "cves_updated": int}.
    """
    import time

    # Step 1: Collect unique vendor:product pairs from CPE strings.
    if cpe_list is None:
        # Pull CPEs from EASM asset data stored on scan assets.
        from models.models import Asset
        try:
            assets = db.query(Asset.easm_data).filter(
                Asset.easm_data.isnot(None),
            ).all()
            cpe_list = []
            for (easm_data,) in assets:
                if isinstance(easm_data, dict):
                    cpe_list.extend(easm_data.get("cpe_list") or [])
        except Exception:
            cpe_list = []

    # Parse vendor:product from CPE 2.3 strings.
    products_to_query: dict[tuple[str, str], bool] = {}
    for cpe_str in cpe_list:
        parts = cpe_str.split(":")
        if len(parts) >= 5:
            vendor, product = parts[3], parts[4]
            if vendor and product and product != "*":
                products_to_query[(vendor, product)] = True

    if not products_to_query:
        return {"products_queried": 0, "cves_added": 0, "cves_updated": 0}

    # Step 2: Filter out products already covered in threat_cves.
    # Check if any CVE's affected_products JSON contains the product name.
    from sqlalchemy import cast, String
    uncovered = []
    for vendor, product in products_to_query:
        count = db.query(ThreatCVE).filter(
            cast(ThreatCVE.affected_products, String).like(f'%"{product}"%'),
        ).limit(1).count()
        if count == 0:
            uncovered.append((vendor, product))

    if not uncovered:
        logger.info("sync_cves_for_cpes: all %d products already covered", len(products_to_query))
        return {"products_queried": 0, "cves_added": 0, "cves_updated": 0}

    logger.info("sync_cves_for_cpes: querying NVD for %d uncovered products", len(uncovered))

    # Step 3: Query NVD for each uncovered product.
    total_added = 0
    total_updated = 0

    for i, (vendor, product) in enumerate(uncovered):
        if i > 0:
            time.sleep(0.7)  # NVD rate limit: ~5 req/s without API key

        cves = _fetch_nvd_cves_by_cpe(vendor, product)

        for cve_data in cves:
            cve_id = cve_data["cve_id"]
            existing = db.query(ThreatCVE).filter(ThreatCVE.cve_id == cve_id).first()

            if existing:
                # Update affected_products if we have richer data
                if cve_data.get("affected_products") and not existing.affected_products:
                    existing.affected_products = cve_data["affected_products"]
                if cve_data.get("cvss3_score") and not existing.cvss3_score:
                    existing.cvss3_score = cve_data["cvss3_score"]
                    existing.cvss3_vector = cve_data.get("cvss3_vector")
                if cve_data.get("description") and not existing.description:
                    existing.description = cve_data["description"]
                existing.updated_at = datetime.utcnow()
                total_updated += 1
            else:
                record = ThreatCVE(
                    cve_id=cve_id,
                    description=cve_data.get("description", ""),
                    cvss2_score=cve_data.get("cvss2_score"),
                    cvss3_score=cve_data.get("cvss3_score"),
                    cvss3_vector=cve_data.get("cvss3_vector"),
                    cvss4_score=cve_data.get("cvss4_score"),
                    cvss4_vector=cve_data.get("cvss4_vector"),
                    published_date=cve_data.get("published_date", ""),
                    modified_date=cve_data.get("modified_date", ""),
                    affected_products=cve_data.get("affected_products", []),
                    cwe_ids=cve_data.get("cwe_ids", []),
                    nvd_url=cve_data.get("nvd_url", ""),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                db.add(record)
                total_added += 1

        # Commit per product to avoid huge transactions
        try:
            db.commit()
        except Exception as exc:
            logger.warning("sync_cves_for_cpes commit failed for %s:%s: %s", vendor, product, exc)
            db.rollback()

    logger.info(
        "sync_cves_for_cpes done: %d products queried, %d CVEs added, %d updated",
        len(uncovered), total_added, total_updated,
    )
    return {"products_queried": len(uncovered), "cves_added": total_added, "cves_updated": total_updated}


def sync_epss_for_scan_cves(db, scan_id: int = None) -> dict:
    """
    Fetch EPSS scores for all CVEs in the threat_cves table (KEV catalog + scan CVEs).
    When scan_id is given, also ensures scan CVEs are added to threat_cves before scoring.
    Returns {"updated": int}.
    """
    # Optionally seed threat_cves with CVEs from scan findings that aren't there yet
    if scan_id is not None:
        query = db.query(Finding.cves).filter(Finding.scan_id == scan_id)
    else:
        query = db.query(Finding.cves)

    scan_cve_ids: set = set()
    for (cves,) in query.all():
        if cves:
            for cve in cves:
                if cve:
                    scan_cve_ids.add(cve.strip())

    # Upsert any scan CVEs not yet in threat_cves (so EPSS is populated for them too)
    for cve_id in scan_cve_ids:
        if not db.query(ThreatCVE.id).filter(ThreatCVE.cve_id == cve_id).first():
            db.add(ThreatCVE(cve_id=cve_id, created_at=datetime.utcnow(), updated_at=datetime.utcnow()))
    try:
        db.commit()
    except Exception:
        db.rollback()

    # Fetch EPSS for ALL CVEs in threat_cves (batched)
    existing_records = db.query(ThreatCVE).all()
    tracked_cve_ids = [r.cve_id for r in existing_records]

    if not tracked_cve_ids:
        return {"updated": 0}

    logger.info("Fetching EPSS for %d CVEs", len(tracked_cve_ids))
    epss_data = fetch_epss_scores(tracked_cve_ids)

    updated = 0
    for record in existing_records:
        scores = epss_data.get(record.cve_id)
        if scores:
            record.epss_score = scores["epss"]
            record.epss_percentile = scores["percentile"]
            record.updated_at = datetime.utcnow()
            updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_epss_for_scan_cves commit failed: %s", exc)
        db.rollback()

    return {"updated": updated}


def _fetch_mitre_bundle() -> dict:
    """
    Fetch the MITRE ATT&CK Enterprise STIX bundle, using a module-level cache.
    Returns the parsed JSON dict or {} on failure.
    """
    global _MITRE_BUNDLE_CACHE
    if _MITRE_BUNDLE_CACHE is not None:
        return _MITRE_BUNDLE_CACHE

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "python-urllib/3.8", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=120, context=_get_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        _MITRE_BUNDLE_CACHE = data
        return data
    except Exception as exc:
        logger.warning("_fetch_mitre_bundle failed: %s", exc)
        return {}


def fetch_mitre_attack_groups() -> list:
    """
    Fetch MITRE ATT&CK intrusion-set objects (threat groups).
    Returns a list of normalized group dicts.
    """
    bundle = _fetch_mitre_bundle()
    objects = bundle.get("objects", [])
    groups = []

    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        ext_refs = obj.get("external_references", [])
        mitre_id = ext_refs[0].get("external_id", "") if ext_refs else ""
        groups.append({
            "mitre_id": mitre_id,
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "modified": obj.get("modified", ""),
        })

    return groups


def _infer_group_metadata(description: str, name: str, aliases: list) -> dict:
    """
    Infer country, motivation, is_nation_state, and is_ransomware from
    MITRE ATT&CK group description text and known group naming patterns.
    """
    desc_lower = (description or "").lower()
    name_lower = (name or "").lower()
    all_text = desc_lower + " " + " ".join(a.lower() for a in (aliases or []))

    # ── Country inference from description keywords ──
    country_keywords = {
        "China": ["china", "chinese", "prc", "pla", "mss"],
        "Russia": ["russia", "russian", "gru", "fsb", "svr"],
        "Iran": ["iran", "iranian", "irgc"],
        "North Korea": ["north korea", "dprk", "korean", "lazarus"],
        "Vietnam": ["vietnam", "vietnamese"],
        "Pakistan": ["pakistan", "pakistani"],
        "India": ["india", "indian"],
        "Lebanon": ["lebanon", "lebanese", "hezbollah"],
        "Israel": ["israel", "israeli"],
        "Turkey": ["turkey", "turkish"],
        "South Korea": ["south korea"],
    }
    country = None
    for c, keywords in country_keywords.items():
        if any(kw in desc_lower for kw in keywords):
            country = c
            break

    # ── Motivation inference ──
    motivation = None
    if any(kw in desc_lower for kw in ["financial", "financially motivated", "profit", "banking", "payment", "e-crime"]):
        motivation = "financial"
    elif any(kw in desc_lower for kw in ["espionage", "intelligence", "cyber espionage", "nation-state", "government"]):
        motivation = "espionage"
    elif any(kw in desc_lower for kw in ["destruct", "wiper", "sabotage"]):
        motivation = "destruction"
    elif any(kw in desc_lower for kw in ["hacktivist", "activist", "ideological"]):
        motivation = "hacktivism"

    # ── Flags ──
    is_nation_state = country is not None and motivation != "financial"
    is_ransomware = any(kw in all_text for kw in [
        "ransomware", "ransom", "lockbit", "ryuk", "conti", "revil",
        "darkside", "blackmatter", "hive", "clop", "blackcat", "alphv",
        "royal", "play", "akira", "ragnar",
    ])

    # Financial groups with ransomware are not nation-state
    if is_ransomware and not motivation:
        motivation = "financial"

    return {
        "country": country,
        "motivation": motivation,
        "is_nation_state": is_nation_state,
        "is_ransomware": is_ransomware,
    }


def fetch_mitre_attack_techniques() -> list:
    """
    Fetch MITRE ATT&CK attack-pattern objects (techniques / sub-techniques).
    Returns a list of normalized technique dicts.
    """
    bundle = _fetch_mitre_bundle()
    objects = bundle.get("objects", [])
    techniques = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break

        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactic = kill_chain_phases[0].get("phase_name", "") if kill_chain_phases else ""

        techniques.append({
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactic": tactic,
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", ""),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        })

    return techniques


def _fetch_mitre_relationships(bundle: dict) -> list:
    """
    Extract 'uses' relationships from the STIX bundle that link
    intrusion-set (group) → attack-pattern (technique).
    Returns list of (source_stix_id, target_stix_id) tuples.
    """
    rels = []
    for obj in bundle.get("objects", []):
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "uses"
            and obj.get("source_ref", "").startswith("intrusion-set--")
            and obj.get("target_ref", "").startswith("attack-pattern--")
        ):
            rels.append((obj["source_ref"], obj["target_ref"]))
    return rels


def sync_mitre_groups_to_db(db) -> dict:
    """
    Fetch MITRE ATT&CK groups, techniques, and their relationships,
    then upsert ThreatGroup, TTP, and ThreatGroupTTP records.
    Returns {"groups_added", "groups_skipped", "ttps_added", "ttps_skipped", "links_added"}.
    """
    bundle = _fetch_mitre_bundle()
    groups = fetch_mitre_attack_groups()
    techniques = fetch_mitre_attack_techniques()

    # ── 1. Upsert groups ──
    groups_added = 0
    groups_skipped = 0

    for group_data in groups:
        mitre_id = group_data.get("mitre_id", "")
        if not mitre_id:
            groups_skipped += 1
            continue

        meta = _infer_group_metadata(
            group_data.get("description", ""),
            group_data.get("name", ""),
            group_data.get("aliases", []),
        )

        existing = db.query(ThreatGroup).filter(ThreatGroup.mitre_id == mitre_id).first()
        if existing:
            # Backfill metadata if missing
            if not existing.motivation and meta["motivation"]:
                existing.motivation = meta["motivation"]
            if not existing.country and meta["country"]:
                existing.country = meta["country"]
            if not existing.is_nation_state and meta["is_nation_state"]:
                existing.is_nation_state = meta["is_nation_state"]
            if not existing.is_ransomware and meta["is_ransomware"]:
                existing.is_ransomware = meta["is_ransomware"]
            existing.updated_at = datetime.utcnow()
            groups_skipped += 1
            continue

        record = ThreatGroup(
            mitre_id=mitre_id,
            name=group_data.get("name", ""),
            aliases=group_data.get("aliases", []),
            description=group_data.get("description", ""),
            country=meta["country"],
            motivation=meta["motivation"],
            is_nation_state=meta["is_nation_state"],
            is_ransomware=meta["is_ransomware"],
            source="mitre",
            source_url=f"https://attack.mitre.org/groups/{mitre_id}/",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(record)
        groups_added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_mitre_groups_to_db groups commit failed: %s", exc)
        db.rollback()

    # ── 2. Upsert TTPs (techniques) ──
    ttps_added = 0
    ttps_skipped = 0

    for tech in techniques:
        tid = tech.get("technique_id", "")
        if not tid:
            ttps_skipped += 1
            continue

        existing = db.query(TTP).filter(TTP.technique_id == tid).first()
        if existing:
            ttps_skipped += 1
            continue

        parent_id = None
        if tech.get("is_subtechnique") and "." in tid:
            parent_id = tid.rsplit(".", 1)[0]

        record = TTP(
            technique_id=tid,
            name=tech.get("name", ""),
            tactic=tech.get("tactic", ""),
            description=tech.get("description", ""),
            platforms=tech.get("platforms", []),
            detection=tech.get("detection", ""),
            mitre_url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            is_subtechnique=tech.get("is_subtechnique", False),
            parent_technique_id=parent_id,
            created_at=datetime.utcnow(),
        )
        db.add(record)
        ttps_added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_mitre_groups_to_db ttps commit failed: %s", exc)
        db.rollback()

    # ── 3. Link groups ↔ techniques via STIX relationships ──
    relationships = _fetch_mitre_relationships(bundle)

    # Build STIX-id → mitre-id lookup from bundle objects
    stix_to_mitre: Dict[str, str] = {}
    for obj in bundle.get("objects", []):
        stix_id = obj.get("id", "")
        ext_refs = obj.get("external_references", [])
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                stix_to_mitre[stix_id] = ref.get("external_id", "")
                break

    # Cache DB lookups
    group_id_map: Dict[str, int] = {
        r.mitre_id: r.id for r in db.query(ThreatGroup.mitre_id, ThreatGroup.id).all()
    }
    ttp_id_map: Dict[str, int] = {
        r.technique_id: r.id for r in db.query(TTP.technique_id, TTP.id).all()
    }

    # Existing links for dedup
    existing_links: set = set()
    for row in db.query(ThreatGroupTTP.group_id, ThreatGroupTTP.ttp_id).all():
        existing_links.add((row[0], row[1]))

    links_added = 0
    for src_stix, tgt_stix in relationships:
        group_mitre = stix_to_mitre.get(src_stix)
        tech_mitre = stix_to_mitre.get(tgt_stix)
        if not group_mitre or not tech_mitre:
            continue

        gid = group_id_map.get(group_mitre)
        tid = ttp_id_map.get(tech_mitre)
        if not gid or not tid:
            continue

        if (gid, tid) in existing_links:
            continue

        db.add(ThreatGroupTTP(group_id=gid, ttp_id=tid))
        existing_links.add((gid, tid))
        links_added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_mitre_groups_to_db links commit failed: %s", exc)
        db.rollback()

    logger.info(
        "MITRE sync: %d groups added, %d TTPs added, %d links added",
        groups_added, ttps_added, links_added,
    )
    return {
        "groups_added": groups_added,
        "groups_skipped": groups_skipped,
        "ttps_added": ttps_added,
        "ttps_skipped": ttps_skipped,
        "links_added": links_added,
    }


def enrich_findings_from_threat_intel(db, scan_id: int = None) -> dict:
    """
    Backfill Finding rows with threat intel data from the threat_cves table.

    For each finding that has CVEs, look up the corresponding ThreatCVE records
    and populate: is_kev, epss_score, epss_percentile, ransomware_linked,
    trending_in_news.  Uses the *best* (most severe) value across all CVEs
    on a finding.

    Returns {"enriched": int, "skipped": int}.
    """
    # Build a lookup from all ThreatCVE records
    all_threat_cves = db.query(ThreatCVE).all()
    if not all_threat_cves:
        return {"enriched": 0, "skipped": 0}

    cve_lookup: Dict[str, ThreatCVE] = {r.cve_id: r for r in all_threat_cves}

    # Query findings (optionally scoped to a scan)
    fq = db.query(Finding).filter(Finding.cves.isnot(None))
    if scan_id is not None:
        fq = fq.filter(Finding.scan_id == scan_id)
    findings = fq.all()

    enriched = 0
    skipped = 0

    for f in findings:
        if not f.cves:
            skipped += 1
            continue

        best_epss = None
        best_epss_pct = None
        is_kev = False
        ransomware = False
        trending = False
        best_cvss2 = None
        best_cvss3 = None
        best_cvss3_vec = None
        best_cvss4 = None
        best_cvss4_vec = None

        for cve_id in f.cves:
            tc = cve_lookup.get(cve_id.strip() if cve_id else None)
            if not tc:
                continue
            if tc.in_kev:
                is_kev = True
            if tc.epss_score is not None:
                if best_epss is None or tc.epss_score > best_epss:
                    best_epss = tc.epss_score
                    best_epss_pct = tc.epss_percentile
            if tc.kev_ransomware_use and tc.kev_ransomware_use.lower() not in ("", "unknown"):
                ransomware = True
            if tc.trending_in_news:
                trending = True
            # CVSS backfill — pick highest score per version
            if tc.cvss2_score is not None and (best_cvss2 is None or tc.cvss2_score > best_cvss2):
                best_cvss2 = tc.cvss2_score
            if tc.cvss3_score is not None and (best_cvss3 is None or tc.cvss3_score > best_cvss3):
                best_cvss3 = tc.cvss3_score
                best_cvss3_vec = tc.cvss3_vector
            if tc.cvss4_score is not None and (best_cvss4 is None or tc.cvss4_score > best_cvss4):
                best_cvss4 = tc.cvss4_score
                best_cvss4_vec = tc.cvss4_vector

        changed = False
        if f.is_kev != is_kev:
            f.is_kev = is_kev
            changed = True
        if best_epss is not None and f.epss_score != best_epss:
            f.epss_score = best_epss
            f.epss_percentile = best_epss_pct
            changed = True
        if f.ransomware_linked != ransomware:
            f.ransomware_linked = ransomware
            changed = True
        if f.trending_in_news != trending:
            f.trending_in_news = trending
            changed = True
        # Backfill CVSS scores only when the finding is missing them
        if best_cvss2 is not None and not f.cvss2_score:
            f.cvss2_score = best_cvss2
            changed = True
        if best_cvss3 is not None and not f.cvss3_score:
            f.cvss3_score = best_cvss3
            if best_cvss3_vec:
                f.cvss3_vector = best_cvss3_vec
            changed = True
        if best_cvss4 is not None and not f.cvss4_score:
            f.cvss4_score = best_cvss4
            if best_cvss4_vec:
                f.cvss4_vector = best_cvss4_vec
            changed = True

        if changed:
            enriched += 1
        else:
            skipped += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("enrich_findings_from_threat_intel commit failed: %s", exc)
        db.rollback()

    logger.info("Finding enrichment: %d enriched, %d skipped", enriched, skipped)
    return {"enriched": enriched, "skipped": skipped}


# ─────────────────────────────────────────────────────────────────────────────
# CISA Advisories sync
# ─────────────────────────────────────────────────────────────────────────────

# CISA advisory RSS feed candidates (tried in order until one works)
_CISA_ADVISORY_FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.cisa.gov/cybersecurity-advisories/alerts.xml",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Known co-sealer agency keywords → display name
_COAUTHORS = {
    "nsa": "NSA", "national security agency": "NSA",
    "fbi": "FBI", "federal bureau": "FBI",
    "cisa": "CISA",
    "ms-isac": "MS-ISAC",
    "ncsc-uk": "NCSC-UK", "uk ncsc": "NCSC-UK", "united kingdom": "NCSC-UK",
    "acsc": "ACSC", "australian signals": "ACSC",
    "cccs": "CCCS", "canadian centre": "CCCS",
    "nz ncsc": "NZ-NCSC", "new zealand": "NZ-NCSC",
    "cyber command": "USCYBERCOM",
    "dod": "DoD",
    "odni": "ODNI",
}

_SECTOR_KEYWORDS = {
    "energy": "Energy",
    "water": "Water",
    "healthcare": "Healthcare",
    "financial": "Financial",
    "transportation": "Transportation",
    "critical infrastructure": "Critical Infrastructure",
    "manufacturing": "Manufacturing",
    "government": "Government",
    "education": "Education",
    "defense": "Defense",
    "telecommunications": "Telecom",
    "oil and gas": "Oil & Gas",
    "chemical": "Chemical",
}


def _detect_advisory_type(title: str, link: str) -> str:
    t = title.lower()
    l = (link or "").lower()
    if "icsa" in t or "icsma" in t or "icsa" in l or "ics-advisory" in l:
        return "ics"
    if "icsma" in l or "medical" in t:
        return "ics_medical"
    if "malware" in t or "malware-analysis" in l:
        return "malware"
    if "alert" in l or t.startswith("alert"):
        return "alert"
    return "advisory"


def _extract_co_sealers(text: str) -> list:
    found = set()
    lower = text.lower()
    for keyword, label in _COAUTHORS.items():
        if keyword in lower:
            found.add(label)
    return sorted(found)


def _extract_sectors(text: str) -> list:
    found = set()
    lower = text.lower()
    for keyword, label in _SECTOR_KEYWORDS.items():
        if keyword in lower:
            found.add(label)
    return sorted(found)


def _parse_rss_feed(raw_bytes: bytes) -> list:
    """
    Parse an RSS 2.0 or Atom feed and return a list of entry dicts.
    Each dict has: title, link, pub_date, summary.
    """
    entries = []
    try:
        root = ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        logger.warning("RSS parse error: %s", e)
        return entries

    ns = {"atom": "http://www.w3.org/2005/Atom"}

    # RSS 2.0
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or item.findtext("dc:date") or "").strip()
        desc = (item.findtext("description") or "").strip()
        if title:
            entries.append({"title": title, "link": link, "pub_date": pub, "summary": desc})

    # Atom
    if not entries:
        for entry in root.findall("atom:entry", ns) or root.findall("{http://www.w3.org/2005/Atom}entry"):
            title_el = entry.find("{http://www.w3.org/2005/Atom}title") or entry.find("title")
            link_el = entry.find("{http://www.w3.org/2005/Atom}link") or entry.find("link")
            updated_el = entry.find("{http://www.w3.org/2005/Atom}updated") or entry.find("updated")
            summary_el = entry.find("{http://www.w3.org/2005/Atom}summary") or entry.find("summary")
            title = (title_el.text or "").strip() if title_el is not None else ""
            link = ""
            if link_el is not None:
                link = link_el.get("href", "") or (link_el.text or "")
            pub = (updated_el.text or "").strip() if updated_el is not None else ""
            desc = (summary_el.text or "").strip() if summary_el is not None else ""
            if title:
                entries.append({"title": title, "link": link, "pub_date": pub, "summary": desc})

    return entries


def _parse_pub_date(raw: str) -> Optional[str]:
    """Convert various date formats to an ISO date string (YYYY-MM-DD)."""
    if not raw:
        return None
    # Already ISO-ish
    m = re.match(r"(\d{4}-\d{2}-\d{2})", raw)
    if m:
        return m.group(1)
    # RFC 2822: "Tue, 11 Mar 2026 00:00:00 +0000" or 2-digit year "Fri, 13 Mar 26 12:00:00 +0000"
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z",
                "%a, %d %b %y %H:%M:%S %z", "%a, %d %b %y %H:%M:%S %Z",
                "%d %b %Y %H:%M:%S %z", "%d %b %Y",
                "%d %b %y %H:%M:%S %z", "%d %b %y"):
        try:
            return datetime.strptime(raw.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def _extract_advisory_id(title: str, link: str) -> Optional[str]:
    """Try to extract a structured advisory ID like AA25-071A or ICSA-26-069-04 from title or URL."""
    for text in (title, link):
        m = re.search(r"\b(AA\d{2}-\d{3}[A-Z]?|ICSA-\d{2}-\d{3}-\d{2,3}|ICSMA-\d{2}-\d{3}-\d{2,3})\b", text, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def sync_cisa_advisories_to_db(db) -> dict:
    """
    Fetch the CISA cybersecurity advisories RSS feed, parse entries, and
    upsert them into the cisa_advisories table.
    Cross-references CVE IDs extracted from summaries and matches known
    threat group names.
    Returns {"added": int, "updated": int, "total": int}.
    """
    raw_bytes: Optional[bytes] = None
    used_url = None

    for feed_url in _CISA_ADVISORY_FEEDS:
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": "python-urllib/3.8", "Accept": "application/rss+xml, application/xml, text/xml"},
            )
            with urllib.request.urlopen(req, timeout=15, context=_get_ssl_context()) as resp:
                raw_bytes = resp.read()
            used_url = feed_url
            logger.info("Fetched CISA advisory feed from %s (%d bytes)", feed_url, len(raw_bytes))
            break
        except Exception as exc:
            logger.warning("CISA advisory feed %s failed: %s", feed_url, exc)

    if not raw_bytes:
        logger.warning("All CISA advisory feed URLs failed — skipping advisory sync")
        return {"added": 0, "updated": 0, "total": 0}

    entries = _parse_rss_feed(raw_bytes)
    if not entries:
        logger.warning("CISA advisory feed parsed 0 entries from %s", used_url)
        return {"added": 0, "updated": 0, "total": 0}

    # Pre-load all ThreatGroup names for cross-linking
    group_rows = db.query(ThreatGroup.id, ThreatGroup.name, ThreatGroup.aliases).all()
    # Build name+alias → id map (lowercase)
    group_name_map: Dict[str, int] = {}
    group_id_to_name: Dict[int, str] = {}
    for gid, gname, aliases in group_rows:
        group_name_map[gname.lower()] = gid
        group_id_to_name[gid] = gname
        for alias in (aliases or []):
            if alias:
                group_name_map[alias.lower()] = gid

    added = updated = 0

    for entry in entries:
        title = entry["title"]
        link = entry["link"]
        summary = entry["summary"]
        pub_date = _parse_pub_date(entry["pub_date"])

        # Derive a stable advisory_id
        advisory_id = _extract_advisory_id(title, link)
        if not advisory_id:
            # Fall back to URL slug + short hash to guarantee uniqueness
            slug = link.rstrip("/").split("/")[-1] if link else ""
            base = slug or title
            short_hash = hashlib.md5(f"{title}{link}".encode()).hexdigest()[:8]
            advisory_id = f"{base[:60]}-{short_hash}" if base else short_hash

        if not advisory_id:
            continue

        advisory_type = _detect_advisory_type(title, link)
        combined_text = f"{title} {summary}"
        cve_ids = sorted(set(c.upper() for c in _CVE_RE.findall(combined_text)))
        co_sealers = _extract_co_sealers(combined_text)
        sectors = _extract_sectors(combined_text)

        # Match threat groups mentioned by name in the advisory text
        matched_group_ids = []
        matched_group_names = []
        lower_text = combined_text.lower()
        for gname_lower, gid in group_name_map.items():
            if len(gname_lower) >= 4 and gname_lower in lower_text:
                if gid not in matched_group_ids:
                    matched_group_ids.append(gid)
                    matched_group_names.append(group_id_to_name[gid])

        existing = db.query(CisaAdvisory).filter(CisaAdvisory.advisory_id == advisory_id).first()
        if existing:
            # Update if anything changed
            changed = False
            if existing.title != title:
                existing.title = title; changed = True
            if pub_date and existing.pub_date != pub_date:
                existing.pub_date = pub_date; changed = True
            if summary and existing.summary != summary:
                existing.summary = summary; changed = True
            if cve_ids and existing.cve_ids != cve_ids:
                existing.cve_ids = cve_ids; changed = True
            if co_sealers and existing.co_sealers != co_sealers:
                existing.co_sealers = co_sealers; changed = True
            if sectors and existing.sectors != sectors:
                existing.sectors = sectors; changed = True
            if matched_group_ids and existing.threat_group_ids != matched_group_ids:
                existing.threat_group_ids = matched_group_ids
                existing.threat_group_names = matched_group_names
                changed = True
            if changed:
                existing.updated_at = datetime.utcnow()
                updated += 1
        else:
            record = CisaAdvisory(
                advisory_id=advisory_id,
                title=title,
                advisory_type=advisory_type,
                pub_date=pub_date,
                summary=summary,
                url=link,
                co_sealers=co_sealers,
                sectors=sectors,
                cve_ids=cve_ids,
                threat_group_ids=matched_group_ids,
                threat_group_names=matched_group_names,
                is_ics=(advisory_type in ("ics", "ics_medical")),
            )
            db.add(record)
            # Commit individually so one duplicate never rolls back the whole batch
            try:
                db.commit()
                added += 1
            except Exception as exc:
                logger.debug("Skipping duplicate advisory %s: %s", advisory_id, exc)
                db.rollback()
            continue

        # Commit updates in small groups
        try:
            db.commit()
        except Exception as exc:
            logger.warning("sync_cisa_advisories update commit failed: %s", exc)
            db.rollback()

    total = db.query(CisaAdvisory).count()
    logger.info("CISA advisories sync: +%d added, %d updated, %d total", added, updated, total)
    return {"added": added, "updated": updated, "total": total}


# ═══════════════════════════════════════════════════════════════════════
# endoflife.date — Product Lifecycle Data
# ═══════════════════════════════════════════════════════════════════════

_COMPONENT_TO_EOL_SLUG = {
    ".net": "dotnet",
    "dotnet": "dotnet",
    "asp.net core": "dotnet",
    ".net framework": "dotnet-framework",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "openssl": "openssl",
    "apache": "apache",
    "apache http server": "apache",
    "nginx": "nginx",
    "php": "php",
    "python": "python",
    "ruby": "ruby",
    "java": "java-se",
    "openjdk": "java-se",
    "jquery": "jquery",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "spring framework": "spring-framework",
    "spring boot": "spring-boot",
    "iis": "iis",
    "sql server": "mssqlserver",
    "windows server": "windows-server",
    "windows server 2016": "windows-server",
    "windows server 2019": "windows-server",
    "windows server 2022": "windows-server",
    "windows 10": "windows",
    "windows 11": "windows",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "red hat enterprise linux": "rhel",
    "rhel": "rhel",
    "vmware esxi": "esxi",
    "docker engine": "docker-engine",
    "kubernetes": "kubernetes",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "angular": "angular",
    "react": "react",
    "vue": "vue",
    "django": "django",
    "rails": "ruby-on-rails",
    "wordpress": "wordpress",
    "curl": "curl",
    "git": "git",
    "jenkins": "jenkins",
    "grafana": "grafana",
    "kong": "kong",
    "haproxy": "haproxy",
    "varnish": "varnish",
    "rabbitmq": "rabbitmq",
    "kafka": "kafka",
    "terraform": "terraform",
    "ansible": "ansible",
}


def _resolve_slug(component):
    """Map a component name (from scan/aggregation) to an endoflife.date slug."""
    if not component:
        return None
    import re
    c = component.lower().strip()
    # Strip common prefixes
    c = re.sub(r'^(microsoft|security updates? for)\s+', '', c)
    c = re.sub(r'\s+', ' ', c).strip()

    # Direct match
    if c in _COMPONENT_TO_EOL_SLUG:
        return _COMPONENT_TO_EOL_SLUG[c]

    # Try without trailing version/noise
    c_base = re.sub(r'\s*\d+(\.\d+)*\s*$', '', c).strip()
    if c_base in _COMPONENT_TO_EOL_SLUG:
        return _COMPONENT_TO_EOL_SLUG[c_base]

    # Partial match — check if any key is a substring
    for key, slug in _COMPONENT_TO_EOL_SLUG.items():
        if key in c or c in key:
            return slug

    return None


def fetch_endoflife_cycles(slug):
    """Fetch release cycles from endoflife.date API for a product slug."""
    import urllib.request
    url = "https://endoflife.date/api/%s.json" % slug
    try:
        ctx = _get_ssl_context()
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "hakuna/1.0",
        })
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            import json
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.debug("endoflife.date fetch failed for %s: %s", slug, e)
        return []


def _fetch_all_endoflife_products():
    """Fetch the full product catalog from endoflife.date."""
    url = "https://endoflife.date/api/all.json"
    try:
        ctx = _get_ssl_context()
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "hakuna/1.0",
        })
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        logger.warning("endoflife.date catalog fetch failed: %s", e)
        return []


def sync_product_lifecycles(db, scan_id=None):
    """
    Sync product lifecycle data from endoflife.date for ALL products
    in their catalog.

    Fetches the full product list from endoflife.date/api/all.json,
    then fetches release cycles for each product.
    """
    import time
    from models.threat_intel_models import ProductLifecycle

    # Fetch full product catalog
    all_slugs = _fetch_all_endoflife_products()
    if not all_slugs:
        logger.warning("endoflife.date sync: could not fetch product catalog")
        return {"products_synced": 0, "cycles_upserted": 0}

    logger.info("endoflife.date sync: found %d products in catalog", len(all_slugs))

    # Build slug → display_name map (prettify slug as display name)
    slug_map = {}
    for slug in all_slugs:
        if isinstance(slug, str) and slug.strip():
            display = slug.replace("-", " ").title()
            slug_map[slug.strip()] = display

    if not slug_map:
        logger.info("endoflife.date sync: no products to sync")
        return {"products_synced": 0, "cycles_upserted": 0}

    products_synced = 0
    cycles_upserted = 0

    total_slugs = len(slug_map)
    for idx, (slug, display_name) in enumerate(slug_map.items()):
        if idx % 50 == 0:
            logger.info("endoflife.date sync: %d/%d products...", idx, total_slugs)
        cycles = fetch_endoflife_cycles(slug)
        if not cycles:
            continue

        products_synced += 1

        for cycle_data in cycles:
            cycle = str(cycle_data.get("cycle", ""))
            if not cycle:
                continue

            # Parse EOL status
            eol_raw = cycle_data.get("eol", False)
            is_eol = False
            eol_str = str(eol_raw) if eol_raw is not None else ""
            if isinstance(eol_raw, bool):
                is_eol = eol_raw
            elif isinstance(eol_raw, str) and eol_raw not in ("", "false"):
                if eol_raw == "true":
                    is_eol = True
                else:
                    try:
                        from datetime import datetime as _dt
                        eol_date = _dt.strptime(eol_raw, "%Y-%m-%d")
                        is_eol = eol_date < _dt.utcnow()
                    except (ValueError, TypeError):
                        pass

            # Parse LTS
            lts_raw = cycle_data.get("lts", False)
            is_lts = lts_raw is True or lts_raw == "true"

            # Support end
            support_raw = cycle_data.get("support", "")
            support_str = str(support_raw) if support_raw not in (None, True, False) else ""

            # Upsert
            existing = (
                db.query(ProductLifecycle)
                .filter(ProductLifecycle.slug == slug, ProductLifecycle.cycle == cycle)
                .first()
            )
            if existing:
                existing.product_name = display_name
                existing.latest_version = str(cycle_data.get("latest", ""))
                existing.release_date = str(cycle_data.get("releaseDate", ""))
                existing.eol = eol_str
                existing.is_eol = is_eol
                existing.lts = is_lts
                existing.support_end = support_str
                existing.latest_release_date = str(cycle_data.get("latestReleaseDate", ""))
                existing.link = cycle_data.get("link", "")
                existing.raw_data = cycle_data
                existing.updated_at = datetime.utcnow()
            else:
                record = ProductLifecycle(
                    product_name=display_name,
                    slug=slug,
                    cycle=cycle,
                    latest_version=str(cycle_data.get("latest", "")),
                    release_date=str(cycle_data.get("releaseDate", "")),
                    eol=eol_str,
                    is_eol=is_eol,
                    lts=is_lts,
                    support_end=support_str,
                    latest_release_date=str(cycle_data.get("latestReleaseDate", "")),
                    link=cycle_data.get("link", ""),
                    raw_data=cycle_data,
                )
                db.add(record)
            cycles_upserted += 1

        try:
            db.commit()
        except Exception as e:
            logger.warning("endoflife.date commit failed for %s: %s", slug, e)
            db.rollback()

        time.sleep(0.1)  # be polite to community API

    logger.info("endoflife.date sync: %d products, %d cycles upserted", products_synced, cycles_upserted)
    return {"products_synced": products_synced, "cycles_upserted": cycles_upserted}


# ─────────────────────────────────────────────────────────────────────────────
# ExploitDB + Metasploit module sync
# ─────────────────────────────────────────────────────────────────────────────

_METASPLOIT_MODULES_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)
_EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)


def _fetch_json(url: str, timeout: int = 180) -> Optional[dict]:
    """Fetch JSON from a URL, return None on failure."""
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def _fetch_text(url: str) -> Optional[str]:
    """Fetch text content from a URL, return None on failure."""
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def sync_metasploit_modules_to_db(db) -> dict:
    """
    Fetch Metasploit module metadata and create ExploitReference records for CVE-mapped modules.
    """
    logger.info("Metasploit sync: fetching module metadata...")
    data = _fetch_json(_METASPLOIT_MODULES_URL)
    if not data:
        return {"added": 0, "skipped": 0}

    added = 0
    skipped = 0

    for module_key, meta in data.items():
        if not isinstance(meta, dict):
            continue
        references = meta.get("references", [])
        cve_ids = [r for r in references if r.startswith("CVE-")]
        if not cve_ids:
            skipped += 1
            continue

        mod_name = meta.get("name", module_key)
        mod_type = meta.get("mod_type", "exploit")
        mod_path = meta.get("fullname", module_key)
        platform_list = meta.get("platform", "")
        if isinstance(platform_list, list):
            platform_str = ",".join(platform_list)
        else:
            platform_str = str(platform_list)

        for cve_id in cve_ids:
            existing = (
                db.query(ExploitReference)
                .filter(
                    ExploitReference.cve_id == cve_id,
                    ExploitReference.source == "metasploit",
                    ExploitReference.source_id == mod_path,
                )
                .first()
            )
            if existing:
                skipped += 1
                continue

            record = ExploitReference(
                cve_id=cve_id,
                source="metasploit",
                source_id=mod_path,
                title=mod_name,
                description=meta.get("description", ""),
                url=f"https://github.com/rapid7/metasploit-framework/tree/master/modules/{mod_path}.rb",
                exploit_type=mod_type,
                platform=platform_str,
                verified=True,  # Metasploit modules are vetted
                maturity="functional",
                published_date=meta.get("disclosure_date", ""),
                raw_data=meta,
            )
            db.add(record)
            added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("Metasploit sync commit failed: %s", exc)
        db.rollback()

    # Update ThreatCVE exploit counts
    _update_exploit_counts(db)

    logger.info("Metasploit sync: %d added, %d skipped", added, skipped)
    return {"added": added, "skipped": skipped}


def sync_exploitdb_to_db(db) -> dict:
    """
    Fetch ExploitDB CSV index and create ExploitReference records for CVE-mapped exploits.
    """
    logger.info("ExploitDB sync: fetching exploit index...")
    csv_text = _fetch_text(_EXPLOITDB_CSV_URL)
    if not csv_text:
        return {"added": 0, "skipped": 0}

    import csv
    import io

    reader = csv.DictReader(io.StringIO(csv_text))
    added = 0
    skipped = 0

    for row in reader:
        codes_raw = row.get("codes", "")
        if not codes_raw:
            skipped += 1
            continue

        cve_ids = [c.strip() for c in codes_raw.split(";") if c.strip().startswith("CVE-")]
        if not cve_ids:
            skipped += 1
            continue

        edb_id = row.get("id", "").strip()
        if not edb_id:
            skipped += 1
            continue

        title = row.get("description", "")
        platform = row.get("platform", "")
        exploit_type = row.get("type", "")
        verified = row.get("verified", "0") == "1"
        date_published = row.get("date_published", "")

        for cve_id in cve_ids:
            existing = (
                db.query(ExploitReference)
                .filter(
                    ExploitReference.cve_id == cve_id,
                    ExploitReference.source == "exploitdb",
                    ExploitReference.source_id == edb_id,
                )
                .first()
            )
            if existing:
                skipped += 1
                continue

            record = ExploitReference(
                cve_id=cve_id,
                source="exploitdb",
                source_id=edb_id,
                title=title,
                url=f"https://www.exploit-db.com/exploits/{edb_id}",
                exploit_type=exploit_type,
                platform=platform,
                verified=verified,
                maturity="poc" if not verified else "functional",
                published_date=date_published,
            )
            db.add(record)
            added += 1

        # Commit in batches of 500
        if added > 0 and added % 500 == 0:
            try:
                db.commit()
            except Exception as exc:
                logger.warning("ExploitDB batch commit failed: %s", exc)
                db.rollback()

    try:
        db.commit()
    except Exception as exc:
        logger.warning("ExploitDB final commit failed: %s", exc)
        db.rollback()

    _update_exploit_counts(db)

    logger.info("ExploitDB sync: %d added, %d skipped", added, skipped)
    return {"added": added, "skipped": skipped}


def _update_exploit_counts(db):
    """
    Update ThreatCVE records with aggregated exploit counts and maturity from ExploitReference table.
    """
    from sqlalchemy import func as sa_func

    # Aggregate per CVE: count, sources, best maturity
    exploit_data = (
        db.query(
            ExploitReference.cve_id,
            sa_func.count(ExploitReference.id),
            sa_func.group_concat(ExploitReference.source.distinct()),
        )
        .group_by(ExploitReference.cve_id)
        .all()
    )

    maturity_order = {"weaponized": 4, "functional": 3, "poc": 2, "none": 1}

    for cve_id, count, sources_str in exploit_data:
        tc = db.query(ThreatCVE).filter(ThreatCVE.cve_id == cve_id).first()
        if not tc:
            continue

        sources = list(set(sources_str.split(","))) if sources_str else []
        tc.exploit_count = count
        tc.exploit_sources = sources
        tc.has_public_exploit = True

        # Determine best maturity across all exploits for this CVE
        best_maturity = "poc"
        exploit_records = db.query(ExploitReference.maturity).filter(ExploitReference.cve_id == cve_id).all()
        for (mat,) in exploit_records:
            if mat and maturity_order.get(mat, 0) > maturity_order.get(best_maturity, 0):
                best_maturity = mat
        tc.exploit_maturity_level = best_maturity

    try:
        db.commit()
    except Exception as exc:
        logger.warning("Exploit count update commit failed: %s", exc)
        db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# CISA SSVC (Vulnrichment) sync
# ─────────────────────────────────────────────────────────────────────────────

_VULNRICHMENT_ZIP_URL = (
    "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"
)


# CISA SSVC v2.0.3 decision tree lookup.
# Maps (Exploitation, Automatable, Technical Impact) → decision.
# See https://www.cisa.gov/ssvc
_SSVC_DECISION_TREE = {
    # Exploitation: active
    ("active", "yes", "total"):   "Act",
    ("active", "yes", "partial"): "Act",
    ("active", "no",  "total"):   "Act",
    ("active", "no",  "partial"): "Attend",
    # Exploitation: poc
    ("poc", "yes", "total"):   "Attend",
    ("poc", "yes", "partial"): "Attend",
    ("poc", "no",  "total"):   "Track*",
    ("poc", "no",  "partial"): "Track*",
    # Exploitation: none
    ("none", "yes", "total"):   "Track*",
    ("none", "yes", "partial"): "Track",
    ("none", "no",  "total"):   "Track",
    ("none", "no",  "partial"): "Track",
}


def _derive_ssvc_decision(exploitation: str, automatable: str, technical_impact: str) -> str:
    """Derive the SSVC decision from the three decision point values."""
    key = (exploitation.lower().strip(), automatable.lower().strip(), technical_impact.lower().strip())
    return _SSVC_DECISION_TREE.get(key, "")


def _parse_ssvc_from_cve_json(cve_data: dict) -> Optional[dict]:
    """
    Extract SSVC decision from a single vulnrichment CVE JSON file.
    The content.options[] format is: [{"Exploitation": "none"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]
    The decision (Act/Attend/Track*/Track) is derived from the SSVC v2.0.3 decision tree.
    """
    # The CVE ID is in the top-level cveMetadata or at root
    cve_metadata = cve_data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId", cve_data.get("cveId", ""))
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    # SSVC data is in containers.adp[] entries from CISA
    containers = cve_data.get("containers", {})
    adp_list = containers.get("adp", [])
    if not isinstance(adp_list, list):
        adp_list = [adp_list]

    for adp in adp_list:
        if not isinstance(adp, dict):
            continue
        provider = adp.get("providerMetadata", {}).get("shortName", "")
        if provider.upper() not in ("CISA-ADP", "CISA", ""):
            continue

        metrics = adp.get("metrics", [])
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            other = metric.get("other", {})
            if not isinstance(other, dict):
                continue
            if other.get("type", "").lower() != "ssvc":
                continue

            content = other.get("content", {})
            options = content.get("options", [])
            exploitation_val = ""
            automatable_val = ""
            tech_impact_val = ""
            timestamp = content.get("timestamp", adp.get("dateUpdated", ""))

            # Parse options: each is a single-key dict like {"Exploitation": "none"}
            for opt in options:
                if not isinstance(opt, dict):
                    continue
                for key, value in opt.items():
                    key_lower = key.lower().replace(" ", "").replace("_", "")
                    if key_lower == "exploitation":
                        exploitation_val = value
                    elif key_lower == "automatable":
                        automatable_val = value
                    elif key_lower in ("technicalimpact", "impact"):
                        tech_impact_val = value

            if not exploitation_val or not automatable_val or not tech_impact_val:
                continue

            decision_val = _derive_ssvc_decision(exploitation_val, automatable_val, tech_impact_val)
            if not decision_val:
                continue

            return {
                "cve_id": cve_id,
                "decision": decision_val,
                "exploitation": exploitation_val,
                "automatable": automatable_val,
                "technical_impact": tech_impact_val,
                "timestamp": timestamp,
            }

    return None


def sync_ssvc_decisions_to_db(db) -> dict:
    """
    Download the CISA vulnrichment repository and extract SSVC decisions
    from per-CVE JSON files.
    """
    import zipfile
    import io
    import tempfile

    logger.info("SSVC sync: downloading CISA vulnrichment repository...")
    ctx = _get_ssl_context()
    req = urllib.request.Request(_VULNRICHMENT_ZIP_URL, headers={"User-Agent": _USER_AGENT})
    # Stream to a temp file to avoid loading 240MB into RAM all at once
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
            total = 0
            while True:
                chunk = resp.read(1 << 20)  # 1 MiB at a time
                if not chunk:
                    break
                tmp.write(chunk)
                total += len(chunk)
        tmp.flush()
        tmp.close()
    except Exception as exc:
        logger.warning("SSVC sync: failed to download vulnrichment repo: %s", exc)
        return {"added": 0, "updated": 0}

    logger.info("SSVC sync: downloaded %d bytes, extracting...", total)

    try:
        zf = zipfile.ZipFile(tmp.name)
    except Exception as exc:
        logger.warning("SSVC sync: failed to open zip: %s", exc)
        os.unlink(tmp.name)
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0
    parsed = 0

    for name in zf.namelist():
        # Only process CVE JSON files (e.g. vulnrichment-develop/2024/0xxx/CVE-2024-0001.json)
        if not name.endswith(".json") or "/CVE-" not in name:
            continue

        try:
            raw = zf.read(name)
            cve_data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            continue

        result = _parse_ssvc_from_cve_json(cve_data)
        if not result:
            continue

        parsed += 1
        cve_id = result["cve_id"]

        existing = db.query(SSVCDecision).filter(SSVCDecision.cve_id == cve_id).first()
        if existing:
            existing.decision = result["decision"]
            existing.exploitation = result["exploitation"]
            existing.automatable = result["automatable"]
            existing.technical_impact = result["technical_impact"]
            existing.timestamp = result["timestamp"]
            existing.updated_at = datetime.utcnow()
            updated += 1
        else:
            record = SSVCDecision(
                cve_id=cve_id,
                decision=result["decision"],
                exploitation=result["exploitation"],
                automatable=result["automatable"],
                technical_impact=result["technical_impact"],
                provider="CISA",
                timestamp=result["timestamp"],
            )
            db.add(record)
            added += 1

        # Commit in batches
        if (added + updated) % 500 == 0:
            try:
                db.commit()
            except Exception as exc:
                logger.warning("SSVC batch commit failed: %s", exc)
                db.rollback()

    zf.close()
    try:
        os.unlink(tmp.name)
    except Exception:
        pass

    try:
        db.commit()
    except Exception as exc:
        logger.warning("SSVC sync commit failed: %s", exc)
        db.rollback()

    # Update ThreatCVE records with SSVC data — bulk fetch to avoid N individual queries
    all_ssvc = db.query(SSVCDecision).all()
    ssvc_by_cve = {s.cve_id: s for s in all_ssvc}
    threat_cves = (
        db.query(ThreatCVE)
        .filter(ThreatCVE.cve_id.in_(ssvc_by_cve.keys()))
        .all()
    )
    for tc in threat_cves:
        s = ssvc_by_cve[tc.cve_id]
        tc.ssvc_decision = s.decision
        tc.ssvc_exploitation = s.exploitation

    try:
        db.commit()
    except Exception as exc:
        logger.warning("SSVC → ThreatCVE update commit failed: %s", exc)
        db.rollback()

    logger.info("SSVC sync: %d parsed, %d added, %d updated", parsed, added, updated)
    return {"added": added, "updated": updated}


# ─────────────────────────────────────────────────────────────────────────────
# CWE full catalog sync
# ─────────────────────────────────────────────────────────────────────────────

_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# Top-level CWE category mapping for common weakness families
_CWE_CATEGORY_MAP = {
    "injection": ["CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-95", "CWE-96"],
    "authentication": ["CWE-287", "CWE-288", "CWE-289", "CWE-290", "CWE-294", "CWE-295", "CWE-306", "CWE-307"],
    "authorization": ["CWE-269", "CWE-276", "CWE-281", "CWE-284", "CWE-285", "CWE-732", "CWE-862", "CWE-863"],
    "cryptography": ["CWE-310", "CWE-311", "CWE-312", "CWE-319", "CWE-320", "CWE-326", "CWE-327", "CWE-328", "CWE-330"],
    "memory_safety": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-127", "CWE-131", "CWE-787"],
    "input_validation": ["CWE-20", "CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"],
    "information_disclosure": ["CWE-200", "CWE-201", "CWE-203", "CWE-209", "CWE-532"],
    "configuration": ["CWE-16", "CWE-250", "CWE-732"],
    "race_condition": ["CWE-362", "CWE-364", "CWE-366", "CWE-367"],
    "resource_management": ["CWE-400", "CWE-401", "CWE-404", "CWE-770", "CWE-771"],
}

# Build reverse map: CWE-ID → category
_CWE_ID_TO_CATEGORY = {}
for cat, cwe_ids in _CWE_CATEGORY_MAP.items():
    for cid in cwe_ids:
        _CWE_ID_TO_CATEGORY[cid] = cat


def sync_cwe_catalog_to_db(db) -> dict:
    """
    Fetch the full CWE XML catalog and upsert CWEEntry records.
    """
    import zipfile
    import io

    logger.info("CWE sync: fetching catalog from MITRE...")
    ctx = _get_ssl_context()
    req = urllib.request.Request(_CWE_URL, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            zip_bytes = resp.read()
    except Exception as exc:
        logger.warning("CWE sync: failed to download: %s", exc)
        return {"added": 0, "updated": 0}

    # Extract XML from zip
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
            if not xml_names:
                logger.warning("CWE sync: no XML file in zip")
                return {"added": 0, "updated": 0}
            xml_content = zf.read(xml_names[0])
    except Exception as exc:
        logger.warning("CWE sync: failed to extract zip: %s", exc)
        return {"added": 0, "updated": 0}

    # Parse XML
    try:
        root = ET.fromstring(xml_content)
    except Exception as exc:
        logger.warning("CWE sync: failed to parse XML: %s", exc)
        return {"added": 0, "updated": 0}

    # CWE XML uses namespaces
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    weaknesses = root.findall(f".//{ns}Weaknesses/{ns}Weakness") or root.findall(f".//{ns}Weakness")

    added = 0
    updated = 0

    for w in weaknesses:
        cwe_num = w.get("ID", "")
        if not cwe_num:
            continue
        cwe_id = f"CWE-{cwe_num}"
        name = w.get("Name", "")
        weakness_type = w.get("Abstraction", "")
        status = w.get("Status", "")

        # Description
        desc_el = w.find(f"{ns}Description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""

        ext_desc_el = w.find(f"{ns}Extended_Description")
        extended_desc = ""
        if ext_desc_el is not None:
            # May contain mixed content (p, ul, etc.) — extract all text
            extended_desc = "".join(ext_desc_el.itertext()).strip()

        # Parent CWE IDs (ChildOf relationships)
        parent_ids = []
        for rel in w.findall(f".//{ns}Related_Weakness"):
            if rel.get("Nature") == "ChildOf":
                parent_ids.append(f"CWE-{rel.get('CWE_ID', '')}")

        # Child CWE IDs (ParentOf relationships)
        child_ids = []
        for rel in w.findall(f".//{ns}Related_Weakness"):
            if rel.get("Nature") == "ParentOf":
                child_ids.append(f"CWE-{rel.get('CWE_ID', '')}")

        # Related attack patterns (CAPEC)
        capec_ids = []
        for rap in w.findall(f".//{ns}Related_Attack_Pattern"):
            capec_id = rap.get("CAPEC_ID", "")
            if capec_id:
                capec_ids.append(f"CAPEC-{capec_id}")

        # Applicable platforms
        platforms = []
        for lang in w.findall(f".//{ns}Applicable_Platforms/{ns}Language"):
            pname = lang.get("Name") or lang.get("Class", "")
            if pname:
                platforms.append(pname)

        # Common consequences
        consequences = []
        for conseq in w.findall(f".//{ns}Common_Consequences/{ns}Consequence"):
            scope_el = conseq.find(f"{ns}Scope")
            impact_el = conseq.find(f"{ns}Impact")
            consequences.append({
                "scope": scope_el.text.strip() if scope_el is not None and scope_el.text else "",
                "impact": impact_el.text.strip() if impact_el is not None and impact_el.text else "",
            })

        # Mitigations
        mitigations = []
        for mit in w.findall(f".//{ns}Potential_Mitigations/{ns}Mitigation"):
            phase_el = mit.find(f"{ns}Phase")
            desc_mit_el = mit.find(f"{ns}Description")
            mitigations.append({
                "phase": phase_el.text.strip() if phase_el is not None and phase_el.text else "",
                "description": "".join(desc_mit_el.itertext()).strip() if desc_mit_el is not None else "",
            })

        # Detection methods
        detections = []
        for det in w.findall(f".//{ns}Detection_Methods/{ns}Detection_Method"):
            method_el = det.find(f"{ns}Method")
            det_desc_el = det.find(f"{ns}Description")
            detections.append({
                "method": method_el.text.strip() if method_el is not None and method_el.text else "",
                "description": "".join(det_desc_el.itertext()).strip() if det_desc_el is not None else "",
            })

        # Category from our mapping
        category = _CWE_ID_TO_CATEGORY.get(cwe_id, "")
        if not category and parent_ids:
            for pid in parent_ids:
                cat = _CWE_ID_TO_CATEGORY.get(pid, "")
                if cat:
                    category = cat
                    break

        existing = db.query(CWEEntry).filter(CWEEntry.cwe_id == cwe_id).first()
        if existing:
            existing.name = name
            existing.description = description
            existing.extended_description = extended_desc
            existing.weakness_type = weakness_type
            existing.status = status
            existing.parent_cwe_ids = parent_ids
            existing.child_cwe_ids = child_ids
            existing.related_attack_patterns = capec_ids
            existing.applicable_platforms = platforms
            existing.common_consequences = consequences[:10]
            existing.detection_methods = detections[:5]
            existing.mitigations = mitigations[:10]
            existing.category = category
            existing.url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            existing.updated_at = datetime.utcnow()
            updated += 1
        else:
            record = CWEEntry(
                cwe_id=cwe_id,
                name=name,
                description=description,
                extended_description=extended_desc,
                weakness_type=weakness_type,
                status=status,
                parent_cwe_ids=parent_ids,
                child_cwe_ids=child_ids,
                related_attack_patterns=capec_ids,
                applicable_platforms=platforms,
                common_consequences=consequences[:10],
                detection_methods=detections[:5],
                mitigations=mitigations[:10],
                category=category,
                url=f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
            )
            db.add(record)
            added += 1

        # Commit in batches
        if (added + updated) % 200 == 0:
            try:
                db.commit()
            except Exception as exc:
                logger.warning("CWE batch commit failed: %s", exc)
                db.rollback()

    try:
        db.commit()
    except Exception as exc:
        logger.warning("CWE final commit failed: %s", exc)
        db.rollback()

    # Resolve CWE names on ThreatCVE records
    _resolve_cwe_names(db)

    logger.info("CWE sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


def _resolve_cwe_names(db):
    """Resolve CWE IDs on ThreatCVE records to names and categories from CWEEntry."""
    cwe_lookup = {r.cwe_id: r for r in db.query(CWEEntry).all()}
    if not cwe_lookup:
        return

    threat_cves = db.query(ThreatCVE).filter(ThreatCVE.cwe_ids.isnot(None)).all()
    for tc in threat_cves:
        if not tc.cwe_ids:
            continue
        names = []
        categories = set()
        for cid in tc.cwe_ids:
            cwe = cwe_lookup.get(cid)
            if cwe:
                names.append(f"{cid}: {cwe.name}")
                if cwe.category:
                    categories.add(cwe.category)
        tc.cwe_names = names
        tc.cwe_categories = sorted(categories)

    try:
        db.commit()
    except Exception as exc:
        logger.warning("CWE name resolution commit failed: %s", exc)
        db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# MSRC Patch Tuesday sync
# ─────────────────────────────────────────────────────────────────────────────

_MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"


def _fetch_msrc_document(doc_id: str) -> Optional[dict]:
    """Fetch a single MSRC CVRF document as JSON."""
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{doc_id}"
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("MSRC fetch doc %s failed: %s", doc_id, exc)
        return None


def sync_msrc_patches_to_db(db, months: int = 3) -> dict:
    """
    Fetch recent MSRC Patch Tuesday releases and extract CVE-to-KB mappings.
    Only fetches the last `months` documents to stay fast.
    """
    import time

    logger.info("MSRC sync: fetching Patch Tuesday updates index...")
    ctx = _get_ssl_context()
    req = urllib.request.Request(_MSRC_UPDATES_URL, headers={
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            updates = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("MSRC sync: failed to fetch updates index: %s", exc)
        return {"added": 0, "documents_processed": 0}

    # Get document IDs (e.g. "2025-Mar", "2025-Feb")
    docs = updates.get("value", [])
    if not docs:
        return {"added": 0, "documents_processed": 0}

    # Sort by date descending and take last N months
    docs.sort(key=lambda d: d.get("InitialReleaseDate", ""), reverse=True)
    recent_docs = docs[:months]

    added = 0
    documents_processed = 0
    seen_keys = set()  # Track (cve_id, kb_id, product_id) to avoid in-session duplicates

    for doc_meta in recent_docs:
        doc_id = doc_meta.get("ID", "")
        if not doc_id:
            continue

        cvrf = _fetch_msrc_document(doc_id)
        if not cvrf:
            continue

        documents_processed += 1
        release_date = doc_meta.get("InitialReleaseDate", "")[:10]

        # Build product name lookup from ProductTree (recursive traversal)
        product_name_map = {}
        product_tree = cvrf.get("ProductTree", {})

        def _walk_branches(branches):
            for branch in branches:
                if not isinstance(branch, dict):
                    continue
                # Leaf nodes with ProductID
                pid = branch.get("ProductID")
                if pid:
                    product_name_map[pid] = branch.get("Value", "")
                # Recurse into nested Items/Branch
                for key in ("Items", "Branch"):
                    children = branch.get(key, [])
                    if isinstance(children, list):
                        _walk_branches(children)

        _walk_branches(product_tree.get("Branch", []))
        # Also check FullProductName at top level
        for fpn in product_tree.get("FullProductName", []):
            if isinstance(fpn, dict) and fpn.get("ProductID"):
                product_name_map[fpn["ProductID"]] = fpn.get("Value", "")

        # Build per-product severity/impact lookup from Threats
        # Threats can be scoped to specific ProductIDs
        vulns = cvrf.get("Vulnerability", [])
        for vuln in vulns:
            cve_id = vuln.get("CVE", "")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            title = vuln.get("Title", {}).get("Value", "")

            # Pre-build severity/impact maps: product_id -> value
            severity_map = {}  # product_id -> severity
            impact_map = {}    # product_id -> impact
            default_severity = ""
            default_impact = ""
            for threat in vuln.get("Threats", []):
                ttype = threat.get("Type")
                desc_val = threat.get("Description", {}).get("Value", "")
                threat_product_ids = threat.get("ProductID", [])
                if isinstance(threat_product_ids, str):
                    threat_product_ids = [threat_product_ids]
                if ttype == 3:  # Severity
                    if threat_product_ids:
                        for tpid in threat_product_ids:
                            severity_map[tpid] = desc_val
                    else:
                        default_severity = desc_val
                elif ttype == 0:  # Impact
                    if threat_product_ids:
                        for tpid in threat_product_ids:
                            impact_map[tpid] = desc_val
                    else:
                        default_impact = desc_val

            # Extract KB articles from Remediations
            remediations = vuln.get("Remediations", [])
            for rem in remediations:
                if rem.get("Type") != 2:  # Type 2 = Vendor Fix
                    continue

                kb_raw = rem.get("Description", {}).get("Value", "")
                # KB numbers are numeric strings
                kb_id = f"KB{kb_raw}" if kb_raw and kb_raw.isdigit() else kb_raw

                product_id = ""
                product_ids = rem.get("ProductID", [])
                if product_ids:
                    product_id = product_ids[0] if isinstance(product_ids, list) else str(product_ids)

                product_name = product_name_map.get(product_id, "")

                url = rem.get("URL", "")
                supercedence = rem.get("Supercedence", "")
                restart = rem.get("RestartRequired", {}).get("Value", "")

                # Use per-product severity/impact, falling back to defaults
                severity = severity_map.get(product_id, default_severity)
                impact = impact_map.get(product_id, default_impact)

                if not kb_id:
                    continue

                dedup_key = (cve_id, kb_id, product_id)
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                existing = (
                    db.query(MSRCPatch)
                    .filter(
                        MSRCPatch.cve_id == cve_id,
                        MSRCPatch.kb_id == kb_id,
                        MSRCPatch.product_id == product_id,
                    )
                    .first()
                )
                if existing:
                    existing.severity = severity
                    existing.impact = impact
                    existing.supercedence = supercedence
                    existing.restart_required = restart
                    existing.article_url = url
                    existing.release_date = release_date
                    existing.updated_at = datetime.utcnow()
                else:
                    record = MSRCPatch(
                        cve_id=cve_id,
                        kb_id=kb_id,
                        product_name=product_name,
                        product_id=product_id,
                        article_url=url,
                        severity=severity,
                        impact=impact,
                        supercedence=supercedence,
                        restart_required=restart,
                        release_date=release_date,
                    )
                    db.add(record)
                    added += 1

        try:
            db.commit()
        except Exception as exc:
            logger.warning("MSRC commit failed for doc %s: %s", doc_id, exc)
            db.rollback()

        time.sleep(1.0)  # Be polite to MSRC API

    # Update ThreatCVE with KB IDs
    _update_msrc_kb_ids(db)

    logger.info("MSRC sync: %d patches added from %d documents", added, documents_processed)
    return {"added": added, "documents_processed": documents_processed}


def _update_msrc_kb_ids(db):
    """Aggregate KB IDs from MSRCPatch into ThreatCVE.msrc_kb_ids."""
    from sqlalchemy import func as sa_func

    kb_data = (
        db.query(MSRCPatch.cve_id, sa_func.group_concat(MSRCPatch.kb_id.distinct()))
        .group_by(MSRCPatch.cve_id)
        .all()
    )

    for cve_id, kb_str in kb_data:
        tc = db.query(ThreatCVE).filter(ThreatCVE.cve_id == cve_id).first()
        if tc and kb_str:
            tc.msrc_kb_ids = list(set(kb_str.split(",")))

    try:
        db.commit()
    except Exception as exc:
        logger.warning("MSRC KB ID update commit failed: %s", exc)
        db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# Extended finding enrichment (adds new intel fields)
# ─────────────────────────────────────────────────────────────────────────────

def enrich_findings_extended(db, scan_id: int = None) -> dict:
    """
    Enrich findings with new intel data: exploit_count, exploit_maturity_level,
    ssvc_decision. Called after the core enrichment.
    """
    all_threat_cves = db.query(ThreatCVE).all()
    if not all_threat_cves:
        return {"enriched": 0}

    cve_lookup: Dict[str, ThreatCVE] = {r.cve_id: r for r in all_threat_cves}

    fq = db.query(Finding).filter(Finding.cves.isnot(None))
    if scan_id is not None:
        fq = fq.filter(Finding.scan_id == scan_id)
    findings = fq.all()

    enriched = 0

    for f in findings:
        if not f.cves:
            continue

        best_exploit_count = 0
        best_exploit_maturity = None
        best_ssvc = None

        maturity_order = {"weaponized": 4, "functional": 3, "poc": 2, "none": 1}
        ssvc_order = {"Act": 4, "Attend": 3, "Track*": 2, "Track": 1}

        for cve_id in f.cves:
            tc = cve_lookup.get(cve_id.strip() if cve_id else None)
            if not tc:
                continue

            if tc.exploit_count and tc.exploit_count > best_exploit_count:
                best_exploit_count = tc.exploit_count

            if tc.exploit_maturity_level:
                if best_exploit_maturity is None or maturity_order.get(tc.exploit_maturity_level, 0) > maturity_order.get(best_exploit_maturity, 0):
                    best_exploit_maturity = tc.exploit_maturity_level

            if tc.ssvc_decision:
                if best_ssvc is None or ssvc_order.get(tc.ssvc_decision, 0) > ssvc_order.get(best_ssvc, 0):
                    best_ssvc = tc.ssvc_decision

        changed = False
        if best_exploit_count and f.exploit_count != best_exploit_count:
            f.exploit_count = best_exploit_count
            changed = True
        if best_exploit_maturity and f.exploit_maturity_level != best_exploit_maturity:
            f.exploit_maturity_level = best_exploit_maturity
            changed = True
        if best_ssvc and f.ssvc_decision != best_ssvc:
            f.ssvc_decision = best_ssvc
            changed = True

        if changed:
            enriched += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("Extended enrichment commit failed: %s", exc)
        db.rollback()

    logger.info("Extended finding enrichment: %d enriched", enriched)
    return {"enriched": enriched}


# ─────────────────────────────────────────────────────────────────────────────
# Patch Catalog Aggregator — multi-source advisory sync
# ─────────────────────────────────────────────────────────────────────────────

def _load_patch_config() -> dict:
    """Load patch catalog configuration."""
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "patch_config.json")
    try:
        with open(config_path) as f:
            return json.load(f)
    except Exception:
        return {"enabled": True, "sources": {}, "max_advisory_age_days": 365}


def _normalize_severity(raw: str) -> str:
    """Normalize severity values to the Hakuna standard: critical/important/moderate/low."""
    mapping = {
        "critical": "critical",
        "high": "important",
        "important": "important",
        "medium": "moderate",
        "moderate": "moderate",
        "low": "low",
        "negligible": "low",
        "unimportant": "low",
        "not yet assigned": "moderate",
    }
    return mapping.get((raw or "").lower().strip("*"), "moderate")


def _upsert_patch_advisory(db, source: str, source_advisory_id: str, **kwargs) -> bool:
    """Upsert a PatchAdvisory record. Returns True if a new record was created."""
    # Always normalize severity to Hakuna standard (critical/important/moderate/low)
    if "severity" in kwargs and kwargs["severity"] is not None:
        kwargs["severity"] = _normalize_severity(kwargs["severity"])
    existing = (
        db.query(PatchAdvisory)
        .filter(PatchAdvisory.source == source, PatchAdvisory.source_advisory_id == source_advisory_id)
        .first()
    )
    if existing:
        for key, value in kwargs.items():
            if value is not None:
                setattr(existing, key, value)
        existing.updated_at = datetime.utcnow()
        return False
    else:
        record = PatchAdvisory(
            source=source,
            source_advisory_id=source_advisory_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            **{k: v for k, v in kwargs.items() if v is not None},
        )
        db.add(record)
        return True


def _fetch_json(url: str, timeout: int = 30) -> Optional[dict]:
    """Fetch JSON from a URL with SSL and User-Agent handling."""
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def _fetch_text(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch text/XML from a URL."""
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


def _fetch_gzip_text(url: str, timeout: int = 60) -> Optional[str]:
    """Fetch gzip-compressed text."""
    import gzip
    ctx = _get_ssl_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read()
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Failed to fetch gzip %s: %s", url, exc)
        return None


# ── Ubuntu USN ────────────────────────────────────────────────────────────────

def sync_ubuntu_usn_to_db(db) -> dict:
    """
    Fetch Ubuntu Security Notices from the USN database JSON.
    Returns {"added": int, "updated": int}.
    """
    url = "https://ubuntu.com/security/notices.json"
    # Try the structured JSON endpoint first, fall back to RSS
    data = _fetch_json(url, timeout=60)
    added = 0
    updated = 0

    if data and isinstance(data, dict):
        notices = data.get("notices", [])
        if isinstance(data, list):
            notices = data
    else:
        # Fallback: parse RSS feed
        notices = _parse_ubuntu_rss()

    for notice in notices:
        if isinstance(notice, dict):
            usn_id = notice.get("id", "") or notice.get("notice_id", "")
            if not usn_id:
                continue
            # Normalize to USN-XXXX-X format
            if not usn_id.startswith("USN-"):
                usn_id = f"USN-{usn_id}"

            title = notice.get("title", "") or notice.get("description", "")
            cve_ids = notice.get("cves", [])
            if isinstance(cve_ids, list):
                cve_ids = [c if isinstance(c, str) else c.get("id", "") for c in cve_ids]
                cve_ids = [c for c in cve_ids if c.startswith("CVE-")]

            release_date = notice.get("published", "") or notice.get("date", "")
            description = notice.get("description", "") or notice.get("summary", "")

            # Extract affected packages
            packages = []
            release_packages = notice.get("release_packages", {})
            if isinstance(release_packages, dict):
                for release_name, pkgs in release_packages.items():
                    if isinstance(pkgs, list):
                        for pkg in pkgs:
                            if isinstance(pkg, dict):
                                packages.append({
                                    "name": pkg.get("name", ""),
                                    "version_fixed": pkg.get("version", ""),
                                    "release": release_name,
                                    "arch": pkg.get("arch", ""),
                                })

            severity = notice.get("priority", "medium")

            is_new = _upsert_patch_advisory(
                db, source="ubuntu", source_advisory_id=usn_id,
                title=title[:500] if title else None,
                description=description[:2000] if description else None,
                severity=severity,
                release_date=release_date[:10] if release_date else None,
                advisory_url=f"https://ubuntu.com/security/notices/{usn_id}",
                affected_packages=packages,
                cve_ids=cve_ids,
                raw_data=notice,
            )
            if is_new:
                added += 1
            else:
                updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_ubuntu_usn_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Ubuntu USN sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


def _parse_ubuntu_rss() -> list:
    """Parse Ubuntu Security Notices RSS feed as fallback."""
    xml_text = _fetch_text("https://ubuntu.com/security/notices/rss.xml", timeout=30)
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    notices = []
    for item in root.iter("item"):
        title = item.findtext("title", "")
        link = item.findtext("link", "")
        pub_date = item.findtext("pubDate", "")
        description = item.findtext("description", "")
        # Extract USN ID from link
        usn_id = ""
        if "/notices/" in link:
            usn_id = link.rsplit("/notices/", 1)[-1].strip("/")

        # Extract CVEs from description
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", description + " " + title)

        notices.append({
            "id": usn_id,
            "title": title,
            "description": description,
            "published": pub_date,
            "cves": list(set(cve_ids)),
        })
    return notices


# ── Debian Security Tracker ───────────────────────────────────────────────────

def sync_debian_dsa_to_db(db) -> dict:
    """
    Fetch Debian Security Tracker JSON and upsert patch advisories.
    The JSON is keyed by package name, each containing CVE → release status mappings.
    Returns {"added": int, "updated": int}.
    """
    url = "https://security-tracker.debian.org/tracker/data/json"
    data = _fetch_json(url, timeout=120)
    if not data or not isinstance(data, dict):
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0

    # Debian JSON structure: {package_name: {CVE-ID: {releases: {release: {status, fixed_version}}}}}
    # We invert this to create per-CVE advisories grouped by package
    cve_package_map: Dict[str, list] = {}

    for pkg_name, cve_dict in data.items():
        if not isinstance(cve_dict, dict):
            continue
        for cve_id, info in cve_dict.items():
            if not cve_id.startswith("CVE-"):
                continue
            releases = info.get("releases", {})
            if not isinstance(releases, dict):
                continue
            for release_name, release_info in releases.items():
                if not isinstance(release_info, dict):
                    continue
                status = release_info.get("status", "")
                fixed_version = release_info.get("fixed_version", "")
                urgency = release_info.get("urgency", "")

                if status == "resolved" and fixed_version:
                    if cve_id not in cve_package_map:
                        cve_package_map[cve_id] = []
                    cve_package_map[cve_id].append({
                        "name": pkg_name,
                        "version_fixed": fixed_version,
                        "release": release_name,
                        "urgency": urgency,
                    })

    # Create one advisory per CVE (Debian doesn't have advisory IDs like DSA for all)
    for cve_id, packages in cve_package_map.items():
        advisory_id = f"DEB-{cve_id}"
        severity = _debian_urgency_to_severity(packages[0].get("urgency", "")) if packages else "medium"

        is_new = _upsert_patch_advisory(
            db, source="debian", source_advisory_id=advisory_id,
            title=f"Debian fix for {cve_id}",
            severity=severity,
            advisory_url=f"https://security-tracker.debian.org/tracker/{cve_id}",
            affected_packages=packages,
            cve_ids=[cve_id],
        )
        if is_new:
            added += 1
        else:
            updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_debian_dsa_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Debian sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


def _debian_urgency_to_severity(urgency: str) -> str:
    """Map Debian urgency to normalized severity."""
    return _normalize_severity(urgency)


# ── RHEL / CentOS ────────────────────────────────────────────────────────────

def sync_rhel_cves_to_db(db) -> dict:
    """
    Fetch RHEL security data from Red Hat Security Data API.
    Returns {"added": int, "updated": int}.
    """
    import time

    # Fetch recent CVEs (paginated, last 90 days by default)
    base_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    added = 0
    updated = 0
    page = 1
    per_page = 500

    while True:
        url = f"{base_url}?per_page={per_page}&page={page}"
        data = _fetch_json(url, timeout=60)
        if not data or not isinstance(data, list) or len(data) == 0:
            break

        for entry in data:
            cve_id = entry.get("CVE", "")
            if not cve_id.startswith("CVE-"):
                continue

            severity = entry.get("severity", "moderate")
            advisory_ids = entry.get("advisories", [])
            # Use the first RHSA/RHBA advisory ID, or synthesize one
            rhsa_id = ""
            for adv in (advisory_ids if isinstance(advisory_ids, list) else []):
                if isinstance(adv, str) and adv.startswith("RH"):
                    rhsa_id = adv
                    break
            if not rhsa_id:
                rhsa_id = f"RHEL-{cve_id}"

            bugzilla = entry.get("bugzilla", "")
            bugzilla_desc = entry.get("bugzilla_description", "")
            resource_url = entry.get("resource_url", "")
            affected = entry.get("affected_packages", [])

            packages = []
            if isinstance(affected, list):
                for pkg_str in affected:
                    if isinstance(pkg_str, str):
                        packages.append({"name": pkg_str, "version_fixed": "", "arch": ""})

            is_new = _upsert_patch_advisory(
                db, source="rhel", source_advisory_id=rhsa_id,
                title=bugzilla_desc[:500] if bugzilla_desc else f"Red Hat fix for {cve_id}",
                severity=_rhel_severity(severity),
                advisory_url=resource_url or f"https://access.redhat.com/security/cve/{cve_id}",
                affected_packages=packages,
                cve_ids=[cve_id],
                raw_data=entry,
            )
            if is_new:
                added += 1
            else:
                updated += 1

        # Paginate — stop after 5 pages or if we got fewer results than per_page
        if len(data) < per_page or page >= 5:
            break
        page += 1
        time.sleep(1.0)  # Be polite

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_rhel_cves_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("RHEL sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


def _rhel_severity(severity: str) -> str:
    """Normalize Red Hat severity to standard values."""
    return _normalize_severity(severity)


# ── Amazon Linux ──────────────────────────────────────────────────────────────

def sync_amazon_alas_to_db(db) -> dict:
    """
    Fetch Amazon Linux Security Advisories from RSS feeds (AL2 + AL2023).
    Returns {"added": int, "updated": int}.
    """
    feeds = [
        ("https://alas.aws.amazon.com/alas2.rss", "amazon_linux_2"),
        ("https://alas.aws.amazon.com/alas2023.rss", "amazon_linux_2023"),
    ]
    added = 0
    updated = 0

    for feed_url, al_version in feeds:
        xml_text = _fetch_text(feed_url, timeout=30)
        if not xml_text:
            continue

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("Amazon Linux RSS parse failed for %s: %s", feed_url, exc)
            continue

        for item in root.iter("item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            description = item.findtext("description", "")
            pub_date = item.findtext("pubDate", "")

            # Extract ALAS ID from title, e.g. "ALAS-2024-1234" or "ALAS2-2024-1234"
            alas_match = re.search(r"(ALAS2?(?:023)?-\d{4}-\d+)", title)
            alas_id = alas_match.group(1) if alas_match else ""
            if not alas_id:
                continue

            # Extract CVEs from description
            cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", description + " " + title)))

            # Determine severity from title
            severity = "moderate"
            title_lower = title.lower()
            if "critical" in title_lower:
                severity = "critical"
            elif "important" in title_lower:
                severity = "important"
            elif "medium" in title_lower:
                severity = "moderate"
            elif "low" in title_lower:
                severity = "low"

            is_new = _upsert_patch_advisory(
                db, source="amazon_linux", source_advisory_id=alas_id,
                title=title[:500],
                description=description[:2000] if description else None,
                severity=severity,
                release_date=pub_date[:10] if pub_date else None,
                advisory_url=link,
                cve_ids=cve_ids,
                raw_data={"al_version": al_version},
            )
            if is_new:
                added += 1
            else:
                updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_amazon_alas_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Amazon Linux ALAS sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


# ── Apple Security Releases ───────────────────────────────────────────────────

def sync_apple_security_to_db(db) -> dict:
    """
    Scrape Apple Security Releases page for CVE-to-update mappings.
    Returns {"added": int, "updated": int}.
    """
    url = "https://support.apple.com/en-us/100100"
    html = _fetch_text(url, timeout=30)
    if not html:
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0

    # Parse the HTML table rows — each row has: update name, available for, release date
    # Use regex to extract table rows (avoid BeautifulSoup dependency for consistency with codebase)
    # Apple's page has <tr> rows with <td> cells containing update info and CVE links
    rows = re.findall(
        r'<tr[^>]*>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>',
        html, re.DOTALL
    )

    for name_html, platforms_html, date_html in rows:
        # Extract advisory name and URL
        name_match = re.search(r'<a[^>]+href="([^"]*)"[^>]*>(.*?)</a>', name_html, re.DOTALL)
        if not name_match:
            continue
        advisory_url = name_match.group(1)
        advisory_name = re.sub(r'<[^>]+>', '', name_match.group(2)).strip()

        if not advisory_name:
            continue

        # Generate an advisory ID from the name
        advisory_id = re.sub(r'[^a-zA-Z0-9.-]', '_', advisory_name)

        # Extract HT identifier from URL if present
        ht_match = re.search(r'(HT\d+)', advisory_url)
        if ht_match:
            advisory_id = ht_match.group(1)

        # Clean platform text
        platforms_text = re.sub(r'<[^>]+>', '', platforms_html).strip()
        release_date = re.sub(r'<[^>]+>', '', date_html).strip()

        # Fetch CVEs from the advisory detail page
        cve_ids = []
        if advisory_url and advisory_url.startswith("http"):
            detail_html = _fetch_text(advisory_url, timeout=15)
            if detail_html:
                cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", detail_html)))

        is_new = _upsert_patch_advisory(
            db, source="apple", source_advisory_id=advisory_id,
            title=advisory_name,
            severity="important",  # Apple doesn't provide severity in the table
            release_date=release_date,
            advisory_url=advisory_url if advisory_url.startswith("http") else f"https://support.apple.com{advisory_url}",
            cve_ids=cve_ids,
            raw_data={"platforms": platforms_text},
        )
        if is_new:
            added += 1
        else:
            updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_apple_security_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Apple security sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


# ── Google Chrome ─────────────────────────────────────────────────────────────

def sync_chrome_releases_to_db(db) -> dict:
    """
    Fetch Chrome stable release versions and map to security advisories.
    Returns {"added": int, "updated": int}.
    """
    url = "https://versionhistory.googleapis.com/v1/chrome/platforms/all/channels/stable/versions"
    data = _fetch_json(url, timeout=30)
    if not data or not isinstance(data, dict):
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0

    versions = data.get("versions", [])
    for version_info in versions[:50]:  # Limit to recent 50 versions
        version = version_info.get("version", "")
        if not version:
            continue

        # Chrome security advisories are on the Chrome Releases blog
        # The version history API gives us versions; we create advisories per version
        advisory_id = f"CHROME-{version}"

        is_new = _upsert_patch_advisory(
            db, source="chrome", source_advisory_id=advisory_id,
            title=f"Google Chrome {version}",
            advisory_url=f"https://chromereleases.googleblog.com/search/label/Stable%20updates",
            affected_packages=[{"name": "google-chrome-stable", "version_fixed": version}],
            raw_data=version_info,
        )
        if is_new:
            added += 1
        else:
            updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_chrome_releases_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Chrome sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


# ── Mozilla Firefox ───────────────────────────────────────────────────────────

def sync_firefox_advisories_to_db(db) -> dict:
    """
    Fetch Mozilla Firefox security advisories.
    Returns {"added": int, "updated": int}.
    """
    import time

    # Get current version info
    versions_data = _fetch_json("https://product-details.mozilla.org/1.0/firefox_versions.json", timeout=15)

    # Fetch security advisories index page
    index_html = _fetch_text("https://www.mozilla.org/en-US/security/advisories/", timeout=30)
    if not index_html:
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0

    # Extract MFSA advisory links (e.g., mfsa2024-01)
    mfsa_ids = re.findall(r'(mfsa\d{4}-\d+)', index_html)
    mfsa_ids = list(dict.fromkeys(mfsa_ids))[:30]  # Dedupe, limit to recent 30

    for mfsa_id in mfsa_ids:
        advisory_url = f"https://www.mozilla.org/en-US/security/advisories/{mfsa_id}/"
        detail_html = _fetch_text(advisory_url, timeout=15)
        if not detail_html:
            time.sleep(0.5)
            continue

        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', detail_html, re.DOTALL)
        title = re.sub(r'<[^>]+>', '', title_match.group(1)).strip() if title_match else mfsa_id

        # Extract CVEs
        cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", detail_html)))

        # Determine severity from page content
        severity = "moderate"
        detail_lower = detail_html.lower()
        if "critical" in detail_lower:
            severity = "critical"
        elif "high" in detail_lower:
            severity = "important"
        elif "low" in detail_lower:
            severity = "low"

        # Extract affected product from title
        product = "Firefox"
        if "thunderbird" in title.lower():
            product = "Thunderbird"
        elif "firefox esr" in title.lower():
            product = "Firefox ESR"

        is_new = _upsert_patch_advisory(
            db, source="firefox", source_advisory_id=mfsa_id.upper(),
            title=title[:500],
            severity=severity,
            advisory_url=advisory_url,
            cve_ids=cve_ids,
            affected_packages=[{"name": product.lower().replace(" ", "-")}],
            raw_data={"product": product},
        )
        if is_new:
            added += 1
        else:
            updated += 1

        time.sleep(0.5)  # Be polite to Mozilla

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_firefox_advisories_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Firefox sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


# ── Adobe Security Bulletins ──────────────────────────────────────────────────

def sync_adobe_bulletins_to_db(db) -> dict:
    """
    Fetch Adobe Security Bulletins from RSS feed.
    Returns {"added": int, "updated": int}.
    """
    url = "https://helpx.adobe.com/security/security-bulletin.rss"
    xml_text = _fetch_text(url, timeout=30)
    if not xml_text:
        return {"added": 0, "updated": 0}

    added = 0
    updated = 0

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("Adobe RSS parse failed: %s", exc)
        return {"added": 0, "updated": 0}

    for item in root.iter("item"):
        title = item.findtext("title", "")
        link = item.findtext("link", "")
        pub_date = item.findtext("pubDate", "")
        description = item.findtext("description", "")

        if not title:
            continue

        # Generate advisory ID from title or link
        # Adobe bulletin IDs like APSB24-01
        apsb_match = re.search(r"(APSB\d{2}-\d+)", title + " " + link)
        advisory_id = apsb_match.group(1) if apsb_match else re.sub(r'[^a-zA-Z0-9.-]', '_', title[:50])

        # Extract CVEs from description
        cve_ids = list(set(re.findall(r"CVE-\d{4}-\d{4,}", description + " " + title)))

        # Determine product from title
        product = "adobe"
        title_lower = title.lower()
        if "acrobat" in title_lower or "reader" in title_lower:
            product = "adobe-acrobat"
        elif "flash" in title_lower:
            product = "adobe-flash"
        elif "photoshop" in title_lower:
            product = "adobe-photoshop"
        elif "illustrator" in title_lower:
            product = "adobe-illustrator"
        elif "indesign" in title_lower:
            product = "adobe-indesign"
        elif "premiere" in title_lower:
            product = "adobe-premiere"
        elif "after effects" in title_lower:
            product = "adobe-after-effects"
        elif "creative cloud" in title_lower:
            product = "adobe-creative-cloud"
        elif "commerce" in title_lower or "magento" in title_lower:
            product = "adobe-commerce"
        elif "coldfusion" in title_lower:
            product = "adobe-coldfusion"
        elif "experience manager" in title_lower:
            product = "adobe-experience-manager"

        # Determine severity
        severity = "important"
        if "critical" in description.lower() or "critical" in title_lower:
            severity = "critical"

        is_new = _upsert_patch_advisory(
            db, source="adobe", source_advisory_id=advisory_id,
            title=title[:500],
            description=description[:2000] if description else None,
            severity=severity,
            release_date=pub_date[:10] if pub_date else None,
            advisory_url=link,
            cve_ids=cve_ids,
            affected_packages=[{"name": product}],
            raw_data={"product": product},
        )
        if is_new:
            added += 1
        else:
            updated += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_adobe_bulletins_to_db commit failed: %s", exc)
        db.rollback()

    logger.info("Adobe sync: %d added, %d updated", added, updated)
    return {"added": added, "updated": updated}


# ── Patch Catalog Orchestrator ────────────────────────────────────────────────

def sync_all_patch_advisories(db) -> dict:
    """
    Master orchestrator — syncs all enabled patch advisory sources.
    Reads config/patch_config.json to determine which sources are enabled.
    Returns {"results": {source: {added, updated}}, "total_added": int, "total_updated": int}.
    """
    config = _load_patch_config()
    if not config.get("enabled", True):
        logger.info("Patch catalog sync disabled in config")
        return {"results": {}, "total_added": 0, "total_updated": 0}

    sources = config.get("sources", {})
    sync_map = {
        "ubuntu": sync_ubuntu_usn_to_db,
        "debian": sync_debian_dsa_to_db,
        "rhel": sync_rhel_cves_to_db,
        "amazon_linux": sync_amazon_alas_to_db,
        "apple": sync_apple_security_to_db,
        "chrome": sync_chrome_releases_to_db,
        "firefox": sync_firefox_advisories_to_db,
        "adobe": sync_adobe_bulletins_to_db,
    }

    results = {}
    total_added = 0
    total_updated = 0

    for source_name, sync_fn in sync_map.items():
        source_config = sources.get(source_name, {})
        if not source_config.get("enabled", True):
            logger.info("Patch source %s disabled, skipping", source_name)
            continue

        try:
            result = sync_fn(db)
            results[source_name] = result
            total_added += result.get("added", 0)
            total_updated += result.get("updated", 0)
        except Exception as exc:
            logger.warning("Patch source %s sync failed: %s", source_name, exc)
            results[source_name] = {"error": str(exc)}

    logger.info("Patch catalog sync complete: %d added, %d updated across %d sources",
                total_added, total_updated, len(results))
    return {"results": results, "total_added": total_added, "total_updated": total_updated}

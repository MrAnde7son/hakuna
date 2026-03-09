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

from threat_intel_models import ThreatCVE, ThreatGroup, TTP, ThreatGroupTTP
from models import Finding

logger = logging.getLogger(__name__)

_MITRE_BUNDLE_CACHE = None  # module-level cache to avoid re-fetching the large STIX bundle
_SSL_CONTEXT = None          # cached SSL context


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

        # CVSS v3
        cvss3_score = None
        cvss3_vector = None
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss3_score = cvss_data.get("baseScore")
                cvss3_vector = cvss_data.get("vectorString")
                break

        # Affected products
        affected_products = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        affected_products.append({
                            "vendor": parts[3],
                            "product": parts[4],
                            "versions": cpe_match.get("versionEndIncluding", ""),
                        })

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
            "cvss3_score": cvss3_score,
            "cvss3_vector": cvss3_vector,
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
                kev_date_added=entry.get("dateAdded", ""),
                kev_due_date=entry.get("dueDate", ""),
                kev_ransomware_use=entry.get("knownRansomwareCampaignUse", ""),
                kev_notes=entry.get("notes", ""),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(record)
            added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_kev_to_db commit failed: %s", exc)
        db.rollback()

    return {"added": added, "updated": updated, "total": len(entries)}


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


def sync_mitre_groups_to_db(db) -> dict:
    """
    Fetch MITRE ATT&CK groups and techniques, then upsert ThreatGroup records.
    Skips groups whose mitre_id already exists in the DB.
    Returns {"added": int, "skipped": int}.
    """
    groups = fetch_mitre_attack_groups()
    # Also prime the bundle cache for techniques (called together)
    fetch_mitre_attack_techniques()

    added = 0
    skipped = 0

    for group_data in groups:
        mitre_id = group_data.get("mitre_id", "")
        if not mitre_id:
            skipped += 1
            continue

        existing = db.query(ThreatGroup).filter(ThreatGroup.mitre_id == mitre_id).first()
        if existing:
            skipped += 1
            continue

        record = ThreatGroup(
            mitre_id=mitre_id,
            name=group_data.get("name", ""),
            aliases=group_data.get("aliases", []),
            description=group_data.get("description", ""),
            source="mitre",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(record)
        added += 1

    try:
        db.commit()
    except Exception as exc:
        logger.warning("sync_mitre_groups_to_db commit failed: %s", exc)
        db.rollback()

    return {"added": added, "skipped": skipped}

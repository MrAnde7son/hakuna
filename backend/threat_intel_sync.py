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

    records = (
        db.query(ThreatCVE)
        .filter(ThreatCVE.cvss3_score.is_(None))
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

        if nvd_data.get("cvss3_score") is not None:
            record.cvss3_score = nvd_data["cvss3_score"]
        if nvd_data.get("cvss3_vector"):
            record.cvss3_vector = nvd_data["cvss3_vector"]
        if nvd_data.get("description") and not record.description:
            record.description = nvd_data["description"]
        if nvd_data.get("affected_products") and not record.affected_products:
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

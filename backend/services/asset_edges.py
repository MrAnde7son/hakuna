"""Edge upsert helper — single write path into `asset_relationships`.

Every producer (EASM ingest, VM scanner, parsers, audit agents'
`emit_edge` tool, knowledge_graph) goes through `upsert_edge` so the
substrate stays consistent: one row per (org, src, dst, type, props)
tuple, with `last_seen_at` bumped on every re-observation and
`enabled_by_findings` accumulating the finding ids that justify the
edge.

See `docs/cross-scan-chain-coordinator-plan.md` (F1).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Iterable

from sqlalchemy.orm import Session

from models.asset_edges import (
    CONFIDENCE_LEVELS, CVE_ON_ASSET, EDGE_TYPES, INTERNET_TO_ASSET,
)
from models.models import AssetRelationship

logger = logging.getLogger(__name__)


# Confidence rank — used when we re-observe an edge with a different
# confidence and want to keep the strongest signal we've seen so far.
_CONFIDENCE_RANK = {label: rank for rank, label in enumerate(("low", "medium", "high", "confirmed"))}


def compute_properties_hash(properties: dict | None) -> str:
    """Deterministic sha256 over the canonical-JSON encoding of `properties`.

    Two edges with the same logical content (key order varies, ints vs
    floats stable) collapse to the same hash. Empty / missing properties
    hash to ``""`` so legacy rows (and edges without properties) keep
    their existing dedup semantics.
    """
    if not properties:
        return ""
    canon = json.dumps(properties, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _better_confidence(current: str | None, incoming: str | None) -> str:
    """Pick the stronger of two confidence labels (or `current` if equal)."""
    cur_rank = _CONFIDENCE_RANK.get((current or "").lower(), -1)
    inc_rank = _CONFIDENCE_RANK.get((incoming or "").lower(), -1)
    if inc_rank > cur_rank:
        return (incoming or current or "high").lower()
    return (current or "high").lower()


def upsert_edge(
    db: Session,
    *,
    org_id: int,
    edge_type: str,
    source_system: str,
    src_asset_id: int | None = None,
    dst_asset_id: int | None = None,
    weight: float = 1.0,
    confidence: str = "high",
    properties: dict | None = None,
    enabled_by_finding_id: int | None = None,
    enabled_by_finding_ids: Iterable[int] | None = None,
    source_detail: dict | None = None,
) -> AssetRelationship | None:
    """Upsert an edge by (org_id, src, dst, edge_type, properties_hash).

    Existing row → bump `last_seen_at`, take the stronger confidence,
    keep `weight` at max(existing, incoming), and merge any newly
    enabling finding ids.

    Returns the row, or `None` if validation fails (unknown edge_type,
    missing both endpoints, etc).
    """
    if edge_type not in EDGE_TYPES:
        logger.warning("upsert_edge: unknown edge_type=%s", edge_type)
        return None
    if not org_id:
        logger.warning("upsert_edge: org_id is required")
        return None
    if src_asset_id is None and dst_asset_id is None:
        logger.warning("upsert_edge: at least one of src/dst asset must be set")
        return None
    confidence = (confidence or "high").lower()
    if confidence not in CONFIDENCE_LEVELS:
        confidence = "high"
    weight = max(0.0, min(1.0, float(weight)))
    properties = dict(properties or {})
    props_hash = compute_properties_hash(properties)

    finding_ids: list[int] = []
    if enabled_by_finding_id is not None:
        finding_ids.append(int(enabled_by_finding_id))
    if enabled_by_finding_ids:
        finding_ids.extend(int(fid) for fid in enabled_by_finding_ids)

    # Lookup — null-safe because of the COALESCE-based partial unique
    # index (see migration 054). At ORM layer we still match on equality
    # / IS NULL explicitly.
    q = db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == edge_type,
        AssetRelationship.properties_hash == props_hash,
    )
    if src_asset_id is None:
        q = q.filter(AssetRelationship.source_asset_id.is_(None))
    else:
        q = q.filter(AssetRelationship.source_asset_id == src_asset_id)
    if dst_asset_id is None:
        q = q.filter(AssetRelationship.target_asset_id.is_(None))
    else:
        q = q.filter(AssetRelationship.target_asset_id == dst_asset_id)
    existing = q.first()

    now = datetime.utcnow()

    if existing:
        existing.last_seen_at = now
        existing.confidence = _better_confidence(existing.confidence, confidence)
        if (existing.weight or 0.0) < weight:
            existing.weight = weight
        if source_system and not existing.source_system:
            existing.source_system = source_system
        if source_detail:
            merged_detail = dict(existing.source_detail or {})
            merged_detail.update(source_detail)
            existing.source_detail = merged_detail
        if finding_ids:
            existing_ids = list(existing.enabled_by_findings or [])
            seen = set(existing_ids)
            for fid in finding_ids:
                if fid not in seen:
                    existing_ids.append(fid)
                    seen.add(fid)
            existing.enabled_by_findings = existing_ids
        # `properties` is part of the lookup key — same hash means
        # logical equality, no merging needed.
        return existing

    edge = AssetRelationship(
        org_id=org_id,
        source_asset_id=src_asset_id,
        target_asset_id=dst_asset_id,
        relationship_type=edge_type,
        confidence=confidence,
        weight=weight,
        properties=properties,
        properties_hash=props_hash,
        enabled_by_findings=finding_ids,
        source_system=source_system,
        source_detail=source_detail or {},
        created_at=now,
        updated_at=now,
        last_seen_at=now,
    )
    db.add(edge)
    db.flush()
    return edge


# ── Producer-specific helpers ────────────────────────────────────────


# Common HTTP/management ports — used to keep the internet_to_asset edge
# set bounded when EASM reports a long open-port list. We don't drop
# data; we just emit a single edge per "interesting" port, since the
# Coordinator only walks family-level reachability for hypothesis
# enumeration. Anything else is captured as a single
# `port="other"` edge so the chain still sees the asset is reachable.
_EASM_PORT_FAMILIES: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    111:   "rpcbind",
    135:   "msrpc",
    139:   "smb",
    143:   "imap",
    161:   "snmp",
    389:   "ldap",
    443:   "https",
    445:   "smb",
    465:   "smtps",
    587:   "smtp_submission",
    636:   "ldaps",
    993:   "imaps",
    995:   "pop3s",
    1433:  "mssql",
    2375:  "docker",
    2376:  "docker_tls",
    3306:  "mysql",
    3389:  "rdp",
    3000:  "http_alt",
    5432:  "postgres",
    5601:  "kibana",
    5900:  "vnc",
    5985:  "winrm",
    5986:  "winrm_tls",
    6379:  "redis",
    8080:  "http_alt",
    8443:  "https_alt",
    9200:  "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


def _coerce_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 65536 else None
    if isinstance(value, str):
        try:
            n = int(value.strip())
        except (TypeError, ValueError):
            return None
        return n if 0 < n < 65536 else None
    if isinstance(value, dict):
        # easm_data["open_ports"] sometimes carries dicts like {port: 443, proto: tcp}
        for key in ("port", "number", "p"):
            n = _coerce_port(value.get(key))
            if n is not None:
                return n
    return None


def write_easm_internet_edges(
    db: Session,
    *,
    org_id: int,
    asset_id: int,
    open_ports: Iterable[object] | None,
    confidence: str = "high",
) -> int:
    """Emit `internet_to_asset` edges for every port EASM reports open.

    `src_asset_id` is NULL — internet pseudo-source. One edge per
    distinct port (deduped via properties_hash), plus a single
    catch-all if nothing parsed (so the chain at least sees the host
    is reachable).

    Returns the number of edges upserted.
    """
    if not org_id or not asset_id:
        return 0

    ports: list[int] = []
    seen: set[int] = set()
    for raw in (open_ports or []):
        n = _coerce_port(raw)
        if n is None or n in seen:
            continue
        seen.add(n)
        ports.append(n)

    written = 0
    if not ports:
        # Reachability is known (EASM returned the asset) even if we
        # couldn't parse any ports — emit one catch-all so BFS still
        # sees an internet-side entry point.
        edge = upsert_edge(
            db,
            org_id=org_id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            src_asset_id=None,
            dst_asset_id=asset_id,
            weight=1.0,
            confidence=confidence,
            properties={"port": "any"},
        )
        return 1 if edge is not None else 0

    for port in ports:
        family = _EASM_PORT_FAMILIES.get(port, "other")
        edge = upsert_edge(
            db,
            org_id=org_id,
            edge_type=INTERNET_TO_ASSET,
            source_system="easm",
            src_asset_id=None,
            dst_asset_id=asset_id,
            weight=1.0,
            confidence=confidence,
            properties={"port": port, "family": family, "protocol": "tcp"},
        )
        if edge is not None:
            written += 1
    return written


def write_sbom_kev_edge(
    db: Session,
    *,
    org_id: int,
    asset_id: int,
    cve_id: str,
    finding_id: int | None = None,
    component_name: str | None = None,
    component_version: str | None = None,
) -> AssetRelationship | None:
    """Emit a `cve_on_asset` edge tagged `source_system='sbom'`.

    Called from `services.sbom_pipeline.build_sbom_from_inventory` for
    every KEV-flagged CVE matched to an SBOM component. The chain
    coordinator's `sbom_unpatched` pattern reads only edges with this
    source tag — without this writer the pattern is inert.
    """
    if not org_id or not asset_id or not cve_id:
        return None
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    properties: dict = {"cve": cve, "kev": True}
    if component_name:
        properties["component"] = component_name
    if component_version:
        properties["version"] = component_version
    return upsert_edge(
        db,
        org_id=org_id,
        edge_type=CVE_ON_ASSET,
        source_system="sbom",
        src_asset_id=None,
        dst_asset_id=asset_id,
        weight=1.0,
        confidence="confirmed",
        properties=properties,
        enabled_by_finding_id=finding_id,
    )


def write_kev_cve_edges_for_scan(
    db: Session,
    *,
    org_id: int,
    scan_id: int,
) -> int:
    """Emit `cve_on_asset` edges for every KEV-flagged finding in a scan.

    Idempotent — re-runs only update `last_seen_at` and merge finding
    ids. Called from `services.post_ingest.finalize_scan` right after
    threat-intel enrichment (which is what sets `Finding.is_kev`).

    Returns the number of edges upserted.
    """
    from models.models import Finding  # local — avoid module-load cycle

    if not org_id or not scan_id:
        return 0

    rows = (
        db.query(Finding.id, Finding.asset_id, Finding.cves)
        .filter(
            Finding.scan_id == scan_id,
            Finding.is_kev.is_(True),
            Finding.asset_id.isnot(None),
            Finding.cves.isnot(None),
        )
        .all()
    )

    written = 0
    for finding_id, asset_id, cves in rows:
        if not cves:
            continue
        for cve_raw in cves:
            cve = (cve_raw or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            edge = upsert_edge(
                db,
                org_id=org_id,
                edge_type=CVE_ON_ASSET,
                source_system="vm_scanner",
                src_asset_id=None,
                dst_asset_id=asset_id,
                weight=1.0,
                confidence="confirmed",
                properties={"cve": cve, "kev": True},
                enabled_by_finding_id=finding_id,
            )
            if edge is not None:
                written += 1
    return written

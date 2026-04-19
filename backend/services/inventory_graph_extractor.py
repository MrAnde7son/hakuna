"""
Inventory → Asset Relationship extractor.

Reads structured inventory tables populated by scanner parsers (Nessus,
Qualys, Rapid7, credentialed-scan enrichment) and by direct-connect
integrations (AD/LDAP, CMDB, EDR) to materialise `AssetRelationship`
edges that attack-path BFS can traverse.

Edge types emitted here (stored in `AssetRelationship.relationship_type`):

    connects_to            — InventoryNetConn remote endpoint resolves to
                             another asset in the org (ESTABLISHED session
                             or LISTEN with a peer).
    trusts_domain          — InventoryDomainTrust: enumerating host in domain
                             A has a trust edge to hosts in domain B.
    member_of_domain       — Host is a member of a domain we also scanned —
                             edge from the host to a representative domain
                             controller (assets that enumerate AD data).
    shares_credential_with — Two hosts share a non-privileged human session
                             (logged-on user reuse across machines).
    runs_as_principal      — A service/scheduled task on host H runs as a
                             domain principal P that has sessions on other
                             hosts — edge H → those hosts.

Each extractor is independent, idempotent (check-then-insert), dialect-
agnostic (pure ORM / core expressions, no DB-specific JSON ops), and
capped so a single pathological account (e.g. SYSTEM, backup svc on every
box) cannot explode into an O(N²) edge blast.

Wired into `post_ingest.finalize_scan` as step 9.6, before finding
correlation so attack-path BFS sees the edges.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import Iterable

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.models import (
    Asset,
    AssetRelationship,
    InventoryDomainTrust,
    InventoryLoggedOn,
    InventoryNetConn,
    InventoryScheduledTask,
    InventoryService,
    InventoryUser,
    Scan,
)

logger = logging.getLogger(__name__)


# Caps prevent any one signal (SYSTEM account, backup service) from
# producing O(N²) edges that drown the graph.
MAX_EDGES_PER_SHARED_USER = 100
MAX_TARGETS_PER_TRUST_DOMAIN = 25
MAX_TARGETS_PER_RUNS_AS = 25

# Low-signal accounts — present on every Windows/Linux host, not useful
# for credential-reuse edges.
_NOISE_PRINCIPALS = {
    "system", "local system", "nt authority\\system",
    "localservice", "networkservice",
    "nt authority\\local service", "nt authority\\network service",
    "root", "daemon", "nobody", "www-data",
    "administrator",  # too generic without domain qualifier
}


def extract_inventory_edges(db: Session, org_id: int, scan_id: int | None = None) -> dict:
    """Public entry point — runs every extractor, returns per-type counts.

    Scan-scoped when `scan_id` is given (incremental ingest), org-wide
    otherwise (backfill / manual rebuild).
    """
    stats = {
        "connects_to": 0,
        "trusts_domain": 0,
        "member_of_domain": 0,
        "shares_credential_with": 0,
        "runs_as_principal": 0,
    }

    asset_ip_index = _build_asset_ip_index(db, org_id)
    domain_controllers = _identify_domain_controllers(db, org_id)

    stats["connects_to"] = _extract_netconn_edges(
        db, org_id, scan_id, asset_ip_index
    )
    stats["trusts_domain"] = _extract_trust_edges(
        db, org_id, scan_id, domain_controllers
    )
    stats["member_of_domain"] = _extract_membership_edges(
        db, org_id, scan_id, domain_controllers
    )
    stats["shares_credential_with"] = _extract_shared_session_edges(
        db, org_id, scan_id
    )
    stats["runs_as_principal"] = _extract_runs_as_edges(
        db, org_id, scan_id
    )

    db.flush()
    logger.info("org=%d inventory edges: %s", org_id, stats)
    return stats


# ── Extractors ──────────────────────────────────────────────────────


def _extract_netconn_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
    asset_ip_index: dict[str, int],
) -> int:
    """One `connects_to` edge per (source_asset, resolved_remote_asset, remote_port).

    Skips loopback, multicast, and unresolvable remote addresses. LISTEN
    rows with a concrete peer address are treated the same as ESTABLISHED
    since they prove reachability from the peer.
    """
    q = db.query(InventoryNetConn).filter(
        InventoryNetConn.remote_addr.isnot(None),
        InventoryNetConn.remote_port.isnot(None),
    )
    if scan_id is not None:
        q = q.filter(InventoryNetConn.scan_id == scan_id)
    else:
        org_scan_ids = _org_scan_ids(db, org_id)
        q = q.filter(InventoryNetConn.scan_id.in_(org_scan_ids))

    seen: set[tuple[int, int, int]] = set()
    created = 0
    for row in q.yield_per(500):
        remote_ip = _canonical_ip(row.remote_addr)
        if not remote_ip or _is_noise_address(remote_ip):
            continue
        target_id = asset_ip_index.get(remote_ip)
        if not target_id or target_id == row.asset_id:
            continue

        key = (row.asset_id, target_id, row.remote_port)
        if key in seen:
            continue
        seen.add(key)

        if _upsert_edge(
            db, org_id,
            source_asset_id=row.asset_id,
            target_asset_id=target_id,
            rel_type="connects_to",
            confidence="high" if (row.state or "").upper() == "ESTABLISHED" else "medium",
            weight=0.9,
            properties={
                "remote_port": row.remote_port,
                "proto": row.proto,
                "state": row.state,
                "source_plugin": row.source_plugin,
            },
        ):
            created += 1
    return created


def _extract_trust_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
    domain_controllers: dict[str, list[int]],
) -> int:
    """`trusts_domain` edges from the enumerating host to up to N assets in
    the trusted domain. Prefers DCs of the trusted domain as targets.
    """
    q = db.query(InventoryDomainTrust).filter(
        InventoryDomainTrust.trusted_domain.isnot(None),
    )
    if scan_id is not None:
        q = q.filter(InventoryDomainTrust.scan_id == scan_id)
    else:
        q = q.filter(InventoryDomainTrust.scan_id.in_(_org_scan_ids(db, org_id)))

    created = 0
    for trust in q.all():
        trusted = (trust.trusted_domain or "").strip().lower()
        if not trusted:
            continue

        # Prefer DCs of the trusted domain; fall back to any asset with a
        # user in that domain (covers member servers/workstations).
        targets = list(domain_controllers.get(trusted, []))
        if len(targets) < MAX_TARGETS_PER_TRUST_DOMAIN:
            targets.extend(
                _assets_in_domain(db, org_id, trusted, exclude=set(targets))
            )
        targets = targets[:MAX_TARGETS_PER_TRUST_DOMAIN]

        for target_id in targets:
            if target_id == trust.asset_id:
                continue
            if _upsert_edge(
                db, org_id,
                source_asset_id=trust.asset_id,
                target_asset_id=target_id,
                rel_type="trusts_domain",
                confidence="high" if trust.trust_direction in ("bidirectional", "outbound") else "medium",
                weight=0.7,
                properties={
                    "trusted_domain": trust.trusted_domain,
                    "trust_direction": trust.trust_direction,
                    "trust_type": trust.trust_type,
                    "is_transitive": trust.is_transitive,
                    "source_plugin": trust.source_plugin,
                },
            ):
                created += 1
    return created


def _extract_membership_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
    domain_controllers: dict[str, list[int]],
) -> int:
    """`member_of_domain` edges from each asset to the DC(s) of its domain.

    Domain membership is inferred from any InventoryUser collected on the
    host with a non-local `domain`. We match the domain against the DC
    index and emit one edge per (host, DC).
    """
    if not domain_controllers:
        return 0

    q = db.query(InventoryUser.asset_id, InventoryUser.domain).filter(
        InventoryUser.asset_id.isnot(None),
        InventoryUser.domain.isnot(None),
        InventoryUser.user_type != "local_user",
    )
    if scan_id is not None:
        q = q.filter(InventoryUser.scan_id == scan_id)
    else:
        q = q.filter(InventoryUser.scan_id.in_(_org_scan_ids(db, org_id)))

    seen: set[tuple[int, int]] = set()
    created = 0
    for asset_id, domain in q.distinct().all():
        dom = (domain or "").strip().lower()
        dcs = domain_controllers.get(dom)
        if not dcs:
            continue
        for dc_id in dcs:
            if dc_id == asset_id:
                continue
            key = (asset_id, dc_id)
            if key in seen:
                continue
            seen.add(key)
            if _upsert_edge(
                db, org_id,
                source_asset_id=asset_id,
                target_asset_id=dc_id,
                rel_type="member_of_domain",
                confidence="high",
                weight=0.85,
                properties={"domain": domain},
            ):
                created += 1
    return created


def _extract_shared_session_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
) -> int:
    """Pairwise `shares_credential_with` edges for assets where the same
    non-noise principal has an active session — bidirectional, capped so
    a service account on every box doesn't create a clique.
    """
    q = db.query(
        InventoryLoggedOn.asset_id,
        InventoryLoggedOn.domain,
        InventoryLoggedOn.username,
    ).filter(
        InventoryLoggedOn.asset_id.isnot(None),
        InventoryLoggedOn.username.isnot(None),
    )
    if scan_id is None:
        # Session reuse is inherently cross-scan — always scan org-wide.
        q = q.filter(InventoryLoggedOn.scan_id.in_(_org_scan_ids(db, org_id)))
    else:
        q = q.filter(InventoryLoggedOn.scan_id.in_(_org_scan_ids(db, org_id)))

    principal_to_hosts: dict[str, set[int]] = defaultdict(set)
    for asset_id, domain, username in q.distinct().all():
        principal = _principal_key(domain, username)
        if not principal or principal in _NOISE_PRINCIPALS:
            continue
        principal_to_hosts[principal].add(asset_id)

    created = 0
    for principal, hosts in principal_to_hosts.items():
        if len(hosts) < 2:
            continue
        # Deterministic ordering so we don't re-emit (a,b) and (b,a).
        sorted_hosts = sorted(hosts)
        budget = MAX_EDGES_PER_SHARED_USER
        for i, src in enumerate(sorted_hosts):
            for tgt in sorted_hosts[i + 1:]:
                if budget <= 0:
                    break
                if _upsert_edge(
                    db, org_id,
                    source_asset_id=src,
                    target_asset_id=tgt,
                    rel_type="shares_credential_with",
                    confidence="medium",
                    weight=0.6,
                    properties={"principal": principal},
                ):
                    created += 1
                budget -= 1
            if budget <= 0:
                break
    return created


def _extract_runs_as_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
) -> int:
    """`runs_as_principal` edges from hosts running services/tasks as a
    domain principal to other hosts where that principal has a session
    or is a local admin.

    The semantic: compromise of the source host yields the principal's
    credentials, and the principal has access to the target host.
    """
    org_scan_ids = _org_scan_ids(db, org_id)

    # ── Collect (host, principal) pairs from services + scheduled tasks ──
    svc_rows: list[tuple[int, str]] = []
    svc_q = db.query(InventoryService.asset_id, InventoryService.run_as_user).filter(
        InventoryService.asset_id.isnot(None),
        InventoryService.run_as_user.isnot(None),
    )
    task_q = db.query(InventoryScheduledTask.asset_id, InventoryScheduledTask.run_as_user).filter(
        InventoryScheduledTask.asset_id.isnot(None),
        InventoryScheduledTask.run_as_user.isnot(None),
    )
    if scan_id is not None:
        svc_q = svc_q.filter(InventoryService.scan_id == scan_id)
        task_q = task_q.filter(InventoryScheduledTask.scan_id == scan_id)
    else:
        svc_q = svc_q.filter(InventoryService.scan_id.in_(org_scan_ids))
        task_q = task_q.filter(InventoryScheduledTask.scan_id.in_(org_scan_ids))

    for asset_id, run_as in svc_q.distinct().all():
        svc_rows.append((asset_id, run_as))
    for asset_id, run_as in task_q.distinct().all():
        svc_rows.append((asset_id, run_as))

    # ── Build principal → {hosts where principal has access} index ──
    # Sessions (InventoryLoggedOn) + local-admin membership (InventoryUser.is_local_admin).
    principal_to_access: dict[str, set[int]] = defaultdict(set)

    sess_q = db.query(
        InventoryLoggedOn.asset_id,
        InventoryLoggedOn.domain,
        InventoryLoggedOn.username,
    ).filter(InventoryLoggedOn.asset_id.isnot(None)).filter(
        InventoryLoggedOn.scan_id.in_(org_scan_ids)
    )
    for asset_id, domain, username in sess_q.distinct().all():
        key = _principal_key(domain, username)
        if key:
            principal_to_access[key].add(asset_id)

    admin_q = db.query(
        InventoryUser.asset_id,
        InventoryUser.domain,
        InventoryUser.username,
    ).filter(
        InventoryUser.asset_id.isnot(None),
        InventoryUser.is_local_admin == True,  # noqa: E712
        InventoryUser.scan_id.in_(org_scan_ids),
    )
    for asset_id, domain, username in admin_q.distinct().all():
        key = _principal_key(domain, username)
        if key:
            principal_to_access[key].add(asset_id)

    # ── Emit edges ──
    created = 0
    seen: set[tuple[int, int, str]] = set()
    for src_asset_id, run_as in svc_rows:
        principal = _normalize_run_as(run_as)
        if not principal or principal in _NOISE_PRINCIPALS:
            continue
        targets = principal_to_access.get(principal, set())
        budget = MAX_TARGETS_PER_RUNS_AS
        for tgt in sorted(targets):
            if budget <= 0:
                break
            if tgt == src_asset_id:
                continue
            key = (src_asset_id, tgt, principal)
            if key in seen:
                continue
            seen.add(key)
            if _upsert_edge(
                db, org_id,
                source_asset_id=src_asset_id,
                target_asset_id=tgt,
                rel_type="runs_as_principal",
                confidence="medium",
                weight=0.65,
                properties={"principal": principal},
            ):
                created += 1
            budget -= 1
    return created


# ── Helpers ─────────────────────────────────────────────────────────


def _upsert_edge(
    db: Session,
    org_id: int,
    *,
    source_asset_id: int,
    target_asset_id: int,
    rel_type: str,
    confidence: str,
    weight: float,
    properties: dict | None,
) -> bool:
    """Insert a relationship row idempotently. Returns True when created."""
    if source_asset_id == target_asset_id:
        return False
    existing = db.query(AssetRelationship.id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.source_asset_id == source_asset_id,
        AssetRelationship.target_asset_id == target_asset_id,
        AssetRelationship.relationship_type == rel_type,
    ).first()
    if existing:
        return False

    props = {k: v for k, v in (properties or {}).items() if v is not None}
    rel = AssetRelationship(
        org_id=org_id,
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        relationship_type=rel_type,
        confidence=confidence,
        weight=weight,
        properties=props,
    )
    db.add(rel)
    try:
        db.flush()
        return True
    except IntegrityError:
        db.rollback()
        return False


def _org_scan_ids(db: Session, org_id: int):
    """Scalar subquery of all scan IDs for an org — used by all extractors."""
    return db.query(Scan.id).filter(Scan.org_id == org_id).scalar_subquery()


def _build_asset_ip_index(db: Session, org_id: int) -> dict[str, int]:
    """Map canonical IP string → asset_id for every asset in the org.

    Multiple assets can share an IP (e.g. stale + fresh records during
    dedup). We prefer the highest asset_id since dedup keeps the newest.
    """
    rows = db.query(Asset.id, Asset.ip).join(Scan, Scan.id == Asset.scan_id).filter(
        Scan.org_id == org_id,
        Asset.ip.isnot(None),
    ).all()
    index: dict[str, int] = {}
    for asset_id, ip in rows:
        canonical = _canonical_ip(ip)
        if not canonical:
            continue
        if canonical not in index or asset_id > index[canonical]:
            index[canonical] = asset_id
    return index


def _identify_domain_controllers(db: Session, org_id: int) -> dict[str, list[int]]:
    """Return {domain_lower: [asset_id, ...]} for assets acting as DCs.

    Heuristics (union, deduplicated):
      1. Any asset that enumerated AD trusts — only DCs see them.
      2. Any asset running a service whose display_name contains AD/DC
         strings ('Active Directory Domain Services', 'Kerberos Key
         Distribution Center', 'Netlogon').
    """
    org_scan_ids = _org_scan_ids(db, org_id)
    result: dict[str, set[int]] = defaultdict(set)

    trust_rows = db.query(
        InventoryDomainTrust.asset_id,
        InventoryDomainTrust.source_domain,
    ).filter(
        InventoryDomainTrust.asset_id.isnot(None),
        InventoryDomainTrust.scan_id.in_(org_scan_ids),
    ).distinct().all()
    for asset_id, source_domain in trust_rows:
        dom = (source_domain or "").strip().lower()
        if dom:
            result[dom].add(asset_id)

    # Service-based DC detection — domain name comes from co-located users.
    dc_service_patterns = (
        "active directory domain",
        "kerberos key distribution",
        "netlogon",
        "ntds",
    )
    svc_rows = db.query(InventoryService.asset_id, InventoryService.display_name).filter(
        InventoryService.asset_id.isnot(None),
        InventoryService.scan_id.in_(org_scan_ids),
    ).all()
    dc_asset_ids = {
        asset_id for asset_id, display_name in svc_rows
        if display_name and any(p in display_name.lower() for p in dc_service_patterns)
    }
    if dc_asset_ids:
        # Attach each DC to the domain(s) its collected users belong to.
        user_rows = db.query(
            InventoryUser.asset_id,
            InventoryUser.domain,
        ).filter(
            InventoryUser.asset_id.in_(dc_asset_ids),
            InventoryUser.domain.isnot(None),
            InventoryUser.user_type != "local_user",
            InventoryUser.scan_id.in_(org_scan_ids),
        ).distinct().all()
        for asset_id, domain in user_rows:
            dom = (domain or "").strip().lower()
            if dom:
                result[dom].add(asset_id)

    return {dom: sorted(aids) for dom, aids in result.items()}


def _assets_in_domain(
    db: Session,
    org_id: int,
    domain_lower: str,
    exclude: set[int] | None = None,
) -> Iterable[int]:
    """Assets whose InventoryUser rows show membership in `domain_lower`."""
    exclude = exclude or set()
    rows = db.query(InventoryUser.asset_id).join(
        Scan, Scan.id == InventoryUser.scan_id,
    ).filter(
        Scan.org_id == org_id,
        InventoryUser.asset_id.isnot(None),
        InventoryUser.domain.isnot(None),
        InventoryUser.user_type != "local_user",
    ).distinct().all()
    for (asset_id,) in rows:
        if asset_id in exclude:
            continue
        # Domain filter applied in Python so we can normalize case without
        # dialect-specific LOWER() semantics.
        user_row = db.query(InventoryUser.domain).filter(
            InventoryUser.asset_id == asset_id,
            InventoryUser.domain.isnot(None),
        ).first()
        if user_row and (user_row.domain or "").strip().lower() == domain_lower:
            yield asset_id


def _canonical_ip(raw: str | None) -> str | None:
    """Return a normalized string form of an IP, or None if not parseable."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # netstat output sometimes includes scope IDs or ::ffff: prefixes.
    s = s.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _is_noise_address(ip: str) -> bool:
    """Skip loopback, multicast, link-local, unspecified, and broadcast."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_loopback
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_reserved
    )


def _principal_key(domain: str | None, username: str | None) -> str | None:
    """Normalize (domain, username) to a lowercased DOMAIN\\user key."""
    if not username:
        return None
    u = username.strip().lower()
    if not u:
        return None
    d = (domain or "").strip().lower()
    if d:
        return f"{d}\\{u}"
    return u


def _normalize_run_as(raw: str | None) -> str | None:
    """Normalise service/task run_as strings into a principal_key form."""
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    # Strip UPN suffix: "svc@corp.local" → domain=corp.local, user=svc
    if "@" in s and "\\" not in s:
        user, _, domain = s.partition("@")
        return _principal_key(domain, user)
    if "\\" in s:
        domain, _, user = s.partition("\\")
        return _principal_key(domain, user)
    return _principal_key(None, s)

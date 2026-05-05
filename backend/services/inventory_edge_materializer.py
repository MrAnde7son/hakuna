"""Inventory → unified `asset_edges` materializer (Phase 2).

Reads structured inventory tables (`InventoryNetConn`, `InventoryLoggedOn`,
`InventoryUser`, `InventoryDomainTrust`) and emits edges using the
unified taxonomy declared in `models.asset_edges`:

    asset_to_asset_port  — netconn ESTABLISHED / LISTEN-with-peer.
    user_to_asset        — privileged user has a session on the host
                           (or is a local/domain admin on it).
    asset_to_asset_auth  — domain trust / membership / shared session
                           edges between hosts.

This is **complementary** to `services.inventory_graph_extractor`, which
emits the legacy `connects_to` / `trusts_domain` / `member_of_domain`
edge types still consumed by the existing attack-path BFS. Both
materializers write to the same `asset_relationships` table; the
Coordinator and the new blast-radius read path walk the unified
edge family. Long-term, the legacy types will be retired.

Caps prevent any one signal from generating O(N²) edges. Idempotent —
re-runs only bump `last_seen_at`.

See `docs/cross-scan-chain-coordinator-plan.md` Phase 2.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from typing import Iterable

from sqlalchemy.orm import Session

from models.asset_edges import (
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_PORT,
    USER_TO_ASSET,
)
from models.models import (
    Asset,
    InventoryDomainTrust,
    InventoryLoggedOn,
    InventoryNetConn,
    InventoryUser,
    Scan,
)
from services.asset_edges import upsert_edge

logger = logging.getLogger(__name__)


# ── Caps ────────────────────────────────────────────────────────────
MAX_NETCONN_EDGES_PER_ASSET = 50           # top-K outbound by recency proxy
MAX_USER_TO_ASSET_PER_USER = 50
MAX_AUTH_EDGES_PER_PRINCIPAL = 100


_NOISE_PRINCIPALS = {
    "system", "local system", "nt authority\\system",
    "localservice", "networkservice",
    "nt authority\\local service", "nt authority\\network service",
    "root", "daemon", "nobody", "www-data",
    "administrator",
}


def materialize_inventory_edges(
    db: Session,
    *,
    org_id: int,
    scan_id: int | None = None,
) -> dict:
    """Run every inventory→edge materializer. Returns per-type counts.

    Scan-scoped when `scan_id` is given (incremental ingest), org-wide
    otherwise (periodic backfill / manual rebuild).
    """
    if not org_id:
        return {}

    asset_ip_index = _build_asset_ip_index(db, org_id)

    stats = {
        "asset_to_asset_port": _materialize_netconn_edges(
            db, org_id, scan_id, asset_ip_index,
        ),
        "user_to_asset": _materialize_user_to_asset_edges(
            db, org_id, scan_id,
        ),
        "asset_to_asset_auth": _materialize_auth_edges(
            db, org_id, scan_id,
        ),
    }
    db.flush()
    logger.info("org=%d inventory unified edges: %s", org_id, stats)
    return stats


# ── Materializers ───────────────────────────────────────────────────


def _materialize_netconn_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
    asset_ip_index: dict[str, int],
) -> int:
    """One `asset_to_asset_port` edge per (src, dst, port).

    Sourced from `InventoryNetConn`. Skips loopback / multicast /
    unresolvable peers. Capped per-source at MAX_NETCONN_EDGES_PER_ASSET
    so a single connection-heavy host (DC, jumpbox) can't dominate the
    graph.
    """
    q = db.query(InventoryNetConn).filter(
        InventoryNetConn.remote_addr.isnot(None),
        InventoryNetConn.remote_port.isnot(None),
    )
    if scan_id is not None:
        q = q.filter(InventoryNetConn.scan_id == scan_id)
    else:
        q = q.filter(InventoryNetConn.scan_id.in_(_org_scan_ids(db, org_id)))

    seen: set[tuple[int, int, int, str]] = set()
    per_src: dict[int, int] = defaultdict(int)
    written = 0

    for row in q.yield_per(500):
        remote_ip = _canonical_ip(row.remote_addr)
        if not remote_ip or _is_noise_address(remote_ip):
            continue
        target_id = asset_ip_index.get(remote_ip)
        if not target_id or target_id == row.asset_id:
            continue

        proto = (row.proto or "").lower() or "tcp"
        if proto.startswith("tcp"):
            proto = "tcp"
        elif proto.startswith("udp"):
            proto = "udp"

        key = (row.asset_id, target_id, int(row.remote_port), proto)
        if key in seen:
            continue
        seen.add(key)

        if per_src[row.asset_id] >= MAX_NETCONN_EDGES_PER_ASSET:
            continue
        per_src[row.asset_id] += 1

        state = (row.state or "").upper()
        confidence = "high" if state == "ESTABLISHED" else "medium"

        edge = upsert_edge(
            db,
            org_id=org_id,
            edge_type=ASSET_TO_ASSET_PORT,
            source_system="inventory",
            src_asset_id=row.asset_id,
            dst_asset_id=target_id,
            weight=0.9,
            confidence=confidence,
            properties={
                "port": int(row.remote_port),
                "proto": proto,
                "state": state or None,
            },
            source_detail={"plugin": row.source_plugin} if row.source_plugin else None,
        )
        if edge is not None:
            written += 1
    return written


def _materialize_user_to_asset_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
) -> int:
    """`user_to_asset` edges for privileged identity → host coverage.

    `src_asset_id` is NULL — the source is an identity (the principal),
    not an asset. The principal is encoded in `properties.principal`
    (`domain\\user`, lowercased).

    Two signals:
      1. Active sessions (`InventoryLoggedOn`) where the principal is
         flagged privileged in `InventoryUser`.
      2. Direct admin records (`InventoryUser.is_local_admin /
         is_domain_admin / is_privileged`) declared on the host.
    """
    org_scan_ids = _org_scan_ids(db, org_id)

    # Build a privileged-principals index. Multiple `InventoryUser` rows
    # can share a username — collapse them down to a flag set.
    user_q = db.query(
        InventoryUser.domain,
        InventoryUser.username,
        InventoryUser.is_domain_admin,
        InventoryUser.is_local_admin,
        InventoryUser.is_privileged,
    ).filter(
        InventoryUser.username.isnot(None),
        InventoryUser.scan_id.in_(org_scan_ids),
    )
    flags_by_principal: dict[str, dict] = defaultdict(
        lambda: {"da": False, "la": False, "priv": False}
    )
    for domain, username, da, la, priv in user_q.all():
        principal = _principal_key(domain, username)
        if not principal or principal in _NOISE_PRINCIPALS:
            continue
        f = flags_by_principal[principal]
        if da:   f["da"] = True
        if la:   f["la"] = True
        if priv: f["priv"] = True

    edges_per_principal: dict[str, int] = defaultdict(int)
    written = 0

    # 1. Sessions of privileged principals on hosts
    sess_q = db.query(
        InventoryLoggedOn.asset_id,
        InventoryLoggedOn.domain,
        InventoryLoggedOn.username,
    ).filter(
        InventoryLoggedOn.asset_id.isnot(None),
        InventoryLoggedOn.username.isnot(None),
    )
    if scan_id is not None:
        sess_q = sess_q.filter(InventoryLoggedOn.scan_id == scan_id)
    else:
        sess_q = sess_q.filter(InventoryLoggedOn.scan_id.in_(org_scan_ids))

    for asset_id, domain, username in sess_q.distinct().all():
        principal = _principal_key(domain, username)
        if not principal or principal in _NOISE_PRINCIPALS:
            continue
        flags = flags_by_principal.get(principal)
        # Session edges are only interesting when the principal is privileged
        # somewhere in the org — otherwise the graph drowns in service
        # accounts and helpdesk chatter.
        if not flags or not (flags["da"] or flags["la"] or flags["priv"]):
            continue
        if edges_per_principal[principal] >= MAX_USER_TO_ASSET_PER_USER:
            continue

        edge = upsert_edge(
            db,
            org_id=org_id,
            edge_type=USER_TO_ASSET,
            source_system="inventory",
            src_asset_id=None,
            dst_asset_id=asset_id,
            weight=0.85 if flags["da"] else 0.7,
            confidence="high",
            properties={
                "principal": principal,
                "via": "session",
                "is_domain_admin": flags["da"],
                "is_local_admin": flags["la"],
            },
        )
        if edge is not None:
            written += 1
            edges_per_principal[principal] += 1

    # 2. Admin records (declared admins on a host, with or without a session)
    admin_q = db.query(
        InventoryUser.asset_id,
        InventoryUser.domain,
        InventoryUser.username,
        InventoryUser.is_domain_admin,
        InventoryUser.is_local_admin,
    ).filter(
        InventoryUser.asset_id.isnot(None),
        InventoryUser.username.isnot(None),
    )
    if scan_id is not None:
        admin_q = admin_q.filter(InventoryUser.scan_id == scan_id)
    else:
        admin_q = admin_q.filter(InventoryUser.scan_id.in_(org_scan_ids))

    for asset_id, domain, username, da, la in admin_q.all():
        if not (da or la):
            continue
        principal = _principal_key(domain, username)
        if not principal or principal in _NOISE_PRINCIPALS:
            continue
        if edges_per_principal[principal] >= MAX_USER_TO_ASSET_PER_USER:
            continue

        edge = upsert_edge(
            db,
            org_id=org_id,
            edge_type=USER_TO_ASSET,
            source_system="inventory",
            src_asset_id=None,
            dst_asset_id=asset_id,
            weight=0.95 if da else 0.8,
            confidence="confirmed",
            properties={
                "principal": principal,
                "via": "admin_grant",
                "is_domain_admin": bool(da),
                "is_local_admin": bool(la),
            },
        )
        if edge is not None:
            written += 1
            edges_per_principal[principal] += 1

    return written


def _materialize_auth_edges(
    db: Session,
    org_id: int,
    scan_id: int | None,
) -> int:
    """`asset_to_asset_auth` edges for cross-host trust / shared-session
    relationships.

    Signals:
      1. Domain trusts — trust collected on host A reaches every other
         host that holds a domain user from the trusted domain (capped).
      2. Shared privileged sessions — same privileged principal logged
         on to two distinct hosts (deterministic ordering, pairwise).

    These are the inputs the Coordinator's `coerce_to_dc` and
    `cred_found` patterns need.
    """
    org_scan_ids = _org_scan_ids(db, org_id)

    # ── 1. Domain trusts ─────────────────────────────────────────────
    # Trusted domain → asset_ids in that domain.
    domain_to_assets: dict[str, set[int]] = defaultdict(set)
    user_dom_q = db.query(
        InventoryUser.asset_id,
        InventoryUser.domain,
    ).filter(
        InventoryUser.asset_id.isnot(None),
        InventoryUser.domain.isnot(None),
        InventoryUser.user_type != "local_user",
        InventoryUser.scan_id.in_(org_scan_ids),
    )
    for asset_id, domain in user_dom_q.distinct().all():
        dom = (domain or "").strip().lower()
        if dom:
            domain_to_assets[dom].add(asset_id)

    trust_q = db.query(InventoryDomainTrust).filter(
        InventoryDomainTrust.trusted_domain.isnot(None),
    )
    if scan_id is not None:
        trust_q = trust_q.filter(InventoryDomainTrust.scan_id == scan_id)
    else:
        trust_q = trust_q.filter(InventoryDomainTrust.scan_id.in_(org_scan_ids))

    written = 0
    for trust in trust_q.all():
        trusted = (trust.trusted_domain or "").strip().lower()
        if not trusted:
            continue
        targets = sorted(domain_to_assets.get(trusted, set()))
        # Cap in line with legacy extractor.
        for tgt in targets[:25]:
            if tgt == trust.asset_id:
                continue
            edge = upsert_edge(
                db,
                org_id=org_id,
                edge_type=ASSET_TO_ASSET_AUTH,
                source_system="inventory",
                src_asset_id=trust.asset_id,
                dst_asset_id=tgt,
                weight=0.7,
                confidence="high" if trust.trust_direction in ("bidirectional", "outbound") else "medium",
                properties={
                    "via": "domain_trust",
                    "trusted_domain": trust.trusted_domain,
                    "direction": trust.trust_direction,
                    "transitive": bool(trust.is_transitive),
                },
            )
            if edge is not None:
                written += 1

    # ── 2. Shared privileged sessions ────────────────────────────────
    # Build privileged-principals set so we don't emit edges for every
    # service account on every box.
    priv_principals: set[str] = set()
    user_priv_q = db.query(
        InventoryUser.domain,
        InventoryUser.username,
    ).filter(
        InventoryUser.username.isnot(None),
        InventoryUser.scan_id.in_(org_scan_ids),
        # noqa pattern from peer extractors: SQLAlchemy boolean cmp
        (InventoryUser.is_domain_admin == True)  # noqa: E712
        | (InventoryUser.is_local_admin == True)  # noqa: E712
        | (InventoryUser.is_privileged == True),  # noqa: E712
    )
    for domain, username in user_priv_q.distinct().all():
        p = _principal_key(domain, username)
        if p and p not in _NOISE_PRINCIPALS:
            priv_principals.add(p)

    sess_q = db.query(
        InventoryLoggedOn.asset_id,
        InventoryLoggedOn.domain,
        InventoryLoggedOn.username,
    ).filter(
        InventoryLoggedOn.asset_id.isnot(None),
        InventoryLoggedOn.username.isnot(None),
        # Shared sessions are inherently cross-scan — always org-wide.
        InventoryLoggedOn.scan_id.in_(org_scan_ids),
    )
    principal_to_hosts: dict[str, set[int]] = defaultdict(set)
    for asset_id, domain, username in sess_q.distinct().all():
        principal = _principal_key(domain, username)
        if not principal or principal not in priv_principals:
            continue
        principal_to_hosts[principal].add(asset_id)

    for principal, hosts in principal_to_hosts.items():
        if len(hosts) < 2:
            continue
        sorted_hosts = sorted(hosts)
        budget = MAX_AUTH_EDGES_PER_PRINCIPAL
        for i, src in enumerate(sorted_hosts):
            if budget <= 0:
                break
            for tgt in sorted_hosts[i + 1:]:
                if budget <= 0:
                    break
                edge = upsert_edge(
                    db,
                    org_id=org_id,
                    edge_type=ASSET_TO_ASSET_AUTH,
                    source_system="inventory",
                    src_asset_id=src,
                    dst_asset_id=tgt,
                    weight=0.6,
                    confidence="medium",
                    properties={
                        "via": "shared_session",
                        "principal": principal,
                    },
                )
                if edge is not None:
                    written += 1
                budget -= 1

    return written


# ── Helpers ─────────────────────────────────────────────────────────


def _org_scan_ids(db: Session, org_id: int):
    return db.query(Scan.id).filter(Scan.org_id == org_id).scalar_subquery()


def _build_asset_ip_index(db: Session, org_id: int) -> dict[str, int]:
    """Map canonical IP → asset_id. Newest asset wins on collisions."""
    rows = (
        db.query(Asset.id, Asset.ip)
        .join(Scan, Scan.id == Asset.scan_id)
        .filter(Scan.org_id == org_id, Asset.ip.isnot(None))
        .all()
    )
    index: dict[str, int] = {}
    for asset_id, ip in rows:
        canonical = _canonical_ip(ip)
        if not canonical:
            continue
        if canonical not in index or asset_id > index[canonical]:
            index[canonical] = asset_id
    return index


def _canonical_ip(raw: str | None) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    s = s.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _is_noise_address(ip: str) -> bool:
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
    if not username:
        return None
    u = username.strip().lower()
    if not u:
        return None
    d = (domain or "").strip().lower()
    if d:
        return f"{d}\\{u}"
    return u

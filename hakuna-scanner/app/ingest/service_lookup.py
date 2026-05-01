"""Service-type-driven port gating helpers.

PR #2 of the service-type gating refactor. Downstream enrichment stages
historically filtered assets by hard-coded port numbers (e.g. ``port in
{80, 443, 8080, 8443}``). That pattern misses HTTP services on
non-canonical ports, SSH on 2222, MySQL on 3307, etc.

This module exposes two helpers:

* :func:`load_port_service_types` — bulk-fetch the
  ``asset_ports.service_type`` map for a list of assets so in-Python
  filters can prefer the normalized identity over the port number.

* :func:`port_matches_service` — single port-level gate predicate. Returns
  ``True`` when the port has a matching ``service_type``; falls back to
  the legacy port set when ``service_type`` hasn't been stamped yet (for
  ports not yet re-fingerprinted since PR #1).

The fallback is **mandatory** while we're still rolling service_type
through the pipeline — without it, any port that hasn't been
re-fingerprinted since the migration silently drops out of coverage.
PR #4 will retire the fallback after burn-in.
"""

from __future__ import annotations

import uuid
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def port_matches_service(
    port: int,
    service_type: str | None,
    *,
    service_types: Iterable[str],
    legacy_ports: Iterable[int],
) -> bool:
    """Return True iff the (port, service_type) pair should be probed.

    Match rules (in order):

    1. ``service_type`` set → match by membership in ``service_types``.
       Authoritative — if a fingerprinter labelled the port "ssh" we
       trust it even on a non-canonical port (e.g. 2222).

    2. ``service_type`` unset → fall back to ``port in legacy_ports``.
       Covers ports not yet re-fingerprinted since PR #1.

    Mirrors the SQL predicate in :func:`assets_with_service_types`.
    """
    if service_type is not None:
        return service_type in set(service_types)
    return port in set(legacy_ports)


def asset_has_matching_port(
    asset: dict,
    *,
    service_types: Iterable[str],
    legacy_ports: Iterable[int],
) -> bool:
    """Return True iff any of the asset's open ports matches.

    Convenience wrapper around :func:`port_matches_service` for the
    common ``[a for a in assets if ...]`` filter shape used across the
    enrichment orchestrator.
    """
    open_ports = asset.get("open_ports") or []
    if not open_ports:
        return False
    st_map = asset.get("port_service_types") or {}
    st_set = set(service_types)
    legacy_set = set(legacy_ports)
    for port in open_ports:
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        svc = st_map.get(p)
        if svc is not None:
            if svc in st_set:
                return True
        elif p in legacy_set:
            return True
    return False


def matching_ports_for_asset(
    asset: dict,
    *,
    service_types: Iterable[str],
    legacy_ports: Iterable[int],
) -> list[int]:
    """Return the subset of an asset's open ports that match.

    Used by the in-Python probes (ssh_banner, db_banner, etc.) to
    iterate only the ports they actually want to probe. Preserves
    open_ports order.
    """
    open_ports = asset.get("open_ports") or []
    if not open_ports:
        return []
    st_map = asset.get("port_service_types") or {}
    st_set = set(service_types)
    legacy_set = set(legacy_ports)
    matches: list[int] = []
    for port in open_ports:
        try:
            p = int(port)
        except (TypeError, ValueError):
            continue
        svc = st_map.get(p)
        if svc is not None:
            if svc in st_set:
                matches.append(p)
        elif p in legacy_set:
            matches.append(p)
    return matches


async def load_port_service_types(
    db: AsyncSession,
    asset_ids: Iterable[uuid.UUID],
) -> dict[uuid.UUID, dict[int, str]]:
    """Bulk-load asset_ports.service_type for a set of assets.

    Returns ``{asset_id: {port: service_type}}``. Ports without a
    stamped ``service_type`` are omitted from the inner dict — callers
    use ``.get(port)`` and treat ``None`` as "fall back to legacy port
    gate".

    One round-trip regardless of asset count — the per-asset variant
    was hot enough on 10k-asset scans to push the enrichment phase
    past its soft time limit.
    """
    asset_id_list = [aid for aid in asset_ids if aid is not None]
    if not asset_id_list:
        return {}
    result = await db.execute(
        text("""
            SELECT asset_id, port, service_type
            FROM asset_ports
            WHERE asset_id = ANY(:asset_ids)
              AND service_type IS NOT NULL
        """),
        {"asset_ids": asset_id_list},
    )
    out: dict[uuid.UUID, dict[int, str]] = {}
    for row in result.fetchall():
        out.setdefault(row.asset_id, {})[int(row.port)] = row.service_type
    return out


async def attach_port_service_types(
    db: AsyncSession,
    assets: list[dict],
) -> list[dict]:
    """Mutate-and-return: stamp ``port_service_types`` onto each asset dict.

    The asset dicts produced by ``_get_confirmed_alive_assets`` carry an
    ``id`` (UUID) field. After this call each asset gains
    ``port_service_types: dict[int, str]`` covering whichever ports
    have been fingerprinted since PR #1. Ports without a service_type
    stamp are simply absent from the dict (callers fall back to the
    legacy port set via :func:`port_matches_service`).
    """
    if not assets:
        return assets
    by_id = await load_port_service_types(
        db, [a.get("id") for a in assets if a.get("id") is not None]
    )
    for asset in assets:
        asset["port_service_types"] = by_id.get(asset.get("id"), {})
    return assets


async def assets_with_service_types(
    db: AsyncSession,
    org_id: uuid.UUID | str,
    service_types: Iterable[str],
    legacy_ports: Iterable[int],
    *,
    confirmed_alive_only: bool = True,
) -> list[tuple]:
    """SQL-side variant of :func:`asset_has_matching_port`.

    Returns ``[(asset_id, hostname, ip, port)]`` rows where the port
    matches by either:

    * ``asset_ports.service_type IN service_types``, OR
    * ``asset_ports.service_type IS NULL`` AND the port is in
      ``legacy_ports`` (fallback).

    Only confirmed-alive (or HTTP-responsive unconfirmed) assets are
    returned by default — same gate the enrichment orchestrator
    applies in :func:`tasks.enrichment._get_confirmed_alive_assets`.

    Currently unused by the orchestrator (the in-Python filter on the
    pre-loaded asset list is faster) but kept on hand for future stages
    that bypass the asset preload.
    """
    st_list = [s for s in service_types]
    lp_list = [int(p) for p in legacy_ports]
    if not st_list and not lp_list:
        return []
    alive_clause = (
        "AND (a.liveness_state = 'confirmed_alive' "
        "OR (a.liveness_state = 'unconfirmed' AND a.http_status IS NOT NULL))"
        if confirmed_alive_only
        else ""
    )
    result = await db.execute(
        text(f"""
            SELECT a.id, a.hostname, host(a.ip) AS ip, ap.port
            FROM assets a
            JOIN asset_ports ap ON ap.asset_id = a.id
            WHERE a.org_id = :org_id
              {alive_clause}
              AND (
                  ap.service_type = ANY(:st_list)
                  OR (ap.service_type IS NULL AND ap.port = ANY(:lp_list))
              )
        """),
        {
            "org_id": org_id,
            "st_list": st_list,
            "lp_list": lp_list,
        },
    )
    return [(r.id, r.hostname, r.ip, int(r.port)) for r in result.fetchall()]

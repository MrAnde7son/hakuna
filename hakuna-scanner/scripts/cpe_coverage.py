"""Measure CPE coverage on asset_ports.

Run from the hakuna-scanner repo root:

    python -m scripts.cpe_coverage
    python -m scripts.cpe_coverage --org <org_id>

Reports the % of asset_ports rows with a non-empty cpe_list. Use this to
measure the impact of the CPE inference layer (Stage 5 of the EASM pipeline).

Run once before the inference layer is enabled to capture a baseline, then
again after a full enrichment run to measure the delta. Aim: <20% NULL
post-rollout (down from ~80%).
"""

import argparse
import asyncio

from sqlalchemy import text

from app.database import async_session


async def measure(org_id: str | None) -> dict:
    sql = """
        SELECT
            COUNT(*) AS total_ports,
            COUNT(*) FILTER (
                WHERE cpe_list IS NOT NULL AND jsonb_array_length(cpe_list) > 0
            ) AS ports_with_cpe,
            COUNT(DISTINCT asset_id) AS total_assets,
            COUNT(DISTINCT asset_id) FILTER (
                WHERE cpe_list IS NOT NULL AND jsonb_array_length(cpe_list) > 0
            ) AS assets_with_any_cpe
        FROM asset_ports
    """
    params: dict = {}
    if org_id:
        sql += " WHERE asset_id IN (SELECT id FROM assets WHERE org_id = :org_id)"
        params["org_id"] = org_id

    async with async_session() as db:
        row = (await db.execute(text(sql), params)).fetchone()

    total = row.total_ports or 0
    with_cpe = row.ports_with_cpe or 0
    total_assets = row.total_assets or 0
    assets_with_cpe = row.assets_with_any_cpe or 0

    return {
        "scope": f"org={org_id}" if org_id else "all orgs",
        "total_ports": total,
        "ports_with_cpe": with_cpe,
        "ports_with_cpe_pct": (with_cpe / total * 100) if total else 0.0,
        "total_assets": total_assets,
        "assets_with_any_cpe": assets_with_cpe,
        "assets_with_any_cpe_pct": (assets_with_cpe / total_assets * 100) if total_assets else 0.0,
    }


def _print_report(stats: dict) -> None:
    print(f"CPE coverage — {stats['scope']}")
    print(f"  asset_ports total:        {stats['total_ports']:,}")
    print(f"  asset_ports with CPE:     {stats['ports_with_cpe']:,} ({stats['ports_with_cpe_pct']:.1f}%)")
    print(f"  assets total:             {stats['total_assets']:,}")
    print(f"  assets with any port CPE: {stats['assets_with_any_cpe']:,} ({stats['assets_with_any_cpe_pct']:.1f}%)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure CPE coverage on asset_ports.")
    parser.add_argument("--org", help="Restrict to a single org_id (UUID)", default=None)
    args = parser.parse_args()

    stats = asyncio.run(measure(args.org))
    _print_report(stats)


if __name__ == "__main__":
    main()

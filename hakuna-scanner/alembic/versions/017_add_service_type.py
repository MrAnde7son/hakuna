"""Add service_type/service_product/service_confidence to asset_ports.

PR #1 of 3 in the service-type gating refactor. Introduces a normalized
service identity column that downstream gates can switch over to instead
of relying solely on port numbers (which break for non-canonical ports
like SSH on 2222 or HTTP on 8088).

Three columns are added:

* ``service_type`` — short normalized identifier (e.g. ``ssh``, ``mysql``,
  ``http``, ``https``, ``rdp``, ``modbus``). Indexed because reader gates
  in PR #2 will filter on it.
* ``service_product`` — best-effort vendor/product string (e.g.
  ``OpenSSH``, ``nginx``).
* ``service_confidence`` — 0..100 score so higher-confidence writers
  (banner probe, nmap script) win over lower-confidence ones (httpx
  scheme guess) on subsequent upserts.

This PR is read-by-nobody — gates remain on port numbers. The migration
backfills existing rows so a baked-in deploy already has the column
populated when PR #2 flips the gates.

Revision ID: 017
Revises: 016
Create Date: 2026-04-30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "017"
down_revision: Union[str, None] = "016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mapping from legacy nmap-flavoured ``service_name`` values to the
# normalized ``service_type`` identifier used by PR #2 gates. Kept in sync
# with the per-fingerprinter mapping in app.ingest.enrichment.
_NMAP_SERVICE_TYPE_MAP = {
    "ssh": "ssh",
    "mysql": "mysql",
    "postgresql": "postgres",
    "postgres": "postgres",
    "http": "http",
    "https": "https",
    "ms-wbt-server": "rdp",
    "rdp": "rdp",
    "ipp": "ipp",
    "ajp13": "ajp",
    "ajp": "ajp",
}


def upgrade() -> None:
    op.add_column("asset_ports", sa.Column("service_type", sa.String(length=32), nullable=True))
    op.add_column("asset_ports", sa.Column("service_product", sa.String(length=128), nullable=True))
    op.add_column("asset_ports", sa.Column("service_confidence", sa.SmallInteger(), nullable=True))
    op.create_index(
        "ix_asset_ports_service_type",
        "asset_ports",
        ["service_type"],
    )

    # Backfill from http_url (httpx-fingerprinted rows). Confidence 70
    # because the scheme is a strong signal but the protocol-level
    # confirmation comes from the actual httpx probe at write-time.
    op.execute(
        """
        UPDATE asset_ports
        SET service_type = CASE
                WHEN http_url LIKE 'https://%' THEN 'https'
                ELSE 'http'
            END,
            service_confidence = 70
        WHERE http_url IS NOT NULL
          AND service_type IS NULL
        """
    )

    # Backfill from legacy nmap service_name. Confidence 80 — nmap's
    # service detection is more authoritative than an httpx scheme guess
    # but less than a hand-rolled banner parser (which gets 85-90).
    for nmap_name, svc_type in _NMAP_SERVICE_TYPE_MAP.items():
        op.execute(
            sa.text(
                """
                UPDATE asset_ports
                SET service_type = :svc_type,
                    service_product = COALESCE(service_product, service_version),
                    service_confidence = GREATEST(COALESCE(service_confidence, 0), 80)
                WHERE service_name = :nmap_name
                  AND (service_type IS NULL OR service_confidence < 80)
                """
            ).bindparams(svc_type=svc_type, nmap_name=nmap_name)
        )


def downgrade() -> None:
    op.drop_index("ix_asset_ports_service_type", table_name="asset_ports")
    op.drop_column("asset_ports", "service_confidence")
    op.drop_column("asset_ports", "service_product")
    op.drop_column("asset_ports", "service_type")

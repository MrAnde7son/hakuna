"""Add attribution JSONB column to assets.

Stores tenant attribution for cloud-hosted assets — i.e., who actually
controls the resource on a shared cloud IP. Populated by
app.ingest.attribution from TLS cert SAN/CN, rDNS PTR, and (later)
favicon hash + IP-side passive DNS. Only written when cloud_provider
is non-null (for non-cloud IPs the asset itself attributes the owner).

Shape::

    {
      "best_guess": "acme.com" | null,
      "confidence": 0.0..1.0,
      "owner_candidates": [{"name": "...", "signal": "tls_san", "confidence": 0.9}],
      "signals": {"tls_san": [...], "rdns": "...", "passive_dns": [...]}
    }

Revision ID: 021
Revises: 020
Create Date: 2026-05-05
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "021"
down_revision: Union[str, None] = "020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("attribution", postgresql.JSONB, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "attribution")

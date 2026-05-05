"""Add per-port HTTP probe fields to asset_ports.

Stores the httpx fingerprint (status, title, URL, webserver, tech_stack) on
the per-port row instead of collapsing every host's HTTP probe into a
single ``assets.http_url``. Lets the VM scanner target every fingerprinted
HTTP service (e.g. an admin UI on 8088) instead of only the canonical
80/443 URL.

Revision ID: 016
Revises: 015
Create Date: 2026-04-30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_ports", sa.Column("http_status", sa.Integer(), nullable=True))
    op.add_column("asset_ports", sa.Column("http_title", sa.Text(), nullable=True))
    op.add_column("asset_ports", sa.Column("http_url", sa.Text(), nullable=True))
    op.add_column("asset_ports", sa.Column("http_webserver", sa.String(length=128), nullable=True))
    op.add_column("asset_ports", sa.Column("http_tech_stack", JSONB, nullable=True))
    op.add_column("asset_ports", sa.Column("last_http_probed_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("asset_ports", "last_http_probed_at")
    op.drop_column("asset_ports", "http_tech_stack")
    op.drop_column("asset_ports", "http_webserver")
    op.drop_column("asset_ports", "http_url")
    op.drop_column("asset_ports", "http_title")
    op.drop_column("asset_ports", "http_status")

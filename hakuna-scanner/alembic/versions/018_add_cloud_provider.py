"""Add cloud_provider to assets.

Captures which cloud provider (aws, gcp, azure, cloudflare, oracle,
digitalocean, fastly) owns the asset's resolved IP. Previously this
classification only ran inside the dangling-DNS branch of the liveness
gate; PR 2 of the EASM enhancements lifts it onto every asset so we can
filter inventory by cloud and feed tenant attribution (PR 4).

Revision ID: 018
Revises: 017
Create Date: 2026-05-05
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "018"
down_revision: Union[str, None] = "017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("cloud_provider", sa.String(length=32), nullable=True),
    )
    op.create_index(
        "ix_assets_cloud_provider",
        "assets",
        ["cloud_provider"],
    )


def downgrade() -> None:
    op.drop_index("ix_assets_cloud_provider", table_name="assets")
    op.drop_column("assets", "cloud_provider")

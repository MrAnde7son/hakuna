"""Add easm_data JSON column to assets.

Stores the catch-all EASM blob written by phase-2 enrichment — primarily
``banner_findings`` from app.tasks.enrichment._do_banner_grab (SSH/RDP/
mail/IPP/TR-069/UPnP/DB/AJP banners). The blob is consumed by the
backend's CVE correlator (services.cve_correlator._banner_components),
which expects ``Asset.easm_data['banner_findings']``.

Without this column every banner_grab batch failed with
``ERROR: column "easm_data" does not exist`` and the discovery chain
ate its 4h soft_time_limit.

Revision ID: 020
Revises: 019
Create Date: 2026-05-05
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "020"
down_revision: Union[str, None] = "019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("easm_data", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "easm_data")

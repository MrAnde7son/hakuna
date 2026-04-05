"""Add target_domain to scan_runs for per-domain scan history

Revision ID: 005
Revises: 004
Create Date: 2026-04-05
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("target_domain", sa.String(255), nullable=True))
    op.create_index("ix_scan_runs_target_domain", "scan_runs", ["target_domain"])


def downgrade() -> None:
    op.drop_index("ix_scan_runs_target_domain", table_name="scan_runs")
    op.drop_column("scan_runs", "target_domain")

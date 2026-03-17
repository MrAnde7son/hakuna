"""Add progress tracking fields to scan_runs

Revision ID: 004
Revises: 003
Create Date: 2026-03-17
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("current_stage", sa.String(64), nullable=True))
    op.add_column("scan_runs", sa.Column("stage_index", sa.Integer, server_default=sa.text("0"), nullable=False))
    op.add_column("scan_runs", sa.Column("total_stages", sa.Integer, server_default=sa.text("0"), nullable=False))
    op.add_column("scan_runs", sa.Column("stage_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scan_runs", sa.Column("stage_log", postgresql.JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_runs", "stage_log")
    op.drop_column("scan_runs", "stage_started_at")
    op.drop_column("scan_runs", "total_stages")
    op.drop_column("scan_runs", "stage_index")
    op.drop_column("scan_runs", "current_stage")

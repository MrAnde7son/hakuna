"""Add created_at to scan_runs for queued-scan recovery.

Scans stuck in 'queued' status (Celery message lost on restart) had no
timestamp to detect staleness. This column lets the recovery task identify
and re-dispatch queued scans that were never picked up.

Revision ID: 011
Revises: 010
Create Date: 2026-04-17
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "created_at")

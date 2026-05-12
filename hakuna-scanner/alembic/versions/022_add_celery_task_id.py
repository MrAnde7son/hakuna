"""Add celery_task_id to scan_runs.

The cancel endpoint used to only flip ``status='cancelled'`` — the Celery
worker kept running the task to completion. With the bounded DNS fixes
that's still mostly fine, but for genuinely hung tasks (or scans the user
wants to kill immediately) we need to be able to revoke. Storing the
task_id at dispatch lets cancel_scan call ``AsyncResult(task_id).revoke()``.

Nullable because there will be live scan_runs from before this migration
that have no task_id; the cancel endpoint falls back to status-flip in
that case.

Revision ID: 022
Revises: 021
Create Date: 2026-05-12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "022"
down_revision: Union[str, None] = "021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column("celery_task_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "celery_task_id")

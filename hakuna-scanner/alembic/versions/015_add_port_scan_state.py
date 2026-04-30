"""Add port_scan_state and port_scan_last_at to assets.

Distinguishes three outcomes that previously all collapsed into NULL
``open_ports``:

  pending  — never port-scanned
  scanned  — naabu ran successfully (open_ports may be [] if nothing found)
  failed   — naabu errored or timed out; open_ports left as-is

Backfill: existing rows with non-null ``open_ports`` get ``scanned`` so
they aren't unnecessarily re-scanned by stale-window logic; everything
else stays ``pending``.

Revision ID: 015
Revises: 014
Create Date: 2026-04-30
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("port_scan_state", sa.String(32), nullable=False, server_default="pending"),
    )
    op.add_column(
        "assets",
        sa.Column("port_scan_last_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Backfill: rows that already have port data are clearly scanned.
    op.execute("""
        UPDATE assets
           SET port_scan_state = 'scanned'
         WHERE open_ports IS NOT NULL
    """)


def downgrade() -> None:
    op.drop_column("assets", "port_scan_last_at")
    op.drop_column("assets", "port_scan_state")

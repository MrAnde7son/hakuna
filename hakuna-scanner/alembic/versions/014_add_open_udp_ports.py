"""Add open_udp_ports column to assets (Phase 4.0).

Mirrors `assets.open_ports` but holds UDP ports populated from nmap UDP
scan results. Needed for the audit auto-trigger on UDP-only protocols
(IPMI 623, TFTP 69, NetBIOS 137/5353/5355) — without it, services that
only listen on UDP can't fire ``port_change`` events.

Per-port detail still lives in ``asset_ports`` (with ``protocol='udp'``).
This column is the denormalized "what's open via UDP right now" array
that the delta engine diffs against the previous snapshot.

Revision ID: 014
Revises: 013
Create Date: 2026-04-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("open_udp_ports", ARRAY(sa.Integer), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "open_udp_ports")

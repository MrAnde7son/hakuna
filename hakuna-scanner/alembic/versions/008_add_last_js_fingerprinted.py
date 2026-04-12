"""Add last_js_fingerprinted to assets

Separate staleness column for JS fingerprinting so it isn't blocked
by the shared last_enriched timestamp set by httpx/cdncheck in Group 1.

Revision ID: 008
Revises: 007
Create Date: 2026-04-12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("last_js_fingerprinted", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "last_js_fingerprinted")

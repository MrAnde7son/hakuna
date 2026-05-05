"""Add liveness_score to assets.

Replaces the boolean ``asset_gone`` event with a 0–100 decaying score so
suppression is gradual rather than binary. Successful liveness checks
bump the score by +5 (cap 100); a failed check decays it (-15 unconfirmed,
-25 likely_dead); assets that aren't validated at all in a cycle decay by
-10 (see app.ingest.delta.decay_unseen_assets). Assets below the
suppression threshold (30) are filtered from active findings on the
backend side but kept in inventory with a "stale" badge so exposure
history is preserved.

Revision ID: 019
Revises: 018
Create Date: 2026-05-05
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "019"
down_revision: Union[str, None] = "018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "liveness_score",
            sa.SmallInteger(),
            nullable=False,
            server_default="100",
        ),
    )
    op.create_index(
        "ix_assets_liveness_score",
        "assets",
        ["liveness_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_assets_liveness_score", table_name="assets")
    op.drop_column("assets", "liveness_score")

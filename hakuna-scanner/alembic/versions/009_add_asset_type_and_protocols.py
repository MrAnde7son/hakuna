"""Add asset_type column and protocol_detections to assets

Supports AI/IoT/OT asset classification and protocol probe results.

asset_type: Categorical label from asset_classifier (e.g. plc, camera,
            ai_inference, vector_db, printer, scada, router, nas, etc.)
protocol_detections: JSONB array of protocol probe results (Modbus, S7,
                     MQTT, RTSP, etc.) with metadata.

Revision ID: 009
Revises: 008
Create Date: 2026-04-13
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("asset_type", sa.String(32), nullable=True))
    op.add_column("assets", sa.Column("protocol_detections", JSONB, nullable=True))
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])


def downgrade() -> None:
    op.drop_index("ix_assets_asset_type", table_name="assets")
    op.drop_column("assets", "protocol_detections")
    op.drop_column("assets", "asset_type")

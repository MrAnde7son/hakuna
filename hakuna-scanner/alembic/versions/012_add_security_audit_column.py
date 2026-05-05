"""Add security_audit column to assets

Stores the normalized HTTP-header + cookie audit produced by
app.ingest.http_header_audit.audit_response(). Denormalized onto the
asset (parallel to tls_cert, tech_stack) so the AssetResponse API can
surface it without joining asset_enrichments.

Revision ID: 012
Revises: 011
Create Date: 2026-04-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "012"
down_revision: Union[str, None] = "011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("security_audit", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "security_audit")

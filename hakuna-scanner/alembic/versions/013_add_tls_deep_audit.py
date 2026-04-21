"""Add tls_deep_audit to asset_ports

Stores the sslyze cipher-enumeration + chain-validation + OCSP + CAA output
produced by app.ingest.tls_deep_audit.audit_host(). Per-port (not per-asset)
because a host can run 443 and 8443 with different TLS configs.

Revision ID: 013
Revises: 012
Create Date: 2026-04-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_ports", sa.Column("tls_deep_audit", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("asset_ports", "tls_deep_audit")

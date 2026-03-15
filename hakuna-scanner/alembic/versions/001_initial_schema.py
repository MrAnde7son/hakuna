"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "target_domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("active", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("hostname", sa.Text, nullable=False),
        sa.Column("ip", postgresql.INET, nullable=True),
        sa.Column("asn", sa.String(32), nullable=True),
        sa.Column("asn_org", sa.Text, nullable=True),
        sa.Column("open_ports", postgresql.ARRAY(sa.Integer), nullable=True),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("http_title", sa.Text, nullable=True),
        sa.Column("http_url", sa.Text, nullable=True),
        sa.Column("tech_stack", postgresql.JSON, nullable=True),
        sa.Column("cdn_provider", sa.String(64), nullable=True),
        sa.Column("waf", sa.String(64), nullable=True),
        sa.Column("tls_cert", postgresql.JSON, nullable=True),
        sa.Column("dns_records", postgresql.JSON, nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.Text), nullable=True, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_enriched", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source", sa.String(32), nullable=True),
        sa.Column("nessus_asset_id", sa.String(64), nullable=True),
        sa.UniqueConstraint("org_id", "hostname", name="uq_org_hostname"),
    )

    op.create_table(
        "scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("scan_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), server_default=sa.text("'queued'")),
        sa.Column("assets_found", sa.Integer, server_default=sa.text("0")),
        sa.Column("assets_changed", sa.Integer, server_default=sa.text("0")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
    )

    op.create_table(
        "asset_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id"), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("payload", postgresql.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Indexes for common queries
    op.create_index("ix_assets_org_id", "assets", ["org_id"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"])
    op.create_index("ix_asset_events_org_id", "asset_events", ["org_id"])
    op.create_index("ix_asset_events_created_at", "asset_events", ["created_at"])
    op.create_index("ix_scan_runs_org_id", "scan_runs", ["org_id"])


def downgrade() -> None:
    op.drop_table("asset_events")
    op.drop_table("scan_runs")
    op.drop_table("assets")
    op.drop_table("target_domains")
    op.drop_table("orgs")

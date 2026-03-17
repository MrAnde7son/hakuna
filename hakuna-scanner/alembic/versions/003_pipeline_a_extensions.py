"""Pipeline A extensions: liveness, nmap, ports, enrichment, endpoints, findings

Revision ID: 003
Revises: 002
Create Date: 2026-03-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Asset: new columns ---
    op.add_column("assets", sa.Column(
        "liveness_state", sa.String(32), server_default=sa.text("'unconfirmed'"), nullable=False,
    ))
    op.add_column("assets", sa.Column(
        "consecutive_failures", sa.Integer, server_default=sa.text("0"), nullable=False,
    ))
    op.add_column("assets", sa.Column(
        "last_validated_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("assets", sa.Column(
        "nmap_status", sa.String(32), server_default=sa.text("'pending'"), nullable=False,
    ))
    op.add_column("assets", sa.Column(
        "nmap_last_run", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("assets", sa.Column(
        "os_fingerprint", sa.Text, nullable=True,
    ))
    op.create_index("ix_assets_liveness_state", "assets", ["liveness_state"])

    # --- AssetPort: per open port on an asset ---
    op.create_table(
        "asset_ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(16), server_default=sa.text("'tcp'")),
        sa.Column("service_name", sa.String(128), nullable=True),
        sa.Column("service_version", sa.String(256), nullable=True),
        sa.Column("banner", sa.Text, nullable=True),
        sa.Column("cpe_list", postgresql.JSONB, nullable=True),
        sa.Column("tls_cert", postgresql.JSONB, nullable=True),
        sa.Column("nmap_scripts", postgresql.JSONB, nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),
    )
    op.create_index("ix_asset_ports_asset_id", "asset_ports", ["asset_id"])
    op.create_index("ix_asset_ports_cpe", "asset_ports", ["cpe_list"], postgresql_using="gin")

    # --- AssetEnrichment: per enrichment run ---
    op.create_table(
        "asset_enrichments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("httpx_full", postgresql.JSONB, nullable=True),
        sa.Column("final_url", sa.Text, nullable=True),
        sa.Column("page_title", sa.Text, nullable=True),
        sa.Column("tech_stack", postgresql.JSONB, nullable=True),
        sa.Column("is_cdn", sa.Boolean, server_default=sa.text("false")),
        sa.Column("tlsx_raw", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_asset_enrichments_asset_id", "asset_enrichments", ["asset_id"])

    # --- AssetEndpoint: katana-discovered endpoints ---
    op.create_table(
        "asset_endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("path", sa.Text, nullable=True),
        sa.Column("method", sa.String(16), server_default=sa.text("'GET'")),
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("is_auth_page", sa.Boolean, server_default=sa.text("false")),
    )
    op.create_index("ix_asset_endpoints_asset_id", "asset_endpoints", ["asset_id"])

    # --- Finding: security findings (dangling DNS, cert expiry, etc.) ---
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("orgs.id"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), server_default=sa.text("'info'")),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("metadata", postgresql.JSONB, nullable=True),
        sa.Column("status", sa.String(32), server_default=sa.text("'open'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_type", "findings", ["finding_type"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("asset_endpoints")
    op.drop_table("asset_enrichments")
    op.drop_table("asset_ports")
    op.drop_index("ix_assets_liveness_state", table_name="assets")
    op.drop_column("assets", "os_fingerprint")
    op.drop_column("assets", "nmap_last_run")
    op.drop_column("assets", "nmap_status")
    op.drop_column("assets", "last_validated_at")
    op.drop_column("assets", "consecutive_failures")
    op.drop_column("assets", "liveness_state")

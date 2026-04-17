"""API discovery and JS intelligence extensions.

PR 3 + PR 4 of the Adaptive Scan Plan feature. Extends asset_endpoints with
provenance + parameter metadata so per-endpoint scanning can route templates
intelligently, and adds asset_js_artifacts for JS-derived intelligence
(retire.js hits, source maps, deep LLM analysis).

asset_endpoints additions:
  - source         : where the endpoint came from
                     (katana | kiterunner | openapi | graphql | llm_js |
                      sourcemap | wordlist). Drives planner ranking.
  - auth_required  : OpenAPI ``security`` block or LLM heuristic. Auth-required
                     endpoints rank higher in the per-asset target list.
  - content_type   : Detected from response or OpenAPI ``requestBody.content``.
  - parameters     : Parameter spec from OpenAPI ``parameters``/``requestBody``
                     so DAST templates can fuzz known parameter names.
  - status_code    : HTTP status seen during discovery. Drives plan ranking.
  - evidence       : Free-form provenance JSON (e.g. {"openapi_operation_id": "..."}).

The unique constraint loosens from "(asset_id, url)" (effectively undefined
in 003) to "(asset_id, url, method, source)" so the same path discovered by
multiple sources doesn't get deduped — each source carries different
metadata that the planner consumes.

asset_js_artifacts is new. One row per (asset, artifact_type, js_url):
  - artifact_type  : sourcemap | llm_intelligence | retirejs_scan
  - intelligence   : Free-form JSON (sourcemap stats, LLM analysis output,
                     list of vuln hits with CVEs).
  - content_hash   : SHA-256 of the JS bytes the artifact was derived from.
                     Used by llm_js_deep_analyzer to skip re-analysis when
                     the bundle hasn't changed.

Revision ID: 010
Revises: 009
Create Date: 2026-04-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Extend asset_endpoints. Defaults keep existing rows (katana-discovered)
    # consistent with their original semantics.
    op.add_column("asset_endpoints", sa.Column("source", sa.String(32), nullable=False, server_default="katana"))
    op.add_column("asset_endpoints", sa.Column("auth_required", sa.Boolean, nullable=True))
    op.add_column("asset_endpoints", sa.Column("content_type", sa.String(128), nullable=True))
    op.add_column("asset_endpoints", sa.Column("parameters", JSONB, nullable=True))
    op.add_column("asset_endpoints", sa.Column("status_code", sa.Integer, nullable=True))
    op.add_column("asset_endpoints", sa.Column("evidence", JSONB, nullable=True))

    # Index that supports the planner's "top N endpoints per asset" query.
    # The composite covers the ranking columns we actually filter/sort on.
    op.create_index(
        "ix_asset_endpoints_asset_rank",
        "asset_endpoints",
        ["asset_id", "auth_required", "status_code"],
    )

    # Loosen uniqueness so multiple sources can record the same path with
    # source-specific metadata. The original 003 schema had no UNIQUE on
    # (asset_id, url) — kiterunner.py and llm_js_endpoints.py rely on
    # ``ON CONFLICT DO NOTHING`` against an implicit row-level unique. Add
    # an explicit one so the conflict target is well-defined.
    op.create_unique_constraint(
        "uq_asset_endpoints_addr",
        "asset_endpoints",
        ["asset_id", "url", "method", "source"],
    )

    # New table: asset_js_artifacts.
    op.create_table(
        "asset_js_artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("artifact_type", sa.String(32), nullable=False),
        sa.Column("js_url", sa.Text, nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column("intelligence", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "asset_id", "artifact_type", "js_url",
            name="uq_asset_js_artifacts_addr",
        ),
    )
    op.create_index(
        "ix_asset_js_artifacts_asset_id",
        "asset_js_artifacts",
        ["asset_id"],
    )
    op.create_index(
        "ix_asset_js_artifacts_type",
        "asset_js_artifacts",
        ["artifact_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_asset_js_artifacts_type", table_name="asset_js_artifacts")
    op.drop_index("ix_asset_js_artifacts_asset_id", table_name="asset_js_artifacts")
    op.drop_table("asset_js_artifacts")

    op.drop_constraint("uq_asset_endpoints_addr", "asset_endpoints", type_="unique")
    op.drop_index("ix_asset_endpoints_asset_rank", table_name="asset_endpoints")
    op.drop_column("asset_endpoints", "evidence")
    op.drop_column("asset_endpoints", "status_code")
    op.drop_column("asset_endpoints", "parameters")
    op.drop_column("asset_endpoints", "content_type")
    op.drop_column("asset_endpoints", "auth_required")
    op.drop_column("asset_endpoints", "source")

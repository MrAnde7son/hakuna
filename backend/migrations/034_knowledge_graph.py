"""Add knowledge graph support: weight/properties columns on asset_relationships,
and asset_clusters table for infrastructure clustering.
"""

from sqlalchemy import text


def upgrade(db):
    """Add knowledge graph columns and tables."""
    # Add new columns to asset_relationships
    db.execute(text("""
        ALTER TABLE asset_relationships
        ADD COLUMN IF NOT EXISTS weight FLOAT DEFAULT 1.0,
        ADD COLUMN IF NOT EXISTS properties JSONB DEFAULT '{}'::jsonb
    """))

    # Create asset_clusters table
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS asset_clusters (
            id SERIAL PRIMARY KEY,
            org_id INTEGER NOT NULL REFERENCES organizations(id),
            cluster_type VARCHAR NOT NULL,
            label VARCHAR,
            pivot_value VARCHAR,
            asset_ids JSONB DEFAULT '[]'::jsonb,
            asset_count INTEGER DEFAULT 0,
            cluster_metadata JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))

    db.execute(text("CREATE INDEX IF NOT EXISTS ix_asset_cluster_org ON asset_clusters(org_id)"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_asset_cluster_type ON asset_clusters(org_id, cluster_type)"))

    db.commit()
    print("Migration 034: Knowledge graph support added.")


def downgrade(db):
    """Remove knowledge graph columns and tables."""
    db.execute(text("DROP TABLE IF EXISTS asset_clusters"))
    db.execute(text("ALTER TABLE asset_relationships DROP COLUMN IF EXISTS weight"))
    db.execute(text("ALTER TABLE asset_relationships DROP COLUMN IF EXISTS properties"))
    db.commit()
    print("Migration 034: Knowledge graph support removed.")

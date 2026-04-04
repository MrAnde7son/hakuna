"""
Migration: Create asset_type_rules table for low-code asset classification.

Allows users to define condition-based rules that classify assets into types
(web_app, cloud_instance, etc.) during ingestion from any source.

Safe to run multiple times (checks for table existence).

Usage:
    cd backend
    python migrations/019_add_asset_type_rules.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text, inspect
from core.database import engine


def _table_exists(conn, table: str) -> bool:
    insp = inspect(conn)
    return table in insp.get_table_names()


# ── Built-in classification rules ─────────────────────────────────
#
# Rules are source-agnostic unless a source_filter is set.
# Data is normalized before evaluation (easm_data flattened, derived
# fields computed), so the same rule works for Nessus, EASM, VM
# scanner, and any integration that provides equivalent fields.
#
# Priority tiers:
#   10-19  Scanner-reported type (highest confidence)
#   20-29  Explicit URL / HTTP response (strong signal)
#   30-39  Service fingerprint (port + service name)
#   40-49  Tech stack / CPE heuristic
#   50-59  Port-only heuristic (weaker signal)
#   999    Catch-all host default

SEED_RULES = [
    # ─── Tier 1: Scanner-reported type (any source) ──────────────
    {
        "name": "Scanner-reported web application",
        "description": "Scanner explicitly reports system_type=web_application (Nessus WAS, Qualys WAS, etc.).",
        "conditions": json.dumps([
            {"field": "system_type", "op": "eq", "value": "web_application"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "@coalesce(best_url,hostname)",
            "domain": "best_domain",
            "display_name": "@coalesce(best_url,hostname)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 10,
        "source_filter": None,
    },
    # ─── Tier 2: Explicit URL evidence ───────────────────────────
    {
        "name": "URL-style hostname",
        "description": "Hostname starts with http:// or https:// (WAS scans, integration imports).",
        "conditions": json.dumps([
            {"field": "hostname", "op": "regex", "value": "^https?://"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "hostname",
            "domain": "@extract_domain(hostname)",
            "display_name": "hostname",
        }),
        "default_attributes": json.dumps({}),
        "priority": 20,
        "source_filter": None,
    },
    {
        "name": "HTTP URL from enrichment",
        "description": "Asset has an http_url (from EASM httpx, integration mapping, or VM scanner).",
        "conditions": json.dumps([
            {"field": "http_url", "op": "regex", "value": "^https?://"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "http_url",
            "domain": "@extract_domain(http_url)",
            "display_name": "@coalesce(http_title,http_url)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 21,
        "source_filter": None,
    },
    # ─── Tier 3: Service fingerprint (port + identified service) ──
    {
        "name": "Web service on HTTP port",
        "description": "Service fingerprint identified an HTTP/HTTPS service (e.g. naabu -sV, Nessus service detection).",
        "conditions": json.dumps([
            {"field": "has_web_service", "op": "is_true"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "@coalesce(best_url,http_url,fqdn,hostname)",
            "domain": "best_domain",
            "display_name": "@coalesce(best_url,fqdn,hostname)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 30,
        "source_filter": None,
    },
    # ─── Tier 4: Tech stack / CPE heuristic ───────────────────────
    {
        "name": "Web tech in tech stack",
        "description": "Tech stack contains web frameworks/servers (Apache, nginx, React, WordPress, etc.).",
        "conditions": json.dumps([
            {"field": "has_web_tech", "op": "is_true"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "@coalesce(best_url,http_url,fqdn,hostname)",
            "domain": "best_domain",
            "display_name": "@coalesce(http_title,best_url,fqdn,hostname)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 40,
        "source_filter": None,
    },
    {
        "name": "Web CPE detected",
        "description": "CPE list contains a web server/framework CPE (Apache, nginx, IIS, Tomcat, etc.).",
        "conditions": json.dumps([
            {"field": "has_web_cpe", "op": "is_true"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "@coalesce(best_url,http_url,fqdn,hostname)",
            "domain": "best_domain",
            "display_name": "@coalesce(http_title,best_url,fqdn,hostname)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 41,
        "source_filter": None,
    },
    # ─── Tier 5: Port-only heuristic ──────────────────────────────
    {
        "name": "HTTP port open (no service ID)",
        "description": "Asset has common HTTP ports open (80, 443, 8080, 8443) but no service fingerprint. Weak signal — classify as web_app if nothing else matched.",
        "conditions": json.dumps([
            {"field": "has_http_port", "op": "is_true"},
        ]),
        "condition_logic": "AND",
        "target_asset_type": "web_app",
        "identity_mapping": json.dumps({
            "url": "@coalesce(best_url,http_url,fqdn,hostname)",
            "domain": "best_domain",
            "display_name": "@coalesce(fqdn,hostname,ip)",
        }),
        "default_attributes": json.dumps({}),
        "priority": 50,
        "source_filter": None,
    },
]


def upgrade():
    with engine.connect() as conn:
        if _table_exists(conn, "asset_type_rules"):
            print("Table asset_type_rules already exists — skipping.")
            return

        conn.execute(text("""
            CREATE TABLE asset_type_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id INTEGER REFERENCES organizations(id),
                name VARCHAR NOT NULL,
                description VARCHAR,
                conditions JSON NOT NULL DEFAULT '[]',
                condition_logic VARCHAR DEFAULT 'AND',
                target_asset_type VARCHAR NOT NULL,
                identity_mapping JSON NOT NULL DEFAULT '{}',
                default_attributes JSON NOT NULL DEFAULT '{}',
                priority INTEGER DEFAULT 100,
                source_filter VARCHAR,
                is_enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text(
            "CREATE INDEX ix_asset_type_rules_org_id ON asset_type_rules(org_id)"
        ))
        conn.execute(text(
            "CREATE INDEX ix_asset_type_rules_priority ON asset_type_rules(priority)"
        ))

        # Seed built-in rules (org_id=NULL → global, applies to all tenants)
        for rule in SEED_RULES:
            conn.execute(text("""
                INSERT INTO asset_type_rules
                    (org_id, name, description, conditions, condition_logic,
                     target_asset_type, identity_mapping, default_attributes,
                     priority, source_filter, is_enabled)
                VALUES
                    (NULL, :name, :description, :conditions, :condition_logic,
                     :target_asset_type, :identity_mapping, :default_attributes,
                     :priority, :source_filter, 1)
            """), rule)
        conn.commit()
        print(f"Created asset_type_rules table with indexes and {len(SEED_RULES)} seed rules.")


def downgrade():
    with engine.connect() as conn:
        if not _table_exists(conn, "asset_type_rules"):
            print("Table asset_type_rules does not exist — nothing to drop.")
            return
        conn.execute(text("DROP TABLE asset_type_rules"))
        conn.commit()
        print("Dropped asset_type_rules table.")


if __name__ == "__main__":
    upgrade()

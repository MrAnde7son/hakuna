import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./nessus_remediation.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from models import (  # noqa: F401
        Organization, User, MSSPOrgAccess,
        Scan, Asset, Finding, AutomateClick,
        InventoryUser, InventoryGroup, InventoryService,
        InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
        AssetOwnership, FindingOwnership,
        Campaign, CampaignFinding,
        Tag, TagAssignment, AutoTagRule,
        SLAConfig,
        Workflow, WorkflowNode, WorkflowEdge,
        WorkflowExecution, WorkflowExecutionLog,
        IntegrationConfig,
        ReportTemplate,
        Agent, AgentRun, AgentSchedule,
    )
    from threat_intel_models import (  # noqa: F401
        ThreatGroup, TTP, ThreatGroupTTP,
        ThreatCVE, ThreatCampaign, IntelRemediationCampaign,
    )
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def _migrate_add_columns():
    """Add columns to existing tables that create_all won't handle."""
    migrations = {
        "assets": [
            ("inferred_primary_user", "VARCHAR"),
            ("inferred_admin_contacts", "JSON"),
            ("inferred_team", "VARCHAR"),
            ("owner_confidence", 'VARCHAR DEFAULT "low"'),
        ],
        "findings": [
            ("first_seen", "DATETIME"),
            ("last_seen", "DATETIME"),
            ("times_seen", "INTEGER DEFAULT 1"),
            ("is_regression", "BOOLEAN DEFAULT 0"),
            ("cvss4_score", "FLOAT"),
            ("cvss4_vector", "VARCHAR"),
        ],
        "threat_cves": [
            ("cvss4_score", "FLOAT"),
            ("cvss4_vector", "VARCHAR"),
        ],
        "finding_exceptions": [
            ("conditions", "JSON"),
            ("condition_logic", 'VARCHAR DEFAULT "AND"'),
            ("override_severity", "INTEGER"),
            ("scope_tags", "JSON"),
            ("compensating_control_detail", "TEXT"),
            ("exclude_from_reports", "BOOLEAN DEFAULT 1"),
            ("review_by", "DATETIME"),
            ("org_id", "INTEGER"),
        ],
        # Multi-tenancy: add org_id to all tenant-scoped tables
        "scans": [("org_id", "INTEGER")],
        "tags": [("org_id", "INTEGER")],
        "auto_tag_rules": [("org_id", "INTEGER")],
        "campaigns": [("org_id", "INTEGER")],
        "workflows": [("org_id", "INTEGER")],
        "sla_configs": [("org_id", "INTEGER")],
        "integration_configs": [("org_id", "INTEGER")],
        "report_templates": [("org_id", "INTEGER")],
        "agent_schedules": [("next_run_at", "DATETIME")],
    }
    insp = inspect(engine)
    with engine.connect() as conn:
        for table, columns in migrations.items():
            try:
                existing = {c["name"] for c in insp.get_columns(table)}
            except Exception:
                continue
            for col_name, col_type in columns:
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
        conn.commit()

import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./nessus_remediation.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
_pool_kwargs = {} if DATABASE_URL.startswith("sqlite") else {
    "pool_pre_ping": True,   # detect stale connections (important for Cloud Run cold starts)
    "pool_recycle": 300,     # recycle connections every 5 min to avoid Cloud SQL idle timeouts
}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, **_pool_kwargs)
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
    from models.models import (  # noqa: F401
        Organization, User, MSSPOrgAccess,
        Scan, Asset, Finding, AutomateClick,
        InventoryUser, InventoryGroup, InventoryDomainTrust, InventoryService,
        InventoryNetConn, InventoryScheduledTask, InventoryPatch, InventoryLoggedOn,
        InventoryShare, InventorySoftware, InventorySecurityControl,
        InventoryComputer, InventoryPasswordPolicy, InventoryEnvVar, InventoryCertificate,
        SBOMComponent, SBOMVulnerability,
        AssetOwnership, FindingOwnership,
        Campaign, CampaignFinding,
        Tag, TagAssignment, AutoTagRule,
        SLAConfig,
        Workflow, WorkflowNode, WorkflowEdge,
        WorkflowExecution, WorkflowExecutionLog,
        IntegrationConfig,
        ReportTemplate,
        Agent, AgentRun, AgentSchedule,
        FindingException, ScanComparison,
        AggregatedSolution,
        AuditLog,
        # Integration Builder
        IntegrationCredential, DiscoveredSpec, Integration, IntegrationRun,
    )
    from models.threat_intel_models import (  # noqa: F401
        ThreatGroup, TTP, ThreatGroupTTP,
        ThreatCVE, ThreatCampaign, IntelRemediationCampaign, CisaAdvisory,
        ProductLifecycle,
        CWEEntry, ExploitReference, SSVCDecision, MSRCPatch,
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
            ("owner_confidence", "VARCHAR DEFAULT 'low'"),
            ("environment_confirmed", "BOOLEAN DEFAULT FALSE"),
            ("business_context_confirmed", "BOOLEAN DEFAULT FALSE"),
            ("first_seen", "TIMESTAMP"),
            ("last_seen", "TIMESTAMP"),
            ("times_seen", "INTEGER DEFAULT 1"),
            ("asset_status", "VARCHAR DEFAULT 'active'"),
            ("stale_since", "TIMESTAMP"),
            ("system_type", "VARCHAR"),
            ("easm_data", "JSON"),
            ("internet_facing_confidence", "VARCHAR"),
            ("internet_facing_methods", "JSON"),
            ("source_id", "VARCHAR"),
            ("source_system", "VARCHAR"),
            ("user_edited_fields", "JSON"),
            ("device_type", "VARCHAR"),
            ("cpe", "JSON"),
            ("os_confidence", "INTEGER"),
            ("source_systems", "JSON"),
        ],
        "findings": [
            ("first_seen", "TIMESTAMP"),
            ("last_seen", "TIMESTAMP"),
            ("times_seen", "INTEGER DEFAULT 1"),
            ("is_regression", "BOOLEAN DEFAULT FALSE"),
            ("auto_resolved", "BOOLEAN DEFAULT FALSE"),
            ("auto_resolved_at", "TIMESTAMP"),
            ("auto_resolved_by_scan_id", "INTEGER"),
            ("cvss4_score", "FLOAT"),
            ("cvss4_vector", "VARCHAR"),
            ("matched_ttps", "JSON"),
            ("aggregated_solution_id", "INTEGER"),
            ("source_type", "VARCHAR DEFAULT 'nessus'"),
            ("source_vuln_id", "VARCHAR"),
            ("normalized_id", "VARCHAR"),
            ("exploit_count", "INTEGER DEFAULT 0"),
            ("exploit_maturity_level", "VARCHAR"),
            ("ssvc_decision", "VARCHAR"),
            ("greynoise_seen", "BOOLEAN DEFAULT FALSE"),
            ("source_id", "VARCHAR"),
            ("source_system", "VARCHAR"),
            ("user_edited_fields", "JSON"),
            ("source_systems", "JSON"),
        ],
        "threat_cves": [
            ("cvss4_score", "FLOAT"),
            ("cvss4_vector", "VARCHAR"),
            ("exploit_count", "INTEGER DEFAULT 0"),
            ("exploit_sources", "JSON"),
            ("exploit_maturity_level", "VARCHAR"),
            ("ssvc_decision", "VARCHAR"),
            ("ssvc_exploitation", "VARCHAR"),
            ("greynoise_seen", "BOOLEAN DEFAULT 0"),
            ("greynoise_classification", "VARCHAR"),
            ("cwe_names", "JSON"),
            ("cwe_categories", "JSON"),
            ("msrc_kb_ids", "JSON"),
            ("affected_products", "JSON"),
        ],
        "finding_exceptions": [
            ("conditions", "JSON"),
            ("condition_logic", "VARCHAR DEFAULT 'AND'"),
            ("override_severity", "INTEGER"),
            ("scope_tags", "JSON"),
            ("compensating_control_detail", "TEXT"),
            ("exclude_from_reports", "BOOLEAN DEFAULT TRUE"),
            ("review_by", "TIMESTAMP"),
            ("org_id", "INTEGER"),
            ("debt_category", "VARCHAR"),
            ("mitigation_plan", "TEXT"),
        ],
        # Multi-tenancy: add org_id to all tenant-scoped tables
        "scans": [
            ("org_id", "INTEGER"),
            ("source_type", "VARCHAR DEFAULT 'nessus'"),
            ("source_version", "VARCHAR"),
            ("raw_metadata", "JSON"),
            ("schedule", "VARCHAR"),
            ("status", "VARCHAR DEFAULT 'completed'"),
            ("last_run_at", "DATETIME"),
            ("next_run_at", "DATETIME"),
            ("run_count", "INTEGER DEFAULT 0"),
        ],
        "tags": [("org_id", "INTEGER")],
        "auto_tag_rules": [("org_id", "INTEGER")],
        "campaigns": [("org_id", "INTEGER")],
        "workflows": [("org_id", "INTEGER")],
        "sla_configs": [("org_id", "INTEGER")],
        "integration_configs": [("org_id", "INTEGER")],
        "report_templates": [("org_id", "INTEGER")],
        "inventory_users": [
            ("identity_type", "VARCHAR DEFAULT 'unknown'"),
            ("identity_subtype", "VARCHAR"),
            ("source_systems", "JSON"),
            ("department", "VARCHAR"),
            ("job_title", "VARCHAR"),
            ("manager_dn", "VARCHAR"),
            ("manager_username", "VARCHAR"),
        ],
        "custom_roles": [
            ("deny_permissions", "JSON"),
        ],
        "tag_permissions": [
            ("effect", "VARCHAR DEFAULT 'allow'"),
        ],
        "agent_schedules": [("next_run_at", "DATETIME")],
        "integrations": [
            ("logo_url", "VARCHAR"),
        ],
        "integration_runs": [
            ("triggered_by", "VARCHAR DEFAULT 'manual'"),
            ("duration_ms", "INTEGER"),
            ("error_message", "TEXT"),
        ],
        "aggregated_solutions": [
            ("affected_component", "VARCHAR"),
            ("current_version", "VARCHAR"),
            ("target_version", "VARCHAR"),
            ("root_cause_type", "VARCHAR"),
            ("action_type", "VARCHAR"),
            ("action_details", "JSON"),
            ("vs_alternative", "TEXT"),
            ("asset_ids", "JSON"),
            ("asset_count", "INTEGER DEFAULT 0"),
            ("cve_ids", "JSON"),
            ("risk_reduction", "FLOAT DEFAULT 0"),
            ("efficiency_score", "FLOAT DEFAULT 0"),
            ("downstream_impact", "JSON"),
        ],
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

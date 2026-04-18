import logging
import os

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./nessus_remediation.db")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
_pool_kwargs = {} if DATABASE_URL.startswith("sqlite") else {
    "pool_size": 10,         # persistent connections in the pool
    "max_overflow": 20,      # extra connections allowed above pool_size under load
    "pool_timeout": 30,      # seconds to wait for a connection before raising
    "pool_recycle": 1800,    # recycle connections every 30 min to avoid idle timeouts
    "pool_pre_ping": True,   # detect stale connections (important for Cloud Run cold starts)
}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, **_pool_kwargs)

# SQLite requires PRAGMA foreign_keys=ON per connection for ON DELETE CASCADE to work
if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Postgres: enforce a default statement timeout so a runaway query on one
# endpoint can't saturate the connection pool or DB CPU. The default is
# reset on every checkout so a long-running job that temporarily raised
# the limit can't leak that state into the next request via pool reuse.
# TODO: 27 background-job sites open their own SessionLocal() and may issue
# statements >30s (threat-intel sync, EASM scheduler, report PDFs, lake
# maintenance, agent runs). Audit those before tightening below 120s, and
# wrap any legitimate long-running statement in disable_statement_timeout().
_DEFAULT_STATEMENT_TIMEOUT_MS = int(os.environ.get("DB_STATEMENT_TIMEOUT_MS", "120000"))
if DATABASE_URL.startswith("postgresql"):
    @event.listens_for(engine, "connect")
    def _set_pg_connect_defaults(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute(f"SET statement_timeout = {_DEFAULT_STATEMENT_TIMEOUT_MS}")
        cursor.execute("SET idle_in_transaction_session_timeout = 60000")
        cursor.close()

    @event.listens_for(engine, "checkout")
    def _reset_pg_timeout(dbapi_conn, connection_record, connection_proxy):
        # Rebind to the per-request default in case the previous user of
        # this pooled connection changed it (e.g. a long-running ingest
        # issued `SET statement_timeout = 0`).
        cursor = dbapi_conn.cursor()
        cursor.execute(f"SET statement_timeout = {_DEFAULT_STATEMENT_TIMEOUT_MS}")
        cursor.close()

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
        Scan, Asset, Finding, FindingTicket, AutomateClick,
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
        LLMInteraction, LLMInteractionOutcome,
        FindingException, ScanComparison,
        AggregatedSolution,
        AuditLog,
        # Integration Builder
        IntegrationCredential, DiscoveredSpec, Integration, IntegrationRun,
        # SIEM
        SIEMEvent, IngestEndpoint, DetectionRule, Alert, SuppressionRule,
    )
    from models.threat_intel_models import (  # noqa: F401
        ThreatGroup, TTP, ThreatGroupTTP,
        ThreatCVE, ThreatCampaign, IntelRemediationCampaign, CisaAdvisory,
        ProductLifecycle,
        CWEEntry, ExploitReference, SSVCDecision, MSRCPatch,
    )
    Base.metadata.create_all(bind=engine)
    # Ensure stub tables exist for orphaned FK references (e.g. alerts.incident_id)
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS incidents ("
            "  id INTEGER PRIMARY KEY"
            ")"
        ))
        conn.commit()
    _migrate_add_columns()
    _run_migrations()


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
            ("asset_type", "VARCHAR DEFAULT 'host'"),
            ("asset_identity", "JSON"),
            ("asset_attributes", "JSON"),
            ("custom_fields", "JSON"),
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
            ("custom_fields", "JSON"),
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
            ("last_run_at", "TIMESTAMP"),
            ("next_run_at", "TIMESTAMP"),
            ("run_count", "INTEGER DEFAULT 0"),
            ("nessus_version", "VARCHAR"),
        ],
        "tags": [("org_id", "INTEGER")],
        "auto_tag_rules": [("org_id", "INTEGER")],
        "campaigns": [("org_id", "INTEGER"), ("owner_id", "INTEGER"), ("slack_channel_id", "VARCHAR"), ("slack_channel_name", "VARCHAR")],
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
            ("is_locked", "BOOLEAN DEFAULT 0"),
            ("email", "VARCHAR"),
            ("upn", "VARCHAR"),
            ("source", "VARCHAR"),
            ("source_id", "VARCHAR"),
            ("org_id", "INTEGER"),
            ("last_synced_at", "DATETIME"),
            ("password_age_days", "INTEGER"),
            ("last_logon_days_ago", "INTEGER"),
        ],
        "inventory_groups": [
            ("source", "VARCHAR"),
            ("source_id", "VARCHAR"),
            ("org_id", "INTEGER"),
            ("group_scope", "VARCHAR"),
            ("group_type", "VARCHAR"),
            ("member_count", "INTEGER"),
            ("last_synced_at", "DATETIME"),
        ],
        "custom_roles": [
            ("deny_permissions", "JSON"),
        ],
        "tag_permissions": [
            ("effect", "VARCHAR DEFAULT 'allow'"),
        ],
        "agent_schedules": [("next_run_at", "DATETIME")],
        "users": [
            ("password_reset_token", "VARCHAR"),
            ("password_reset_expires", "TIMESTAMP"),
            ("google_id", "VARCHAR"),
            ("email_verified", "BOOLEAN DEFAULT FALSE"),
            ("email_verify_token", "VARCHAR"),
            ("email_verify_expires", "TIMESTAMP"),
            ("saml_subject_id", "VARCHAR"),
        ],
        "organizations": [
            ("stripe_customer_id", "VARCHAR"),
            ("stripe_subscription_id", "VARCHAR"),
            ("subscription_tier", "VARCHAR DEFAULT 'free'"),
            ("subscription_status", "VARCHAR"),
            ("trial_ends_at", "TIMESTAMP"),
            ("current_period_end", "TIMESTAMP"),
            ("ai_tokens_used", "INTEGER DEFAULT 0"),
            ("ai_tokens_reset_at", "TIMESTAMP"),
        ],
        "integrations": [
            ("logo_url", "VARCHAR"),
        ],
        "alerts": [
            ("entity_type", "VARCHAR"),
            ("entity_value", "VARCHAR"),
            ("asset_criticality", "INTEGER"),
            ("open_vulnerabilities", "INTEGER"),
            ("internet_facing", "BOOLEAN"),
            ("exposure_context", "JSON"),
            ("suppressed", "BOOLEAN DEFAULT FALSE"),
            ("suppression_rule_id", "INTEGER"),
            ("triage_reason", "VARCHAR"),
            ("notes", "TEXT"),
        ],
        "detection_rules": [
            ("asset_filter", "JSON"),
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
    is_pg = DATABASE_URL.startswith("postgresql")
    for table, columns in migrations.items():
        try:
            existing = {c["name"] for c in insp.get_columns(table)}
        except Exception:
            continue
        for col_name, col_type in columns:
            if col_name in existing:
                continue
            # Each ALTER TABLE runs in its own connection so one failure doesn't
            # roll back the others (important for PostgreSQL where DDL is transactional)
            try:
                with engine.connect() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
            except Exception as exc:
                logger.warning("_migrate_add_columns: skipping %s.%s — %s", table, col_name, exc)


def _run_migrations():
    """Auto-run all migration scripts in backend/migrations/ in numeric order.

    Each script must expose an upgrade() function and be idempotent.
    Tracks which migrations have already been applied in a _migrations table.
    """
    import importlib.util
    from pathlib import Path

    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    if not migrations_dir.is_dir():
        return

    # Ensure tracking table exists
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS _migrations ("
            "  name VARCHAR PRIMARY KEY,"
            "  applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
            ")"
        ))
        conn.commit()
        applied = {row[0] for row in conn.execute(text("SELECT name FROM _migrations")).fetchall()}

    scripts = sorted(migrations_dir.glob("[0-9]*.py"))
    for script in scripts:
        if script.name in applied:
            continue
        try:
            spec = importlib.util.spec_from_file_location(script.stem, script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "upgrade"):
                mod.upgrade()
                with engine.connect() as conn:
                    try:
                        conn.execute(
                            text("INSERT INTO _migrations (name) VALUES (:name)"),
                            {"name": script.name},
                        )
                        conn.commit()
                    except IntegrityError:
                        # Another worker/replica recorded this migration first
                        # (concurrent boot race). The migration body is required
                        # to be idempotent (see docstring), so this is safe.
                        conn.rollback()
                        logger.info(
                            "Migration %s already recorded by another worker",
                            script.name,
                        )
                logger.info("Migration applied: %s", script.name)
            else:
                logger.warning("Migration %s has no upgrade() — skipping", script.name)
        except Exception as exc:
            logger.error("Migration %s failed: %s", script.name, exc)
            break  # Stop on first failure to preserve order


def get_pool_status() -> dict:
    """Return connection pool metrics. Works for QueuePool (Postgres); SQLite uses StaticPool."""
    pool = engine.pool
    pool_class = type(pool).__name__
    status = {"pool_class": pool_class}
    if hasattr(pool, "size"):
        status["pool_size"] = pool.size()
    if hasattr(pool, "checkedin"):
        status["checkedin"] = pool.checkedin()
    if hasattr(pool, "checkedout"):
        status["checkedout"] = pool.checkedout()
    if hasattr(pool, "overflow"):
        status["overflow"] = pool.overflow()
    return status


def check_db_health() -> dict:
    """Quick DB connectivity check + pool status."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "pool": get_pool_status()}
    except Exception as e:
        logger.error("DB health check failed: %s", e)
        return {"status": "error", "error": str(e), "pool": get_pool_status()}

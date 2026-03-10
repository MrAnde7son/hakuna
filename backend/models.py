from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    scan_name = Column(String)
    scan_date = Column(String)
    scan_type = Column(String)
    scanner_ip = Column(String)
    nessus_version = Column(String)
    policy_used = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    ip = Column(String)
    hostname = Column(String)
    fqdn = Column(String)
    os = Column(String)
    netbios_name = Column(String)
    mac_address = Column(String)
    scan_start = Column(String)
    scan_end = Column(String)
    # User-defined
    criticality = Column(Integer, default=5)  # 1-10
    environment_tag = Column(String, default="internal")
    business_context = Column(String)
    # Inferred ownership (auto-populated from inventory data)
    inferred_primary_user = Column(String)         # From InventoryLoggedOn — likely machine user
    inferred_admin_contacts = Column(JSON, default=list)  # Local admins from InventoryUser
    inferred_team = Column(String)                 # Derived from services running on host
    owner_confidence = Column(String, default="low")  # high / medium / low

    # Scanner context (per-asset, from plugin 19506)
    scanner_ip = Column(String)
    is_internet_facing = Column(Boolean, default=False)

    # Computed
    risk_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    scan = relationship("Scan", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    # Plugin metadata
    plugin_id = Column(String, index=True)
    plugin_name = Column(String)
    plugin_family = Column(String)
    plugin_pub_date = Column(String)
    plugin_mod_date = Column(String)

    # Severity
    severity = Column(Integer, default=0)  # 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    severity_label = Column(String)
    risk_factor = Column(String)

    # Scores
    cvss2_score = Column(Float)
    cvss2_vector = Column(String)
    cvss3_score = Column(Float)
    cvss3_vector = Column(String)
    vpr_score = Column(Float)

    # CVE references
    cves = Column(JSON, default=list)
    references = Column(JSON, default=dict)

    # Content
    synopsis = Column(Text)
    description = Column(Text)
    solution = Column(Text)
    see_also = Column(JSON, default=list)

    # Asset context
    port = Column(String)
    protocol = Column(String)
    vulnerability_state = Column(String)
    plugin_output = Column(Text)

    # Enrichment
    exploit_available = Column(Boolean, default=False)
    exploit_maturity = Column(String)
    zero_day = Column(Boolean, default=False)

    # Prioritization
    priority_score = Column(Float, default=0.0)
    effort_level = Column(String)  # quick_win / medium / complex
    owner_suggestion = Column(String)  # IT / DevOps / SecOps / AppSec
    remediation_steps = Column(Text)

    # Temporal tracking (cross-scan lifecycle)
    first_seen = Column(DateTime, nullable=True)     # Earliest scan date where (plugin_id, asset_ip) appeared
    last_seen = Column(DateTime, nullable=True)      # Latest scan date where (plugin_id, asset_ip) appeared
    times_seen = Column(Integer, default=1)           # How many scans this finding has appeared in
    is_regression = Column(Boolean, default=False)    # True if it was fixed then reappeared

    # SLA tracking
    sla_due_date = Column(DateTime, nullable=True)   # Computed: scan.created_at + SLA days
    resolved_at = Column(DateTime, nullable=True)    # When manually marked resolved
    sla_status = Column(String, nullable=True)       # on_track / at_risk / breached / resolved / n/a

    # Workflow status (persists across campaigns)
    workflow_status = Column(String, default="open")  # open / in_progress / resolved / accepted_risk / false_positive
    workflow_assigned_to = Column(String, nullable=True)  # Assigned user/team
    workflow_notes = Column(Text, nullable=True)
    status_changed_at = Column(DateTime, nullable=True)

    # Exception link (set when a global exception matches this finding)
    exception_id = Column(Integer, ForeignKey("finding_exceptions.id"), nullable=True)

    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    automate_clicks = relationship("AutomateClick", back_populates="finding", cascade="all, delete-orphan")


class AutomateClick(Base):
    __tablename__ = "automate_clicks"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    plugin_id = Column(String)
    plugin_name = Column(String)
    asset_ip = Column(String)
    clicked_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="automate_clicks")


# ─────────────────────────────────────────────────────────
# Inventory Models (extracted from Info-level plugin outputs)
# ─────────────────────────────────────────────────────────

class InventoryUser(Base):
    """AD domain users, local users, and accounts seen in scan output."""
    __tablename__ = "inventory_users"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    # The asset where this user data was collected (the host scanned)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    username = Column(String, index=True)
    domain = Column(String, index=True)      # DOMAIN or hostname for local users
    sid = Column(String)
    rid = Column(Integer)                    # Relative ID (last segment of SID)
    dn = Column(String)                      # Distinguished Name (AD users)

    # Type: domain_user | local_user | computer_account | service_account
    user_type = Column(String, default="domain_user")

    # Privilege flags
    is_local_admin = Column(Boolean, default=False)   # In Administrators group on source host
    is_domain_admin = Column(Boolean, default=False)  # Member of Domain Admins / Enterprise Admins
    is_privileged = Column(Boolean, default=False)    # Any privileged group membership

    # Account state flags
    is_disabled = Column(Boolean, default=False)
    password_never_expires = Column(Boolean, default=False)
    never_logged_in = Column(Boolean, default=False)
    never_changed_password = Column(Boolean, default=False)

    # AD details
    uac = Column(Integer)                    # UserAccountControl flags
    spns = Column(JSON, default=list)        # Service Principal Names → Kerberoastable if non-empty
    member_of = Column(JSON, default=list)   # List of group DNs/names
    password_last_set = Column(String)
    date_joined = Column(String)

    # Source tracking (which plugin produced this record)
    source_plugin = Column(String)           # e.g. "69239", "10860", "10902"

    # Last seen logged on to which host
    last_logon_host = Column(String)


class InventoryGroup(Base):
    """AD and local security groups."""
    __tablename__ = "inventory_groups"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    group_name = Column(String, index=True)
    domain = Column(String)
    sid = Column(String)
    dn = Column(String)
    description = Column(String)
    members = Column(JSON, default=list)     # List of member CN/DN strings
    is_privileged = Column(Boolean, default=False)  # DA, EA, Admins, etc.
    source_plugin = Column(String)


class InventoryService(Base):
    """Running Windows/Linux services per host."""
    __tablename__ = "inventory_services"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    service_name = Column(String, index=True)   # Short name (e.g. "DNS")
    display_name = Column(String)               # Long name (e.g. "DNS Server")
    is_running = Column(Boolean, default=True)
    source_plugin = Column(String)


class InventoryNetConn(Base):
    """Network connections from netstat output."""
    __tablename__ = "inventory_netconns"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    proto = Column(String)          # tcp4, tcp6, udp4, udp6, TCP, UDP
    state = Column(String)          # LISTEN, ESTABLISHED, etc.
    local_addr = Column(String)
    local_port = Column(Integer)
    remote_addr = Column(String)
    remote_port = Column(Integer)
    pid = Column(Integer)
    source_plugin = Column(String)


class InventoryScheduledTask(Base):
    """Scheduled tasks enumerated per host."""
    __tablename__ = "inventory_scheduled_tasks"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    task_uri = Column(String)       # e.g. \CreateExplorerShellUnelevatedTask
    author = Column(String)
    run_as_sid = Column(String)     # SID from Principal/UserId
    run_as_user = Column(String)    # Resolved username (filled post-process)
    command = Column(String)
    arguments = Column(String)
    trigger_type = Column(String)
    logon_type = Column(String)
    is_enabled = Column(Boolean, default=True)
    source_plugin = Column(String)


class InventoryPatch(Base):
    """Missing patches from patch report."""
    __tablename__ = "inventory_patches"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    kb_id = Column(String, index=True)      # e.g. KB5046615
    vuln_count = Column(Integer, default=0) # Number of CVEs addressed
    description = Column(Text)              # Patch description / action text
    cves = Column(JSON, default=list)       # CVEs fixed by this patch
    source_plugin = Column(String)


class InventoryLoggedOn(Base):
    """Users currently or recently logged on to each host."""
    __tablename__ = "inventory_logged_on"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    sid = Column(String)
    domain = Column(String)
    username = Column(String, index=True)
    source_plugin = Column(String)


class InventoryShare(Base):
    """Network shares (SMB) enumerated per host."""
    __tablename__ = "inventory_shares"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    share_name = Column(String, index=True)     # e.g. ADMIN$, C$, SYSVOL
    share_type = Column(String)                  # Disk, IPC, Printer
    comment = Column(String)
    path = Column(String)                        # Local path if available
    max_users = Column(Integer)
    # Permission ACEs (from plugin 60119)
    acl = Column(JSON, default=list)             # List of {"account", "type", "permissions"}
    is_writeable = Column(Boolean, default=False)
    is_default_share = Column(Boolean, default=False)  # ADMIN$, C$, IPC$, etc.
    source_plugin = Column(String)


class InventorySoftware(Base):
    """Installed software packages per host."""
    __tablename__ = "inventory_software"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    name = Column(String, index=True)
    version = Column(String)
    installed_on = Column(String)       # Date string
    vendor = Column(String)
    source_plugin = Column(String)


class InventorySecurityControl(Base):
    """Security controls detected per host (AV, firewall, etc.)."""
    __tablename__ = "inventory_security_controls"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    control_type = Column(String, index=True)   # av, edr, firewall, backup, encryption
    product_name = Column(String)
    vendor = Column(String)
    version = Column(String)
    is_enabled = Column(Boolean, default=True)
    is_up_to_date = Column(Boolean)
    signature_date = Column(String)
    details = Column(JSON, default=dict)        # Extra key-value pairs
    source_plugin = Column(String)


class InventoryComputer(Base):
    """AD computer objects enumerated from domain."""
    __tablename__ = "inventory_computers"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    computer_name = Column(String, index=True)  # CN value
    dns_hostname = Column(String)               # dNSHostName
    os = Column(String)                         # operatingSystem
    os_version = Column(String)
    sid = Column(String)
    dn = Column(String)
    is_domain_controller = Column(Boolean, default=False)
    is_disabled = Column(Boolean, default=False)
    uac = Column(Integer)
    date_joined = Column(String)
    source_plugin = Column(String)


class InventoryEnvVar(Base):
    """Environment variables collected per host (plugin 92364)."""
    __tablename__ = "inventory_env_vars"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    name = Column(String, index=True)       # Variable name (lowercase)
    value = Column(Text)                    # Variable value
    scope = Column(String)                  # "global" or "user"
    is_sensitive = Column(Boolean, default=False)  # Detected credential/secret pattern
    source_plugin = Column(String)


class InventoryPasswordPolicy(Base):
    """Domain password policy per scan (one record per domain)."""
    __tablename__ = "inventory_password_policies"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    domain = Column(String)
    min_length = Column(Integer)
    history_count = Column(Integer)         # Passwords remembered
    max_age_days = Column(Integer)
    min_age_days = Column(Integer)
    complexity_enabled = Column(Boolean)
    reversible_encryption = Column(Boolean)
    lockout_threshold = Column(Integer)     # 0 = no lockout
    lockout_duration_mins = Column(Integer)
    lockout_window_mins = Column(Integer)
    # Risk flags
    is_weak = Column(Boolean, default=False)  # min_len < 8 or no complexity
    source_plugin = Column(String)


class InventoryAITool(Base):
    """AI/LLM software detected per host (plugin 196906)."""
    __tablename__ = "inventory_ai_tools"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    tool_name = Column(String, index=True)          # e.g. "ChatGPT for Google", "Ollama"
    # Category derived from section header: browser_extension | application | cloud_service | other
    category = Column(String, index=True)
    source_plugin = Column(String)                  # "196906"


class InventoryCertificate(Base):
    """SSL/TLS certificates discovered per host/port (plugin 10863)."""
    __tablename__ = "inventory_certificates"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    # Subject
    subject_cn    = Column(String, index=True)
    subject_o     = Column(String)
    subject_ou    = Column(String)
    subject_c     = Column(String)
    subject_email = Column(String)

    # Issuer
    issuer_cn  = Column(String, index=True)
    issuer_o   = Column(String)
    issuer_ou  = Column(String)
    issuer_c   = Column(String)

    serial_number = Column(String)
    not_before    = Column(String)
    not_after     = Column(String)
    is_expired    = Column(Boolean, default=False)
    days_until_expiry = Column(Integer)     # negative = already expired

    signature_algorithm = Column(String)
    key_algorithm = Column(String)
    key_bits      = Column(Integer)

    subject_alt_names = Column(JSON, default=list)
    is_ca          = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)

    port      = Column(Integer)
    protocol  = Column(String)
    source_plugin = Column(String)


# ─────────────────────────────────────────────────────────
# Campaigns & Ownership Models
# ─────────────────────────────────────────────────────────

class AssetOwnership(Base):
    """Custom ownership assignment for assets."""
    __tablename__ = "asset_ownership"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, unique=True, index=True)
    owner_name = Column(String)
    owner_email = Column(String)
    owner_role = Column(String)   # IT / DevOps / SecOps / AppSec / Custom
    team = Column(String)
    notes = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", backref="ownership")


class FindingOwnership(Base):
    """Custom ownership assignment for individual findings (overrides asset owner)."""
    __tablename__ = "finding_ownership"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, unique=True, index=True)
    owner_name = Column(String)
    owner_email = Column(String)
    owner_role = Column(String)   # IT / DevOps / SecOps / AppSec / Custom
    team = Column(String)
    notes = Column(Text)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    finding = relationship("Finding", backref="ownership")


# ─────────────────────────────────────────────────────────
# Tagging Models
# ─────────────────────────────────────────────────────────

class Tag(Base):
    """A tag with category:value structure (e.g. network:dmz, team:platform-eng)."""
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False)
    parent_id = Column(Integer, ForeignKey("tags.id"), nullable=True)
    color = Column(String, nullable=True, default="#6366f1")  # hex color for UI
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    parent = relationship("Tag", remote_side=[id], backref="children")
    assignments = relationship("TagAssignment", back_populates="tag", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("category", "value", name="uq_tag_category_value"),
    )


class TagAssignment(Base):
    """Junction: a tag applied to an asset or finding."""
    __tablename__ = "tag_assignments"

    id = Column(Integer, primary_key=True, index=True)
    tag_id = Column(Integer, ForeignKey("tags.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    assigned_by = Column(String, default="user")  # "user" or "rule:{id}"

    tag = relationship("Tag", back_populates="assignments")

    __table_args__ = (
        Index("ix_tag_assignment_tag", "tag_id"),
        Index("ix_tag_assignment_asset", "asset_id"),
        Index("ix_tag_assignment_finding", "finding_id"),
    )


class AutoTagRule(Base):
    """Rule that automatically applies a tag based on asset/finding conditions."""
    __tablename__ = "auto_tag_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), nullable=False)
    target_type = Column(String, nullable=False, default="asset")  # "asset" | "finding" | "both"
    # List of condition dicts: [{"field": "ip_range", "operator": "in_range", "value": "10.0.0.0/8"}]
    conditions = Column(JSON, nullable=False, default=list)
    condition_logic = Column(String, default="AND")  # "AND" | "OR"
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    last_run_count = Column(Integer, nullable=True)

    tag = relationship("Tag")


class Campaign(Base):
    """Remediation campaign grouping findings with a shared query and goal."""
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)  # None = all scans

    name = Column(String, nullable=False)
    description = Column(Text)
    status = Column(String, default="draft")  # draft / active / completed / paused
    # JSON list of condition dicts: [{"type": "has_critical_vuln"}, {"type": "admin_logged_in"}, ...]
    query = Column(JSON, default=list)
    # Logical operator between top-level conditions
    query_logic = Column(String, default="AND")  # AND / OR

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run_at = Column(DateTime)
    finding_count = Column(Integer, default=0)  # cached count from last run

    findings = relationship("CampaignFinding", back_populates="campaign", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────
# SLA Models
# ─────────────────────────────────────────────────────────

class SLAConfig(Base):
    """SLA remediation deadline per severity level."""
    __tablename__ = "sla_configs"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(Integer, unique=True, nullable=False)  # 0=Info,1=Low,2=Med,3=High,4=Critical
    severity_label = Column(String)
    days_to_remediate = Column(Integer, nullable=False)  # SLA window in calendar days
    is_enabled = Column(Boolean, default=True)
    warn_days_before = Column(Integer, default=7)   # "at_risk" threshold before breach
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CampaignFinding(Base):
    """Junction table: findings included in a campaign after query execution."""
    __tablename__ = "campaign_findings"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    # Owner assigned specifically within this campaign context
    owner_name = Column(String)
    owner_email = Column(String)
    owner_role = Column(String)
    team = Column(String)
    notes = Column(Text)
    status = Column(String, default="open")  # open / in_progress / resolved / wont_fix
    added_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("Campaign", back_populates="findings")
    finding = relationship("Finding")


# ─────────────────────────────────────────────────────────
# Workflow Engine Models (n8n-style automation)
# ─────────────────────────────────────────────────────────

class Workflow(Base):
    """An automation workflow with trigger → action graph."""
    __tablename__ = "workflows"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    status = Column(String, default="draft")  # draft / active / paused
    is_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)

    nodes = relationship("WorkflowNode", back_populates="workflow", cascade="all, delete-orphan")
    edges = relationship("WorkflowEdge", back_populates="workflow", cascade="all, delete-orphan")
    executions = relationship("WorkflowExecution", back_populates="workflow", cascade="all, delete-orphan")
    campaign = relationship("Campaign", backref="workflows")


class WorkflowNode(Base):
    """A single node (trigger, action, or condition) in the workflow graph."""
    __tablename__ = "workflow_nodes"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False, index=True)
    node_id = Column(String, nullable=False)  # client-side unique ID (e.g. "node-1")
    node_type = Column(String, nullable=False)  # trigger / action / condition
    node_subtype = Column(String, nullable=False)  # e.g. campaign_run, assign_owner, severity_check
    label = Column(String)
    config = Column(JSON, default=dict)  # node-specific configuration
    position_x = Column(Float, default=0)
    position_y = Column(Float, default=0)

    workflow = relationship("Workflow", back_populates="nodes")

    __table_args__ = (
        UniqueConstraint("workflow_id", "node_id", name="uq_workflow_node_id"),
    )


class WorkflowEdge(Base):
    """A directed connection between two nodes in a workflow."""
    __tablename__ = "workflow_edges"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False, index=True)
    edge_id = Column(String, nullable=False)  # client-side ID
    source_node_id = Column(String, nullable=False)  # references WorkflowNode.node_id
    target_node_id = Column(String, nullable=False)
    source_handle = Column(String, default="output")  # output / true / false
    target_handle = Column(String, default="input")
    label = Column(String)

    workflow = relationship("Workflow", back_populates="edges")


class WorkflowExecution(Base):
    """A single execution run of a workflow."""
    __tablename__ = "workflow_executions"

    id = Column(Integer, primary_key=True, index=True)
    workflow_id = Column(Integer, ForeignKey("workflows.id"), nullable=False, index=True)
    status = Column(String, default="running")  # running / completed / failed
    trigger_type = Column(String)  # what triggered this run
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    items_processed = Column(Integer, default=0)
    result_summary = Column(JSON, default=dict)
    error = Column(Text, nullable=True)

    workflow = relationship("Workflow", back_populates="executions")
    logs = relationship("WorkflowExecutionLog", back_populates="execution", cascade="all, delete-orphan")


class WorkflowExecutionLog(Base):
    """Log entry for a single node execution within a workflow run."""
    __tablename__ = "workflow_execution_logs"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(Integer, ForeignKey("workflow_executions.id"), nullable=False, index=True)
    node_id = Column(String, nullable=False)
    node_type = Column(String)
    node_subtype = Column(String)
    status = Column(String, default="success")  # success / failed / skipped
    items_in = Column(Integer, default=0)
    items_out = Column(Integer, default=0)
    output_data = Column(JSON, default=dict)
    error = Column(Text, nullable=True)
    executed_at = Column(DateTime, default=datetime.utcnow)

    execution = relationship("WorkflowExecution", back_populates="logs")


# ─────────────────────────────────────────────────────────
# Integration Connectors Config
# ─────────────────────────────────────────────────────────

class IntegrationConfig(Base):
    """Configuration for external integrations (Jira, ServiceNow, SMTP, Slack, Teams)."""
    __tablename__ = "integration_configs"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, nullable=False, unique=True, index=True)  # jira, servicenow, email, slack, teams
    display_name = Column(String)
    is_enabled = Column(Boolean, default=False)
    config = Column(JSON, default=dict)  # provider-specific config blob
    last_test_at = Column(DateTime, nullable=True)
    last_test_status = Column(String, nullable=True)  # ok / error
    last_test_detail = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─────────────────────────────────────────────────────────
# Global Exceptions / Waivers
# ─────────────────────────────────────────────────────────

class FindingException(Base):
    """Global exception (accepted risk / false positive) that persists across scans.
    Matched by plugin_id + optional asset scope (ip or all assets) + optional rule conditions."""
    __tablename__ = "finding_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    plugin_id = Column(String, nullable=True, index=True)  # nullable when using conditions-only matching
    plugin_name = Column(String)
    # Scope: specific asset IP or null = all assets
    asset_ip = Column(String, nullable=True, index=True)
    # Type
    exception_type = Column(String, nullable=False, default="accepted_risk")  # accepted_risk / false_positive / severity_override / compensating_control
    override_severity = Column(Integer, nullable=True)  # target severity for severity_override (0-4)
    # Compensating control detail (free-text description of the control in place)
    compensating_control_detail = Column(Text, nullable=True)  # e.g. "WAF blocks exploitation", "Network segmentation isolates host"
    # Scope: tag-based scoping (JSON array of "category:value" strings)
    scope_tags = Column(JSON, nullable=True)  # ["env:prod", "net:dmz"]
    # Rule-based matching (unified rule engine conditions)
    conditions = Column(JSON, nullable=True)  # [{field, op, value}, ...]
    condition_logic = Column(String, default="AND")  # AND / OR
    # Details
    reason = Column(Text)
    approved_by = Column(String)
    # Reporting
    exclude_from_reports = Column(Boolean, default=True)  # exclude matched findings from severity counts & totals
    # Lifecycle
    expires_at = Column(DateTime, nullable=True)  # null = permanent
    review_by = Column(DateTime, nullable=True)  # recertification date (soft reminder, does not deactivate)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_exception_plugin_asset", "plugin_id", "asset_ip"),
    )


# ─────────────────────────────────────────────────────────
# Cross-Scan Delta Tracking
# ─────────────────────────────────────────────────────────

class ScanComparison(Base):
    """Cached result of comparing two scans — tracks new/fixed/recurring findings."""
    __tablename__ = "scan_comparisons"

    id = Column(Integer, primary_key=True, index=True)
    base_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    compare_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    # Counts
    new_count = Column(Integer, default=0)
    fixed_count = Column(Integer, default=0)
    recurring_count = Column(Integer, default=0)
    # Detail lists (JSON arrays of {plugin_id, plugin_name, severity, asset_ip})
    new_findings = Column(JSON, default=list)
    fixed_findings = Column(JSON, default=list)
    # Severity breakdown of changes
    new_by_severity = Column(JSON, default=dict)    # {4: 5, 3: 10, ...}
    fixed_by_severity = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("base_scan_id", "compare_scan_id", name="uq_scan_comparison"),
    )

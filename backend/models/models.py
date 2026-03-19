import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from core.database import Base
from integrations.model_registry import importable


# ─────────────────────────────────────────────────────────
# Auth & Multi-Tenancy Models
# ─────────────────────────────────────────────────────────

class Organization(Base):
    """Tenant — a company, team, or MSSP client."""
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True, index=True)
    org_type = Column(String, default="standard")  # standard | mssp
    parent_org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    settings = Column(JSON, default=dict)  # org-level config overrides
    created_at = Column(DateTime, default=datetime.utcnow)

    # EASM integration (hakuna-scanner)
    easm_org_id = Column(String, nullable=True)       # UUID of org in hakuna-scanner
    easm_domain = Column(String, nullable=True)        # Corporate domain extracted from email

    parent = relationship("Organization", remote_side=[id], backref="children")
    users = relationship("User", back_populates="organization")


class User(Base):
    """Platform user — belongs to one organization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    display_name = Column(String)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    role = Column(String, default="analyst")  # superadmin | org_admin | analyst | viewer | custom
    is_active = Column(Boolean, default=True)
    locale = Column(String, default="en")  # User's preferred language: en, ja, fr, de, he, ru, zh
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="users")

    __table_args__ = (
        Index("ix_user_org", "org_id"),
    )


class MSSPOrgAccess(Base):
    """Grants an MSSP org access to a client org's data."""
    __tablename__ = "mssp_org_access"

    id = Column(Integer, primary_key=True, index=True)
    mssp_org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    client_org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    mssp_org = relationship("Organization", foreign_keys=[mssp_org_id])
    client_org = relationship("Organization", foreign_keys=[client_org_id])

    __table_args__ = (
        UniqueConstraint("mssp_org_id", "client_org_id", name="uq_mssp_client"),
    )


# ─────────────────────────────────────────────────────────
# Custom RBAC — Roles, Tag Permissions, User Assignments
# ─────────────────────────────────────────────────────────

class CustomRole(Base):
    """Org-defined role with configurable base permissions and tag-level access rules."""
    __tablename__ = "custom_roles"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(String)
    # Feature flags: {"read_scans": true, "write_findings": true, "manage_tags": false, ...}
    base_permissions = Column(JSON, default=dict)
    # Deny flags: same keys as base_permissions — deny always wins over allow
    deny_permissions = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    org = relationship("Organization")
    tag_permissions = relationship("TagPermission", back_populates="role", cascade="all, delete-orphan")
    user_assignments = relationship("UserCustomRole", back_populates="role", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_custom_role_org_name"),
        Index("ix_custom_role_org", "org_id"),
    )


class TagPermission(Base):
    """Maps a custom role to read or write access on a specific tag or tag category."""
    __tablename__ = "tag_permissions"

    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("custom_roles.id"), nullable=False)
    target_type = Column(String, nullable=False)       # "tag" | "category"
    target_id = Column(Integer, ForeignKey("tags.id"), nullable=True)      # when target_type="tag"
    target_category = Column(String, nullable=True)    # when target_type="category"
    permission = Column(String, nullable=False)        # "read" | "write"
    effect = Column(String, nullable=False, default="allow")  # "allow" | "deny"

    role = relationship("CustomRole", back_populates="tag_permissions")
    tag = relationship("Tag", foreign_keys=[target_id])

    __table_args__ = (
        UniqueConstraint("role_id", "target_type", "target_id", "target_category", "permission", "effect",
                         name="uq_tag_permission_v2"),
        Index("ix_tag_perm_role", "role_id"),
    )


class UserCustomRole(Base):
    """Assigns a custom role to a user (many-to-many, stacking permissions)."""
    __tablename__ = "user_custom_roles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("custom_roles.id"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    assigned_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
    role = relationship("CustomRole", back_populates="user_assignments")

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_custom_role"),
        Index("ix_ucr_user", "user_id"),
    )


# ─────────────────────────────────────────────────────────
# Core Data Models
# ─────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    filename = Column(String, nullable=False)
    scan_name = Column(String)
    scan_date = Column(String)
    scan_type = Column(String)
    scanner_ip = Column(String)
    nessus_version = Column(String)
    policy_used = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Multi-source provenance
    source_type = Column(String, default="nessus")      # nessus | qualys | rapid7 | openvas | ...
    source_version = Column(String)                       # scanner version (generalizes nessus_version)
    raw_metadata = Column(JSON, default=dict)             # full original scan-level metadata from parser

    # Scheduling support
    schedule = Column(String, nullable=True)              # cron expression (e.g. "0 */6 * * *")
    status = Column(String, default="completed")          # idle | running | completed | failed
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)

    organization = relationship("Organization")
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan", foreign_keys="[Finding.scan_id]")


@importable(
    slug="asset",
    display_name="Asset",
    category="core",
    dedup_keys=["source_system", "source_id"],
    required_fields=["ip", "hostname"],
    description="Network assets — hosts, servers, endpoints, cloud instances",
)
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
    environment_confirmed = Column(Boolean, default=False)
    business_context = Column(String)                   # aka biz_function — "Database Server", "Payment Processing", etc.
    business_context_confirmed = Column(Boolean, default=False)
    biz_num_users = Column(Integer, nullable=True)         # number of users on this asset
    biz_revenue_impact = Column(String, nullable=True)     # none / low / medium / high / critical
    # Inferred ownership (auto-populated from inventory data)
    inferred_primary_user = Column(String)         # From InventoryLoggedOn — likely machine user
    inferred_admin_contacts = Column(JSON, default=list)  # Local admins from InventoryUser
    inferred_team = Column(String)                 # Derived from services running on host
    owner_confidence = Column(String, default="low")  # high / medium / low

    # Scanner context (per-asset, from plugin 19506 / host properties)
    scanner_ip = Column(String)
    is_internet_facing = Column(Boolean, default=False)
    internet_facing_confidence = Column(String, nullable=True)   # confirmed / high / medium / low
    internet_facing_methods = Column(JSON, default=list)          # e.g. ["public_ip", "inbound_netconn", "public_ca_cert"]
    is_credentialed = Column(Boolean, default=False)  # Was the scan authenticated?
    last_auth_run = Column(String)                     # LastAuthenticatedResults timestamp
    system_type = Column(String)                        # e.g. "web_application" for WAS scans

    # OS / device enrichment (from plugins 11936, 45590)
    device_type = Column(String)                        # server, workstation, router, switch, firewall, printer, hypervisor, wap, voip, storage, unknown
    cpe = Column(JSON, default=list)                    # CPE URIs from plugin 45590, e.g. ["cpe:/o:cisco:ios:15.1"]
    os_confidence = Column(Integer)                     # 0-100 confidence from plugin 11936

    # Computed
    risk_score = Column(Float, default=0.0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # EASM enrichment (from hakuna-scanner)
    easm_data = Column(JSON, nullable=True)  # {tech_stack, open_ports, tls_cert, cdn_provider, waf, dns_records, http_status, http_title, http_url, easm_tags, easm_source, easm_asset_id}

    # Lifecycle tracking (cross-scan)
    first_seen = Column(DateTime, nullable=True)       # Earliest scan date this IP appeared
    last_seen = Column(DateTime, nullable=True)        # Latest scan date this IP appeared
    times_seen = Column(Integer, default=1)             # Number of scans this IP appeared in
    asset_status = Column(String, default="active")     # active / stale
    stale_since = Column(DateTime, nullable=True)       # When asset was first not seen in a rescan

    # Integration Builder provenance
    source_id = Column(String, nullable=True)           # Original ID in the source tool
    source_system = Column(String, nullable=True)       # "tenable_sc" | "crowdstrike" | …
    source_systems = Column(JSON, default=list)         # All sources that contributed data: ["nessus", "easm", "crowdstrike"]
    user_edited_fields = Column(JSON, default=list)     # Fields manually changed by user (protected from overwrite)

    scan = relationship("Scan", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


@importable(
    slug="finding",
    display_name="Finding / Vulnerability",
    category="core",
    dedup_keys=["source_system", "source_id"],
    required_fields=["plugin_name", "severity"],
    parent_hint={"field": "asset_id", "parent_slug": "asset", "resolve_by": ["ip", "hostname"]},
    description="Vulnerability findings from scanners and security tools",
)
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)

    # Multi-source provenance
    source_type = Column(String, default="nessus")      # which scanner produced this finding
    source_vuln_id = Column(String)                       # native scanner vuln ID (Nessus=plugin_id, Qualys=QID, etc.)
    normalized_id = Column(String, index=True)            # cross-source identity (CVE-based when available)

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
    cvss4_score = Column(Float)
    cvss4_vector = Column(String)
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

    # Threat intel enrichment (populated from threat_cves table)
    is_kev = Column(Boolean, default=False)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    ransomware_linked = Column(Boolean, default=False)
    trending_in_news = Column(Boolean, default=False)

    # Additional intel enrichment (from new data sources)
    exploit_count = Column(Integer, default=0)  # Total public exploits across all sources
    exploit_maturity_level = Column(String)  # "none" | "poc" | "functional" | "weaponized"
    ssvc_decision = Column(String)  # CISA SSVC decision: "Track" | "Track*" | "Attend" | "Act"
    greynoise_seen = Column(Boolean, default=False)  # Actively exploited per GreyNoise

    # ATT&CK TTP matching (populated by ttp_matcher)
    matched_ttps = Column(JSON, default=list)  # [{technique_id, name, tactic, mitre_url, match_reason, confidence}]

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

    # Delta tracking: auto-set when a prior finding disappears from a rescan
    auto_resolved = Column(Boolean, default=False)      # True if marked fixed by delta logic (vs manual)
    auto_resolved_at = Column(DateTime, nullable=True)  # When delta logic marked it fixed
    auto_resolved_by_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)  # Which new scan caused the auto-resolve

    # SLA tracking
    sla_due_date = Column(DateTime, nullable=True)   # Computed: scan.created_at + SLA days
    resolved_at = Column(DateTime, nullable=True)    # When manually marked resolved
    sla_status = Column(String, nullable=True)       # on_track / at_risk / breached / resolved / n/a

    # Validated context (analyst-confirmed assessment)
    ctx_reachability = Column(String, nullable=True)       # unreachable / internal_only / internet_facing / unknown
    ctx_exploitability = Column(String, nullable=True)     # not_exploitable / requires_conditions / easily_exploitable / unknown
    ctx_accessibility = Column(String, nullable=True)      # restricted / authenticated_only / public / unknown
    ctx_compensating_control = Column(Text, nullable=True) # free-text description of compensating controls

    # Workflow status (persists across campaigns)
    workflow_status = Column(String, default="open")  # open / in_progress / resolved / accepted_risk / false_positive
    workflow_assigned_to = Column(String, nullable=True)  # Assigned user/team
    workflow_notes = Column(Text, nullable=True)
    status_changed_at = Column(DateTime, nullable=True)

    # Exception link (set when a global exception matches this finding)
    exception_id = Column(Integer, ForeignKey("finding_exceptions.id"), nullable=True)

    # Aggregated solution link (set when findings are grouped by root cause)
    aggregated_solution_id = Column(Integer, ForeignKey("aggregated_solutions.id"), nullable=True)

    # Integration Builder provenance
    source_id = Column(String, nullable=True)           # Original ID in the source tool
    source_system = Column(String, nullable=True)       # Source system identifier
    source_systems = Column(JSON, default=list)         # All sources that contributed data: ["nessus", "easm", "qualys"]
    user_edited_fields = Column(JSON, default=list)     # Fields manually changed by user (protected from overwrite)

    scan = relationship("Scan", back_populates="findings", foreign_keys="[Finding.scan_id]")
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

    # Identity classification
    identity_type = Column(String, default="unknown")    # human | non_human | unknown
    identity_subtype = Column(String)                    # service_account | machine_identity | bot | scheduled_task | employee | contractor

    # Source tracking (which plugin produced this record)
    source_plugin = Column(String)           # e.g. "69239", "10860", "10902"
    source_systems = Column(JSON, default=list)  # ["AD", "Windows", "Linux", etc.]

    # Organizational attributes (from AD or enrichment)
    department = Column(String)
    job_title = Column(String)
    manager_dn = Column(String)              # DN of manager (from AD)
    manager_username = Column(String)         # Resolved manager username

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


class InventoryDomainTrust(Base):
    """AD domain trust relationships."""
    __tablename__ = "inventory_domain_trusts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    trusted_domain = Column(String, index=True)     # FQDN of trusted domain (trustPartner)
    flat_name = Column(String)                       # NetBIOS name (e.g. RESEARCH)
    sid = Column(String)                             # Domain SID
    dn = Column(String)                              # DN of trust object
    trust_direction = Column(String)                 # inbound / outbound / bidirectional
    trust_type = Column(String)                      # downlevel / uplevel / mit_kerberos / dce
    trust_attributes = Column(Integer)               # Raw flags
    is_transitive = Column(Boolean, default=False)
    is_sid_filtering_enabled = Column(Boolean, default=True)
    source_domain = Column(String)                   # Domain where the trust was found
    source_plugin = Column(String)
    when_created = Column(String)


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


@importable(
    slug="inventory_software",
    display_name="Installed Software",
    category="inventory",
    dedup_keys=["asset_id", "name", "version"],
    required_fields=["name"],
    parent_hint={"field": "asset_id", "parent_slug": "asset", "resolve_by": ["ip", "hostname"]},
    description="Installed software packages per host from CMDB or scans",
)
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
    category = Column(String, index=True)  # dev_tools, collaboration, security, etc.
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


class InventoryDatabaseInstance(Base):
    """Database server instances detected per host (MSSQL, MySQL, PostgreSQL, Oracle, etc.)."""
    __tablename__ = "inventory_database_instances"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    db_type = Column(String, index=True)        # mssql / mysql / postgresql / oracle / mongodb / redis
    instance_name = Column(String)              # e.g. MSSQLSERVER, SQLEXPRESS
    version = Column(String)                    # detected version string
    port = Column(Integer)                      # listening port
    databases = Column(JSON, default=list)      # list of database names (if extractable)
    named_pipes = Column(JSON, default=list)    # MSSQL named pipes
    is_running = Column(Boolean, default=True)
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


class InventoryProcess(Base):
    """Running processes per host (from WMI process enumeration)."""
    __tablename__ = "inventory_processes"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    process_name = Column(String, index=True)       # e.g. "svchost.exe"
    pid = Column(Integer)
    ppid = Column(Integer)                           # Parent PID (derived from tree)
    session_id = Column(Integer)                     # Windows session ID (SID column)
    parent_name = Column(String)                     # Parent process name
    depth = Column(Integer, default=0)               # Tree depth level
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


class InventoryCredential(Base):
    """Credential exposure findings extracted from credential-related plugins."""
    __tablename__ = "inventory_credentials"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    credential_type = Column(String, index=True)     # default_account | cleartext | brute_forceable | weak_config | shared_credential
    protocol = Column(String, index=True)             # ssh, telnet, ftp, snmp, vnc, smb, http, rdp, etc.
    username = Column(String)                          # detected username if available
    severity = Column(String, index=True)              # critical, high, medium, low
    port = Column(Integer)                             # port where credential issue was found
    description = Column(Text)                         # brief description of the finding
    plugin_name = Column(String)                       # original Nessus plugin name
    source_plugin = Column(String, index=True)         # plugin_id
    remediation = Column(Text)                         # suggested fix


# ─────────────────────────────────────────────────────────
# SBOM Models
# ─────────────────────────────────────────────────────────

@importable(
    slug="sbom_component",
    display_name="SBOM Component",
    category="sbom",
    dedup_keys=["asset_id", "name", "version"],
    required_fields=["name"],
    parent_hint={"field": "asset_id", "parent_slug": "asset", "resolve_by": ["ip", "hostname"]},
    description="Software bill of materials — components with EOL and lifecycle tracking",
)
class SBOMComponent(Base):
    """Software component with EOL & running status, linked from InventorySoftware."""
    __tablename__ = "sbom_components"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    software_id = Column(Integer, ForeignKey("inventory_software.id"), nullable=True)

    name = Column(String, index=True)
    version = Column(String)
    vendor = Column(String)
    cpe = Column(String)                              # CPE 2.3 URI
    purl = Column(String)                             # Package URL
    component_type = Column(String, index=True)       # application | library | runtime | os | firmware

    parent_component_id = Column(Integer, ForeignKey("sbom_components.id"), nullable=True)
    parent = relationship("SBOMComponent", remote_side="SBOMComponent.id", backref="children")

    is_running = Column(Boolean, default=False)
    eol_date = Column(String)
    eol_status = Column(String, default="unknown")    # active | eol | approaching_eol | unknown

    cve_count = Column(Integer, default=0)
    max_severity = Column(Integer, default=0)         # 0-4 matching Finding severity
    max_cvss = Column(Float)
    priority_tier = Column(String)                    # P1-P5

    source_plugin = Column(String)

    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", "name", "version", name="uq_sbom_component"),
    )


class SBOMVulnerability(Base):
    """CVE associated with an SBOM component."""
    __tablename__ = "sbom_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    component_id = Column(Integer, ForeignKey("sbom_components.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True)

    cve_id = Column(String, index=True)
    severity = Column(Integer, default=0)             # 0-4
    cvss_score = Column(Float)
    epss_score = Column(Float)
    in_kev = Column(Boolean, default=False)
    remediation_note = Column(Text)
    priority_tier = Column(String)                    # P1-P5

    component = relationship("SBOMComponent", backref="vulnerabilities")

    __table_args__ = (
        UniqueConstraint("component_id", "cve_id", name="uq_sbom_vuln"),
    )


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
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
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
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), nullable=True)
    target_type = Column(String, nullable=False, default="asset")  # "asset" | "finding" | "both"
    # List of condition dicts: [{"field": "ip_range", "operator": "in_range", "value": "10.0.0.0/8"}]
    conditions = Column(JSON, nullable=False, default=list)
    condition_logic = Column(String, default="AND")  # "AND" | "OR"
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    last_run_count = Column(Integer, nullable=True)

    tag = relationship("Tag")


class OwnershipRule(Base):
    """Rule that automatically assigns ownership to assets/findings based on conditions."""
    __tablename__ = "ownership_rules"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    target_type = Column(String, nullable=False, default="asset")  # "asset" | "finding" | "both"
    conditions = Column(JSON, nullable=False, default=list)
    condition_logic = Column(String, default="AND")  # "AND" | "OR"
    priority = Column(Integer, default=100)          # lower number = evaluated first / wins
    # Action: ownership fields to set (None = leave untouched)
    owner_name = Column(String, nullable=True)
    owner_email = Column(String, nullable=True)
    owner_role = Column(String, nullable=True)       # IT / DevOps / SecOps / AppSec / Custom
    team = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    overwrite_existing = Column(Boolean, default=False)  # overwrite manually-set ownership
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    last_run_count = Column(Integer, nullable=True)


class Campaign(Base):
    """Remediation campaign grouping findings with a shared query and goal."""
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
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
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    severity = Column(Integer, nullable=False)  # 0=Info,1=Low,2=Med,3=High,4=Critical
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
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    status = Column(String, default="draft")  # draft / active / paused
    is_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    run_count = Column(Integer, default=0)
    version = Column(Integer, default=1)
    version_history = Column(JSON, default=list)  # list of {version, nodes, edges, saved_at}

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
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    provider = Column(String, nullable=False, index=True)  # jira, servicenow, email, slack, teams
    display_name = Column(String)
    is_enabled = Column(Boolean, default=False)
    config = Column(JSON, default=dict)  # provider-specific config blob
    last_test_at = Column(DateTime, nullable=True)
    last_test_status = Column(String, nullable=True)  # ok / error
    last_test_detail = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─────────────────────────────────────────────────────────
# External Tag Sources (ServiceNow CMDB, CSV exports, etc.)
# ─────────────────────────────────────────────────────────

class ExternalTagSource(Base):
    """A named external system that provides asset tags (CMDB, CSV, REST API)."""
    __tablename__ = "external_tag_sources"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)           # "ServiceNow CMDB", "Infoblox", etc.
    source_type = Column(String, nullable=False)    # "csv" | "servicenow" | "api"
    # How to match the external record to an internal asset
    match_field = Column(String, default="any")     # "ip" | "hostname" | "fqdn" | "any"
    # API source config (ServiceNow / generic REST)
    api_url = Column(String, nullable=True)
    api_config = Column(JSON, default=dict)         # {"auth_type": "basic|token", "username": ..., "password": ..., "token": ..., "tag_field": ..., "id_field": ...}
    # Whether to auto-create unmapped tags in the internal tag tree
    auto_create_tags = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_synced_at = Column(DateTime, nullable=True)
    last_sync_count = Column(Integer, nullable=True)  # assets tagged in last sync
    last_sync_error = Column(String, nullable=True)

    maps = relationship("ExternalTagMap", back_populates="source", cascade="all, delete-orphan")


class ExternalTagMap(Base):
    """Translation rule: external tag value → internal Tag."""
    __tablename__ = "external_tag_maps"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("external_tag_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    external_tag = Column(String, nullable=False)       # e.g. "network:dmz", "Production", "DMZ Servers"
    internal_tag_id = Column(Integer, ForeignKey("tags.id", ondelete="SET NULL"), nullable=True)
    # null internal_tag_id + auto_create_tags=True on source → create tag from external_tag string

    source = relationship("ExternalTagSource", back_populates="maps")
    internal_tag = relationship("Tag")


# ─────────────────────────────────────────────────────────
# Global Exceptions / Waivers
# ─────────────────────────────────────────────────────────

class FindingException(Base):
    """Global exception (accepted risk / false positive) that persists across scans.
    Matched by plugin_id + optional asset scope (ip or all assets) + optional rule conditions."""
    __tablename__ = "finding_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    plugin_id = Column(String, nullable=True, index=True)  # nullable when using conditions-only matching
    plugin_name = Column(String)
    # Scope: specific asset IP or null = all assets
    asset_ip = Column(String, nullable=True, index=True)
    # Type
    exception_type = Column(String, nullable=False, default="accepted_risk")  # accepted_risk / false_positive / severity_override / compensating_control / technical_debt
    override_severity = Column(Integer, nullable=True)  # target severity for severity_override (0-4)
    # Compensating control detail (free-text description of the control in place)
    compensating_control_detail = Column(Text, nullable=True)  # e.g. "WAF blocks exploitation", "Network segmentation isolates host"
    # Technical debt fields (used when exception_type = "technical_debt")
    debt_category = Column(String, nullable=True)  # legacy_system / business_requirement / vendor_dependency / compatibility / cost
    mitigation_plan = Column(Text, nullable=True)  # What compensating controls are in place
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

class ReportTemplate(Base):
    """Saved report/dashboard template configuration."""
    __tablename__ = "report_templates"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    config = Column(JSON, nullable=False, default=dict)  # {widgets: [...]}
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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


# ── Mini Agents ──────────────────────────────────────────────────────

class Agent(Base):
    """User-defined mini agent with instructions, tools, guardrails, and memory."""
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String)
    system_prompt = Column(Text, nullable=False)          # agent instructions
    tools = Column(JSON, default=list)                    # list of tool names from registry
    guardrails = Column(JSON, default=dict)               # {max_steps, read_only, blocked_tools, scope_scan_id}
    memory = Column(JSON, default=dict)                   # persistent key-value memory
    model = Column(String, default="claude-sonnet-4-6")   # which Claude model to use
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = relationship("AgentRun", back_populates="agent", cascade="all, delete-orphan")
    documents = relationship("AgentDocument", back_populates="agent", cascade="all, delete-orphan")


class AgentDocument(Base):
    """Uploaded file for RAG context — chunked text attached to an agent."""
    __tablename__ = "agent_documents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    content_type = Column(String)                         # MIME type
    size_bytes = Column(Integer, default=0)
    chunks = Column(JSON, default=list)                   # list of text chunks for retrieval
    chunk_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    agent = relationship("Agent", back_populates="documents")


class AgentRun(Base):
    """A single execution of a mini agent."""
    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    input = Column(Text, nullable=False)
    output = Column(Text)
    trace = Column(JSON, default=list)       # step-by-step log [{role, content, tool_calls, ...}]
    status = Column(String, default="pending")  # pending / running / done / failed
    error = Column(Text)
    steps_used = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)

    agent = relationship("Agent", back_populates="runs")


class AgentSchedule(Base):
    """Cron schedule for automated agent runs."""
    __tablename__ = "agent_schedules"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)
    cron_expression = Column(String, nullable=False)  # e.g. "0 8 * * 1-5"
    input_template = Column(Text)                      # default input for scheduled runs
    is_enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    agent = relationship("Agent")


# ─────────────────────────────────────────────────────────
# Aggregated Solutions (root-cause grouping)
# ─────────────────────────────────────────────────────────

class AggregatedSolution(Base):
    """Groups related findings across assets by root cause into a single remediation action."""
    __tablename__ = "aggregated_solutions"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # Component fingerprint
    affected_component = Column(String, index=True)          # "Node.js", "OpenSSL", "VMware Tools"
    current_version = Column(String, nullable=True)          # "14.x" (if detectable)
    target_version = Column(String, nullable=True)           # "18.17.1" (from solution)

    # Classification
    root_cause_type = Column(String, nullable=False, index=True)  # outdated_version, deprecated_protocol, eol_software, misconfiguration, missing_patch
    action_type = Column(String, nullable=False, index=True)      # upgrade_component, disable_protocol, migrate_to_supported, remediate_config, apply_patch, bulk_patch

    # Human-readable
    title = Column(String, nullable=False)
    description = Column(Text)
    action_details = Column(JSON, nullable=True)             # {from_version, to_version, cmd, config_change, ...}
    vs_alternative = Column(Text, nullable=True)             # "Would otherwise require 42 individual actions"

    # Cross-asset scope
    asset_ids = Column(JSON, default=list)                   # [asset_id, ...]
    asset_count = Column(Integer, default=0)

    # Findings & CVEs collapsed
    finding_count = Column(Integer, default=0)
    finding_ids = Column(JSON, default=list)
    cve_ids = Column(JSON, default=list)                     # All unique CVEs resolved by this action

    # Scoring
    severity_max = Column(Integer, default=0)
    priority_score = Column(Float, default=0.0)
    risk_reduction = Column(Float, default=0.0)              # % of total scan risk resolved
    efficiency_score = Column(Float, default=0.0)            # (vulns_resolved / actions) × risk × breadth

    # Downstream impact assessment (populated for upgrade_component / migrate_to_supported)
    downstream_impact = Column(JSON, nullable=True)          # {verdict, net_severity_delta, introduced_cves, alternative_versions}

    effort_level = Column(String)
    owner_suggestion = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Keep backward compat FK (nullable now)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    scan = relationship("Scan")

    # Legacy category alias for backward compat
    @property
    def category(self):
        return self.root_cause_type


# ─────────────────────────────────────────────────────────
# Benchmarks
# ─────────────────────────────────────────────────────────

class BenchmarkReference(Base):
    """Industry benchmark reference data for comparing org metrics against peers."""
    __tablename__ = "benchmark_references"

    id = Column(Integer, primary_key=True, index=True)
    metric = Column(String, nullable=False, index=True)       # e.g. risk_grade, mttr_critical, sla_compliance
    industry = Column(String, nullable=False, default="all")  # all, financial, healthcare, technology, government, etc.
    org_size = Column(String, nullable=False, default="all")  # all, small, medium, large, enterprise
    p25 = Column(Float, nullable=False)                       # 25th percentile (bottom quartile)
    p50 = Column(Float, nullable=False)                       # median
    p75 = Column(Float, nullable=False)                       # 75th percentile (top quartile)
    p90 = Column(Float, nullable=True)                        # 90th percentile (top decile)
    unit = Column(String, default="")                         # days, percent, score, count
    higher_is_better = Column(Boolean, default=True)          # risk_grade score: higher=better; MTTR: lower=better
    source = Column(String, nullable=True)                    # e.g. "Qualys 2024", "Verizon DBIR 2024"
    source_year = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("metric", "industry", "org_size", name="uq_benchmark_ref"),
    )


# ─────────────────────────────────────────────────────────
# Audit / Change Log
# ─────────────────────────────────────────────────────────

class AuditLog(Base):
    """Immutable record of every create/update/delete action on platform entities."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    # Actor
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    actor_email = Column(String, nullable=True)          # snapshot at time of action
    actor_display_name = Column(String, nullable=True)
    # Action
    action = Column(String, nullable=False, index=True)  # create / update / delete / enable / disable / assign
    # Subject
    entity_type = Column(String, nullable=False, index=True)  # exception / sla_config / campaign / workflow / asset_ownership / finding_ownership / finding_status / tag / auto_tag_rule
    entity_id = Column(Integer, nullable=True, index=True)
    entity_name = Column(String, nullable=True)          # human-readable label at time of action
    # Diff
    changes = Column(JSON, nullable=True)                # {"field": {"old": X, "new": Y}}
    # Context
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


# ─────────────────────────────────────────────────────────
# Integration Builder Models
# ─────────────────────────────────────────────────────────

def _gen_uuid():
    return str(uuid.uuid4())


class IntegrationCredential(Base):
    """Encrypted credential sets for external tool connections."""
    __tablename__ = "integration_credentials"

    id = Column(String, primary_key=True, default=_gen_uuid)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    connector_id = Column(String, nullable=False, index=True)
    auth_type = Column(String, nullable=False)  # api_key | oauth2 | basic | bearer | pat
    encrypted_values = Column(Text, nullable=False)  # AES-256-GCM encrypted JSON
    instance_url = Column(String, nullable=True)
    connected_user = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # OAuth access token expiry
    encrypted_refresh_token = Column(Text, nullable=True)  # AES-256-GCM encrypted

    integrations = relationship("Integration", back_populates="credential")


class DiscoveredSpec(Base):
    """Cached discovered API specs from external tools."""
    __tablename__ = "discovered_specs"

    id = Column(String, primary_key=True, default=_gen_uuid)
    hostname = Column(String, nullable=False, unique=True, index=True)
    spec_source = Column(String, nullable=False)  # openapi | graphql | llm | registry | upload
    raw_spec = Column(JSON, nullable=True)
    parsed_spec = Column(JSON, nullable=False)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    refreshed_at = Column(DateTime, nullable=True)


class Integration(Base):
    """Saved integration definitions — a configured connection to an external tool."""
    __tablename__ = "integrations"

    id = Column(String, primary_key=True, default=_gen_uuid)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    direction = Column(String, nullable=False)  # pull | push
    entity = Column(String, nullable=False)  # asset | finding | action
    transport_type = Column(String, nullable=False)  # api | sql | file | mcp
    transport_config = Column(JSON, nullable=False, default=dict)
    credentials_id = Column(String, ForeignKey("integration_credentials.id"), nullable=True)
    records_path = Column(String, nullable=True)  # dot-path to records array in response
    field_map = Column(JSON, nullable=False, default=list)
    dedup_key = Column(JSON, nullable=False, default=list)  # stored as JSON array (SQLite has no array type)
    params = Column(JSON, nullable=False, default=dict)
    schedule = Column(String, nullable=True)  # cron expression
    enabled = Column(Boolean, nullable=False, default=False)
    template_id = Column(String, nullable=True)  # OOTB template used
    logo_url = Column(String, nullable=True)  # custom logo URL or auto-fetched favicon
    spec_cache_id = Column(String, ForeignKey("discovered_specs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String, default="never")  # success | error | running | never
    last_run_records = Column(Integer, default=0)

    credential = relationship("IntegrationCredential", back_populates="integrations")
    spec_cache = relationship("DiscoveredSpec")
    runs = relationship("IntegrationRun", back_populates="integration", cascade="all, delete-orphan")


class IntegrationRun(Base):
    """Run history for integration executions."""
    __tablename__ = "integration_runs"

    id = Column(String, primary_key=True, default=_gen_uuid)
    integration_id = Column(String, ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, index=True)
    triggered_by = Column(String, default="manual")  # manual | schedule
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)  # execution duration in milliseconds
    status = Column(String, default="running")  # success | error | partial | running
    records_fetched = Column(Integer, default=0)
    records_inserted = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    records_skipped = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)  # top-level error message for quick display
    errors = Column(JSON, nullable=False, default=list)
    step_log = Column(JSON, nullable=False, default=list)

    integration = relationship("Integration", back_populates="runs")

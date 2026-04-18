import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index, text
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

    # Stripe billing
    stripe_customer_id = Column(String, nullable=True, index=True)
    stripe_subscription_id = Column(String, nullable=True)
    subscription_tier = Column(String, default="free")          # free | pro
    subscription_status = Column(String, nullable=True)         # active | past_due | canceled | trialing
    trial_ends_at = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)

    # AI token quota (Pro plan)
    ai_tokens_used = Column(Integer, default=0)
    ai_tokens_reset_at = Column(DateTime, nullable=True)

    parent = relationship("Organization", remote_side=[id], backref="children")
    users = relationship("User", back_populates="organization")


class User(Base):
    """Platform user — belongs to one organization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, unique=True, index=True)
    hashed_password = Column(String, nullable=True)  # Nullable for Google OAuth users
    google_id = Column(String, nullable=True, unique=True, index=True)  # Google sub claim
    display_name = Column(String)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    role = Column(String, default="analyst")  # superadmin | org_admin | analyst | viewer | custom
    is_active = Column(Boolean, default=True)
    locale = Column(String, default="en")  # User's preferred language: en, ja, fr, de, he, ru, zh
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)
    password_reset_token = Column(String, nullable=True, index=True)
    password_reset_expires = Column(DateTime, nullable=True)
    email_verified = Column(Boolean, default=False)
    email_verify_token = Column(String, nullable=True, index=True)
    email_verify_expires = Column(DateTime, nullable=True)
    saml_subject_id = Column(String, nullable=True, index=True)  # SAML NameID from IdP

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


class OrgInvite(Base):
    """Self-serve invite for an MSSP to onboard a new client org."""
    __tablename__ = "org_invites"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, nullable=False, unique=True, index=True)
    mssp_org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    invited_email = Column(String, nullable=True)       # Pre-fill email; null = open invite
    client_org_name = Column(String, nullable=True)     # Pre-fill org name suggestion
    expires_at = Column(DateTime, nullable=False)
    accepted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    mssp_org = relationship("Organization", foreign_keys=[mssp_org_id])


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
    # Built-in team roles are seeded per-org from core.builtin_team_roles. They
    # are protected from deletion and regenerate if missing on org startup.
    is_builtin = Column(Boolean, default=False, nullable=False)
    # If set, this role restricts finding/asset visibility to resources whose
    # resolved owner_role matches. One of core.ownership_teams.OWNERSHIP_ROLES.
    scope_owner_role = Column(String, nullable=True)
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
# SAML SSO Configuration
# ─────────────────────────────────────────────────────────

class SAMLConfig(Base):
    """Per-organization SAML 2.0 SSO configuration for enterprise identity providers."""
    __tablename__ = "saml_configs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    is_enabled = Column(Boolean, default=False)
    # IdP metadata
    idp_entity_id = Column(String, nullable=False)          # IdP Entity ID / Issuer
    idp_sso_url = Column(String, nullable=False)             # IdP Single Sign-On URL
    idp_slo_url = Column(String, nullable=True)              # IdP Single Logout URL (optional)
    idp_x509_cert = Column(Text, nullable=False)             # IdP X.509 signing certificate (PEM)
    # SP settings
    sp_entity_id = Column(String, nullable=True)             # Override SP entity ID (auto-generated if null)
    # Behavior
    default_role = Column(String, default="analyst")         # Role for JIT-provisioned users
    auto_provision = Column(Boolean, default=True)           # Create users on first SAML login
    force_sso = Column(Boolean, default=False)               # Require SSO (disable password login for org)
    # Attribute mapping (JSON: {"email": "...", "display_name": "...", "role": "..."})
    attribute_mapping = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    org = relationship("Organization")

    __table_args__ = (
        Index("ix_saml_config_org", "org_id"),
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
    dedup_keys=["source_system", "source_id", "asset_type"],
    required_fields=[],
    description="Assets — hosts, web apps, cloud instances, APIs, identities, containers, and custom types",
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

    # Multi-type asset identity
    asset_type = Column(String, default="host", index=True)   # host, web_app, cloud_instance, api_endpoint, identity, container_image, code_repo, k8s_workload, or any custom type
    asset_identity = Column(JSON, default=dict)                # structured identity keys per type (e.g. {"url": "..."} for web_app, {"instance_id": "..."} for cloud)
    asset_attributes = Column(JSON, default=dict)              # type-specific metadata overflow

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
    last_enriched = Column(DateTime, nullable=True)            # Set by scanner after enrichment pass; NULL → needs re-enrichment
    last_js_fingerprinted = Column(DateTime, nullable=True)    # Set by scanner after JS fingerprinting pass

    # Adaptive Scan Plan (services/scan_planner) — JSON ScanPlan dict.
    # Computed at end of enrichment, refreshed when scan_plan_signature changes,
    # consumed by VM scanner via the /vm/scans/ POST body. NULL → scanner falls
    # back to legacy TemplateRouter behavior.
    scan_plan = Column(JSON, nullable=True)
    scan_plan_computed_at = Column(DateTime, nullable=True)
    scan_plan_version = Column(Integer, default=0)             # bumped on each replan; scanner reports back what version it executed
    scan_plan_signature = Column(String(64), nullable=True)    # sha256 over plan inputs — short-circuits recomputation

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

    # User-defined custom fields (see CustomFieldDefinition). Flat {key: value} dict keyed by definition.key
    custom_fields = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="assets")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    observations = relationship("AssetObservation", back_populates="asset", cascade="all, delete-orphan")
    outbound_relationships = relationship("AssetRelationship", foreign_keys="[AssetRelationship.source_asset_id]",
                                          back_populates="source_asset", cascade="all, delete-orphan")
    inbound_relationships = relationship("AssetRelationship", foreign_keys="[AssetRelationship.target_asset_id]",
                                         back_populates="target_asset", cascade="all, delete-orphan")


class AssetObservation(Base):
    """Per-source snapshot of an asset — one row per (asset, source_system).

    Stores the raw fields each source reported so the UI can show
    what each scanner/integration contributed to the merged asset.
    """
    __tablename__ = "asset_observations"
    __table_args__ = (
        UniqueConstraint("asset_id", "source_system", name="uq_asset_obs_source"),
        Index("ix_asset_observations_asset_id", "asset_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    source_system = Column(String, nullable=False)       # "nessus" | "crowdstrike" | "wiz" | "easm" | …
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)

    # Raw fields as reported by this source
    raw_fields = Column(JSON, default=dict)              # Full snapshot: {ip, hostname, fqdn, os, ...}

    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    times_seen = Column(Integer, default=1)

    asset = relationship("Asset", back_populates="observations")


class AssetRelationship(Base):
    """Directional edge between two assets (e.g. DNS record → cloud workload)."""
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint("org_id", "source_asset_id", "target_asset_id", "relationship_type",
                         name="uq_asset_relationship"),
        Index("ix_asset_rel_source", "source_asset_id"),
        Index("ix_asset_rel_target", "target_asset_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    source_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    target_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String, nullable=False)   # resolves_to, alias_of, hosts_service, runs_technology, shares_certificate, same_jarm_cluster, same_ip, exposes_endpoint, authenticates_via
    confidence = Column(String, default="high")           # high / medium / low
    source_detail = Column(JSON, default=dict)            # provenance: {connector, dns_record_type}
    weight = Column(Float, default=1.0)                  # edge weight for graph algorithms (0.0-1.0)
    properties = Column(JSON, default=dict)              # edge-specific metadata (e.g. shared cert fingerprint, JARM hash)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    source_asset = relationship("Asset", foreign_keys=[source_asset_id], back_populates="outbound_relationships")
    target_asset = relationship("Asset", foreign_keys=[target_asset_id], back_populates="inbound_relationships")


class AssetCluster(Base):
    """Group of assets sharing infrastructure signals (cert, JARM, IP range, tech stack)."""
    __tablename__ = "asset_clusters"
    __table_args__ = (
        Index("ix_asset_cluster_org", "org_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    cluster_type = Column(String, nullable=False)  # shared_certificate, same_jarm, shared_ip_range, shared_tech_stack
    label = Column(String)                         # human-readable label (e.g. "*.example.com cert cluster")
    pivot_value = Column(String)                   # the shared signal value (cert fingerprint, JARM hash, CIDR, etc.)
    asset_ids = Column(JSON, default=list)          # list of asset IDs in this cluster
    asset_count = Column(Integer, default=0)
    cluster_metadata = Column("cluster_metadata", JSON, default=dict)  # cluster-specific data
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AttackPath(Base):
    """Attack path — a chain of exploitable findings across related assets.

    Generated by the cross-finding correlator using BFS through the knowledge graph
    from internet-facing entry points.
    """
    __tablename__ = "attack_paths"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    severity = Column(String(32))  # Critical, High, Medium
    steps = Column(JSON, default=list)  # [{asset_id, hostname, finding_id, finding_name, severity, edge_type}]
    entry_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    target_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    chain_length = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # LLM-generated attack narrative + prioritized mitigations
    # (populated by services.attack_chain_narrator)
    narrative = Column(Text, nullable=True)
    recommended_mitigations = Column(JSON, nullable=True)
    # [{finding_id, finding_name, severity, chains_broken, action}]


class ScannerEventCursor(Base):
    """Per-org cursor tracking the last-consumed scanner event.

    Used by services.scanner_event_bridge to avoid reprocessing events.
    One row per organization; cursor advances as events are consumed.
    """
    __tablename__ = "scanner_event_cursors"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)
    last_event_at = Column(DateTime, nullable=True)   # UTC timestamp of the newest consumed event
    last_event_id = Column(String, nullable=True)     # UUID of newest consumed event (tiebreaker)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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

    # Control validation (populated by control_assessment engine)
    control_mitigation_status = Column(String, nullable=True)   # mitigated / partially_mitigated / not_mitigated / null
    control_mitigation_summary = Column(String, nullable=True)  # "Mitigated by CrowdStrike (exploit prevention: BLOCK)"

    # Prioritization
    priority_score = Column(Float, default=0.0)
    effort_level = Column(String)  # quick_win / medium / complex
    owner_suggestion = Column(String)  # canonical role, see core.ownership_teams.OWNERSHIP_ROLES
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

    # User-defined custom fields (see CustomFieldDefinition). Flat {key: value} dict keyed by definition.key
    custom_fields = Column(JSON, default=dict)

    # LLM vulnerability validation (populated by llm_vuln_validator)
    # {verdict: "true_positive"|"false_positive"|"needs_review", confidence: 0.0-1.0, reasoning: "...", validated_at: "..."}
    llm_validation = Column(JSON, nullable=True)

    scan = relationship("Scan", back_populates="findings", foreign_keys="[Finding.scan_id]")
    asset = relationship("Asset", back_populates="findings")
    automate_clicks = relationship("AutomateClick", back_populates="finding", cascade="all, delete-orphan")
    tickets = relationship("FindingTicket", back_populates="finding", cascade="all, delete-orphan")
    observations = relationship("FindingObservation", back_populates="finding", cascade="all, delete-orphan")


class FindingObservation(Base):
    """Per-source snapshot of a finding — one row per (finding, source_system).

    Stores the raw fields each source reported so the UI can show
    what each scanner/integration contributed to the merged finding.
    """
    __tablename__ = "finding_observations"
    __table_args__ = (
        UniqueConstraint("finding_id", "source_system", name="uq_finding_obs_source"),
        Index("ix_finding_observations_finding_id", "finding_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    source_system = Column(String, nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)

    raw_fields = Column(JSON, default=dict)

    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    times_seen = Column(Integer, default=1)

    finding = relationship("Finding", back_populates="observations")


class CustomFieldDefinition(Base):
    """Per-org user-defined custom field on Asset or Finding entities.

    Values are resolved at ingest (or via PATCH for manual) and stored in the
    `custom_fields` JSON column on the target entity, keyed by `key`.
    """
    __tablename__ = "custom_field_definitions"
    __table_args__ = (
        UniqueConstraint("org_id", "entity_type", "key", name="uq_custom_field_org_entity_key"),
        Index("ix_custom_field_defs_org_entity", "org_id", "entity_type"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String, nullable=False)        # "asset" | "finding"
    key = Column(String, nullable=False)                # snake_case slug, e.g. "data_center"
    label = Column(String, nullable=False)              # display label
    description = Column(Text, nullable=True)

    data_type = Column(String, nullable=False, default="string")   # string|number|boolean|date|enum
    enum_values = Column(JSON, nullable=True)                       # list[str] when data_type == "enum"

    source_type = Column(String, nullable=False, default="manual")  # mapping | formula | manual
    mapping_source = Column(String, nullable=True)                  # dot-path into source observation raw_fields
    mapping_transform = Column(JSON, nullable=True)                 # same shape field_mapper._apply_transform accepts
    mapping_source_system = Column(String, nullable=True)           # optional: restrict mapping to a specific source_system
    formula_expression = Column(Text, nullable=True)                # sandboxed expression over merged entity dict

    show_in_list = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FindingTicket(Base):
    """Tracks external tickets (Jira/ServiceNow) linked to a finding for bidirectional sync."""
    __tablename__ = "finding_tickets"
    __table_args__ = (
        UniqueConstraint("finding_id", "ticket_system", "ticket_id", name="uq_finding_ticket"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)

    # External ticket identity
    ticket_system = Column(String, nullable=False)       # "jira" | "servicenow"
    ticket_id = Column(String, nullable=False)            # Jira issue ID or ServiceNow sys_id
    ticket_key = Column(String, nullable=True)            # Jira key (e.g. "SEC-123") or SNOW number ("INC0012345")
    ticket_url = Column(String, nullable=True)

    # Status sync
    external_status = Column(String, nullable=True)       # Raw status from external system
    mapped_status = Column(String, nullable=True)         # Mapped Hakuna workflow_status equivalent
    last_synced_at = Column(DateTime, nullable=True)
    sync_error = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="tickets")


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
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    # The asset where this user data was collected (the host scanned)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)

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
    is_locked = Column(Boolean, default=False)        # AD lockout flag
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
    email = Column(String)                   # From AD mail attribute
    upn = Column(String)                     # userPrincipalName
    manager_dn = Column(String)              # DN of manager (from AD)
    manager_username = Column(String)         # Resolved manager username

    # Direct-connect source tracking (for AD/LDAP connector, not scanner-based)
    source = Column(String, nullable=True)           # 'active_directory' | 'okta' | etc.
    source_id = Column(String, nullable=True)        # objectGUID or external unique ID
    org_id = Column(Integer, nullable=True, index=True)  # For direct-connect (no scan context)
    last_synced_at = Column(DateTime, nullable=True)

    # Password / logon age tracking
    password_age_days = Column(Integer, nullable=True)
    last_logon_days_ago = Column(Integer, nullable=True)

    # Last seen logged on to which host
    last_logon_host = Column(String)


class InventoryGroup(Base):
    """AD and local security groups."""
    __tablename__ = "inventory_groups"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)

    group_name = Column(String, index=True)
    domain = Column(String)
    sid = Column(String)
    dn = Column(String)
    description = Column(String)
    members = Column(JSON, default=list)     # List of member CN/DN strings
    is_privileged = Column(Boolean, default=False)  # DA, EA, Admins, etc.
    source_plugin = Column(String)

    # Direct-connect fields (for AD/LDAP connector)
    source = Column(String, nullable=True)           # 'active_directory'
    source_id = Column(String, nullable=True)        # objectGUID or DN
    org_id = Column(Integer, nullable=True, index=True)
    group_scope = Column(String, nullable=True)      # domain_local | global | universal
    group_type = Column(String, nullable=True)       # security | distribution
    member_count = Column(Integer, nullable=True)
    last_synced_at = Column(DateTime, nullable=True)


class IdentityGroupMembership(Base):
    """Join table linking identities to groups."""
    __tablename__ = "identity_group_memberships"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, nullable=False, index=True)
    identity_source = Column(String, nullable=False)    # 'active_directory'
    identity_source_id = Column(String, nullable=False)  # User objectGUID
    group_source = Column(String, nullable=False)        # 'active_directory'
    group_source_id = Column(String, nullable=False)     # Group objectGUID or DN
    group_name = Column(String, nullable=True)
    synced_at = Column(DateTime, nullable=True)


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
    startup_type = Column(String)               # Automatic, Manual, Disabled, etc.
    run_as_user = Column(String)                # LocalSystem, NT AUTHORITY\NetworkService, custom account
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
    auto_update_status = Column(String, index=True)  # enabled, disabled, unknown, null=not_detected
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
    owner_role = Column(String)   # canonical role, see core.ownership_teams.OWNERSHIP_ROLES
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
    owner_role = Column(String)   # canonical role, see core.ownership_teams.OWNERSHIP_ROLES
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
        # Partial unique indexes — a row always has exactly one of
        # asset_id / finding_id set, so enforce uniqueness per side.
        Index(
            "uq_tag_assignment_tag_asset", "tag_id", "asset_id",
            unique=True,
            sqlite_where=text("asset_id IS NOT NULL"),
            postgresql_where=text("asset_id IS NOT NULL"),
        ),
        Index(
            "uq_tag_assignment_tag_finding", "tag_id", "finding_id",
            unique=True,
            sqlite_where=text("finding_id IS NOT NULL"),
            postgresql_where=text("finding_id IS NOT NULL"),
        ),
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
    owner_role = Column(String, nullable=True)       # canonical role, see core.ownership_teams.OWNERSHIP_ROLES
    team = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    overwrite_existing = Column(Boolean, default=False)  # overwrite manually-set ownership
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    last_run_count = Column(Integer, nullable=True)


class AssetTypeRule(Base):
    """Low-code rule that classifies assets into a target asset_type based on conditions.

    Evaluated during ingestion (scan upload, integration sync) before asset creation.
    First matching rule (by priority) wins.  Uses the unified rule-engine condition format.
    """
    __tablename__ = "asset_type_rules"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    # Conditions: same format as AutoTagRule / Campaign
    # [{"field": "system_type", "op": "eq", "value": "web_application"}, ...]
    conditions = Column(JSON, nullable=False, default=list)
    condition_logic = Column(String, default="AND")  # "AND" | "OR"
    # What to set when conditions match
    target_asset_type = Column(String, nullable=False)  # e.g. "web_app", "cloud_instance", "host"
    # JSON mapping: which raw fields populate asset_identity keys
    # e.g. {"url": "hostname", "domain": "@extract_domain(hostname)"}
    identity_mapping = Column(JSON, nullable=False, default=dict)
    # Static attributes to merge into asset_attributes
    default_attributes = Column(JSON, nullable=False, default=dict)
    priority = Column(Integer, default=100)  # lower = evaluated first
    source_filter = Column(String, nullable=True)  # optional: only apply for this source (nessus, qualys, easm, integration, etc.)
    is_enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Campaign(Base):
    """Remediation campaign grouping findings with a shared query and goal."""
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)  # None = all scans

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # campaign owner

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

    slack_channel_id = Column(String)    # Slack channel ID (e.g. C0123456789)
    slack_channel_name = Column(String)  # Slack channel name (e.g. campaign-log4shell)

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

@importable(
    slug="finding_exception",
    display_name="Finding Exception",
    category="core",
    dedup_keys=["org_id", "source_system", "source_id"],
    required_fields=["exception_type"],
    description="Accepted risks, false positives, severity overrides, and compensating controls imported from other VM tools",
)
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
    # Provenance — set when imported from a third-party VM tool via the integration builder
    source_system = Column(String, nullable=True, index=True)
    source_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    __table_args__ = (
        Index("ix_exception_plugin_asset", "plugin_id", "asset_ip"),
        Index("ix_exception_source", "source_system", "source_id"),
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


class ReportSchedule(Base):
    """Schedule for automated delivery of a saved report as an email attachment."""
    __tablename__ = "report_schedules"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    report_template_id = Column(Integer, ForeignKey("report_templates.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    name = Column(String, nullable=True)                # optional display name; defaults to template name
    # Delivery
    recipients = Column(Text, nullable=False)            # comma-separated email list
    subject_template = Column(String, nullable=True)
    body_template = Column(Text, nullable=True)
    format = Column(String, default="pdf")               # pdf (only supported format today)
    # Schedule
    frequency = Column(String, default="weekly")         # daily | weekly | monthly | custom
    day_of_week = Column(Integer, nullable=True)         # 0=Mon..6=Sun (weekly)
    day_of_month = Column(Integer, nullable=True)        # 1..28 (monthly)
    hour = Column(Integer, default=8)                    # 0-23 UTC
    minute = Column(Integer, default=0)                  # 0-59
    cron_expression = Column(String, nullable=True)      # used when frequency == "custom"
    timezone = Column(String, default="UTC")
    # State
    is_enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String, nullable=True)          # success | error
    last_error = Column(Text, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    template = relationship("ReportTemplate")


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


class AgentApproval(Base):
    """Pending human-in-the-loop approval for a write/destructive tool call during an agent run."""
    __tablename__ = "agent_approvals"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False, index=True)

    # Tool being gated
    tool_name = Column(String, nullable=False)
    tool_input = Column(JSON, default=dict)

    # Execution state snapshot for seamless resume
    messages_snapshot = Column(JSON, default=list)   # messages list BEFORE the paused assistant turn
    assistant_content = Column(JSON, default=list)   # full assistant content block (all tool_use blocks)
    provider = Column(String)                        # "anthropic" / "openai" / "groq"
    model_name = Column(String)                      # which model was running
    current_step = Column(Integer, default=0)        # step index in the agent loop
    tool_use_id = Column(String)                     # tool_use block ID (Anthropic) or tool_call ID (OpenAI)

    # Decision
    status = Column(String, default="pending")       # pending / approved / rejected / expired
    requested_at = Column(DateTime, default=datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)
    decided_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    rejection_reason = Column(Text, nullable=True)

    run = relationship("AgentRun")
    agent = relationship("Agent")


class CopilotConversation(Base):
    """Multi-turn conversation between a user and the Security Copilot."""
    __tablename__ = "copilot_conversations"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    title = Column(String, default="New conversation")
    messages = Column(JSON, default=list)  # [{role, content, timestamp, tool_calls?}]
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ─────────────────────────────────────────────────────────
# LLM Feedback Loop — every LLM call is logged with optional
# outcome linkage so future turns can retrieve tenant-scoped
# few-shot exemplars (see services/llm_feedback.py).
# ─────────────────────────────────────────────────────────

class LLMInteraction(Base):
    """One row per LLM call — agent runs and one-shot services.

    Embeddings are populated asynchronously on Postgres only (pgvector).
    On SQLite (dev) the column is omitted by the migration.
    """
    __tablename__ = "llm_interactions"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Source — 'agent' | 'vuln_validator' | 'alert_triage' | 'scan_planner' | ...
    surface = Column(String, nullable=False, index=True)
    surface_ref_type = Column(String)   # 'finding' | 'alert' | 'scan' | 'conversation' | ...
    surface_ref_id = Column(String)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=True, index=True)

    provider = Column(String)
    model = Column(String)
    system_prompt_hash = Column(String, index=True)
    system_prompt = Column(Text)
    messages = Column(JSON, default=list)       # input turn(s)
    response_text = Column(Text)
    tool_calls = Column(JSON, default=list)     # [{name, args, result_summary, ok, ms}]
    input_tokens = Column(Integer)
    output_tokens = Column(Integer)
    latency_ms = Column(Integer)
    error = Column(Text)
    status = Column(String, default="ok")       # 'ok' | 'error'
    redacted = Column(Boolean, default=False)

    # pgvector column is added only on Postgres by the migration — the
    # ORM attribute stays optional; retrieval code handles absence.
    embedding_model = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_llm_int_org_surface_created", "org_id", "surface", "created_at"),
    )


class LLMInteractionOutcome(Base):
    """Outcome signal linked to an interaction.

    Populated asynchronously by services.llm_outcome_linker. A composite
    outcome_score in [-1, +1] drives the RAG ranking for exemplar retrieval.
    """
    __tablename__ = "llm_interaction_outcomes"

    id = Column(Integer, primary_key=True, index=True)
    interaction_id = Column(Integer, ForeignKey("llm_interactions.id"), nullable=False, unique=True, index=True)
    org_id = Column(Integer, nullable=False, index=True)

    user_rating = Column(Integer)             # -1, 0, +1
    user_edit_distance = Column(Float)        # normalized distance between AI output and accepted output
    accepted = Column(Boolean)

    finding_outcome = Column(String)          # 'remediated' | 'false_positive' | 'still_open_30d'
    ticket_outcome = Column(String)           # 'closed_resolved' | 'closed_wontfix' | 'still_open'
    approval_outcome = Column(String)         # 'approved' | 'rejected' | 'expired'
    workflow_outcome = Column(String)         # 'completed' | 'failed'

    outcome_score = Column(Float, index=True)
    computed_at = Column(DateTime, default=datetime.utcnow)


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
# Notifications
# ─────────────────────────────────────────────────────────

class Notification(Base):
    """Org-scoped notification generated by system events."""
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    category = Column(String, nullable=False)  # scan_complete | scan_failed | critical_findings | new_assets | kev_update | campaign_findings | sla_breach
    title = Column(String, nullable=False)
    body = Column(Text, nullable=True)
    link = Column(String, nullable=True)        # e.g. "/findings?scan_id=5"
    entity_type = Column(String, nullable=True)  # scan | finding | asset | campaign | threat_intel
    entity_id = Column(Integer, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)  # extra context for frontend rendering
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("ix_notifications_org_created", "org_id", "created_at"),
    )


class NotificationRead(Base):
    """Per-user read tracking for notifications."""
    __tablename__ = "notification_reads"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    notification_id = Column(Integer, ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False)
    read_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "notification_id", name="uq_user_notification_read"),
        Index("ix_notification_reads_user", "user_id"),
    )


class UserPageVisit(Base):
    """Tracks when a user last visited a page, for 'new since' badges."""
    __tablename__ = "user_page_visits"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    page_key = Column(String, nullable=False)   # findings | assets | campaigns:{id} | threat_intel
    last_visited_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "page_key", name="uq_user_page_visit"),
        Index("ix_user_page_visit_user", "user_id"),
    )


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
    transport_type = Column(String, nullable=False)  # api | sql | file | mcp | relay | stream
    transport_config = Column(JSON, nullable=False, default=dict)
    stream_config = Column(JSON, nullable=True)  # parser, sample_event, vrl_transform (for transport_type=stream)
    cursor_state = Column(JSON, nullable=True)   # incremental sync state: {last_event_time, offset, token, ...}
    credentials_id = Column(String, ForeignKey("integration_credentials.id"), nullable=True)
    records_path = Column(String, nullable=True)  # dot-path to records array in response
    field_map = Column(JSON, nullable=False, default=list)
    dedup_key = Column(JSON, nullable=False, default=list)  # stored as JSON array (SQLite has no array type)
    params = Column(JSON, nullable=False, default=dict)
    schedule = Column(String, nullable=True)  # cron expression
    enabled = Column(Boolean, nullable=False, default=False)
    template_id = Column(String, nullable=True)  # OOTB template used
    logo_url = Column(String, nullable=True)  # custom logo URL or auto-fetched favicon
    relay_agent_id = Column(String, ForeignKey("relay_agents.id"), nullable=True)
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


# ─────────────────────────────────────────────────────────
# SIEM Events (hot tier)
# ─────────────────────────────────────────────────────────

@importable(
    slug="siem_event",
    display_name="SIEM Event",
    category="siem",
    dedup_keys=["org_id", "dedup_hash"],
    required_fields=["event_time", "source_system", "event_type"],
    description="Security event from SIEM sources (logs, alerts, telemetry)",
)
class SIEMEvent(Base):
    """Security event stored in the hot tier (Postgres, last 72h)."""
    __tablename__ = "siem_events"

    id = Column(String, primary_key=True, default=_gen_uuid)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    event_time = Column(DateTime, nullable=False, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    source_system = Column(String, nullable=False, index=True)       # e.g. palo_alto, crowdstrike, syslog
    source_id = Column(String, nullable=True)                        # original event ID in source
    event_type = Column(String, nullable=False, index=True)          # e.g. authentication, network, process
    event_category = Column(String, nullable=True)                   # ECS category: threat, intrusion_detection, etc.
    severity = Column(String, nullable=False, default="info")        # low | medium | high | critical | info
    action = Column(String, nullable=True)                           # allowed, denied, dropped, etc.
    outcome = Column(String, nullable=True)                          # success, failure, unknown
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    user_name = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    host_name = Column(String, nullable=True)
    message = Column(Text, nullable=True)
    raw = Column(JSON, nullable=True)                                # original event payload
    normalized = Column(JSON, nullable=True)                         # ECS-normalized fields
    dedup_hash = Column(String, nullable=False, index=True)          # unique per org for dedup
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("org_id", "dedup_hash", name="uq_siem_events_org_dedup"),
        Index("ix_siem_events_org_time", "org_id", event_time.desc()),
    )


class IngestEndpoint(Base):
    """Token-authenticated push endpoint for SIEM event ingestion."""
    __tablename__ = "ingest_endpoints"

    id = Column(String, primary_key=True, default=_gen_uuid)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    integration_id = Column(String, ForeignKey("integrations.id"), nullable=True)
    name = Column(String, nullable=False)
    token_hash = Column(String, nullable=False)           # bcrypt hash of bearer token
    token_prefix = Column(String, nullable=True)          # first 8 chars for display
    hmac_secret_hash = Column(String, nullable=False)     # bcrypt hash of HMAC secret
    parser_type = Column(String, nullable=False, default="json")  # json | hec | cef | leef | syslog_rfc5424
    is_active = Column(Boolean, default=True)
    # LLM-inferred extractors applied after the format parser to fill empty
    # canonical fields (event_type/outcome/action/user_name/source_ip/...) from
    # unstructured payloads. Generated once at onboarding, applied deterministically
    # at runtime. See services/mapping_inference.py for schema.
    field_extractors = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    request_count = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_ingest_endpoints_org", "org_id"),
    )


# ─────────────────────────────────────────────────────────
# Relay Agents (on-prem connectivity)
# ─────────────────────────────────────────────────────────

class RelayAgent(Base):
    """A relay agent deployed in a customer's network for on-prem integrations."""
    __tablename__ = "relay_agents"

    id = Column(String, primary_key=True, default=_gen_uuid)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False)             # "NYC Office Agent"
    token_hash = Column(String, nullable=False)        # bcrypt hash of agent token
    token_prefix = Column(String, nullable=True)       # "hka_abc1…" for display
    status = Column(String, default="disconnected")    # connected | disconnected
    last_seen_at = Column(DateTime, nullable=True)
    agent_version = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)         # source IP for audit
    allowed_hosts = Column(JSON, default=list)         # optional URL allowlist
    credentials_mode = Column(String, default="agent_local")  # agent_local | cloud_managed
    labels = Column(JSON, default=dict)                # freeform metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)


# ─────────────────────────────────────────────────────────
# Security Control Validation
# ─────────────────────────────────────────────────────────

@importable(
    slug="security_control_policy",
    display_name="Security Control Policy",
    category="inventory",
    dedup_keys=["org_id", "product_key", "policy_external_id"],
    required_fields=["product_key", "policy_external_id", "settings"],
    description="Policy configurations from security products (EDR prevention, firewall rules, AV settings)",
)
class SecurityControlPolicy(Base):
    """Actual policy config pulled from a security product API."""
    __tablename__ = "security_control_policies"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    product_key = Column(String, nullable=False, index=True)   # crowdstrike_falcon, ms_defender, palo_alto_ngfw
    product_name = Column(String)                              # CrowdStrike Falcon
    vendor = Column(String)
    policy_external_id = Column(String, index=True)            # ID from source API
    policy_name = Column(String)                               # "Default Prevention Policy"
    policy_type = Column(String, index=True)                   # prevention, firewall, av_realtime, device_control
    settings = Column(JSON, nullable=False)                    # product-specific config blob
    raw_response = Column(JSON)                                # full API response for audit
    source_integration_id = Column(String, ForeignKey("integrations.id"), nullable=True)
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("org_id", "product_key", "policy_external_id", name="uq_scp_org_product_policy"),
        Index("ix_scp_org_product", "org_id", "product_key"),
    )

    assignments = relationship("SecurityControlPolicyAssignment", back_populates="policy", cascade="all, delete-orphan")
    assessments = relationship("ControlAssessment", back_populates="policy", cascade="all, delete-orphan")


class SecurityControlPolicyAssignment(Base):
    """Maps a policy to an asset (resolved from host groups)."""
    __tablename__ = "security_control_policy_assignments"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    policy_id = Column(Integer, ForeignKey("security_control_policies.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    assignment_source = Column(String)          # host_group, direct, default_policy
    source_group_id = Column(String)
    source_group_name = Column(String)
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("policy_id", "asset_id", name="uq_scpa_policy_asset"),
        Index("ix_scpa_org_asset", "org_id", "asset_id"),
    )

    policy = relationship("SecurityControlPolicy", back_populates="assignments")


class ControlAssessment(Base):
    """Per-finding verdict: is this finding mitigated by a specific policy?"""
    __tablename__ = "control_assessments"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    policy_id = Column(Integer, ForeignKey("security_control_policies.id"), nullable=False, index=True)
    verdict = Column(String, nullable=False)     # mitigated, partially_mitigated, not_mitigated, unknown
    confidence = Column(String, nullable=False)  # high, medium, low
    explanation = Column(Text, nullable=False)
    matched_techniques = Column(JSON, default=list)
    policy_settings_snapshot = Column(JSON)      # settings evaluated (audit trail)
    assessed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("finding_id", "policy_id", name="uq_ca_finding_policy"),
        Index("ix_ca_org_finding", "org_id", "finding_id"),
        Index("ix_ca_org_asset", "org_id", "asset_id"),
    )

    policy = relationship("SecurityControlPolicy", back_populates="assessments")


# ── Firewall Policy (network access rules from NGFW / UTM appliances) ────
@importable(
    slug="firewall_policy",
    display_name="Firewall Policy Rule",
    category="network",
    dedup_keys=["org_id", "vendor", "rule_id"],
    required_fields=["vendor", "rule_id", "action"],
    description="Network firewall rules from Palo Alto, Fortinet, Check Point for lateral movement & blast radius analysis",
)
class FirewallPolicy(Base):
    """Normalized firewall rule pulled from a network appliance API."""
    __tablename__ = "firewall_policies"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    vendor = Column(String, nullable=False, index=True)           # palo_alto, fortinet, checkpoint
    source_integration_id = Column(String, ForeignKey("integrations.id"), nullable=True)
    rule_id = Column(String, nullable=False, index=True)          # rule name or policy ID from appliance
    rule_name = Column(String)                                    # human-readable rule name
    from_zone = Column(String)                                    # source zone / interface
    to_zone = Column(String)                                      # destination zone / interface
    src_cidrs = Column(JSON, default=list)                        # ["10.0.1.0/24"]
    dst_cidrs = Column(JSON, default=list)                        # ["10.0.2.0/24"]
    applications = Column(JSON, default=list)                     # ["ssh", "rdp"] (PAN-style)
    services = Column(JSON, default=list)                         # [{"port": 22, "protocol": "tcp"}]
    action = Column(String, nullable=False, index=True)           # allow / deny / accept / drop / reject
    enabled = Column(Boolean, default=True)
    logged = Column(Boolean, default=False)
    nat = Column(Boolean, default=False)
    raw_response = Column(JSON)                                   # full vendor payload for audit
    synced_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("org_id", "vendor", "rule_id", name="uq_fwp_org_vendor_rule"),
        Index("ix_fwp_org_vendor", "org_id", "vendor"),
        Index("ix_fwp_action", "org_id", "action"),
    )


# ─────────────────────────────────────────────────────────
# SIEM Detection Rules & Alerts
# ─────────────────────────────────────────────────────────

class DetectionRule(Base):
    """A stateful, windowed detection rule that queries SIEM events."""
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="medium")      # low | medium | high | critical
    enabled = Column(Boolean, default=True)
    query = Column(JSON, nullable=False, default=dict)               # filters in rule_engine format
    window_seconds = Column(Integer, default=300)                    # time window for threshold
    threshold = Column(Integer, default=1)                           # fire if event count >= threshold
    group_by = Column(JSON, default=list)                            # group by fields (e.g. ["source_ip", "user_name"])
    schedule_minutes = Column(Integer, default=5)                    # run every N minutes
    mitre_techniques = Column(JSON, default=list)                    # e.g. ["T1110", "T1059.001"]
    asset_filter = Column(JSON, default=dict)                        # asset context filter: {"min_criticality": 8, "internet_facing": true}
    source = Column(String, default="manual")                       # manual | sigma
    sigma_rule_id = Column(String, nullable=True)                   # original Sigma rule ID
    last_run_at = Column(DateTime, nullable=True)
    last_alert_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    alerts = relationship("Alert", back_populates="rule", cascade="all, delete-orphan")


class Alert(Base):
    """An alert fired by a detection rule when threshold is met."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    fired_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    status = Column(String, default="open")                         # open | triaged | closed | false_positive
    event_count = Column(Integer, default=0)
    group_key = Column(String, nullable=True)                       # serialized group-by values
    first_event_id = Column(String, nullable=True)
    last_event_id = Column(String, nullable=True)
    context = Column(JSON, default=dict)                            # matching events sample, group values
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)

    # Entity identification (primary entity this alert is about)
    entity_type = Column(String, nullable=True)                     # ip | hostname | user
    entity_value = Column(String, nullable=True)

    # Exposure enrichment (snapshot at alert time from linked asset)
    asset_criticality = Column(Integer, nullable=True)              # 1-10 from asset
    open_vulnerabilities = Column(Integer, nullable=True)           # critical + high count
    internet_facing = Column(Boolean, nullable=True)
    exposure_context = Column(JSON, default=dict)                   # full enrichment snapshot

    # Suppression
    suppressed = Column(Boolean, default=False, index=True)
    suppression_rule_id = Column(Integer, ForeignKey("suppression_rules.id"), nullable=True)

    # Investigation
    triage_reason = Column(String, nullable=True)
    notes = Column(Text, nullable=True)

    # LLM triage verdict (written by services/alert_triage before notification)
    triage_verdict = Column(String, nullable=True)       # true_positive | false_positive | needs_review
    triage_confidence = Column(Float, nullable=True)     # 0.0 - 1.0
    triage_summary = Column(Text, nullable=True)         # 1-sentence rationale
    triaged_at = Column(DateTime, nullable=True)
    triage_model = Column(String, nullable=True)         # model id used (for audit)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    rule = relationship("DetectionRule", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_org_status", "org_id", "status"),
        Index("ix_alerts_org_fired", "org_id", fired_at.desc()),
    )


# ─────────────────────────────────────────────────────────
# SIEM Suppression Rules
# ─────────────────────────────────────────────────────────

class SuppressionRule(Base):
    """A rule to suppress known-good alerts (e.g. scanner traffic, maintenance windows)."""
    __tablename__ = "suppression_rules"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    conditions = Column(JSON, nullable=False, default=list)         # same filter format as DetectionRule.query
    conditions_logic = Column(String, default="AND")                # AND | OR
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)  # scope to rule, or null=global
    reason = Column(String, nullable=True)                          # "known scanner", "maintenance window", etc.
    enabled = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)                    # null = never expires
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    suppressed_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

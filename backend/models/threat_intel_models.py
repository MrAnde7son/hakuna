from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from core.database import Base
from integrations.model_registry import importable


@importable(
    slug="threat_group",
    display_name="Threat Group",
    category="threat_intel",
    dedup_keys=["mitre_id"],
    required_fields=["name"],
    description="Threat actor groups — APTs, ransomware gangs, nation-state actors",
)
class ThreatGroup(Base):
    __tablename__ = "threat_groups"

    id = Column(Integer, primary_key=True, index=True)
    mitre_id = Column(String, unique=True, index=True)  # e.g. "G0016"
    name = Column(String, nullable=False, index=True)
    aliases = Column(JSON, default=list)
    country = Column(String)
    motivation = Column(String)  # "financial"/"espionage"/"destruction"/"hacktivism"
    description = Column(Text)
    first_seen = Column(String)
    last_seen = Column(String)
    is_ransomware = Column(Boolean, default=False)
    is_nation_state = Column(Boolean, default=False)
    target_sectors = Column(JSON, default=list)
    target_countries = Column(JSON, default=list)
    source = Column(String, default="mitre")
    source_url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    ttps = relationship("ThreatGroupTTP", back_populates="group", cascade="all, delete-orphan")
    campaigns = relationship("ThreatCampaign", back_populates="threat_group")


@importable(
    slug="ttp",
    display_name="TTP / ATT&CK Technique",
    category="threat_intel",
    dedup_keys=["technique_id"],
    required_fields=["technique_id", "name"],
    description="MITRE ATT&CK techniques and sub-techniques",
)
class TTP(Base):
    __tablename__ = "ttps"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, index=True)  # e.g. "T1059.001"
    name = Column(String, nullable=False)
    tactic = Column(String)  # "initial-access"/"execution"/etc
    description = Column(Text)
    platforms = Column(JSON, default=list)
    detection = Column(Text)
    data_sources = Column(JSON, default=list)
    mitre_url = Column(String)
    is_subtechnique = Column(Boolean, default=False)
    parent_technique_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    group_ttps = relationship("ThreatGroupTTP", back_populates="ttp", cascade="all, delete-orphan")


class ThreatGroupTTP(Base):
    __tablename__ = "threat_group_ttps"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("threat_groups.id"), index=True)
    ttp_id = Column(Integer, ForeignKey("ttps.id"), index=True)

    __table_args__ = (
        UniqueConstraint("group_id", "ttp_id", name="uq_threat_group_ttp"),
    )

    group = relationship("ThreatGroup", back_populates="ttps")
    ttp = relationship("TTP", back_populates="group_ttps")


@importable(
    slug="threat_cve",
    display_name="Threat CVE",
    category="threat_intel",
    dedup_keys=["cve_id"],
    required_fields=["cve_id"],
    description="CVE vulnerability intelligence — CVSS, EPSS, KEV, exploit maturity",
)
class ThreatCVE(Base):
    __tablename__ = "threat_cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)  # e.g. "CVE-2024-1234"
    description = Column(Text)
    cvss2_score = Column(Float)
    cvss3_score = Column(Float)
    cvss3_vector = Column(String)
    cvss4_score = Column(Float)
    cvss4_vector = Column(String)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    in_kev = Column(Boolean, default=False)
    kev_date_added = Column(String)
    kev_due_date = Column(String)
    kev_ransomware_use = Column(String)
    kev_notes = Column(String)
    published_date = Column(String)
    modified_date = Column(String)
    affected_products = Column(JSON, default=list)  # list of {"vendor","product","versions"} dicts
    patch_urls = Column(JSON, default=list)
    has_public_exploit = Column(Boolean, default=False)
    exploit_references = Column(JSON, default=list)  # list of {"source","url","description"} dicts
    cwe_ids = Column(JSON, default=list)
    nvd_url = Column(String)
    trending_in_news = Column(Boolean, default=False)
    # New enrichment fields from additional intel sources
    exploit_count = Column(Integer, default=0)  # Total public exploits (ExploitDB + Metasploit + Nuclei)
    exploit_sources = Column(JSON, default=list)  # ["exploitdb", "metasploit", "nuclei"]
    exploit_maturity_level = Column(String)  # "none" | "poc" | "functional" | "weaponized"
    ssvc_decision = Column(String)  # CISA SSVC: "Track" | "Track*" | "Attend" | "Act"
    ssvc_exploitation = Column(String)  # "none" | "poc" | "active"
    greynoise_seen = Column(Boolean, default=False)  # Actively being exploited per GreyNoise
    greynoise_classification = Column(String)  # "benign" | "malicious" | "unknown"
    cwe_names = Column(JSON, default=list)  # Resolved CWE names for display
    cwe_categories = Column(JSON, default=list)  # Top-level CWE categories
    msrc_kb_ids = Column(JSON, default=list)  # Microsoft KB IDs for patching
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


@importable(
    slug="threat_campaign",
    display_name="Threat Campaign",
    category="threat_intel",
    dedup_keys=["name"],
    required_fields=["name"],
    parent_hint={"field": "threat_group_id", "parent_slug": "threat_group", "resolve_by": ["mitre_id", "name"]},
    description="Attack campaigns linking threat groups, CVEs, TTPs, and malware",
)
class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    aliases = Column(JSON, default=list)
    threat_group_id = Column(Integer, ForeignKey("threat_groups.id"), nullable=True)
    description = Column(Text)
    first_seen = Column(String)
    last_seen = Column(String)
    target_sectors = Column(JSON, default=list)
    target_countries = Column(JSON, default=list)
    malware_used = Column(JSON, default=list)
    cve_ids = Column(JSON, default=list)       # list of CVE ID strings
    ttp_ids = Column(JSON, default=list)       # list of technique_id strings
    is_active = Column(Boolean, default=True)
    severity = Column(String, default="high")  # "critical"/"high"/"medium"/"low"
    source = Column(String)
    source_url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    threat_group = relationship("ThreatGroup", back_populates="campaigns")
    remediation_campaigns = relationship("IntelRemediationCampaign", back_populates="threat_campaign")


@importable(
    slug="cisa_advisory",
    display_name="CISA Advisory",
    category="threat_intel",
    dedup_keys=["advisory_id"],
    required_fields=["advisory_id", "title"],
    description="CISA cybersecurity advisories, alerts, and ICS advisories",
)
class CisaAdvisory(Base):
    """CISA Cybersecurity Advisory — fetched from the CISA RSS feed."""
    __tablename__ = "cisa_advisories"

    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(String, unique=True, index=True)   # e.g. "AA25-071A" or "ICSA-26-069-04"
    title = Column(String, nullable=False)
    advisory_type = Column(String, default="advisory")      # "advisory" | "alert" | "ics" | "ics_medical" | "malware"
    pub_date = Column(String)                               # ISO date string
    summary = Column(Text)
    url = Column(String)
    co_sealers = Column(JSON, default=list)                 # ["NSA", "FBI", ...]
    sectors = Column(JSON, default=list)                    # ["energy", "healthcare", ...]
    cve_ids = Column(JSON, default=list)                    # CVEs extracted from text
    threat_group_ids = Column(JSON, default=list)           # matched ThreatGroup IDs
    threat_group_names = Column(JSON, default=list)         # matched ThreatGroup names
    is_ics = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IntelRemediationCampaign(Base):
    __tablename__ = "intel_remediation_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text)
    threat_campaign_id = Column(Integer, ForeignKey("threat_campaigns.id"), nullable=True)
    cve_ids = Column(JSON, default=list)
    ttp_ids = Column(JSON, default=list)
    status = Column(String, default="draft")  # "draft"/"active"/"completed"
    affected_asset_ids = Column(JSON, default=list)    # list of ints
    affected_finding_ids = Column(JSON, default=list)  # list of ints
    affected_asset_count = Column(Integer, default=0)
    suggested_sigma_rules = Column(JSON, default=list)  # list of {"title","url","content"} dicts
    suggested_patches = Column(JSON, default=list)      # list of {"kb"/"advisory_id","url","description"} dicts
    priority_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    threat_campaign = relationship("ThreatCampaign", back_populates="remediation_campaigns")


@importable(
    slug="product_lifecycle",
    display_name="Product Lifecycle",
    category="threat_intel",
    dedup_keys=["slug", "cycle"],
    required_fields=["product_name", "slug", "cycle"],
    description="Product lifecycle and EOL tracking from endoflife.date or custom sources",
)
class ProductLifecycle(Base):
    """Product lifecycle data from endoflife.date — tracks latest versions and EOL status."""
    __tablename__ = "product_lifecycles"

    id = Column(Integer, primary_key=True, index=True)
    product_name = Column(String, nullable=False, index=True)   # Display name: ".NET", "Node.js"
    slug = Column(String, nullable=False, index=True)            # endoflife.date slug: "dotnet", "nodejs"
    cycle = Column(String, nullable=False)                       # Release cycle: "6.0", "18", "3.11"
    latest_version = Column(String)                              # Latest patch: "6.0.36"
    release_date = Column(String)                                # Cycle first released
    eol = Column(String)                                         # EOL date string or "true"/"false"
    is_eol = Column(Boolean, default=False)                      # Computed: past EOL or eol=="true"
    lts = Column(Boolean, default=False)
    support_end = Column(String)                                 # Active support end date
    latest_release_date = Column(String)                         # When latest_version was released
    link = Column(String)                                        # URL to release page
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("slug", "cycle", name="uq_product_lifecycle_slug_cycle"),
    )


class CWEEntry(Base):
    """CWE (Common Weakness Enumeration) full catalog entry."""
    __tablename__ = "cwe_entries"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String, unique=True, index=True, nullable=False)  # e.g. "CWE-79"
    name = Column(String, nullable=False)  # e.g. "Improper Neutralization of Input During Web Page Generation"
    description = Column(Text)
    extended_description = Column(Text)
    weakness_type = Column(String)  # "Class" | "Base" | "Variant" | "Compound"
    status = Column(String)  # "Draft" | "Stable" | "Incomplete" | "Deprecated"
    parent_cwe_ids = Column(JSON, default=list)  # Parent CWE IDs (ChildOf relationships)
    child_cwe_ids = Column(JSON, default=list)  # Child CWE IDs
    related_attack_patterns = Column(JSON, default=list)  # CAPEC IDs
    applicable_platforms = Column(JSON, default=list)  # ["C", "Java", "PHP", ...]
    common_consequences = Column(JSON, default=list)  # [{"scope": "...", "impact": "..."}]
    detection_methods = Column(JSON, default=list)
    mitigations = Column(JSON, default=list)  # [{"phase": "...", "description": "..."}]
    category = Column(String)  # Top-level grouping: "injection", "auth", "crypto", etc.
    owasp_top_ten = Column(JSON, default=list)  # e.g. ["A03:2021"]
    url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


@importable(
    slug="exploit_reference",
    display_name="Exploit Reference",
    category="threat_intel",
    dedup_keys=["cve_id", "source", "source_id"],
    required_fields=["cve_id", "source"],
    description="Public exploit references — ExploitDB, Metasploit, Nuclei, PoCs",
)
class ExploitReference(Base):
    """Public exploit references from ExploitDB, Metasploit, Nuclei templates, etc."""
    __tablename__ = "exploit_references"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True, nullable=False)
    source = Column(String, nullable=False, index=True)  # "exploitdb" | "metasploit" | "nuclei"
    source_id = Column(String)  # ExploitDB ID, Metasploit module path, Nuclei template ID
    title = Column(String)
    description = Column(Text)
    url = Column(String)
    exploit_type = Column(String)  # "local" | "remote" | "webapps" | "dos" | "shellcode"
    platform = Column(String)  # "linux" | "windows" | "multiple" etc.
    verified = Column(Boolean, default=False)
    maturity = Column(String)  # "poc" | "functional" | "weaponized"
    published_date = Column(String)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("cve_id", "source", "source_id", name="uq_exploit_ref_cve_source"),
        Index("ix_exploit_ref_source", "source"),
    )


class SSVCDecision(Base):
    """CISA SSVC (Stakeholder-Specific Vulnerability Categorization) decisions from vulnrichment."""
    __tablename__ = "ssvc_decisions"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    decision = Column(String, nullable=False)  # "Track" | "Track*" | "Attend" | "Act"
    exploitation = Column(String)  # "none" | "poc" | "active"
    automatable = Column(String)  # "no" | "yes"
    technical_impact = Column(String)  # "partial" | "total"
    provider = Column(String, default="CISA")
    timestamp = Column(String)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GreyNoiseTag(Base):
    """GreyNoise internet scan/exploit activity for CVEs."""
    __tablename__ = "greynoise_tags"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True, nullable=False)
    seen = Column(Boolean, default=False)  # Whether GreyNoise has observed exploitation attempts
    last_seen = Column(String)
    noise = Column(Boolean, default=False)  # Mass scanning activity
    riot = Column(Boolean, default=False)  # Common business service (benign)
    classification = Column(String)  # "benign" | "malicious" | "unknown"
    name = Column(String)  # Tag/actor name from GreyNoise
    link = Column(String)  # GreyNoise URL
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MSRCPatch(Base):
    """Microsoft Security Response Center patch data (Patch Tuesday)."""
    __tablename__ = "msrc_patches"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True, nullable=False)
    kb_id = Column(String, index=True)  # e.g. "KB5034763"
    product_name = Column(String)  # e.g. "Windows Server 2019"
    product_id = Column(String)
    article_url = Column(String)
    download_url = Column(String)
    severity = Column(String)  # "Critical" | "Important" | "Moderate" | "Low"
    impact = Column(String)  # "Remote Code Execution" | "Elevation of Privilege" etc.
    supercedence = Column(String)  # KB that this patch supersedes
    restart_required = Column(String)  # "Yes" | "Maybe" | "No"
    release_date = Column(String)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("cve_id", "kb_id", "product_id", name="uq_msrc_cve_kb_product"),
    )

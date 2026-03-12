from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, JSON, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from database import Base


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
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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

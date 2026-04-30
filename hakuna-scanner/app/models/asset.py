import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSON, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("org_id", "hostname", name="uq_org_hostname"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    asn: Mapped[str | None] = mapped_column(String(32), nullable=True)
    asn_org: Mapped[str | None] = mapped_column(Text, nullable=True)
    open_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    # UDP-side counterpart populated from nmap UDP scan (see migration 014).
    # Kept separate because UDP "open" semantics differ from TCP and we want
    # transport-aware port_change events for the audit auto-trigger.
    open_udp_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    services: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    tech_stack: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cdn_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    waf: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tls_cert: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Normalized HTTP-header + cookie audit — see app.ingest.http_header_audit.
    # Denormalized from asset_enrichments.httpx_full.security_audit so the
    # AssetResponse API can return it without joining.
    security_audit: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dns_records: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_enriched: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_js_fingerprinted: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    nessus_asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Extension 5: Asset classification and protocol probing
    asset_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    protocol_detections: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Extension 2: Liveness validation
    liveness_state: Mapped[str] = mapped_column(String(32), default="unconfirmed")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Extension 4: Nmap fingerprinting
    nmap_status: Mapped[str] = mapped_column(String(32), default="pending")
    nmap_last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    os_fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Port-scan outcome tracking (migration 015). Distinguishes "scan ran
    # successfully with zero open ports found" from "never scanned" or
    # "scan failed/timed out". Empty-but-scanned hosts have
    # port_scan_state='scanned' and open_ports='{}' (zero-length array).
    # Values: pending | scanned | failed.
    port_scan_state: Mapped[str] = mapped_column(String(32), default="pending")
    port_scan_last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    org: Mapped["Org"] = relationship(back_populates="assets")  # noqa: F821
    events: Mapped[list["AssetEvent"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    ports: Mapped[list["AssetPort"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    enrichments: Mapped[list["AssetEnrichment"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    endpoints: Mapped[list["AssetEndpoint"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetPort(Base):
    """Per open port on an asset — stores service fingerprint, CPE, TLS, nmap scripts."""
    __tablename__ = "asset_ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_proto"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpe_list: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    tls_cert: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Deep-audit result (sslyze cipher enum + chain validation + OCSP + CAA)
    # produced by app.ingest.tls_deep_audit. See migration 013.
    tls_deep_audit: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    nmap_scripts: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # Per-port HTTP fingerprint from httpx (migration 016). Lets downstream
    # scanners target every web service on a host (e.g. admin UI on 8088)
    # instead of just the canonical 80/443 URL on assets.http_url.
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_webserver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    http_tech_stack: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    last_http_probed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset: Mapped["Asset"] = relationship(back_populates="ports")


class AssetEnrichment(Base):
    """Per enrichment run — stores full httpx/tlsx output."""
    __tablename__ = "asset_enrichments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    httpx_full: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    final_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    page_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    tech_stack: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_cdn: Mapped[bool] = mapped_column(Boolean, default=False)
    tlsx_raw: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    screenshot_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset: Mapped["Asset"] = relationship(back_populates="enrichments")


class AssetEndpoint(Base):
    """Discovered web/API endpoints (katana, kiterunner, openapi, graphql, llm_js, sourcemap, wordlist)."""
    __tablename__ = "asset_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_auth_page: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="katana")
    auth_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parameters: Mapped[dict | list | None] = mapped_column(JSONB, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="endpoints")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    assets_found: Mapped[int] = mapped_column(Integer, default=0)
    assets_changed: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Progress tracking
    current_stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stage_index: Mapped[int] = mapped_column(Integer, default=0)
    total_stages: Mapped[int] = mapped_column(Integer, default=0)
    stage_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stage_log: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Orphan recovery: how many times this run has been re-dispatched after
    # the worker lost it (crash, OOM, deploy). Capped at MAX_RECOVERY_ATTEMPTS
    # in app.tasks.recovery.
    recovery_attempts: Mapped[int] = mapped_column(Integer, default=0)

    org: Mapped["Org"] = relationship(back_populates="scan_runs")  # noqa: F821


class AssetEvent(Base):
    __tablename__ = "asset_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("orgs.id"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset: Mapped["Asset"] = relationship(back_populates="events")

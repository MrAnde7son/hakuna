"""Auto-dispatch unauthenticated audits when hakuna-scanner reports newly
opened ports on an asset.

Wired into ``services.scanner_event_bridge``: after each ``port_change``
event is forwarded to the workflow engine, this iterates the
``AUTO_TRIGGER_RULES`` registry, matches newly-added ports against rule
port lists, and — if the org/asset gating allows — kicks off the
relevant audit through the standard
``services.audit_runner.dispatch_audit_run`` pipeline with
``credential_id=None``.

Per-rule cooldown is stored on
``Asset.easm_data["_auto_audit_last"]`` so a flapping port doesn't fan
out a fresh audit on every poll cycle.

## Adding a family

Append an ``AutoTriggerRule`` to ``AUTO_TRIGGER_RULES``. The rule
declares: which ports are evidence (multi-port-per-protocol like
445+139→smb collapses naturally), which protocol+mission to dispatch,
which org-level setting key gates it, and the cooldown. OT-class
families set ``requires_per_asset_consent=True`` so they refuse to fire
without a fresh ``Asset.easm_data["ot_audit_consent"]`` record even
when the org-level switch is on.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.models import Asset, Organization, RelayAgent, Scan
from services.audit_runner import AuditDispatchError, dispatch_audit_run

logger = logging.getLogger(__name__)


# OT consent records expire after this window, forcing a fresh approval
# before another auto-dispatched run can target the asset. Same window
# applies regardless of the cooldown_hours on the rule.
_OT_CONSENT_TTL = timedelta(days=90)


@dataclass(frozen=True)
class AutoTriggerRule:
    """One scanner-event → audit dispatch rule.

    Multiple rules may match a single event (e.g. an asset that just
    exposed both 6379 and 27017 will fire two ``exposed_datastore`` runs
    — though future families may collapse via predicates). 445 + 139
    collapsing to a single SMB run is handled by both ports mapping to
    the same ``protocol`` value plus ``setdefault`` semantics in the
    matcher.
    """
    protocol: str
    mission: str
    ports: tuple[int, ...]
    transport: str = "tcp"  # "tcp" | "udp" — checked against the event when
                             # scanner emits transport-aware port_change events
    cooldown: timedelta = timedelta(hours=24)
    # Org-level setting key in ``Organization.settings`` that enables this
    # rule. Each family gets its own switch so customers can turn on
    # datastore auditing without also turning on AI auditing, etc.
    enabled_setting_key: str = "auto_audit_anon"
    # OT and other high-touch families set this to True. Even with the
    # org-level switch on, dispatch refuses without a fresh per-asset
    # consent record on ``Asset.easm_data["ot_audit_consent"]``.
    requires_per_asset_consent: bool = False
    # Optional predicate evaluated against the resolved Asset (and the
    # relay that would dispatch the run, when relevant). Used by:
    #   * families with port collisions (e.g. AI services share 3000/5000/8000
    #     with generic web apps) — the rule fires only when banner-grab
    #     data confirms the service identity.
    #   * LAN-local audits (NetBIOS/LLMNR/mDNS) — the rule fires only when
    #     the relay shares a broadcast domain with the asset.
    # Predicates that don't need the relay should ignore the second arg.
    predicate: Optional[Callable[[Asset, Optional[RelayAgent]], bool]] = field(
        default=None, compare=False,
    )


# Discoverable registry of every ``auto_audit_*`` setting key. Both the
# port-driven auto-trigger here and the chain coordinator's
# `_org_setting_enables` consult this set; admins flip the value via
# `Organization.settings[key] = True/False`. ``default`` is what
# ``_rule_enabled_for_org`` falls back to when no explicit value is set.
#
# Adding a new family: register the key here AND wire it into either
# ``AUTO_TRIGGER_RULES`` (port-driven) or
# ``services.chain_coordinator._PROTOCOL_TO_SETTING`` (graph-driven).
AUTO_AUDIT_SETTING_KEYS: dict[str, dict] = {
    "auto_audit_anon":          {"default": True,  "description": "Anonymous protocol audits (SMB/SNMP/LDAP)."},
    "auto_audit_datastore":     {"default": True,  "description": "Datastore exposure audits (MongoDB/Redis/Elastic/etc)."},
    "auto_audit_ai":            {"default": True,  "description": "AI service exposure audits (Ollama/MCP/etc)."},
    "auto_audit_anon_protocol": {"default": True,  "description": "Anonymous-protocol triage (FTP/Telnet/etc)."},
    "auto_audit_ipmi":          {"default": True,  "description": "IPMI BMC exposure audits."},
    "auto_audit_netbios":       {"default": True,  "description": "Local NetBIOS poisoning audits."},
    "auto_audit_ot":            {"default": False, "description": "OT/ICS audits (requires per-asset consent)."},
    # Coordinator-only keys. Default OFF — these dispatch credentialed
    # or heavy work that operators should opt into explicitly.
    "auto_audit_credentialed":  {"default": False, "description": "Credentialed mgmt-protocol audits (WMI/SSH) dispatched by the chain coordinator."},
    "auto_audit_vm_rescan":     {"default": False, "description": "VM rescan markers requested by the chain coordinator's sbom_unpatched pattern."},
}


# Module-level rule registry. Order matters only when two rules match
# the same (port, protocol) — first match wins. Keep it short and
# explicit; no auto-derivation from ``AUDITS`` since not every audit
# should auto-fire.
AUTO_TRIGGER_RULES: list[AutoTriggerRule] = [
    # ── Family: anon_standard (today's behavior) ──
    AutoTriggerRule(
        protocol="smb",
        mission="exposure_audit",
        ports=(445, 139),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_anon",
    ),
    AutoTriggerRule(
        protocol="snmp",
        mission="exposure_audit",
        ports=(161,),
        transport="udp",
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_anon",
    ),
    # ── Family: anon_datastore (Phase 1a) ──
    # One rule per datastore protocol. They all dispatch into the same
    # ``exposed_datastore`` audit registration with mission="triage" — the
    # protocol field on the rule is the AUDITS key, not a separate concept.
    # Each rule has its own port list and the family is gated by a single
    # org switch ``auto_audit_datastore`` so an org can opt into the whole
    # family without also turning on the legacy SMB/SNMP auto-trigger.
    AutoTriggerRule(
        protocol="exposed_datastore",
        mission="triage",
        ports=(
            # Phase 1a
            6379, 27017, 9200, 2375, 6443, 2379,
            # Phase 1b
            11211, 5601, 10250, 5984,
        ),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_datastore",
    ),
    # ── Family: anon_ai_exposure (Phase 3, gap-fill scope) ──
    # Phase 3 is "Option D": the EASM scanner already covers Ollama (11434),
    # vLLM (8000), and the eight other native ai_exposure_* services. The
    # auto-trigger fires only on the gap-fill ports the scanner does not
    # already classify. 11434/8000 are deliberately excluded from the rule
    # because the scanner emits findings for them at scan time — the audit
    # would just double-emit.
    #
    # Ports 3000/5000/8080 collide with generic web frameworks (Grafana,
    # Flask apps, web admin UIs). The predicate gates the rule on the
    # scanner's classifier output: only fire if asset_classifier tagged the
    # asset as one of the AI-shaped types. Other gap-fill ports (8888 for
    # Jupyter, 8265 for Ray, 6006 for TensorBoard, 1234 for LM Studio) are
    # AI-specific and don't need the predicate — but the same rule covers
    # them, so the predicate is "AI-typed OR port is unambiguous." We pick
    # the simpler form: require AI-typed for the colliding ports, allow
    # unambiguous ports through.
    AutoTriggerRule(
        protocol="exposed_ai_service",
        mission="triage",
        ports=(8888, 8265, 5000, 6006, 8080, 1234, 3000),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_ai",
        predicate=lambda asset, _relay: _ai_service_predicate(asset),
    ),
    # ── Family: anon_standard (Phase 4.1) ──
    # Legacy anon-misconfig protocols. Single registration covers the
    # five member protocols; the audit's tools palette + relay handler
    # dispatch on op. UDP-only TFTP (port 69) is currently not surfaced
    # via the scanner's TCP-based port_change events — it'll join when
    # Phase 4.0 (UDP port_change) lands. The other four ports are TCP.
    AutoTriggerRule(
        protocol="exposed_anon_protocol",
        mission="triage",
        ports=(21, 53, 88, 5900),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_anon_protocol",
    ),
    # ── Family: anon_ipmi (Phase 4.2) ──
    # IPMI BMC on UDP 623 → cipher zero + RAKP-3 hash leak triage. UDP-only;
    # depends on Phase 4.0 transport-aware port_change events to fire.
    AutoTriggerRule(
        protocol="ipmi_bmc",
        mission="triage",
        ports=(623,),
        transport="udp",
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_ipmi",
    ),
    # ── Family: anon_lan_local (Phase 4.3) ──
    # NetBIOS-NS / LLMNR / mDNS — only valid when the relay shares a
    # broadcast domain with the asset. The predicate enforces that by
    # comparing the asset's IP against the relay's reported local CIDRs.
    # Without same-subnet, multicast-style protocols won't reach the host
    # and the LLM would burn budget on probes destined to time out.
    AutoTriggerRule(
        protocol="netbios_local",
        mission="triage",
        ports=(137, 5355, 5353),
        transport="udp",
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_netbios",
        predicate=lambda asset, relay: _lan_local_predicate(asset, relay),
    ),
    # SIP / RTSP unicast endpoint discovery. Same broadcast-domain gate as
    # NetBIOS — the SIP probe only works against the asset's own IP, not a
    # multicast group, but the realistic deployments are LAN-only (an IP
    # phone or RTSP camera is virtually never directly internet-exposed).
    # Two rules, one per transport: SIP commonly runs on UDP 5060 *and*
    # TCP 5060/5061, and RTSP is TCP 554. Phase 4.0's transport-aware
    # delta would skip half the ports without separate rules.
    AutoTriggerRule(
        protocol="endpoint_discovery",
        mission="endpoint_fingerprint",
        ports=(554, 5060, 5061),
        transport="tcp",
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_endpoint_discovery",
        predicate=lambda asset, relay: _lan_local_predicate(asset, relay),
    ),
    AutoTriggerRule(
        protocol="endpoint_discovery",
        mission="endpoint_fingerprint",
        ports=(5060,),
        transport="udp",
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_endpoint_discovery",
        predicate=lambda asset, relay: _lan_local_predicate(asset, relay),
    ),
    # ── Family E: ot_safe (Phase 5) ──
    # Active OT/ICS audit. Same gating shape as the other families (org-level
    # ``auto_audit_ot`` master switch) PLUS a per-asset consent record on
    # ``Asset.easm_data['ot_audit_consent']`` (90-day TTL) — operators sign
    # off on each PLC/DCS/RTU individually because even read-only PDUs land
    # on plant safety hardware. Both gates must pass to auto-fire.
    # 7-day cooldown so we don't re-poke a PLC daily. Two rules — one per
    # transport — because OT fingerprints split across TCP and UDP and
    # Phase 4.0's transport-aware delta means we'd miss UDP-only protocols
    # (BACnet, Omron FINS, PROFINET) without a UDP rule.
    AutoTriggerRule(
        protocol="ot_protocol",
        mission="triage",
        ports=(502, 102, 44818, 4840, 5007, 2404),
        transport="tcp",
        cooldown=timedelta(days=7),
        enabled_setting_key="auto_audit_ot",
        requires_per_asset_consent=True,
    ),
    AutoTriggerRule(
        protocol="ot_protocol",
        mission="triage",
        ports=(47808, 9600, 34962),
        transport="udp",
        cooldown=timedelta(days=7),
        enabled_setting_key="auto_audit_ot",
        requires_per_asset_consent=True,
    ),
    # ── Family E': ot_passive_only (Phase 5) ──
    # Passive listener — bind a UDP socket and wait for vendor-signature
    # frames. No PDU is ever sent. Same per-asset consent gate as the
    # active audit. There's no canonical port_change trigger for a passive
    # listener (it works against any open-port set), so this rule fires on
    # the same UDP-port set that suggests OT presence. Consent + cooldown
    # do the rest of the gating.
    AutoTriggerRule(
        protocol="ot_passive",
        mission="triage",
        ports=(47808, 9600, 34962),
        transport="udp",
        cooldown=timedelta(days=7),
        enabled_setting_key="auto_audit_ot",
        requires_per_asset_consent=True,
    ),
]


def _lan_local_predicate(asset: Asset, relay: Optional[RelayAgent]) -> bool:
    """Gate LAN-local audits on relay-and-asset same-subnet.

    Reads the relay's reported local interfaces from
    ``RelayAgent.labels["local_interfaces"]`` (a list of CIDR strings
    populated at relay registration). The audit fires only when the
    asset's IP falls inside one of those CIDRs. Missing labels = treat
    as "not on same subnet" (defensive default — better to skip than to
    fire LLM budget on a probe that can't reach the host).
    """
    if relay is None or not asset.ip:
        return False
    labels = getattr(relay, "labels", None) or {}
    cidrs = labels.get("local_interfaces") if isinstance(labels, dict) else None
    if not cidrs or not isinstance(cidrs, list):
        return False
    try:
        addr = ipaddress.ip_address(str(asset.ip))
    except (TypeError, ValueError):
        return False
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except (TypeError, ValueError):
            continue
        if addr in net:
            return True
    return False


# Ports where the rule fires regardless of asset_type — these are
# AI-specific ports with no realistic non-AI service collision.
_AI_UNAMBIGUOUS_PORTS = frozenset({8888, 8265, 6006, 1234})

# AI-typed asset_type values produced by the scanner's asset_classifier.
_AI_ASSET_TYPES = frozenset({"ai_inference", "ai_gateway", "ai_agent", "vector_db"})


def _ai_service_predicate(asset: Asset) -> bool:
    """Gate the exposed-AI auto-trigger on classifier-confirmed AI shape.

    Fires when EITHER:
      * any of the new ports is unambiguously AI (8888, 8265, 6006, 1234), OR
      * the scanner's classifier tagged this asset as an AI/vector type.

    Without this predicate, dropping a generic web app on port 3000 would
    burn LLM budget on a probe destined to return ``auth_required: true``
    or non-200. The classifier already disambiguates these ports during
    enrichment; reuse it.
    """
    open_ports = set()
    easm = asset.easm_data or {}
    if isinstance(easm, dict):
        for p in easm.get("open_ports") or []:
            try:
                open_ports.add(int(p))
            except (TypeError, ValueError):
                continue
    if open_ports & _AI_UNAMBIGUOUS_PORTS:
        return True
    # asset_type lives on the column; scanners that haven't propagated yet
    # may stash it in easm_data. Check both.
    asset_type = (asset.asset_type or "").strip()
    if not asset_type and isinstance(easm, dict):
        asset_type = str(easm.get("asset_type") or "").strip()
    return asset_type in _AI_ASSET_TYPES


def _rule_enabled_for_org(rule: AutoTriggerRule, org: Organization) -> bool:
    """Per-org enable gate.

    Anonymous audit families (SMB/SNMP, datastore, AI, anon-protocol, IPMI,
    NetBIOS) default to ON — newly-discovered exposed services get triaged
    automatically. An admin can flip the family-specific setting to ``False``
    to opt out.

    Rules that require per-asset consent (OT/ICS) stay default-OFF: the org
    setting must be explicitly ``True`` AND a fresh consent record must exist
    on the asset before any PDU is sent at plant-safety hardware.
    """
    explicit = (org.settings or {}).get(rule.enabled_setting_key)
    if explicit is not None:
        return bool(explicit)
    return not rule.requires_per_asset_consent


def _has_fresh_consent(asset: Asset, protocol: str, now: datetime) -> bool:
    """Per-asset consent gate for OT-class rules.

    Looks for ``Asset.easm_data["ot_audit_consent"]`` keyed by protocol with
    a non-expired ``granted_at`` timestamp. Missing or stale → no consent.
    """
    consent_map = (asset.easm_data or {}).get("ot_audit_consent") or {}
    record = consent_map.get(protocol)
    if not isinstance(record, dict):
        return False
    granted_raw = record.get("granted_at")
    if not granted_raw:
        return False
    try:
        granted = datetime.fromisoformat(granted_raw)
    except (TypeError, ValueError):
        return False
    if granted.tzinfo is None:
        granted = granted.replace(tzinfo=timezone.utc)
    return (now - granted) < _OT_CONSENT_TTL


def _resolve_backend_asset(
    db: Session, org_id: int, scanner_asset_id: Optional[str], hostname: Optional[str],
) -> Optional[Asset]:
    """Map the scanner-side UUID back to a backend ``Asset`` in this org.

    The scanner emits its own UUID; backend assets store it in
    ``easm_data["easm_asset_id"]``. Filtering JSON across SQLite (tests)
    and Postgres (prod) is dialect-specific, so narrow with ``hostname``
    when available and finish the match in Python — the candidate set is
    small (one asset per fqdn per org).
    """
    if not scanner_asset_id:
        return None
    q = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Scan.org_id == org_id, Asset.easm_data.isnot(None))
    )
    if hostname:
        q = q.filter(or_(Asset.hostname == hostname, Asset.fqdn == hostname))
    for asset in q.limit(50).all():
        if (asset.easm_data or {}).get("easm_asset_id") == scanner_asset_id:
            return asset
    return None


def _pick_relay(
    db: Session, org_id: int, asset: Optional[Asset] = None,
) -> Optional[RelayAgent]:
    """Pick a connected relay for ``org_id``, biased by asset reachability.

    Selection rules:
      * Internet-facing assets prefer ``relay_type='cloud_scanner'`` (Hakuna
        runs one in GCP per org — no customer deployment required for public
        targets).
      * Everything else prefers ``relay_type='agent'`` (customer-deployed
        on-prem relays — only those can reach private networks).
      * If the preferred type isn't connected, fall back to whatever is —
        better to dispatch through a non-ideal relay than skip the audit.

    Within a type, most-recently-seen wins (matches prior behavior).
    """
    base = db.query(RelayAgent).filter(
        RelayAgent.org_id == org_id, RelayAgent.status == "connected",
    )

    prefer_cloud = bool(asset and getattr(asset, "is_internet_facing", False))
    preferred_type = "cloud_scanner" if prefer_cloud else "agent"

    preferred = (
        base.filter(RelayAgent.relay_type == preferred_type)
        .order_by(RelayAgent.last_seen_at.desc().nullslast())
        .first()
    )
    if preferred:
        return preferred

    # Fallback: any connected relay, most-recently-seen first.
    return base.order_by(RelayAgent.last_seen_at.desc().nullslast()).first()


def _within_cooldown(asset: Asset, protocol: str, cooldown: timedelta, now: datetime) -> bool:
    last_map = (asset.easm_data or {}).get("_auto_audit_last") or {}
    raw = last_map.get(protocol)
    if not raw:
        return False
    try:
        last = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) < cooldown


def _stamp_cooldown(asset: Asset, protocol: str, now: datetime) -> None:
    easm = dict(asset.easm_data or {})
    last_map = dict(easm.get("_auto_audit_last") or {})
    last_map[protocol] = now.isoformat()
    easm["_auto_audit_last"] = last_map
    asset.easm_data = easm


def _match_rules(new_ports: set[int], transport: str = "tcp") -> dict[str, AutoTriggerRule]:
    """Pick the first rule (in registry order) per protocol whose port set
    intersects ``new_ports`` AND whose declared transport matches ``transport``.

    Phase 4.0 introduced transport-aware port_change events (the scanner
    emits one event per (asset, transport) per scan). Rules declare their
    transport on the dataclass; matcher rejects rules whose transport
    doesn't match the event. UDP-only services (SNMP 161, IPMI 623, TFTP
    69, NetBIOS 137/5353/5355) only fire when ``transport='udp'``; TCP
    services only fire when ``transport='tcp'``.

    Events without a ``transport`` field (legacy / pre-4.0) default to
    ``'tcp'`` for back-compat — matching the historical TCP-only behavior.
    """
    matched: dict[str, AutoTriggerRule] = {}
    for rule in AUTO_TRIGGER_RULES:
        if rule.protocol in matched:
            continue
        if rule.transport != transport:
            continue
        if any(p in new_ports for p in rule.ports):
            matched[rule.protocol] = rule
    return matched


def maybe_auto_trigger_anon_audits(
    db: Session, org: Organization, event: dict,
    *, asset: Optional[Asset] = None,
) -> int:
    """Inspect a scanner ``port_change`` event and dispatch matching audits.

    Returns the number of audits actually dispatched. Per-rule short-circuits
    return 0 individually: org switch off, no consent (for OT-class rules),
    cooldown active, predicate rejects, no relay, or asset unresolved.

    Callers that already hold a backend ``Asset`` (e.g. the VM scanner ingest
    path, where the asset row was just upserted) can pass it via ``asset=``
    to skip the scanner-id resolution step. The event still drives port and
    transport extraction.
    """
    if event.get("event_type") != "port_change":
        return 0

    payload = event.get("payload") or {}
    new_ports: set[int] = set()
    for p in payload.get("new_ports") or []:
        try:
            new_ports.add(int(p))
        except (TypeError, ValueError):
            continue
    # Phase 4.0: events carry a transport tag; legacy events without one
    # are treated as TCP. SNMP/IPMI/TFTP/NetBIOS rules declare transport=udp
    # and only fire on UDP events.
    transport = (payload.get("transport") or "tcp").lower()
    matched = _match_rules(new_ports, transport)
    if not matched:
        return 0

    # Filter on org-level enablement before any DB work — the common case
    # is an org with auto_audit_anon=False, and we'd rather skip the
    # asset-resolution query for those.
    matched = {p: r for p, r in matched.items() if _rule_enabled_for_org(r, org)}
    if not matched:
        return 0

    if asset is None:
        asset = _resolve_backend_asset(
            db, org.id,
            scanner_asset_id=event.get("asset_id"),
            hostname=payload.get("hostname"),
        )
    if not asset:
        logger.info(
            "auto-audit: org=%d skipped — scanner asset %s not yet linked to backend",
            org.id, event.get("asset_id"),
        )
        return 0

    # Per-scan opt-out: when the EASM scan that discovered this asset was
    # started with the "Run automated follow-up scans" checkbox unticked,
    # the scan record carries ``suppress_auto_followup=True``. Honor it
    # across all rules — the operator already declined family-by-family
    # granularity by unchecking at scan time. Same flag also blocks the
    # post-ingest VM (Nuclei) scan; see ``post_ingest._auto_vm_scan_for_easm``.
    scan = asset.scan
    if scan and (scan.raw_metadata or {}).get("suppress_auto_followup"):
        logger.info(
            "auto-audit: org=%d asset=%d suppressed — scan %d opted out at creation",
            org.id, asset.id, scan.id,
        )
        return 0

    relay = _pick_relay(db, org.id, asset)
    if not relay:
        logger.info(
            "auto-audit: org=%d skipped — no connected relay for asset %d",
            org.id, asset.id,
        )
        return 0

    now = datetime.now(timezone.utc)
    dispatched = 0
    for protocol, rule in matched.items():
        if rule.requires_per_asset_consent and not _has_fresh_consent(asset, protocol, now):
            logger.info(
                "auto-audit: org=%d asset=%d protocol=%s suppressed — no fresh consent",
                org.id, asset.id, protocol,
            )
            continue
        if rule.predicate is not None and not rule.predicate(asset, relay):
            logger.debug(
                "auto-audit: org=%d asset=%d protocol=%s suppressed by predicate",
                org.id, asset.id, protocol,
            )
            continue
        if _within_cooldown(asset, protocol, rule.cooldown, now):
            logger.debug(
                "auto-audit: org=%d asset=%d protocol=%s suppressed by cooldown",
                org.id, asset.id, protocol,
            )
            continue
        try:
            result = dispatch_audit_run(
                db, org,
                protocol=protocol,
                mission=rule.mission,
                relay_agent_id=relay.id,
                credential_id=None,
                asset_ids=[asset.id],
            )
        except AuditDispatchError as e:
            logger.warning(
                "auto-audit: org=%d asset=%d protocol=%s dispatch failed: %s",
                org.id, asset.id, protocol, e,
            )
            continue
        _stamp_cooldown(asset, protocol, now)
        dispatched += 1
        logger.info(
            "auto-audit: org=%d asset=%d protocol=%s mission=%s scan=%s dispatched on port_change",
            org.id, asset.id, protocol, rule.mission, result.get("scan_id"),
        )
    if dispatched:
        db.commit()
    return dispatched

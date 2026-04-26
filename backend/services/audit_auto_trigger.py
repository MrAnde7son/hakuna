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
    # Optional predicate evaluated against the resolved Asset. Used by
    # families with port collisions (e.g. AI services share 3000/5000/8000
    # with generic web apps) — the rule fires only when banner-grab data
    # confirms the service identity.
    predicate: Optional[Callable[[Asset], bool]] = field(default=None, compare=False)


# Module-level rule registry. Order matters only when two rules match
# the same (port, protocol) — first match wins. Keep it short and
# explicit; no auto-derivation from ``AUDITS`` since not every audit
# should auto-fire.
AUTO_TRIGGER_RULES: list[AutoTriggerRule] = [
    # ── Family: anon_standard (today's behavior) ──
    AutoTriggerRule(
        protocol="smb",
        mission="null_session",
        ports=(445, 139),
        cooldown=timedelta(hours=24),
        enabled_setting_key="auto_audit_anon",
    ),
    AutoTriggerRule(
        protocol="snmp",
        mission="device_posture",
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
]


def _rule_enabled_for_org(rule: AutoTriggerRule, org: Organization) -> bool:
    """Per-org opt-in via the rule's setting key. Default OFF so this never
    spends LLM budget without explicit consent — the org admin flips it on."""
    return bool((org.settings or {}).get(rule.enabled_setting_key))


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


def _pick_relay(db: Session, org_id: int) -> Optional[RelayAgent]:
    """Most-recently-seen connected relay for the org. Audits run over the
    relay; without one we have nowhere to send the request."""
    return (
        db.query(RelayAgent)
        .filter(RelayAgent.org_id == org_id, RelayAgent.status == "connected")
        .order_by(RelayAgent.last_seen_at.desc().nullslast())
        .first()
    )


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


def _match_rules(new_ports: set[int]) -> dict[str, AutoTriggerRule]:
    """Pick the first rule (in registry order) per protocol whose port set
    intersects ``new_ports``. Collapsing on protocol means 445+139 produces
    exactly one SMB rule match — and a future ``exposed_datastore`` rule
    spanning many ports likewise produces one match per protocol per event.
    """
    matched: dict[str, AutoTriggerRule] = {}
    for rule in AUTO_TRIGGER_RULES:
        if rule.protocol in matched:
            continue
        if any(p in new_ports for p in rule.ports):
            matched[rule.protocol] = rule
    return matched


def maybe_auto_trigger_anon_audits(
    db: Session, org: Organization, event: dict,
) -> int:
    """Inspect a scanner ``port_change`` event and dispatch matching audits.

    Returns the number of audits actually dispatched. Per-rule short-circuits
    return 0 individually: org switch off, no consent (for OT-class rules),
    cooldown active, predicate rejects, no relay, or asset unresolved.
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
    matched = _match_rules(new_ports)
    if not matched:
        return 0

    # Filter on org-level enablement before any DB work — the common case
    # is an org with auto_audit_anon=False, and we'd rather skip the
    # asset-resolution query for those.
    matched = {p: r for p, r in matched.items() if _rule_enabled_for_org(r, org)}
    if not matched:
        return 0

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

    relay = _pick_relay(db, org.id)
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
        if rule.predicate is not None and not rule.predicate(asset):
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

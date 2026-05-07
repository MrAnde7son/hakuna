"""Cross-Scan Chain Coordinator — Phase 3 (v1).

The Coordinator chains findings across producers (EASM, VM scanner, audit
agents, parsers) into validated multi-hop attack paths. v1 ships one
hypothesis pattern (`easm_to_smb`) and a closure detector that walks the
unified edge graph (`asset_relationships` after migration 054) from
internet entry points to crown-jewel assets.

See `docs/cross-scan-chain-coordinator-plan.md` (Phase 3 section) for the
full design. Notable invariants:

  * **No LLM in the loop.** Hypothesis enumeration, scoring, dispatch,
    and closure detection are deterministic graph walks. The narrator
    (`services.attack_chain_narrator`) still runs over the resulting
    `AttackPath` rows on its own schedule.

  * **Honors the auto-trigger cooldown.** Before dispatching, the
    Coordinator checks `Asset.easm_data["_auto_audit_last"]` — the same
    timestamp `audit_auto_trigger.py` writes. No parallel cooldown table.

  * **Composable with the auto-trigger.** Both consume post-ingest
    events; the auto-trigger fires on `port_change` (one asset, one
    protocol), the Coordinator fires on `tick` (whole-org graph state)
    and adds graph-aware hypotheses the auto-trigger can't reach.

  * **Approval gate scaffolding** is in place even though no v1 pattern
    needs it. Patterns flagged ``requires_approval=True`` are skipped
    in v1 — the operator will pick them up via the AttackPaths UI when
    Phase 4 patterns (e.g. `cred_found`) land.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from models.asset_edges import (
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_COERCE,
    ASSET_TO_ASSET_PORT,
    CVE_ON_ASSET,
    INTERNET_TO_ASSET,
    LOCAL_ROOT,
)
from models.models import (
    AgentApproval,
    AgentLead,
    Asset,
    AssetRelationship,
    AttackPath,
    Finding,
    Organization,
    Scan,
)

logger = logging.getLogger(__name__)


# ── Public API ──────────────────────────────────────────────────────


def tick(db: Session, *, org_id: int, scan_id: int | None = None) -> dict:
    """Single coordinator tick — enumerate hypotheses, dispatch top-N,
    detect closures, emit `ValidatedChain` findings.

    Wired to the post-ingest event stream (`_fire_data_triggers`)
    through `services.job_manager.dispatch` with per-org debounce —
    multi-batch ingests collapse to one tick.

    Returns a small dict for pipeline / job-result logging.
    """
    if not org_id:
        return {"dispatched": 0, "validated_chains": 0, "skipped": "no_org"}

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if org is None:
        return {"dispatched": 0, "validated_chains": 0, "skipped": "no_org"}

    affected = _recompute_affected_subgraph(db, org_id, scan_id)

    hypotheses = enumerate_hypotheses(db, org_id, affected)
    ranked = rank_hypotheses(hypotheses)

    dispatched = 0
    skipped: list[dict] = []
    for hyp in ranked[:_MAX_DISPATCH_PER_TICK]:
        outcome = _dispatch_hypothesis(db, org, hyp)
        if outcome.get("dispatched"):
            dispatched += 1
        else:
            skipped.append(outcome)

    closures = detect_closures(db, org_id, affected)
    validated = 0
    emitted_findings: list[Finding] = []
    for chain in closures:
        f = _emit_validated_chain(db, org_id, chain)
        if f is not None:
            emitted_findings.append(f)
            validated += 1

    if dispatched or validated:
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise

    # Fire ``validated_chain`` events AFTER the commit so the agent's
    # background session can actually find the rows we just wrote. The
    # dispatcher queues run_agent on the job manager — bus calls return
    # immediately, so this doesn't slow tick(). Failures are logged and
    # don't roll back the validated chain itself.
    for f in emitted_findings:
        try:
            from services.event_bus import emit as _emit
            chain_meta = (f.custom_fields or {}).get("chain") or {}
            _emit(
                db,
                event_type="validated_chain",
                org_id=org_id,
                payload={
                    "finding_id": f.id,
                    "scan_id": f.scan_id,
                    "asset_id": f.asset_id,
                    "severity_label": f.severity_label,
                    "priority_score": f.priority_score,
                    # Pass a *summary* of the chain — entry/target ids,
                    # source systems, score, signature. The narrator can
                    # call query_findings(finding_id) to fetch the full
                    # custom_fields["chain"] (edge summaries, CVEs, TTPs)
                    # if it needs them.
                    "chain_summary": {
                        "entry_asset_id": chain_meta.get("entry_asset_id"),
                        "target_asset_id": chain_meta.get("target_asset_id"),
                        "asset_ids": chain_meta.get("asset_ids") or [],
                        "edge_count": len(chain_meta.get("edge_ids") or []),
                        "source_systems": chain_meta.get("source_systems") or [],
                        "score": chain_meta.get("score"),
                        "signature": chain_meta.get("signature"),
                    },
                },
                # finding_id keys debounce so two chains validated in
                # the same tick each get their own narrator run. The
                # default per-event-type debounce would have collapsed
                # them.
                dedup_key=f.id,
            )
        except Exception:
            logger.exception(
                "chain_coordinator: validated_chain emit failed finding=%d", f.id,
            )

    logger.info(
        "chain_coordinator: org=%d scan=%s hyp=%d dispatched=%d validated=%d",
        org_id, scan_id, len(hypotheses), dispatched, validated,
    )
    return {
        "hypotheses": len(hypotheses),
        "dispatched": dispatched,
        "validated_chains": validated,
        "skipped": skipped[:10],   # cap so the job_result payload stays bounded
    }


# ── Hypothesis enumeration ──────────────────────────────────────────


@dataclass(frozen=True)
class Hypothesis:
    """Partial path with at least one missing edge a known scan can fill.

    The Coordinator dispatches the suggested probe and waits for the
    edge graph to fill in on a future tick.
    """
    pattern: str                      # e.g. "easm_to_smb"
    asset_id: int
    protocol: str                     # `dispatch_audit_run` protocol arg
    mission: str                      # `dispatch_audit_run` mission arg
    score: float = 0.0                # produced by `rank_hypotheses`
    score_factors: dict = field(default_factory=dict)
    requires_approval: bool = False   # off by default; Phase 4 turns on cred_found etc.
    rationale: str = ""               # short string for logging / UI
    # Optional non-standard port discovered by EASM service fingerprinting.
    # When set, ``_dispatch_hypothesis`` stamps it onto
    # ``Asset.easm_data['audit_target_port']`` before calling
    # ``audit_runner.dispatch_audit_run`` so the audit tools target
    # ``host:port`` instead of the protocol's hardcoded standard port.
    # Cooldowns + debounce key on ``(protocol, port)`` when this is set so
    # SSH on 22 and SSH on 2222 don't share gating state.
    port: int | None = None


def enumerate_hypotheses(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """Run every registered pattern's `match` over the affected subgraph.

    Patterns are functions, not config — adding one is a new function
    and a row in the table in the design doc. v1 ships only `easm_to_smb`.
    """
    out: list[Hypothesis] = []
    for fn in _PATTERNS:
        try:
            out.extend(fn(db, org_id, affected_set))
        except Exception:                    # noqa: BLE001 — pattern is best-effort
            logger.exception("chain_coordinator: pattern %s raised", fn.__name__)
    return out


def rank_hypotheses(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    """Deterministic scorer — see the doc for the formula. Stable sort
    by (score desc, asset_id) so two equal-score hypotheses don't flap
    between ticks.
    """
    scored: list[Hypothesis] = []
    for h in hypotheses:
        s, factors = _score_hypothesis(h)
        scored.append(
            Hypothesis(
                pattern=h.pattern,
                asset_id=h.asset_id,
                protocol=h.protocol,
                mission=h.mission,
                score=s,
                score_factors=factors,
                requires_approval=h.requires_approval,
                rationale=h.rationale,
                port=h.port,
            )
        )
    scored.sort(key=lambda h: (-h.score, h.asset_id, h.port or 0))
    return scored


# ── Pattern: easm_to_smb ────────────────────────────────────────────


def _pattern_easm_to_smb(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """An EASM-discovered Windows host with port 445 reachable from the
    internet, but no SMB audit ran in the cooldown window — dispatch the
    SMB exposure_audit (anonymous mission) so we can prove or disprove
    the next-hop edges (coerce, auth) for later closure.

    Predicate:
      * `internet_to_asset` edge with port 445 / family=smb
      * Windows-shaped asset (os contains "windows" or known SMB banners)
      * No `_auto_audit_last["smb"]` within 24h
      * No outbound `asset_to_asset_coerce` / `asset_to_asset_auth` edges
        already on this asset (else the chain is already in motion and
        the closure detector will pick it up).
    """
    # Pull every internet→asset edge with port 445, optionally restricted
    # to the affected set so a tick driven by a specific scan doesn't
    # re-poke unrelated assets.
    rows = db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == INTERNET_TO_ASSET,
        AssetRelationship.target_asset_id.isnot(None),
    ).all()

    smb_targets: set[int] = set()
    for edge in rows:
        props = edge.properties or {}
        port = props.get("port")
        family = (props.get("family") or "").lower()
        if family == "smb" or port in (445, 139):
            smb_targets.add(edge.target_asset_id)

    if affected_set:
        smb_targets &= affected_set

    if not smb_targets:
        return []

    # Skip assets that already have outbound coerce/auth edges — the
    # chain is already partly proved and the closure detector will
    # surface it. We don't want to re-fire the same audit while the
    # graph already evolved past it.
    existing = db.query(
        AssetRelationship.source_asset_id,
    ).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type.in_(
            (ASSET_TO_ASSET_COERCE, ASSET_TO_ASSET_AUTH),
        ),
        AssetRelationship.source_asset_id.in_(smb_targets),
    ).distinct().all()
    in_motion = {row[0] for row in existing if row[0] is not None}
    candidates = smb_targets - in_motion
    if not candidates:
        return []

    assets = db.query(Asset).filter(Asset.id.in_(candidates)).all()
    now = datetime.now(timezone.utc)

    out: list[Hypothesis] = []
    for asset in assets:
        if not _looks_like_windows(asset):
            continue
        if _within_smb_cooldown(asset, now):
            continue
        out.append(Hypothesis(
            pattern="easm_to_smb",
            asset_id=asset.id,
            protocol="smb",
            mission="exposure_audit",
            requires_approval=False,
            rationale=(
                f"asset {asset.id} is internet-reachable on SMB and Windows-shaped; "
                "no recent SMB audit and no outbound coerce/auth edges yet"
            ),
        ))
    return out


# ── Pattern: coerce_to_dc ───────────────────────────────────────────


def _pattern_coerce_to_dc(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """An audit emitted a coerce edge somewhere in the org and we have at
    least one DC that hasn't been LDAP-audited recently. Dispatch the
    LDAP exposure_audit so we know which delegations / ACEs / DCSync
    rights are live before chasing the relay leg.

    Predicate:
      * At least one `asset_to_asset_coerce` edge exists in the org
        (the coerce primitive is reachable from somewhere). dst is
        usually NULL on these edges — the relay target is unknown until
        the chain closes — so we don't gate on "edge points at the DC".
      * The DC is on the crown-jewel set (reason="domain_controller").
      * No `_auto_audit_last["ldap"]` within 24h on the DC.
      * The DC has no outbound `principal_to_domain` / dcsync edge yet
        (else the chain is already partly proved; the closure detector
        will pick it up).
    """
    coerce_exists = db.query(AssetRelationship.id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == ASSET_TO_ASSET_COERCE,
    ).first()
    if not coerce_exists:
        return []

    crown = _crown_jewel_assets(db, org_id)
    dc_ids = {aid for aid, meta in crown.items() if meta.get("reason") == "domain_controller"}
    if affected_set:
        dc_ids &= (affected_set | _coerce_endpoint_set(db, org_id))
    if not dc_ids:
        return []

    # DCs already implicated as DCSync sources — skip; the closure walk
    # will pick them up once the rest of the chain materializes.
    proved = db.query(AssetRelationship.source_asset_id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == "principal_to_domain",
        AssetRelationship.source_asset_id.in_(dc_ids),
    ).distinct().all()
    in_motion = {row[0] for row in proved if row[0] is not None}
    candidates = dc_ids - in_motion
    if not candidates:
        return []

    assets = db.query(Asset).filter(Asset.id.in_(candidates)).all()
    now = datetime.now(timezone.utc)

    out: list[Hypothesis] = []
    for asset in assets:
        if _within_protocol_cooldown(asset, "ldap", now):
            continue
        out.append(Hypothesis(
            pattern="coerce_to_dc",
            asset_id=asset.id,
            protocol="ldap",
            mission="exposure_audit",
            requires_approval=False,
            rationale=(
                f"asset {asset.id} is a domain controller with no recent LDAP audit; "
                "an org-internal coerce primitive exists that could relay against it"
            ),
        ))
    return out


def _coerce_endpoint_set(db: Session, org_id: int) -> set[int]:
    """Asset ids that are *involved* in a coerce edge (either endpoint).

    Used so a tick filters DCs to ones in or adjacent to the affected
    subgraph — avoids re-poking every DC in the org just because some
    unrelated asset changed.
    """
    rows = db.query(
        AssetRelationship.source_asset_id,
        AssetRelationship.target_asset_id,
    ).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == ASSET_TO_ASSET_COERCE,
    ).all()
    out: set[int] = set()
    for src, dst in rows:
        if src is not None:
            out.add(int(src))
        if dst is not None:
            out.add(int(dst))
    return out


# ── Pattern: vm_kev_to_audit ────────────────────────────────────────


# Mgmt protocol → port set. The pattern dispatches the audit whose port
# is open on the asset; first hit wins (deterministic order).
_VM_KEV_PROTOCOL_PORTS: tuple[tuple[str, frozenset[int]], ...] = (
    ("smb",  frozenset({445, 139})),
    ("wmi",  frozenset({135, 5985, 5986})),
    ("ssh",  frozenset({22})),
    ("snmp", frozenset({161})),
)


def _pattern_vm_kev_to_audit(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """A KEV-flagged CVE is attached to an asset, the asset has a
    reachable mgmt protocol, and no audit has run on that protocol since
    the CVE was first seen. Dispatch the matching audit so we get the
    privesc/lateral edges KEV exploitation tends to enable.

    Predicate:
      * `cve_on_asset` edge with `properties.kev = True`.
      * Asset has at least one mgmt port open (smb/wmi/ssh/snmp).
      * No `_auto_audit_last[<protocol>]` within 24h.
      * Asset has no outbound `local_root` / `asset_to_asset_*` edges
        already (otherwise we already audited and proved the next hop).
    """
    edge_q = db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == CVE_ON_ASSET,
        AssetRelationship.target_asset_id.isnot(None),
    )
    kev_targets: set[int] = set()
    for edge in edge_q.all():
        props = edge.properties or {}
        if props.get("kev"):
            kev_targets.add(int(edge.target_asset_id))

    if affected_set:
        kev_targets &= affected_set
    if not kev_targets:
        return []

    # Skip assets that already have outbound capability edges — chain in motion.
    already = db.query(AssetRelationship.source_asset_id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type.in_(
            (LOCAL_ROOT, ASSET_TO_ASSET_AUTH, ASSET_TO_ASSET_COERCE),
        ),
        AssetRelationship.source_asset_id.in_(kev_targets),
    ).distinct().all()
    in_motion = {row[0] for row in already if row[0] is not None}
    candidates = kev_targets - in_motion
    if not candidates:
        return []

    assets = db.query(Asset).filter(Asset.id.in_(candidates)).all()
    now = datetime.now(timezone.utc)

    out: list[Hypothesis] = []
    for asset in assets:
        ports = _open_ports(asset)
        if not ports:
            continue
        for protocol, port_set in _VM_KEV_PROTOCOL_PORTS:
            if not (ports & port_set):
                continue
            if _within_protocol_cooldown(asset, protocol, now):
                continue
            out.append(Hypothesis(
                pattern="vm_kev_to_audit",
                asset_id=asset.id,
                protocol=protocol,
                mission="exposure_audit",
                requires_approval=False,
                rationale=(
                    f"asset {asset.id} carries a KEV CVE and {protocol} is open; "
                    "no recent audit on that protocol"
                ),
            ))
            break   # one mgmt-protocol audit per asset per tick is enough
    return out


def _open_ports(asset: Asset) -> set[int]:
    easm = asset.easm_data or {}
    out: set[int] = set()
    for raw in (easm.get("open_ports") or []):
        if isinstance(raw, dict):
            raw = raw.get("port") or raw.get("number")
        try:
            n = int(raw)
        except (TypeError, ValueError):
            continue
        if 0 < n < 65536:
            out.add(n)
    return out


# ── Pattern: lead_followup ──────────────────────────────────────────


def _pattern_lead_followup(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """An `emit_lead` row is open in this org. The Coordinator dispatches
    the suggested protocol/mission against the lead's target. Same gating
    as any other pattern — cooldowns, org settings, etc — so a lead does
    not bypass org policy.

    Predicate:
      * `agent_leads.status = 'open'`.
      * `target_asset_id` resolves (else the lead is informational, not
        dispatchable; left for human review).
      * Target asset hasn't been audited on the suggested protocol within
        the cooldown window.
    """
    leads = (
        db.query(AgentLead)
        .filter(
            AgentLead.org_id == org_id,
            AgentLead.status == "open",
            AgentLead.target_asset_id.isnot(None),
        )
        .order_by(AgentLead.created_at.asc())
        .limit(50)        # bound the per-tick read; older leads remain queryable
        .all()
    )
    if not leads:
        return []

    asset_ids = {l.target_asset_id for l in leads}
    if affected_set:
        # Don't drop a lead just because its asset wasn't in the
        # affected_set this tick — leads are durable and the rationale
        # for dispatching is the lead itself, not the scan window.
        # But if an affected_set exists and the lead's asset isn't in it,
        # defer to a tick that *is* about that asset to keep tick work
        # bounded. Empty affected_set falls through unchanged.
        asset_ids &= affected_set
        if not asset_ids:
            return []

    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()}
    now = datetime.now(timezone.utc)

    out: list[Hypothesis] = []
    for lead in leads:
        asset = assets.get(lead.target_asset_id)
        if asset is None:
            continue
        if _within_protocol_cooldown(asset, lead.suggested_protocol, now):
            continue
        out.append(Hypothesis(
            pattern="lead_followup",
            asset_id=asset.id,
            protocol=lead.suggested_protocol,
            mission=lead.suggested_mission or "exposure_audit",
            requires_approval=False,
            rationale=f"lead #{lead.id}: {lead.reason[:160]}",
        ))
    return out


# ── Pattern: sbom_unpatched ─────────────────────────────────────────


# How fresh a VM scan must be to count as "covered" for sbom_unpatched.
# Tighter than the audit cooldown — if SBOM correlation shows a new KEV
# CVE and the VM scan is older than this, we want a re-fire.
_SBOM_VM_FRESHNESS = timedelta(hours=24)


def _pattern_sbom_unpatched(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """SBOM correlation produced a new `cve_on_asset` (KEV) on an asset
    that hasn't had a VM scan since. Mark the asset for VM rescan via
    a `kind='vm_scan'` hypothesis — `_dispatch_hypothesis` records the
    intent on `Asset.easm_data` for the existing VM-scan worker to
    pick up.

    Predicate:
      * `cve_on_asset` edge with `source_system='sbom'` and `properties.kev=True`.
      * Edge `last_seen_at` newer than every VM scan that covers this asset,
        OR no VM scan in the last 24h for this asset.
    """
    edges = db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == CVE_ON_ASSET,
        AssetRelationship.source_system == "sbom",
        AssetRelationship.target_asset_id.isnot(None),
    ).all()
    if not edges:
        return []

    # Collapse to (asset_id → most-recent SBOM-emitted edge).
    asset_edges: dict[int, AssetRelationship] = {}
    for edge in edges:
        props = edge.properties or {}
        if not props.get("kev"):
            continue
        aid = int(edge.target_asset_id)
        cur = asset_edges.get(aid)
        if cur is None or (edge.last_seen_at or datetime.min) > (cur.last_seen_at or datetime.min):
            asset_edges[aid] = edge
    if not asset_edges:
        return []
    if affected_set:
        asset_edges = {aid: e for aid, e in asset_edges.items() if aid in affected_set}
        if not asset_edges:
            return []

    cutoff = datetime.utcnow() - _SBOM_VM_FRESHNESS
    # Recent VM scans (any) covering each asset. We don't try to be precise
    # about which Nuclei templates were run — for "is this asset covered"
    # any vm_scanner-type Scan finishing after cutoff counts.
    recent_vm = db.query(Finding.asset_id).join(
        Scan, Scan.id == Finding.scan_id,
    ).filter(
        Scan.org_id == org_id,
        Scan.source_type == "vm_scanner",
        Scan.created_at >= cutoff,
        Finding.asset_id.in_(list(asset_edges.keys())),
    ).distinct().all()
    covered = {row[0] for row in recent_vm}

    out: list[Hypothesis] = []
    for aid, edge in asset_edges.items():
        if aid in covered:
            continue
        cve = (edge.properties or {}).get("cve") or "unknown"
        out.append(Hypothesis(
            pattern="sbom_unpatched",
            asset_id=aid,
            protocol="vm_scan",                    # pseudo — sets kind=vm_scan in dispatch
            mission="rescan",
            requires_approval=False,
            rationale=f"SBOM flagged KEV {cve}; no VM scan in the last 24h",
        ))
    return out


# ── Pattern: cred_found ─────────────────────────────────────────────


# Default off — the operator must turn this on per-org via
# `Organization.settings["coordinator_cred_propagation"] = True`.
# The pattern still emits hypotheses regardless (so the AttackPaths UI
# can show "ready to validate" cards) but they always carry
# `requires_approval=True` and the dispatch path skips them.


def _pattern_cred_found(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """An audit recorded a plaintext credential artifact and there's a
    next-hop reachable asset where the credential hasn't been tried.
    Suggest an authenticated audit — but always mark as
    `requires_approval=True`. The operator decides via the AttackPaths
    UI whether to fire it.

    Predicate:
      * A `Finding` exists in this org with
        `custom_fields["artifact_type"] = "plaintext_credential"`
        OR
        an `asset_to_asset_auth` edge with
        `properties.credential = "plaintext"` (whichever the audit emitted).
      * There's at least one neighbor asset reachable from the source
        (`asset_to_asset_port` edge or shared subnet) that has no audit
        on the next hop's mgmt protocol within cooldown.

    Returns an approval-gated hypothesis. v1 only emits a single
    hypothesis per (source_asset, next_hop) pair to keep tick noise low.
    """
    cred_assets = _assets_with_plaintext_credential(db, org_id)
    if affected_set:
        cred_assets &= affected_set
    if not cred_assets:
        return []

    # Find next-hop candidates via outbound auth/port edges.
    neighbors = db.query(
        AssetRelationship.source_asset_id,
        AssetRelationship.target_asset_id,
    ).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type.in_((ASSET_TO_ASSET_AUTH, ASSET_TO_ASSET_PORT)),
        AssetRelationship.source_asset_id.in_(cred_assets),
        AssetRelationship.target_asset_id.isnot(None),
    ).all()
    if not neighbors:
        return []

    pairs: set[tuple[int, int]] = {
        (int(src), int(dst)) for src, dst in neighbors if src is not None and dst is not None and src != dst
    }
    if not pairs:
        return []

    target_assets = {a.id: a for a in db.query(Asset).filter(
        Asset.id.in_({dst for _, dst in pairs}),
    ).all()}
    now = datetime.now(timezone.utc)

    out: list[Hypothesis] = []
    seen: set[tuple[int, int, str]] = set()
    for src, dst in pairs:
        target = target_assets.get(dst)
        if target is None:
            continue
        ports = _open_ports(target)
        if not ports:
            continue
        for protocol, port_set in _VM_KEV_PROTOCOL_PORTS:
            if not (ports & port_set):
                continue
            if _within_protocol_cooldown(target, protocol, now):
                continue
            key = (src, dst, protocol)
            if key in seen:
                continue
            seen.add(key)
            out.append(Hypothesis(
                pattern="cred_found",
                asset_id=dst,
                protocol=protocol,
                mission="exposure_audit",
                requires_approval=True,           # always — operator gates dispatch
                rationale=(
                    f"plaintext credential found on asset {src}; asset {dst} is reachable "
                    f"on {protocol} and hasn't been tried"
                ),
            ))
            break
    return out


def _assets_with_plaintext_credential(db: Session, org_id: int) -> set[int]:
    """Asset ids tagged by an audit as having yielded a plaintext credential.

    Two evidence sources, OR'd:
      * `asset_to_asset_auth` edges with `properties.credential = 'plaintext'`
        — emitted by an audit alongside a `secret found` finding.
      * Findings whose `custom_fields.artifact_type = 'plaintext_credential'`
        (matches the convention in `emit_finding`'s artifact list).
    """
    out: set[int] = set()

    edge_rows = db.query(AssetRelationship.source_asset_id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == ASSET_TO_ASSET_AUTH,
        AssetRelationship.source_asset_id.isnot(None),
    ).all()
    for (src,) in edge_rows:
        # Re-load to inspect properties; cheap because the set is small.
        row = db.query(AssetRelationship.properties).filter(
            AssetRelationship.id.in_(
                db.query(AssetRelationship.id).filter(
                    AssetRelationship.org_id == org_id,
                    AssetRelationship.relationship_type == ASSET_TO_ASSET_AUTH,
                    AssetRelationship.source_asset_id == src,
                )
            )
        ).all()
        for (props,) in row:
            if isinstance(props, dict) and (props.get("credential") or "").lower() == "plaintext":
                out.add(int(src))
                break

    finding_rows = db.query(Finding.asset_id, Finding.custom_fields).join(
        Scan, Scan.id == Finding.scan_id,
    ).filter(
        Scan.org_id == org_id,
        Finding.asset_id.isnot(None),
        Finding.custom_fields.isnot(None),
    ).all()
    for asset_id, custom_fields in finding_rows:
        if not isinstance(custom_fields, dict):
            continue
        if (custom_fields.get("artifact_type") or "").lower() == "plaintext_credential":
            out.add(int(asset_id))

    return out


# ── Pattern: service_fingerprint_audit ──────────────────────────────


def _pattern_service_fingerprint_audit(
    db: Session, org_id: int, affected_set: set[int],
) -> list[Hypothesis]:
    """EASM fingerprinted a service on a port — dispatch the matching audit.

    Predicate:
      * Asset has at least one ``(port, service_name)`` entry in
        ``easm_data['services']`` (or a well-known port that resolves to a
        known service via ``service_router.WELL_KNOWN_PORTS``).
      * The service name maps to a registered audit protocol.
      * No ``_auto_audit_last[<protocol>:<port>]`` cooldown is active.

    The Hypothesis carries the discovered ``port`` so dispatch can stamp
    ``easm_data['audit_target_port']`` before calling
    ``audit_runner.dispatch_audit_run``. The audit tools then target
    ``host:<port>`` instead of the protocol's standard port — this is what
    makes SSH on 2222 / SMB on 4445 / Postgres on 5433 actually scan.

    OT services flagged ``requires_consent=True`` emit hypotheses with
    ``requires_approval=True``; the existing approval gate in
    ``_dispatch_hypothesis`` enforces the per-asset consent check.
    """
    from services.service_router import enumerate_service_audits

    candidate_ids: set[int] = affected_set or set()
    if candidate_ids:
        assets = (
            db.query(Asset)
            .filter(Asset.id.in_(candidate_ids))
            .join(Scan, Asset.scan_id == Scan.id)
            .filter(Scan.org_id == org_id)
            .all()
        )
    else:
        # No affected subgraph — full sweep. Coordinator runs at most once
        # per debounce window so this isn't hot-path. Asset.org_id is an
        # ALTER-added column not in the ORM mapper, so scope via Scan.
        assets = (
            db.query(Asset)
            .join(Scan, Asset.scan_id == Scan.id)
            .filter(Scan.org_id == org_id)
            .all()
        )

    now = datetime.now(timezone.utc)
    out: list[Hypothesis] = []

    for asset in assets:
        for port, service_name, route in enumerate_service_audits(asset.easm_data):
            if _within_protocol_cooldown(asset, route.protocol, now, port=port):
                continue
            out.append(Hypothesis(
                pattern="service_fingerprint_audit",
                asset_id=asset.id,
                protocol=route.protocol,
                mission=route.mission,
                port=port,
                requires_approval=route.requires_consent,
                rationale=(
                    f"asset {asset.id} has {service_name} fingerprinted on "
                    f"port {port}; routing to {route.protocol}/{route.mission}"
                ),
            ))
    return out


# Closed pattern registry — adding a pattern is a new function plus a
# row here. Phase 4 adds the rest of the v1 set described in the doc.
_PATTERNS: tuple = (
    _pattern_easm_to_smb,
    _pattern_coerce_to_dc,
    _pattern_vm_kev_to_audit,
    _pattern_lead_followup,
    _pattern_sbom_unpatched,
    _pattern_cred_found,
    _pattern_service_fingerprint_audit,
)


# ── Hypothesis scoring ──────────────────────────────────────────────


# Static per-pattern prior likelihood that a chain through this gap
# actually exists. Tune by observation, not ML — see doc.
_PATTERN_PRIORS: dict[str, float] = {
    "easm_to_smb":      0.6,
    "coerce_to_dc":     0.75,    # a confirmed coerce primitive + a DC is a high-yield gap
    "vm_kev_to_audit":  0.65,    # KEV exploitability is real but doesn't always chain
    "lead_followup":    0.7,     # the agent already saw something; high signal
    "sbom_unpatched":   0.55,    # SBOM correlation is signal-rich but indirect
    "cred_found":       0.85,    # plaintext creds + reachable host = near-certain pivot
    # Lower than easm_to_smb because the fingerprint-driven sweep fans out
    # across every asset's ports — most hits are non-standard reposts of
    # already-audited protocols. Still positive: the whole point is to
    # cover ports the legacy port-driven rules miss.
    "service_fingerprint_audit": 0.5,
}

# Static per-pattern scan cost — informs the score's denominator. 1 =
# cheap audit, 5 = full VM scan.
_PATTERN_COST: dict[str, float] = {
    "easm_to_smb":      1.0,
    "coerce_to_dc":     1.5,    # LDAP audits are slightly heavier than SMB anon
    "vm_kev_to_audit":  1.5,
    "lead_followup":    1.2,
    "sbom_unpatched":   5.0,    # full VM scan
    "cred_found":       2.0,    # authenticated audit, more steps + creds management
    "service_fingerprint_audit": 1.2,   # range from cheap (FTP) to medium (datastore triage)
}


def _score_hypothesis(h: Hypothesis) -> tuple[float, dict]:
    prior = _PATTERN_PRIORS.get(h.pattern, 0.3)
    cost = _PATTERN_COST.get(h.pattern, 2.0)
    # Entry reachability is "confirmed" for any internet_to_asset-rooted
    # pattern in v1 — they only fire if EASM proved reachability.
    entry_conf = 1.0
    target_crit = 0.6                    # unknown target until the chain closes
    raw = (entry_conf * target_crit * prior) / max(cost, 0.1)
    return round(raw, 4), {
        "prior": prior,
        "cost": cost,
        "entry_confidence": entry_conf,
        "target_criticality": target_crit,
    }


# ── Dispatch gating ─────────────────────────────────────────────────


# Recent-dispatch debounce: don't fire the same (asset, protocol,
# mission) twice within this window even if the audit hasn't completed.
# Keep tight — the 24h cooldown owns the long-term gate; this guards
# only against same-tick / consecutive-tick double-dispatch.
_DISPATCH_DEBOUNCE = timedelta(seconds=60)

# Top-N hypotheses we attempt to dispatch each tick. Configurable via
# Hakuna's env, but defaults match the doc.
_MAX_DISPATCH_PER_TICK = 5


def _dispatch_hypothesis(
    db: Session, org: Organization, hyp: Hypothesis,
) -> dict:
    """Apply gating, then dispatch via `audit_runner.dispatch_audit_run`.

    Gating order — first failure short-circuits:
      1. Approval gate. `requires_approval=True` hypotheses are
         persisted to `coordinator_pending_approvals` so the operator
         can act on them; an existing `approved` row lets the dispatch
         proceed; a `rejected` row blocks it.
      2. Org-level enable flag (`auto_audit_*` settings, same key set
         the auto-trigger reads).
      3. Per-asset cooldown via `Asset.easm_data["_auto_audit_last"]`.
      4. Recent in-flight Coordinator dispatch for the same
         `(asset, protocol, mission)` (≤60s) — checked by querying the
         `scans` table (or the asset's `_pending_vm_rescan` marker for
         the `vm_scan` pseudo-protocol) so the gate works across
         replicas, not just within one process.
      5. Relay availability (`audit_auto_trigger._pick_relay`).

    Returns a small dict — caller logs it into the tick result.
    """
    approval_decision = None
    if hyp.requires_approval:
        approval_decision = _resolve_approval(db, org.id, hyp)
        if approval_decision == "rejected":
            return {
                "dispatched": False, "reason": "rejected",
                "asset_id": hyp.asset_id, "pattern": hyp.pattern,
            }
        if approval_decision != "approved":
            _upsert_pending_approval(db, org.id, hyp)
            return {
                "dispatched": False, "reason": "requires_approval",
                "asset_id": hyp.asset_id, "pattern": hyp.pattern,
            }

    if not _org_setting_enables(org, hyp.protocol):
        return {
            "dispatched": False, "reason": "org_setting_disabled",
            "asset_id": hyp.asset_id, "pattern": hyp.pattern,
        }

    asset = db.query(Asset).filter(Asset.id == hyp.asset_id).first()
    if asset is None:
        return {"dispatched": False, "reason": "asset_missing", "asset_id": hyp.asset_id}

    now = datetime.now(timezone.utc)
    if _within_protocol_cooldown(asset, hyp.protocol, now, port=hyp.port):
        return {
            "dispatched": False, "reason": "cooldown",
            "asset_id": hyp.asset_id, "pattern": hyp.pattern,
        }

    if _recent_coordinator_dispatch(db, org.id, hyp, now):
        return {
            "dispatched": False, "reason": "recent_dispatch",
            "asset_id": hyp.asset_id, "pattern": hyp.pattern,
        }

    # `vm_scan` is a pseudo-protocol — the Coordinator doesn't dispatch
    # the scan inline (vm_scanner.start_vm_scan is async). Instead we
    # mark the asset on `easm_data["_pending_vm_rescan"]` for the
    # existing VM-scan pickup loop. Same cooldown stamping below still
    # applies so we don't re-mark every tick.
    if hyp.protocol == "vm_scan":
        result = _mark_vm_rescan(asset, hyp, now)
    else:
        # Stamp the discovered non-standard port (when the Hypothesis
        # carries one) so the audit tools target ``host:<port>`` instead
        # of the protocol's hardcoded standard port. Read by
        # ``audit_runner._asset_audit_target_port`` and the protocol
        # tools' target builders.
        if hyp.port is not None:
            easm = dict(asset.easm_data or {})
            easm["audit_target_port"] = int(hyp.port)
            asset.easm_data = easm
            db.flush()

        # Reuse the auto-trigger's relay picker — same asset/relay-affinity
        # heuristic should drive any auto-dispatched audit, no matter who
        # asked.
        from services.audit_auto_trigger import _pick_relay
        relay = _pick_relay(db, org.id, asset)
        if relay is None:
            return {"dispatched": False, "reason": "no_relay", "asset_id": hyp.asset_id}

        from services.audit_runner import dispatch_audit_run, AuditDispatchError
        try:
            result = dispatch_audit_run(
                db, org,
                protocol=hyp.protocol,
                mission=hyp.mission,
                relay_agent_id=relay.id,
                credential_id=None,
                asset_ids=[asset.id],
            )
        except AuditDispatchError as e:
            logger.warning(
                "chain_coordinator: dispatch failed asset=%d pattern=%s err=%s",
                asset.id, hyp.pattern, e,
            )
            return {
                "dispatched": False, "reason": f"dispatch_error:{e}",
                "asset_id": asset.id, "pattern": hyp.pattern,
            }

    # If a lead drove this hypothesis, mark it dispatched so the next
    # tick doesn't re-emit the same hypothesis. `consumed_by_scan_id`
    # records which scan picked it up (if there is one — vm_rescan
    # marks asset state, not a Scan row).
    if hyp.pattern == "lead_followup":
        _mark_lead_dispatched(db, org.id, hyp, result.get("scan_id"))

    if approval_decision == "approved":
        _mark_approval_consumed(db, org.id, hyp, result.get("scan_id"))

    # Honor the same cooldown the auto-trigger writes so the next tick
    # (and any concurrent port_change auto-trigger) sees this dispatch.
    # When the hypothesis carries a non-standard port, stamp the
    # port-scoped key (``f"{protocol}:{port}"``) so SSH-on-22 and
    # SSH-on-2222 cool down independently — _within_protocol_cooldown
    # reads the same key.
    from services.audit_auto_trigger import _stamp_cooldown
    if hyp.port is not None:
        easm = dict(asset.easm_data or {})
        last_map = dict(easm.get("_auto_audit_last") or {})
        last_map[f"{hyp.protocol}:{hyp.port}"] = now.isoformat()
        easm["_auto_audit_last"] = last_map
        asset.easm_data = easm
    else:
        _stamp_cooldown(asset, hyp.protocol, now)

    logger.info(
        "chain_coordinator: dispatched asset=%d pattern=%s scan=%s",
        asset.id, hyp.pattern, result.get("scan_id"),
    )
    return {
        "dispatched": True,
        "asset_id": asset.id,
        "pattern": hyp.pattern,
        "protocol": hyp.protocol,
        "mission": hyp.mission,
        "scan_id": result.get("scan_id"),
    }


def _org_setting_enables(org: Organization, protocol: str) -> bool:
    """Map our protocols to the same `auto_audit_*` flags the auto-trigger
    reads. Defaults to the auto-trigger's per-protocol default
    (anonymous families default ON; credentialed + VM rescan default OFF).
    """
    settings = org.settings or {}
    key = _PROTOCOL_TO_SETTING.get(protocol)
    if key is None:
        return False
    explicit = settings.get(key)
    if explicit is not None:
        return bool(explicit)
    # Match audit_auto_trigger._rule_enabled_for_org — non-OT defaults ON,
    # except for credentialed / VM rescan which default OFF.
    return protocol not in _DEFAULT_OFF_PROTOCOLS


# Mapping from Coordinator protocol → auto_audit_* org setting. Matches
# the keys in `services.audit_auto_trigger.AUTO_TRIGGER_RULES`. Phase 4
# adds credentialed mgmt protocols (wmi/ssh) and the `vm_scan` /
# `cred_propagation` pseudo-protocols the Coordinator dispatches without
# the auto-trigger.
_PROTOCOL_TO_SETTING: dict[str, str] = {
    "smb":                   "auto_audit_anon",
    "snmp":                  "auto_audit_anon",
    "exposed_datastore":     "auto_audit_datastore",
    "exposed_ai_service":    "auto_audit_ai",
    "exposed_anon_protocol": "auto_audit_anon_protocol",
    "ipmi_bmc":              "auto_audit_ipmi",
    "netbios_local":         "auto_audit_netbios",
    "ldap":                  "auto_audit_anon",
    # Mgmt-protocol audits used by `vm_kev_to_audit` and `cred_found`.
    # WMI / SSH default off org-wide — they're credentialed in real
    # deployments, and the cred_found pattern that drives them is itself
    # approval-gated.
    "wmi":                   "auto_audit_credentialed",
    "ssh":                   "auto_audit_credentialed",
    # Pseudo-protocol for sbom_unpatched. Lives behind its own switch so
    # an org that doesn't want the Coordinator firing VM scans can opt
    # out without losing audit auto-dispatch.
    "vm_scan":               "auto_audit_vm_rescan",
    # Service-router-dispatched OT protocol audit. Same setting as the
    # legacy port-driven OT rule in ``audit_auto_trigger.AUTO_TRIGGER_RULES``;
    # the per-asset consent record is enforced via ``requires_approval``
    # on the Hypothesis (mapped from ``ServiceAudit.requires_consent``).
    "ot_protocol":           "auto_audit_ot",
}


# Protocols whose org-level setting defaults OFF. Mirrors the
# auto-trigger's "non-OT defaults ON" rule (see
# `audit_auto_trigger._rule_enabled_for_org`) but flipped for
# credentialed / VM dispatch which are heavier and more invasive.
_DEFAULT_OFF_PROTOCOLS: frozenset[str] = frozenset({
    "wmi", "ssh", "vm_scan",
})


def _within_protocol_cooldown(
    asset: Asset, protocol: str, now: datetime, *, port: int | None = None,
) -> bool:
    """Read the same `_auto_audit_last` map the auto-trigger writes.

    Default cooldown for Coordinator-initiated dispatch is 24h (matches
    the auto-trigger). Don't introduce a parallel table.

    When ``port`` is provided (service-fingerprint dispatches), check
    the per-port key ``f"{protocol}:{port}"`` so SSH-on-22 and
    SSH-on-2222 cool down independently. Without a port we fall back to
    the bare protocol key the legacy auto-trigger writes.
    """
    last_map = (asset.easm_data or {}).get("_auto_audit_last") or {}
    key = f"{protocol}:{port}" if port is not None else protocol
    raw = last_map.get(key)
    if not raw:
        return False
    try:
        last = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (now - last) < timedelta(hours=24)


def _within_smb_cooldown(asset: Asset, now: datetime) -> bool:
    """Pattern-side guard, mirrors `_within_protocol_cooldown` but used
    in enumeration so we never even build a hypothesis we'd just gate.
    """
    return _within_protocol_cooldown(asset, "smb", now)


def _recent_coordinator_dispatch(
    db: Session, org_id: int, hyp: Hypothesis, now: datetime,
) -> bool:
    """Has anyone (this replica or another) dispatched the same
    `(asset, protocol, mission)` within `_DISPATCH_DEBOUNCE`?

    Backed by the durable record each dispatch leaves behind:
      * Audit dispatches → a `Scan` row written by
        `audit_runner.dispatch_audit_run` (`scan_type=f"{protocol}_audit"`,
        `raw_metadata.mission`, `raw_metadata.asset_ids`).
      * `vm_scan` pseudo-protocol → the `_pending_vm_rescan` marker
        stamped on `Asset.easm_data` by `_mark_vm_rescan`.

    Reading the DB instead of an in-process dict keeps the debounce
    correct under multi-replica deploys: a Cloud Run pod that spun up
    after another pod fired still sees the recent dispatch.
    """
    cutoff_naive = (now.astimezone(timezone.utc).replace(tzinfo=None)
                    - _DISPATCH_DEBOUNCE)

    if hyp.protocol == "vm_scan":
        asset = db.query(Asset).filter(Asset.id == hyp.asset_id).first()
        if asset is None:
            return False
        pending = (asset.easm_data or {}).get("_pending_vm_rescan") or {}
        raw = pending.get("requested_at")
        if not raw:
            return False
        try:
            last = datetime.fromisoformat(raw)
        except (TypeError, ValueError):
            return False
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return (now - last) < _DISPATCH_DEBOUNCE

    # `Scan.created_at` is naive UTC (default=datetime.utcnow). Compare
    # against a naive UTC cutoff to keep the filter portable across
    # SQLite (tests) and Postgres (prod).
    candidates = (
        db.query(Scan)
        .filter(
            Scan.org_id == org_id,
            Scan.scan_type == f"{hyp.protocol}_audit",
            Scan.created_at >= cutoff_naive,
        )
        .all()
    )
    for scan in candidates:
        md = scan.raw_metadata or {}
        if md.get("mission") != hyp.mission:
            continue
        asset_ids = md.get("asset_ids") or []
        try:
            if int(hyp.asset_id) in {int(a) for a in asset_ids if a is not None}:
                return True
        except (TypeError, ValueError):
            continue
    return False


# ── Closure detection ──────────────────────────────────────────────


# Edge types BFS may traverse when looking for closure paths. Edges
# whose endpoints are pseudo (cve_on_asset, principal_to_domain,
# user_to_asset, internet_to_asset) are excluded from the host→host
# walk; we anchor on internet_to_asset separately as the entry source.
_TRAVERSAL_EDGE_TYPES: frozenset[str] = frozenset({
    ASSET_TO_ASSET_COERCE,
    ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_PORT,
    LOCAL_ROOT,
    # Legacy infra/auth edges that already drove correlator BFS — the
    # Coordinator inherits their semantics.
    "resolves_to",
    "alias_of",
    "trusts_domain",
    "member_of_domain",
    "shares_credential_with",
    "runs_as_principal",
    "connects_to",
})


_MAX_CHAIN_DEPTH = 4


@dataclass
class ClosedChain:
    entry_asset_id: int
    target_asset_id: int
    edge_ids: list[int]                         # ordered traversed edges
    asset_ids: list[int]                        # ordered visited asset ids (entry → … → target)
    enabled_by_findings: list[int]
    source_systems: set[str]
    cves: set[str]
    matched_ttps: list[dict]
    severity_label: str
    score: float
    edge_summaries: list[dict]


def detect_closures(
    db: Session, org_id: int, affected_set: set[int],
) -> list[ClosedChain]:
    """Forward BFS from internet-reachable entries to crown-jewel targets
    over the unified edge graph.

    Restricting to `affected_set` keeps a tick from re-emitting the
    same chains repeatedly — a chain is a closure candidate this tick
    only if at least one of its assets had an edge change in the scan
    window. Empty affected_set means "consider everything" (used on
    full-org recompute).
    """
    crown_jewels = _crown_jewel_assets(db, org_id)
    if not crown_jewels:
        return []
    entries = _internet_entry_assets(db, org_id)
    if not entries:
        return []

    chains: list[ClosedChain] = []
    seen_signatures: set[tuple[int, ...]] = set()

    for entry_id in entries:
        for chain in _bfs_from_entry(
            db, org_id, entry_id, crown_jewels, max_depth=_MAX_CHAIN_DEPTH,
        ):
            if affected_set and not (set(chain.asset_ids) & affected_set):
                continue
            sig = tuple(chain.edge_ids)
            if sig in seen_signatures:
                continue
            # v1 closure rule: must have multi-source corroboration so
            # we don't emit a chain that one producer manufactured.
            if len(chain.source_systems) < 2:
                continue
            seen_signatures.add(sig)
            chains.append(chain)

    return chains


def _bfs_from_entry(
    db: Session,
    org_id: int,
    entry_id: int,
    crown_jewels: dict[int, dict],
    *,
    max_depth: int,
) -> list[ClosedChain]:
    """BFS from `entry_id` until it reaches any crown-jewel asset.

    Carries traversed edge ids + provenance (source_systems,
    enabled_by_findings) in the queue state so closure rows can cite
    every edge that justified them.
    """
    queue: deque[tuple[list[int], list[int], list[int], set[str], list[int]]] = deque()
    # state: (asset_ids_so_far, edge_ids_so_far, finding_ids, source_systems, depth-list-placeholder)
    queue.append(([entry_id], [], [], set(), [0]))
    out: list[ClosedChain] = []

    while queue:
        asset_ids, edge_ids, finding_ids, sources, depth_box = queue.popleft()
        depth = depth_box[0]
        if depth >= max_depth:
            continue
        current = asset_ids[-1]
        edges = _outbound_traversal_edges(db, org_id, current)
        for edge in edges:
            other = (
                edge.target_asset_id
                if edge.source_asset_id == current
                else edge.source_asset_id
            )
            if other is None or other in asset_ids:
                continue
            new_assets = asset_ids + [other]
            new_edges = edge_ids + [edge.id]
            new_findings = finding_ids + list(edge.enabled_by_findings or [])
            new_sources = sources | ({edge.source_system} if edge.source_system else set())

            if other in crown_jewels:
                out.append(
                    _build_closed_chain(
                        db,
                        entry_id=entry_id,
                        target_id=other,
                        target_meta=crown_jewels[other],
                        asset_ids=new_assets,
                        edge_ids=new_edges,
                        finding_ids=new_findings,
                        source_systems=new_sources,
                    )
                )
                # Don't extend past a target — terminating chains keeps
                # the closure set small.
                continue
            queue.append((new_assets, new_edges, new_findings, new_sources, [depth + 1]))

    return out


def _outbound_traversal_edges(
    db: Session, org_id: int, asset_id: int,
) -> list[AssetRelationship]:
    """Edges incident on `asset_id` whose type is in the traversal set.
    Both directions: the closure walk treats asymmetric edge types
    (`asset_to_asset_coerce`, `asset_to_asset_port`) as directed but
    for v1 we follow either direction since the closure question is
    "is there a graph path?", not "is the path semantically valid?".
    """
    return db.query(AssetRelationship).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type.in_(_TRAVERSAL_EDGE_TYPES),
        (
            (AssetRelationship.source_asset_id == asset_id)
            | (AssetRelationship.target_asset_id == asset_id)
        ),
    ).all()


def _build_closed_chain(
    db: Session,
    *,
    entry_id: int,
    target_id: int,
    target_meta: dict,
    asset_ids: list[int],
    edge_ids: list[int],
    finding_ids: list[int],
    source_systems: set[str],
) -> ClosedChain:
    # Pull the actual edge rows once for evidence shaping.
    edges_by_id: dict[int, AssetRelationship] = {}
    if edge_ids:
        for edge in db.query(AssetRelationship).filter(
            AssetRelationship.id.in_(edge_ids),
        ).all():
            edges_by_id[edge.id] = edge

    edge_summaries: list[dict] = []
    cves: set[str] = set()
    matched_ttps: list[dict] = []
    for eid in edge_ids:
        edge = edges_by_id.get(eid)
        if edge is None:
            continue
        edge_summaries.append({
            "edge_id": edge.id,
            "edge_type": edge.relationship_type,
            "src": edge.source_asset_id,
            "dst": edge.target_asset_id,
            "confidence": edge.confidence,
            "weight": edge.weight,
            "source_system": edge.source_system,
            "properties": edge.properties or {},
        })
    if finding_ids:
        f_rows = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
        for f in f_rows:
            for cve in (f.cves or []):
                if isinstance(cve, str):
                    cves.add(cve.upper())
            for ttp in (f.matched_ttps or []):
                if isinstance(ttp, dict) and ttp.get("technique_id"):
                    matched_ttps.append(ttp)

    # Severity label: highest enabling finding's severity wins; fall back
    # to "High" when we have no finding context (the chain still exists,
    # we just can't grade it).
    severity_label = _severity_label_for_chain(db, finding_ids)

    score = _score_closed_chain(
        target_meta, asset_ids, edge_summaries, source_systems, matched_ttps,
    )

    return ClosedChain(
        entry_asset_id=entry_id,
        target_asset_id=target_id,
        edge_ids=edge_ids,
        asset_ids=asset_ids,
        enabled_by_findings=sorted(set(finding_ids)),
        source_systems=set(source_systems),
        cves=cves,
        matched_ttps=matched_ttps,
        severity_label=severity_label,
        score=score,
        edge_summaries=edge_summaries,
    )


def _severity_label_for_chain(db: Session, finding_ids: list[int]) -> str:
    if not finding_ids:
        return "High"
    rows = db.query(Finding.severity).filter(Finding.id.in_(finding_ids)).all()
    max_sev = max((r[0] or 0 for r in rows), default=0)
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(max_sev, "Info")


def _score_closed_chain(
    target_meta: dict,
    asset_ids: list[int],
    edge_summaries: list[dict],
    source_systems: set[str],
    matched_ttps: list[dict],
) -> float:
    """0–10 chain score combining target criticality, multi-source
    corroboration, and TTP coverage. Maps to the existing AttackPath
    score scheme but compressed to the 0–10 range the doc calls for.
    """
    target_crit = float(target_meta.get("criticality", 5))
    base = min(target_crit, 10.0)
    if len(source_systems) >= 3:
        base += 1.0
    elif len(source_systems) >= 2:
        base += 0.5
    distinct_tactics = len({(t.get("tactic") or "").lower() for t in matched_ttps if isinstance(t, dict)})
    if distinct_tactics >= 3:
        base += 0.5
    # Cap chain length bonus modestly — long chains aren't necessarily
    # better, just longer.
    if len(asset_ids) >= 4:
        base += 0.25
    return round(min(base, 10.0), 2)


# ── ValidatedChain emit ────────────────────────────────────────────


def _emit_validated_chain(
    db: Session, org_id: int, chain: ClosedChain,
) -> Finding | None:
    """Create a `Finding` row representing the closed chain, link it to
    a fresh `AttackPath`, and return the finding.

    Idempotent: dedup by ordered edge-id sequence stamped into the
    Finding's `custom_fields["chain_signature"]`. If a finding with the
    same signature already exists in the org, this is a no-op.
    """
    signature = ",".join(str(e) for e in chain.edge_ids)
    existing = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(
            Scan.org_id == org_id,
            Finding.source_type == _CHAIN_SOURCE_TYPE,
            Finding.plugin_id == signature,
        )
        .first()
    )
    if existing is not None:
        return None

    # Anchor scan: create / reuse a synthetic scan row that owns all
    # Coordinator-emitted findings for this org. The scan is a bookkeeping
    # device — UI features that filter by scan still work because the
    # finding has a real scan_id.
    scan = _get_or_create_chain_scan(db, org_id)

    severity_to_int = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    severity_int = severity_to_int.get(chain.severity_label, 3)

    asset_id = chain.target_asset_id   # finding hangs off the crown jewel
    title = _chain_title(db, chain)

    finding = Finding(
        scan_id=scan.id,
        asset_id=asset_id,
        source_type=_CHAIN_SOURCE_TYPE,
        plugin_id=signature,
        plugin_name=title,
        plugin_family="Chain",
        severity=severity_int,
        severity_label=chain.severity_label,
        risk_factor=chain.severity_label,
        cves=sorted(chain.cves),
        synopsis=(
            f"Validated multi-hop attack path from internet entry "
            f"(asset {chain.entry_asset_id}) to crown-jewel "
            f"(asset {chain.target_asset_id})."
        ),
        description=_chain_description(db, chain),
        solution=(
            "Mitigate any one of the underlying findings to break the chain."
        ),
        priority_score=chain.score * 10.0,    # keep priority on the 0–100 axis
        matched_ttps=chain.matched_ttps,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        source_systems=sorted(chain.source_systems),
        custom_fields={
            "chain": {
                "entry_asset_id": chain.entry_asset_id,
                "target_asset_id": chain.target_asset_id,
                "asset_ids": chain.asset_ids,
                "edge_ids": chain.edge_ids,
                "edges": chain.edge_summaries,
                "enabled_by_findings": chain.enabled_by_findings,
                "source_systems": sorted(chain.source_systems),
                "score": chain.score,
                "signature": signature,
            },
        },
    )
    db.add(finding)
    db.flush()

    # Stamp org_id directly — Finding has no ORM-mapped org_id but the
    # column does exist (added by _migrate_add_columns). Mirrors what
    # the test fixtures do.
    db.execute(
        text("UPDATE findings SET org_id = :org WHERE id = :id"),
        {"org": org_id, "id": finding.id},
    )

    # Build / refresh the matching AttackPath row so the UI surfaces
    # this chain alongside correlator paths. We don't deduplicate
    # against existing correlator paths — the Coordinator-emitted row
    # is meaningfully different (linked to the validated finding).
    ap = AttackPath(
        org_id=org_id,
        title=title,
        severity=chain.severity_label,
        steps=_attack_path_steps(db, chain),
        entry_asset_id=chain.entry_asset_id,
        target_asset_id=chain.target_asset_id,
        chain_length=len(chain.asset_ids),
        entry_reason="internet_to_asset",
        target_reason="crown_jewel",
        score=chain.score * 10.0,
        score_breakdown={
            "source": "chain_coordinator",
            "score_0_10": chain.score,
            "source_systems": sorted(chain.source_systems),
            "ttp_coverage": len({t.get("tactic") for t in chain.matched_ttps if isinstance(t, dict)}),
        },
        validated_chain_finding_id=finding.id,
    )
    db.add(ap)
    db.flush()
    return finding


_CHAIN_SOURCE_TYPE = "hakuna_chain_coordinator"
_CHAIN_SCAN_FILENAME = "chain_coordinator://validated_chains"


def _get_or_create_chain_scan(db: Session, org_id: int) -> Scan:
    scan = (
        db.query(Scan)
        .filter(
            Scan.org_id == org_id,
            Scan.source_type == _CHAIN_SOURCE_TYPE,
            Scan.filename == _CHAIN_SCAN_FILENAME,
        )
        .order_by(Scan.id.desc())
        .first()
    )
    if scan is not None:
        return scan
    scan = Scan(
        org_id=org_id,
        filename=_CHAIN_SCAN_FILENAME,
        scan_name="Validated chains (Coordinator)",
        source_type=_CHAIN_SOURCE_TYPE,
        scan_type=_CHAIN_SOURCE_TYPE,
        status="completed",
    )
    db.add(scan)
    db.flush()
    return scan


def _chain_title(db: Session, chain: ClosedChain) -> str:
    entry_h = _hostname(db, chain.entry_asset_id)
    target_h = _hostname(db, chain.target_asset_id)
    return f"Validated chain: {entry_h} → {target_h} ({len(chain.asset_ids) - 1} hops)"


def _chain_description(db: Session, chain: ClosedChain) -> str:
    parts = [
        f"Closed attack path observed across {len(chain.source_systems)} producers: "
        f"{', '.join(sorted(chain.source_systems)) or 'unknown'}.",
    ]
    for i, edge in enumerate(chain.edge_summaries, 1):
        parts.append(
            f"  {i}. [{edge['edge_type']}] asset={edge['src']} → asset={edge['dst']} "
            f"(confidence={edge['confidence']}, source={edge['source_system']})"
        )
    if chain.cves:
        parts.append(f"Underlying CVEs: {', '.join(sorted(chain.cves))}.")
    if chain.matched_ttps:
        techniques = sorted({t.get("technique_id") for t in chain.matched_ttps if isinstance(t, dict)})
        parts.append(f"MITRE techniques: {', '.join(t for t in techniques if t)}.")
    return "\n".join(parts)


def _attack_path_steps(db: Session, chain: ClosedChain) -> list[dict]:
    """Build the same `steps` JSON shape AttackPath rows from the
    correlator use, so the existing UI renders without any branching.
    """
    hostnames = _hostnames(db, chain.asset_ids)
    steps: list[dict] = []
    for idx, asset_id in enumerate(chain.asset_ids):
        edge_in = chain.edge_summaries[idx - 1] if idx > 0 else None
        steps.append({
            "asset_id": asset_id,
            "hostname": hostnames.get(asset_id, "unknown"),
            "edge_type": edge_in["edge_type"] if edge_in else "entry",
            "edge_confidence": edge_in["confidence"] if edge_in else None,
            "edge_weight": edge_in["weight"] if edge_in else None,
            "pivot_quality": "exploit_path_verified" if edge_in and edge_in["edge_type"] == ASSET_TO_ASSET_COERCE else "service_exposed" if edge_in else "entry",
            "why_reachable": (
                f"{edge_in['edge_type']} edge from previous asset"
                if edge_in else "Internet-reachable (EASM)"
            ),
            "what_enables": (
                f"Edge backed by {edge_in['source_system']} (confidence={edge_in['confidence']})"
                if edge_in else "Initial entry point exposed to the internet"
            ),
        })
    return steps


# ── Affected-subgraph + entry / crown-jewel sets ───────────────────


_AFFECTED_LOOKBACK = timedelta(minutes=15)


def _recompute_affected_subgraph(
    db: Session, org_id: int, scan_id: int | None,
) -> set[int]:
    """Set of asset ids whose edges were touched in this scan window.

    For a given scan we fold:
      * Findings ingested by the scan (their asset_ids).
      * Edges with `last_seen_at` within the lookback window.
    Empty result → caller treats as "consider everything" so a
    no-scan-context tick still does work.
    """
    out: set[int] = set()
    if scan_id is not None:
        rows = db.query(Finding.asset_id).filter(
            Finding.scan_id == scan_id,
            Finding.asset_id.isnot(None),
        ).distinct().all()
        for (aid,) in rows:
            out.add(int(aid))

    cutoff = datetime.utcnow() - _AFFECTED_LOOKBACK
    edge_rows = db.query(
        AssetRelationship.source_asset_id,
        AssetRelationship.target_asset_id,
    ).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.last_seen_at >= cutoff,
    ).all()
    for src, dst in edge_rows:
        if src is not None:
            out.add(int(src))
        if dst is not None:
            out.add(int(dst))
    return out


def _internet_entry_assets(db: Session, org_id: int) -> set[int]:
    rows = db.query(AssetRelationship.target_asset_id).filter(
        AssetRelationship.org_id == org_id,
        AssetRelationship.relationship_type == INTERNET_TO_ASSET,
        AssetRelationship.target_asset_id.isnot(None),
    ).distinct().all()
    return {row[0] for row in rows if row[0] is not None}


def _crown_jewel_assets(db: Session, org_id: int) -> dict[int, dict]:
    """Crown-jewel asset set — same heuristic as the correlator's target
    set, lifted here so the Coordinator stays self-contained.
    """
    crown: dict[int, dict] = {}

    # Domain controllers (legacy infra edges).
    dc_rows = db.execute(
        text(
            """
            SELECT DISTINCT ar.target_asset_id AS asset_id
            FROM asset_relationships ar
            WHERE ar.org_id = :org_id
              AND ar.relationship_type = 'member_of_domain'
              AND ar.target_asset_id IS NOT NULL
            UNION
            SELECT DISTINCT ar.source_asset_id AS asset_id
            FROM asset_relationships ar
            WHERE ar.org_id = :org_id
              AND ar.relationship_type = 'trusts_domain'
              AND ar.source_asset_id IS NOT NULL
            """
        ),
        {"org_id": org_id},
    ).fetchall()
    for row in dc_rows:
        if row.asset_id is not None:
            crown[row.asset_id] = {"asset_id": row.asset_id, "criticality": 10, "reason": "domain_controller"}

    # criticality ≥ 8 OR has critical finding.
    asset_rows = db.execute(
        text(
            """
            SELECT a.id, a.criticality
            FROM assets a
            JOIN scans s ON s.id = a.scan_id
            WHERE s.org_id = :org_id
              AND COALESCE(a.criticality, 5) >= 8
            """
        ),
        {"org_id": org_id},
    ).fetchall()
    for row in asset_rows:
        crown.setdefault(row.id, {"asset_id": row.id, "criticality": int(row.criticality or 8), "reason": "high_criticality"})

    crit_rows = db.execute(
        text(
            """
            SELECT DISTINCT a.id, a.criticality
            FROM assets a
            JOIN findings f ON f.asset_id = a.id
            JOIN scans s ON s.id = a.scan_id
            WHERE s.org_id = :org_id
              AND f.severity = 4
              AND f.workflow_status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            """
        ),
        {"org_id": org_id},
    ).fetchall()
    for row in crit_rows:
        crown.setdefault(row.id, {"asset_id": row.id, "criticality": max(int(row.criticality or 7), 7), "reason": "has_critical_finding"})

    return crown


# ── Helpers ────────────────────────────────────────────────────────


def _looks_like_windows(asset: Asset) -> bool:
    os_str = (asset.os or "").lower()
    if "windows" in os_str:
        return True
    easm = asset.easm_data or {}
    banner = " ".join(str(v).lower() for v in (easm.get("banners") or []))
    if "smb" in banner or "microsoft" in banner:
        return True
    asset_type = (asset.asset_type or "").lower()
    if asset_type in ("windows_host", "domain_controller"):
        return True
    return False


def _hostname(db: Session, asset_id: int) -> str:
    row = db.query(Asset.hostname, Asset.ip).filter(Asset.id == asset_id).first()
    if row is None:
        return f"asset#{asset_id}"
    return row.hostname or (str(row.ip) if row.ip else f"asset#{asset_id}")


def _hostnames(db: Session, asset_ids: Iterable[int]) -> dict[int, str]:
    ids = list(asset_ids)
    if not ids:
        return {}
    rows = db.query(Asset.id, Asset.hostname, Asset.ip).filter(Asset.id.in_(ids)).all()
    return {
        r.id: r.hostname or (str(r.ip) if r.ip else f"asset#{r.id}")
        for r in rows
    }


# ── Phase 4 dispatch helpers ───────────────────────────────────────


def _mark_vm_rescan(asset: Asset, hyp: Hypothesis, now: datetime) -> dict:
    """Record an SBOM-driven VM rescan request on the asset.

    The Coordinator can't fire `start_vm_scan` synchronously (it's
    async + needs MinIO + scan record creation). Instead we drop a
    durable marker on `Asset.easm_data["_pending_vm_rescan"]`; an
    out-of-band worker (TBD — Phase 4 followup) picks markers up and
    triggers the VM scan. Same shape as the auto-trigger's
    `_pending_easm_vm_triggers` lifecycle.

    Returns a dict in the same shape `dispatch_audit_run` returns so
    `_dispatch_hypothesis` can stamp the cooldown without branching.
    """
    easm = dict(asset.easm_data or {})
    pending = dict(easm.get("_pending_vm_rescan") or {})
    pending.update({
        "requested_at": now.isoformat(),
        "pattern": hyp.pattern,
        "rationale": hyp.rationale,
    })
    easm["_pending_vm_rescan"] = pending
    asset.easm_data = easm
    return {"scan_id": None, "kind": "vm_rescan_marked"}


def _mark_lead_dispatched(
    db: Session, org_id: int, hyp: Hypothesis, scan_id: int | None,
) -> None:
    """Flip the matching open lead row to status='dispatched'.

    Best-effort match: pick any open lead for this org whose
    (target_asset_id, suggested_protocol, suggested_mission) matches
    the hypothesis. Multiple leads may collapse to a single dispatch —
    we mark the oldest open one and leave the others for the next tick
    (they'll dedup against the now-stamped cooldown).
    """
    lead = (
        db.query(AgentLead)
        .filter(
            AgentLead.org_id == org_id,
            AgentLead.status == "open",
            AgentLead.target_asset_id == hyp.asset_id,
            AgentLead.suggested_protocol == hyp.protocol,
            AgentLead.suggested_mission == hyp.mission,
        )
        .order_by(AgentLead.created_at.asc())
        .first()
    )
    if lead is None:
        return
    lead.status = "dispatched"
    lead.consumed_by_scan_id = int(scan_id) if scan_id else None
    lead.updated_at = datetime.utcnow()


# ── Approval queue helpers ─────────────────────────────────────────


def _hyp_dedup_key(hyp: Hypothesis) -> str:
    """Stable string id used to find the matching ``AgentApproval`` row
    for a hypothesis. Stored in ``tool_input.dedup_key`` so the lookup
    is a cheap exact match against ``tool_input->>'dedup_key'`` instead
    of four separate JSON field comparisons. Empty asset_id renders as
    an empty string so non-asset-keyed patterns still get a stable key.
    """
    return f"{hyp.asset_id or ''}|{hyp.pattern}|{hyp.protocol}|{hyp.mission}"


def _approval_query(db: Session, org_id: int, dedup_key: str):
    """Base query for coordinator approvals — filters by org, source, and
    the precomputed dedup_key. Callers add status filters on top. The
    column is indexed (mig 068) so this is an O(1) lookup regardless of
    queue size.
    """
    return db.query(AgentApproval).filter(
        AgentApproval.org_id == org_id,
        AgentApproval.source == "coordinator",
        AgentApproval.dedup_key == dedup_key,
    )


def _resolve_approval(
    db: Session, org_id: int, hyp: Hypothesis,
) -> str | None:
    """Return the existing approval status for this hypothesis, or None
    if no row exists yet.

    Looked up by ``(org_id, source='coordinator', dedup_key)`` —
    dedup_key encodes the legacy ``(asset_id, pattern, protocol, mission)``
    tuple. Stale ``consumed`` rows are ignored so the coordinator can
    re-prompt after the previous dispatch's cooldown expires.
    """
    row = (
        _approval_query(db, org_id, _hyp_dedup_key(hyp))
        .filter(AgentApproval.status.in_(("pending", "approved", "rejected")))
        .order_by(AgentApproval.requested_at.desc())
        .first()
    )
    return row.status if row is not None else None


def _upsert_pending_approval(
    db: Session, org_id: int, hyp: Hypothesis,
) -> AgentApproval:
    """Create or refresh a pending coordinator approval row.

    Idempotent on the hypothesis's dedup_key. Re-enumeration just bumps
    ``last_seen_at`` (inside ``tool_input``) and refreshes ``score`` /
    ``rationale`` so the operator sees the latest reasoning when they
    revisit the queue.
    """
    now = datetime.utcnow()
    dedup_key = _hyp_dedup_key(hyp)
    row = (
        _approval_query(db, org_id, dedup_key)
        .filter(AgentApproval.status == "pending")
        .first()
    )
    payload = {
        "dedup_key": dedup_key,
        "asset_id": hyp.asset_id,
        "pattern": hyp.pattern,
        "protocol": hyp.protocol,
        "mission": hyp.mission,
        "rationale": hyp.rationale,
        "score": float(hyp.score) if hyp.score is not None else 0.0,
        "score_factors": dict(hyp.score_factors or {}),
        "last_seen_at": now.isoformat(),
    }
    if row is None:
        row = AgentApproval(
            org_id=org_id,
            agent_id=None,
            agent_run_id=None,
            source="coordinator",
            tool_name="dispatch_chain_hypothesis",
            tool_input=payload,
            dedup_key=dedup_key,
            messages_snapshot=[],
            assistant_content=[],
            provider=None,
            model_name=None,
            current_step=0,
            tool_use_id=None,
            status="pending",
            requested_at=now,
        )
        db.add(row)
        db.flush()
    else:
        # Preserve the original requested_at (queue ordering). Just
        # refresh the live fields the operator reads.
        from sqlalchemy.orm.attributes import flag_modified
        existing = dict(row.tool_input or {})
        existing.update(payload)
        row.tool_input = existing
        flag_modified(row, "tool_input")
    return row


def _mark_approval_consumed(
    db: Session, org_id: int, hyp: Hypothesis, scan_id: int | None,
) -> None:
    """Flip the matching ``approved`` coordinator row to ``consumed``
    after dispatch.

    Without this the same approved hypothesis would re-fire every tick
    until its 24h cooldown stamp expired. Marking consumed forces the
    operator to explicitly re-approve once the cooldown clears. The
    consumed_by_scan_id is stamped onto ``tool_input`` for audit.
    """
    row = (
        _approval_query(db, org_id, _hyp_dedup_key(hyp))
        .filter(AgentApproval.status == "approved")
        .order_by(AgentApproval.decided_at.desc())
        .first()
    )
    if row is None:
        return
    from sqlalchemy.orm.attributes import flag_modified
    row.status = "consumed"
    ti = dict(row.tool_input or {})
    ti["consumed_by_scan_id"] = int(scan_id) if scan_id else None
    row.tool_input = ti
    flag_modified(row, "tool_input")

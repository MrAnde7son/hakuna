"""Compliance evaluator — runs every mapping rule against findings and
materializes the per-(finding, control, mapping) and per-(org, control)
state used by the Compliance tab.

Hooked into post_ingest.finalize_batch between global exceptions and
threat-intel enrichment so:
  - findings are already persisted (rule_engine reads ORM objects)
  - exception_id has been resolved (verdict can reflect suppression)
  - threat-intel hasn't run yet (priority/KEV may shift after eval — that's OK,
    rule's `is_kev` check and re-eval on the next finalize will catch it)

Idempotency
-----------
- Per-mapping-key upsert via the unique index on
  ``(finding_id, control_id, mapping_key)``.
- Full-scan mode (new_finding_ids=None) wipes prior rows for the scan first
  so a finding that no longer matches a rule (e.g. because workflow_status
  flipped to resolved) doesn't leave a stale "failing" row behind.
- Incremental mode only upserts for the supplied finding ids — safe to
  call repeatedly during streaming ingest.

Soft-accept
-----------
Findings without CVE *and* without CWE are skipped (per the agentic
emit_finding hardening — they persist as data but are out of compliance
coverage). Surfaced separately in the Compliance tab so analysts see what
the evaluator can't reach.

Limitations (v1)
----------------
- Inventory-namespace conditions (``inventory.kerberoastable_user`` etc.)
  evaluate to False at the finding row level — that's by design in
  rule_engine.evaluate_condition_for_finding. Rules that depend solely on
  inventory facts don't match anything in v1; the rule is preserved in
  the YAML and will start matching when an asset-level evaluator pass
  ships in a follow-up.
- compensating-control linking (verdict="satisfied_by_compensating") is
  not yet wired — the column exists on compliance_finding_status, but
  PR 3 only sets failing / resolved / exception_suppressed verdicts.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.models import (
    Asset,
    ComplianceControl,
    ComplianceControlMapping,
    ComplianceControlStatus,
    ComplianceFindingStatus,
    Finding,
    OrgFrameworkSubscription,
    Scan,
)
from services.rule_engine import (
    evaluate_conditions_for_finding,
    get_matching_assets,
)

logger = logging.getLogger(__name__)


# Bumped in code when evaluator semantics change so finalize re-evaluates
# rows whose stored evaluator_version is below this. v1 = initial release.
EVALUATOR_VERSION = 1


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _is_compliance_evaluable(finding: Finding) -> bool:
    """Per the soft-accept policy: a finding is in compliance scope only when
    we have a cross-source taxonomy key (CVE or CWE) to map it by."""
    if finding.cves:
        return True
    if finding.cwe_ids:
        return True
    return False


def _compute_verdict(finding: Finding) -> str:
    """Map current Finding state to one of the four verdict values.

    Order matters: an explicit exception trumps workflow status (the analyst
    documented why this finding shouldn't count); resolved trumps default."""
    if finding.exception_id is not None:
        return "exception_suppressed"
    status = (finding.workflow_status or "").lower()
    if status in ("resolved",):
        return "resolved"
    return "failing"


def _build_match_signal(finding: Finding, rule: dict) -> dict:
    """Capture *why* the rule matched for auditor traceability.

    Walks the rule's conditions and records the relevant finding attribute
    against each condition's field. Avoids storing the finding's full
    payload — just the signal that justified counting this row.
    """
    signal: dict[str, Any] = {}
    for cond in (rule.get("conditions") or []):
        field = cond.get("field", "")
        if field == "finding.cve" and finding.cves:
            signal.setdefault("cves", list(finding.cves))
        elif field in ("finding.cwe", "finding.has_cwe") and finding.cwe_ids:
            signal.setdefault("cwes", list(finding.cwe_ids))
        elif field == "finding.plugin_family" and finding.plugin_family:
            signal.setdefault("plugin_family", finding.plugin_family)
        elif field == "finding.plugin_id" and finding.plugin_id:
            signal.setdefault("plugin_id", finding.plugin_id)
        elif field == "finding.is_kev" and finding.is_kev:
            signal["is_kev"] = True
        elif field == "finding.severity":
            signal["severity"] = finding.severity
        elif field == "finding.sla_status" and finding.sla_status:
            signal["sla_status"] = finding.sla_status
    return signal


def _matched_via(rule: dict) -> str:
    """Pick the most specific match-channel label for the row."""
    fields = {(c.get("field") or "") for c in (rule.get("conditions") or [])}
    if any(f in ("finding.cve", "finding.has_cve") for f in fields):
        return "cve_cwe"
    if any(f in ("finding.cwe", "finding.has_cwe") for f in fields):
        return "cve_cwe"
    if "finding.plugin_id" in fields:
        return "plugin_id"
    if "finding.plugin_family" in fields:
        return "plugin_family"
    if any(f.startswith("finding.matched_ttps") or f == "finding.technique_id"
           for f in fields):
        return "ttp"
    if any(f.startswith("inventory.") for f in fields):
        return "inventory"
    # Threat-intel-derived booleans (is_kev, ransomware_linked, etc.) — these
    # are populated by enrich_findings_from_threat_intel, not by the parser.
    if any(f in ("finding.is_kev", "finding.ransomware_linked",
                 "finding.trending_in_news", "finding.exploit",
                 "finding.exploit_maturity_level")
           for f in fields):
        return "threat_intel"
    return "other"


def _resolve_scope_asset_ids(
    db: Session,
    sub: OrgFrameworkSubscription,
) -> Optional[set[int]]:
    """Return the set of asset ids in the subscription's scope, or None
    when the scope is unrestricted (all org assets included)."""
    rule = sub.scope_rule
    if not rule:
        return None
    conditions = rule.get("conditions") if isinstance(rule, dict) else None
    if not conditions:
        return None
    logic = (rule.get("logic") if isinstance(rule, dict) else None) or "AND"
    try:
        assets = get_matching_assets(
            conditions=conditions,
            logic=logic,
            db=db,
            org_ids=[sub.org_id],
        )
        return {a.id for a in assets}
    except Exception:
        logger.exception(
            "compliance_evaluator: scope resolution failed for sub %s — "
            "falling back to unrestricted",
            sub.id,
        )
        return None


# ──────────────────────────────────────────────────────────────
# Per-finding evaluation
# ──────────────────────────────────────────────────────────────

def _upsert_finding_status(
    db: Session,
    *,
    org_id: int,
    finding_id: int,
    control_id: int,
    mapping_key: str,
    verdict: str,
    matched_via: str,
    match_signal: dict,
) -> None:
    """Insert or update one compliance_finding_status row."""
    existing = (
        db.query(ComplianceFindingStatus)
        .filter_by(finding_id=finding_id, control_id=control_id, mapping_key=mapping_key)
        .first()
    )
    if existing is None:
        db.add(ComplianceFindingStatus(
            org_id=org_id,
            finding_id=finding_id,
            control_id=control_id,
            mapping_key=mapping_key,
            verdict=verdict,
            matched_via=matched_via,
            match_signal=match_signal,
            scored_at=datetime.utcnow(),
        ))
    else:
        existing.org_id = org_id
        existing.verdict = verdict
        existing.matched_via = matched_via
        existing.match_signal = match_signal
        existing.scored_at = datetime.utcnow()


# ──────────────────────────────────────────────────────────────
# Control-level state recompute
# ──────────────────────────────────────────────────────────────

def _has_automated_mapping(db: Session, control: ComplianceControl) -> bool:
    return db.query(ComplianceControlMapping).filter_by(control_id=control.id).first() is not None


def _recompute_control_status(
    db: Session,
    *,
    org_id: int,
    control: ComplianceControl,
    scope_asset_ids: Optional[set[int]],
) -> None:
    """Update or insert the compliance_control_status row for this control.

    State machine:
      not_applicable        — no automated mappings, or scope is empty
      passing               — at least one mapping AND zero failing-or-satisfied rows
      compensating_control  — only satisfied_by_compensating rows; no raw failing rows
      partial               — both failing AND satisfied_by_compensating rows
      failing               — at least one failing row, no satisfied rows
    """
    # Pull all "open" (non-resolved, non-suppressed) status rows once and
    # bucket by verdict — cheaper than three separate queries.
    open_rows = (
        db.query(ComplianceFindingStatus)
        .filter(
            ComplianceFindingStatus.org_id == org_id,
            ComplianceFindingStatus.control_id == control.id,
            ComplianceFindingStatus.verdict.in_(
                ("failing", "satisfied_by_compensating")
            ),
        )
        .all()
    )
    failing_findings = [r for r in open_rows if r.verdict == "failing"]
    satisfied_findings = [r for r in open_rows if r.verdict == "satisfied_by_compensating"]
    failing_finding_count = len(failing_findings)
    failing_finding_ids = [s.finding_id for s in failing_findings]
    failing_asset_count = 0
    if failing_finding_ids:
        failing_asset_count = (
            db.query(Finding.asset_id)
            .filter(Finding.id.in_(failing_finding_ids))
            .distinct()
            .count()
        )

    if scope_asset_ids is None:
        in_scope_asset_count = (
            db.query(Asset)
            .join(Scan, Asset.scan_id == Scan.id)
            .filter(Scan.org_id == org_id)
            .count()
        )
    else:
        in_scope_asset_count = len(scope_asset_ids)

    # Determine state.
    if not _has_automated_mapping(db, control) or in_scope_asset_count == 0:
        state = "not_applicable"
    elif failing_finding_count == 0 and not satisfied_findings:
        state = "passing"
    elif failing_finding_count == 0 and satisfied_findings:
        state = "compensating_control"
    elif failing_finding_count > 0 and satisfied_findings:
        state = "partial"
    else:
        state = "failing"

    row = (
        db.query(ComplianceControlStatus)
        .filter_by(org_id=org_id, control_id=control.id)
        .first()
    )
    now = datetime.utcnow()
    if row is None:
        db.add(ComplianceControlStatus(
            org_id=org_id,
            control_id=control.id,
            state=state,
            in_scope_asset_count=in_scope_asset_count,
            failing_finding_count=failing_finding_count,
            failing_asset_count=failing_asset_count,
            last_evaluated_at=now,
            evaluator_version=EVALUATOR_VERSION,
            first_failed_at=now if state == "failing" else None,
        ))
    else:
        row.state = state
        row.in_scope_asset_count = in_scope_asset_count
        row.failing_finding_count = failing_finding_count
        row.failing_asset_count = failing_asset_count
        row.last_evaluated_at = now
        row.evaluator_version = EVALUATOR_VERSION
        if state == "failing" and row.first_failed_at is None:
            row.first_failed_at = now
        elif state in ("passing",):
            row.first_failed_at = None


def apply_compensating_control(db: Session, cc) -> int:
    """Mark every failing compliance_finding_status row under (org, control) as
    satisfied_by_compensating, then recompute the control's state.

    v1 simplification: the compensating control applies to the entire
    (org, control) bucket. Per-finding scope filtering via cc.scope_rule
    lands in a follow-up — for now scope_rule is stored for documentation
    and future evaluator passes but does not narrow the apply set.
    Returns the number of rows flipped.
    """
    rows = (
        db.query(ComplianceFindingStatus)
        .filter(
            ComplianceFindingStatus.org_id == cc.org_id,
            ComplianceFindingStatus.control_id == cc.control_id,
            ComplianceFindingStatus.verdict == "failing",
        )
        .all()
    )
    flipped = 0
    for r in rows:
        r.verdict = "satisfied_by_compensating"
        flipped += 1
    db.flush()

    control = db.query(ComplianceControl).filter_by(id=cc.control_id).first()
    if control is not None:
        # Resolve subscription scope so the count reflects the same denominator
        # the rest of the evaluator uses.
        sub = (
            db.query(OrgFrameworkSubscription)
            .filter_by(org_id=cc.org_id, framework_id=control.framework_id)
            .first()
        )
        scope_asset_ids = _resolve_scope_asset_ids(db, sub) if sub else None
        _recompute_control_status(
            db, org_id=cc.org_id, control=control, scope_asset_ids=scope_asset_ids,
        )
    return flipped


def revoke_compensating_control(
    db: Session, *, org_id: int, control_id: int,
) -> int:
    """Flip every satisfied_by_compensating row back to failing for the given
    (org, control), then recompute state. Called when the linked compensating
    control row is deleted or expires.

    Note: the row's source finding is re-evaluated at the next finalize pass,
    which will pick the correct verdict (failing / resolved / exception) based
    on current finding state. The flip-back here is the conservative default
    until the next evaluator run.
    """
    rows = (
        db.query(ComplianceFindingStatus)
        .filter(
            ComplianceFindingStatus.org_id == org_id,
            ComplianceFindingStatus.control_id == control_id,
            ComplianceFindingStatus.verdict == "satisfied_by_compensating",
        )
        .all()
    )
    flipped = 0
    for r in rows:
        # Recompute the verdict from the current finding state — a finding
        # that got resolved while the CC was active should not flip back to
        # failing just because the CC was removed.
        f = db.query(Finding).filter_by(id=r.finding_id).first()
        if f is not None:
            r.verdict = _compute_verdict(f)
        else:
            r.verdict = "failing"
        flipped += 1
    db.flush()

    control = db.query(ComplianceControl).filter_by(id=control_id).first()
    if control is not None:
        sub = (
            db.query(OrgFrameworkSubscription)
            .filter_by(org_id=org_id, framework_id=control.framework_id)
            .first()
        )
        scope_asset_ids = _resolve_scope_asset_ids(db, sub) if sub else None
        _recompute_control_status(
            db, org_id=org_id, control=control, scope_asset_ids=scope_asset_ids,
        )
    return flipped


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

def evaluate(
    db: Session,
    *,
    scan_id: Optional[int] = None,
    new_finding_ids: Optional[list[int]] = None,
    org_id: Optional[int] = None,
) -> dict:
    """Run the compliance evaluator.

    Modes:
      - finalize_batch (incremental): pass scan_id + new_finding_ids
      - finalize_scan (full): pass scan_id only (new_finding_ids=None)
      - backfill: invoke per scan from a script

    Returns a dict for instrumentation / tests:
      {evaluated, controls_touched, status_rows_written, frameworks}
    """
    if scan_id is None and not new_finding_ids:
        return {"evaluated": 0, "reason": "no_scope"}

    # Resolve org from scan when caller didn't supply it.
    if org_id is None and scan_id is not None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or not scan.org_id:
            return {"evaluated": 0, "reason": "no_org"}
        org_id = scan.org_id

    if not org_id:
        return {"evaluated": 0, "reason": "no_org"}

    subs = (
        db.query(OrgFrameworkSubscription)
        .filter(
            OrgFrameworkSubscription.org_id == org_id,
            OrgFrameworkSubscription.enabled == True,  # noqa: E712 — SQL truthy
        )
        .all()
    )
    if not subs:
        return {"evaluated": 0, "reason": "no_subscriptions"}

    # Resolve the finding pool.
    findings_q = db.query(Finding)
    if new_finding_ids is not None:
        findings_q = findings_q.filter(Finding.id.in_(new_finding_ids))
    elif scan_id is not None:
        findings_q = findings_q.filter(Finding.scan_id == scan_id)
        # Full-scan mode: drop prior rows so unmatched findings don't leave
        # stale "failing" ledger entries behind. Compliance_finding_status
        # CASCADEs from finding_id, but the rule may have changed (rule_version
        # bumped) so we wipe per scan, not per finding.
        finding_ids_in_scan = [r[0] for r in (
            db.query(Finding.id).filter(Finding.scan_id == scan_id).all()
        )]
        if finding_ids_in_scan:
            (
                db.query(ComplianceFindingStatus)
                .filter(ComplianceFindingStatus.finding_id.in_(finding_ids_in_scan))
                .delete(synchronize_session=False)
            )

    findings = findings_q.all()
    if not findings:
        # Still recompute control status — the absence of findings is itself
        # a state change (passing → not_applicable).
        _recompute_all_subs(db, org_id, subs)
        db.commit()
        return {"evaluated": 0, "controls_touched": 0, "status_rows_written": 0}

    matched = 0
    affected_controls: set[int] = set()
    framework_results: dict[str, int] = {}

    for sub in subs:
        scope_asset_ids = _resolve_scope_asset_ids(db, sub)
        in_scope_findings = [
            f for f in findings
            if (scope_asset_ids is None or f.asset_id in scope_asset_ids)
            and _is_compliance_evaluable(f)
        ]
        if not in_scope_findings:
            continue

        # Pull this framework's mappings + their parent controls in one query.
        mapping_rows = (
            db.query(ComplianceControlMapping, ComplianceControl)
            .join(ComplianceControl,
                  ComplianceControl.id == ComplianceControlMapping.control_id)
            .filter(ComplianceControl.framework_id == sub.framework_id)
            .all()
        )
        if not mapping_rows:
            continue

        per_fw = 0
        for mapping, control in mapping_rows:
            rule = mapping.rule or {}
            conditions = rule.get("conditions") or []
            if not conditions:
                continue
            logic = rule.get("logic", "AND")
            mv = _matched_via(rule)
            for finding in in_scope_findings:
                try:
                    matched_rule = evaluate_conditions_for_finding(
                        conditions, logic, finding,
                    )
                except Exception:
                    logger.exception(
                        "compliance_evaluator: rule eval crashed for mapping %s",
                        mapping.mapping_key,
                    )
                    continue
                if not matched_rule:
                    continue
                _upsert_finding_status(
                    db,
                    org_id=org_id,
                    finding_id=finding.id,
                    control_id=control.id,
                    mapping_key=mapping.mapping_key,
                    verdict=_compute_verdict(finding),
                    matched_via=mv,
                    match_signal=_build_match_signal(finding, rule),
                )
                matched += 1
                per_fw += 1
                affected_controls.add(control.id)

        framework_results[sub.framework_id] = per_fw

    # Recompute control state across every subscribed framework — even
    # controls we didn't touch this batch (a removed match flips state too).
    _recompute_all_subs(db, org_id, subs)

    db.commit()
    return {
        "evaluated": matched,
        "controls_touched": len(affected_controls),
        "status_rows_written": matched,
        "frameworks": framework_results,
    }


def _recompute_all_subs(
    db: Session,
    org_id: int,
    subs: list[OrgFrameworkSubscription],
) -> None:
    for sub in subs:
        scope_asset_ids = _resolve_scope_asset_ids(db, sub)
        controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == sub.framework_id)
            .all()
        )
        for control in controls:
            _recompute_control_status(
                db,
                org_id=org_id,
                control=control,
                scope_asset_ids=scope_asset_ids,
            )

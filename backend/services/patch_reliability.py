"""
Patch reliability scoring.

Turns raw signals (vendor known-issue advisories, internal rollback observations,
community chatter, supersedence events) into a single 0..1 score + status label
per (patch_source, patch_ref).

Design notes
------------
* Signals are append-only (models.threat_intel_models.PatchReliabilitySignal).
  Nothing in this module mutates them. Scoring is a pure function of the signal
  history, so tuning weights later is just a re-score pass.
* Dedup happens at the signal layer via `fingerprint`. Two rows with the same
  `(signal_source, fingerprint)` collapse to one effective signal — that stops
  a vendor advisory and a Reddit thread reporting the *same* BSOD from stacking.
* Old signals decay exponentially. A patch that was rocky at release but has
  been fine for months should drift back toward stable.
* Vendor recalls are absorbing: once a patch is recalled, no amount of positive
  telemetry flips it back. That has to be undone manually.

The scorer is called:
* On every new signal insertion (via `record_signal`).
* Nightly batch (via `rescore_all` from a scheduler) to apply decay.
* On-demand from the threat_intel_routes endpoints.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from models.threat_intel_models import (
    PatchReliability,
    PatchReliabilitySignal,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Weights — negative values hurt reliability, positive bump confidence.
# Tuned conservatively: a single vendor known-issue drops the score ~0.15,
# three independent issues drop it below the "known_issues" threshold (0.75).
# --------------------------------------------------------------------------- #
SIGNAL_WEIGHTS: dict[str, float] = {
    # Hard stops — absorbing states handled separately in _derive_status
    "recall": -1.0,             # vendor pulled the patch entirely
    "regression": -0.25,        # vendor shipped a follow-up fixing this patch (USN-*-2, RHBA)
    # Soft penalties
    "known_issue": -0.15,       # vendor-documented known issue on the advisory page
    "rollback": -0.20,          # internal: finding closed → reopened within window
    "supersedence": -0.05,      # newer patch supersedes this one — slight demotion
    # Positive signals
    "success": 0.02,            # internal: finding closed cleanly, no re-detect
}

# Decay half-life for soft signals (days). A rollback from 30 days ago counts
# half as much as one from yesterday. Recalls do not decay.
DECAY_HALF_LIFE_DAYS = 30.0

# Status thresholds on the post-decay score.
STATUS_STABLE_MIN = 0.85
STATUS_KNOWN_ISSUES_MIN = 0.50
# < STATUS_KNOWN_ISSUES_MIN = "recalled" unless no signals (→ "unknown")

# Rollback detection window — used by the remediation hook below. Exposed here
# so the wiring in the campaign close path stays in sync with the scorer.
ROLLBACK_WINDOW_DAYS = 14


# --------------------------------------------------------------------------- #
# Signal ingestion
# --------------------------------------------------------------------------- #
def record_signal(
    db: Session,
    *,
    patch_source: str,
    patch_ref: str,
    signal_source: str,
    signal_type: str,
    weight: Optional[float] = None,
    org_id: Optional[int] = None,
    fingerprint: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    observed_at: Optional[datetime] = None,
    rescore: bool = True,
) -> PatchReliabilitySignal:
    """
    Record a single reliability signal and (by default) re-score the patch.

    `fingerprint` is used for dedup: inserting a second signal with the same
    (patch_source, patch_ref, signal_source, fingerprint) is a no-op. This is
    how we keep community scrapers from stacking duplicate reports.
    """
    patch_ref = patch_ref.strip()
    patch_source = patch_source.strip().lower()

    if fingerprint:
        existing = (
            db.query(PatchReliabilitySignal)
            .filter(
                PatchReliabilitySignal.patch_source == patch_source,
                PatchReliabilitySignal.patch_ref == patch_ref,
                PatchReliabilitySignal.signal_source == signal_source,
                PatchReliabilitySignal.fingerprint == fingerprint,
            )
            .first()
        )
        if existing:
            return existing

    if weight is None:
        weight = SIGNAL_WEIGHTS.get(signal_type, 0.0)

    signal = PatchReliabilitySignal(
        patch_source=patch_source,
        patch_ref=patch_ref,
        signal_source=signal_source,
        signal_type=signal_type,
        weight=weight,
        org_id=org_id,
        fingerprint=fingerprint,
        detail=detail or {},
        observed_at=observed_at or datetime.utcnow(),
    )
    db.add(signal)
    db.flush()

    if rescore:
        score_patch(db, patch_source, patch_ref, commit=False)

    return signal


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def score_patch(
    db: Session,
    patch_source: str,
    patch_ref: str,
    *,
    commit: bool = True,
) -> PatchReliability:
    """
    Recompute the reliability record for a single patch from its signal history.
    Creates the PatchReliability row if it doesn't already exist.
    """
    patch_source = patch_source.strip().lower()
    patch_ref = patch_ref.strip()

    signals = (
        db.query(PatchReliabilitySignal)
        .filter(
            PatchReliabilitySignal.patch_source == patch_source,
            PatchReliabilitySignal.patch_ref == patch_ref,
        )
        .order_by(PatchReliabilitySignal.observed_at.asc())
        .all()
    )

    score, status, factors, recalled_at, recall_reason, known_issues, last_signal_at = (
        _compute(signals)
    )

    record = (
        db.query(PatchReliability)
        .filter(
            PatchReliability.patch_source == patch_source,
            PatchReliability.patch_ref == patch_ref,
        )
        .first()
    )
    if record is None:
        record = PatchReliability(
            patch_source=patch_source,
            patch_ref=patch_ref,
        )
        db.add(record)

    record.score = score
    record.status = status
    record.factors = factors
    record.known_issues = known_issues
    record.recalled_at = recalled_at
    record.recall_reason = recall_reason
    record.signal_count = len(signals)
    record.last_signal_at = last_signal_at
    record.last_scored_at = datetime.utcnow()

    if commit:
        db.commit()
    else:
        db.flush()

    return record


def _compute(
    signals: list[PatchReliabilitySignal],
) -> tuple[float, str, dict, Optional[datetime], Optional[str], list, Optional[datetime]]:
    """Pure scoring over a signal list. No DB access — keeps it testable."""
    if not signals:
        return 1.0, "unknown", {}, None, None, [], None

    now = datetime.utcnow()
    score = 1.0
    factors: dict[str, float] = {}
    known_issues: list[dict] = []
    recalled_at: Optional[datetime] = None
    recall_reason: Optional[str] = None
    last_signal_at: Optional[datetime] = None

    # Dedup within a (signal_source, fingerprint) group — keep the earliest.
    deduped: dict[tuple[str, str], PatchReliabilitySignal] = {}
    passthrough: list[PatchReliabilitySignal] = []
    for s in signals:
        if s.fingerprint:
            key = (s.signal_source, s.fingerprint)
            if key not in deduped or s.observed_at < deduped[key].observed_at:
                deduped[key] = s
        else:
            passthrough.append(s)
    effective = list(deduped.values()) + passthrough

    for s in effective:
        if last_signal_at is None or (s.observed_at and s.observed_at > last_signal_at):
            last_signal_at = s.observed_at

        # Recalls are absorbing — record them and note below.
        if s.signal_type == "recall":
            recalled_at = recalled_at or s.observed_at
            detail = s.detail or {}
            recall_reason = recall_reason or detail.get("reason") or detail.get("title")
            factors["recall"] = factors.get("recall", 0) + 1
            continue

        # Regressions (vendor shipped a follow-up patch): treat like a half-strength recall.
        # No decay — a regression is a durable fact.
        if s.signal_type == "regression":
            score += s.weight
            factors["regression"] = factors.get("regression", 0) + 1
            continue

        # Everything else decays exponentially by age.
        weight = s.weight * _decay(s.observed_at, now)
        score += weight
        factors[s.signal_type] = factors.get(s.signal_type, 0) + 1

        if s.signal_type == "known_issue":
            detail = s.detail or {}
            known_issues.append(
                {
                    "title": detail.get("title"),
                    "url": detail.get("url"),
                    "severity": detail.get("severity"),
                    "observed_at": s.observed_at.isoformat() if s.observed_at else None,
                    "source": s.signal_source,
                }
            )

    score = max(0.0, min(1.0, score))
    status = _derive_status(score, recalled_at=recalled_at, has_signals=bool(effective))

    return score, status, factors, recalled_at, recall_reason, known_issues, last_signal_at


def _decay(observed_at: Optional[datetime], now: datetime) -> float:
    """Exponential decay by age vs DECAY_HALF_LIFE_DAYS. Clamped to [0.05, 1.0]."""
    if observed_at is None:
        return 1.0
    age_days = max(0.0, (now - observed_at).total_seconds() / 86400.0)
    factor = math.pow(0.5, age_days / DECAY_HALF_LIFE_DAYS)
    return max(0.05, factor)


def _derive_status(
    score: float,
    *,
    recalled_at: Optional[datetime],
    has_signals: bool,
) -> str:
    if recalled_at is not None:
        return "recalled"
    if not has_signals:
        return "unknown"
    if score >= STATUS_STABLE_MIN:
        return "stable"
    if score >= STATUS_KNOWN_ISSUES_MIN:
        return "known_issues"
    return "recalled"


# --------------------------------------------------------------------------- #
# Batch + lookup helpers (used by routes / agent tools / the remediation engine)
# --------------------------------------------------------------------------- #
def rescore_all(db: Session, *, since: Optional[datetime] = None) -> int:
    """
    Re-score every patch that has at least one signal. Used by the nightly job
    to propagate decay. If `since` is given, only rescore patches with a signal
    newer than that timestamp.
    """
    q = db.query(
        PatchReliabilitySignal.patch_source,
        PatchReliabilitySignal.patch_ref,
    ).distinct()
    if since is not None:
        q = q.filter(PatchReliabilitySignal.observed_at >= since)

    count = 0
    for source, ref in q.all():
        score_patch(db, source, ref, commit=False)
        count += 1
    db.commit()
    logger.info("patch_reliability.rescore_all: rescored %d patches", count)
    return count


def get_reliability_map(
    db: Session, refs: Iterable[tuple[str, str]]
) -> dict[tuple[str, str], PatchReliability]:
    """
    Bulk-fetch reliability records for a list of (source, ref) pairs. Returns
    a dict keyed by the same tuples — missing entries are simply absent.

    Used by the patch catalog query layer to annotate patches without an N+1.
    """
    pairs = {(s.strip().lower(), r.strip()) for s, r in refs if s and r}
    if not pairs:
        return {}

    sources = {s for s, _ in pairs}
    refs_set = {r for _, r in pairs}

    rows = (
        db.query(PatchReliability)
        .filter(
            PatchReliability.patch_source.in_(sources),
            PatchReliability.patch_ref.in_(refs_set),
        )
        .all()
    )
    return {
        (row.patch_source, row.patch_ref): row
        for row in rows
        if (row.patch_source, row.patch_ref) in pairs
    }


def reliability_to_dict(record: Optional[PatchReliability]) -> dict:
    """Shape used by API responses + the agent tool layer."""
    if record is None:
        return {
            "score": None,
            "status": "unknown",
            "recalled_at": None,
            "recall_reason": None,
            "known_issues": [],
            "factors": {},
            "signal_count": 0,
            "last_signal_at": None,
            "last_scored_at": None,
        }
    return {
        "score": round(record.score, 3) if record.score is not None else None,
        "status": record.status,
        "recalled_at": record.recalled_at.isoformat() if record.recalled_at else None,
        "recall_reason": record.recall_reason,
        "known_issues": record.known_issues or [],
        "factors": record.factors or {},
        "signal_count": record.signal_count or 0,
        "last_signal_at": record.last_signal_at.isoformat() if record.last_signal_at else None,
        "last_scored_at": record.last_scored_at.isoformat() if record.last_scored_at else None,
    }


# --------------------------------------------------------------------------- #
# Remediation lifecycle hooks — call these from the campaign/finding close path
# --------------------------------------------------------------------------- #
def record_rollback(
    db: Session,
    *,
    patch_source: str,
    patch_ref: str,
    org_id: int,
    finding_id: int,
    asset_id: Optional[int] = None,
) -> PatchReliabilitySignal:
    """
    Called when a previously-closed finding is reopened within
    ROLLBACK_WINDOW_DAYS of its close. Fingerprint keys on finding_id so the
    same finding flapping open/closed repeatedly only counts once.
    """
    return record_signal(
        db,
        patch_source=patch_source,
        patch_ref=patch_ref,
        signal_source="internal_rollback",
        signal_type="rollback",
        org_id=org_id,
        fingerprint=f"finding:{finding_id}",
        detail={"finding_id": finding_id, "asset_id": asset_id},
    )


def record_success(
    db: Session,
    *,
    patch_source: str,
    patch_ref: str,
    org_id: int,
    finding_id: int,
) -> PatchReliabilitySignal:
    """
    Called when a finding tied to this patch has stayed closed past the
    rollback window. Small positive bump — intentionally small because a single
    successful close is weak evidence compared to a vendor advisory.
    """
    return record_signal(
        db,
        patch_source=patch_source,
        patch_ref=patch_ref,
        signal_source="internal_recheck",
        signal_type="success",
        org_id=org_id,
        fingerprint=f"finding:{finding_id}",
        detail={"finding_id": finding_id},
    )


# --------------------------------------------------------------------------- #
# Platform-scoped rollback helper — called from the finding lifecycle path.
# --------------------------------------------------------------------------- #
# We only want to signal rollback against patches whose platform matches the
# asset's OS. Otherwise an Ubuntu-box rollback would wrongly signal against
# the MSRC KB for the same CVE.
_OS_SOURCE_MAP = [
    ("windows",  {"msrc"}),
    ("ubuntu",   {"ubuntu"}),
    ("debian",   {"debian"}),
    ("red hat",  {"rhel"}),
    ("rhel",     {"rhel"}),
    ("centos",   {"rhel"}),
    ("rocky",    {"rhel"}),
    ("alma",     {"rhel"}),
    ("amazon",   {"amazon_linux"}),
    ("macos",    {"apple"}),
    ("mac os",   {"apple"}),
    ("darwin",   {"apple"}),
]


def sources_for_os(os_string: Optional[str]) -> set[str]:
    """Map an Asset.os string to the patch sources that could have fixed it."""
    if not os_string:
        return set()
    lowered = os_string.lower()
    for needle, sources in _OS_SOURCE_MAP:
        if needle in lowered:
            return sources
    return set()


def handle_finding_reopened(
    db: Session,
    *,
    finding_id: int,
    cves: list[str],
    asset_os: Optional[str],
    asset_id: Optional[int],
    org_id: Optional[int],
    resolved_at: Optional[datetime],
    now: Optional[datetime] = None,
) -> int:
    """
    Emit rollback signals when a previously-resolved finding reopens.

    Safeguards:
    * Only fires if the resolved→open transition is within ROLLBACK_WINDOW_DAYS
      of the original close. Older reopens are probably unrelated.
    * Only signals against patches whose `source` matches the asset's OS
      family. A Ubuntu box rollback won't falsely penalize the MSRC patch
      for the same CVE.
    * Fingerprinted by finding_id so a flapping finding only counts once
      per patch.

    Returns the number of signals emitted.
    """
    if not cves or not resolved_at:
        return 0

    now = now or datetime.utcnow()
    age = now - resolved_at
    if age > timedelta(days=ROLLBACK_WINDOW_DAYS):
        return 0

    eligible_sources = sources_for_os(asset_os)
    if not eligible_sources:
        return 0

    # Lazy import to avoid a services → threat_intel import cycle.
    from threat_intel import patch_catalog

    emitted = 0
    for cve in cves:
        try:
            patches = patch_catalog.get_patches_for_cve(db, cve)
        except Exception as exc:
            logger.warning("handle_finding_reopened: patch lookup failed for %s: %s", cve, exc)
            continue

        for p in patches:
            reliability_source = (p.get("reliability_source") or p.get("source") or "").strip().lower()
            patch_ref = (p.get("advisory_id") or "").strip()
            if not reliability_source or not patch_ref:
                continue
            if reliability_source not in eligible_sources:
                continue

            record_rollback(
                db,
                patch_source=reliability_source,
                patch_ref=patch_ref,
                org_id=org_id or 0,
                finding_id=finding_id,
                asset_id=asset_id,
            )
            emitted += 1

    return emitted

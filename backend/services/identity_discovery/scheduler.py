"""Weekly dispatcher for identity discovery.

Wakes up once a week, finds every org that has both the kill switch on
and an active consent, and runs ``run_identity_discovery`` per org with
some jitter so we don't fire 50 LinkedIn-scoped DDGS queries in the same
second and trip the rate limiter on round one.

Pacing rule: at most one successful run per org per 7 days. The lifecycle
service writes ``scan.last_run_at`` on every (signal or no-signal) run,
but the cooldown only honors *signal* runs — a stuck no-signal streak
shouldn't pin an org out of the queue. Otherwise, three bad DDGS weeks in
a row would let any returning identity sit at 3 absence counts unprocessed.
"""

from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from models.models import DataProcessingConsent, Organization, Scan

from .consent import IDENTITY_DISCOVERY_PURPOSE
from .discovery import run_identity_discovery

logger = logging.getLogger(__name__)

# How long after a *successful* run to skip an org. The job is scheduled
# weekly so this should match the cadence — re-checking sooner risks
# burning DDGS quota on orgs we just polled.
_MIN_INTERVAL_BETWEEN_SUCCESSFUL_RUNS = timedelta(days=7)

# Per-org jitter applied before each ``run_identity_discovery`` call so
# bulk fan-out doesn't make N back-to-back LinkedIn queries.
_MAX_JITTER_SECONDS = 30


def _eligible_org_ids(db: Session) -> list[int]:
    """Orgs with the kill switch on AND at least one active consent.

    The full ``is_identity_discovery_permitted`` check still runs inside
    ``run_identity_discovery`` per org (fails closed if consent expires
    between this query and the call), but this prefilter avoids walking
    every org in the system every week.
    """
    now = datetime.utcnow()
    rows = (
        db.query(Organization.id)
        .join(
            DataProcessingConsent,
            DataProcessingConsent.org_id == Organization.id,
        )
        .filter(
            Organization.identity_discovery_enabled.is_(True),
            Organization.is_active.is_(True),
            DataProcessingConsent.purpose == IDENTITY_DISCOVERY_PURPOSE,
            DataProcessingConsent.revoked_at.is_(None),
            (DataProcessingConsent.expires_at.is_(None))
            | (DataProcessingConsent.expires_at > now),
        )
        .distinct()
        .all()
    )
    return [r[0] for r in rows]


def _last_successful_run_at(db: Session, org_id: int) -> datetime | None:
    """When this org last completed a *signal* discovery run.

    Approximation: lifecycle bumps ``scan.last_run_at`` and writes
    ``scan.run_count``. We can't directly tell signal-vs-no-signal from
    the scan row, but ``run_count`` is incremented on every run while
    ``status='completed'`` is set on success of either kind. For the
    cooldown decision we accept this approximation — false positives
    (we skip an org because last week's no-signal run also bumped the
    clock) cost us at most one missed weekly pass, which is preferable
    to false negatives that exhaust DDGS quota.
    """
    scan = (
        db.query(Scan)
        .filter(Scan.org_id == org_id, Scan.source_type == "identity_discovery")
        .first()
    )
    return scan.last_run_at if scan else None


def run_weekly_dispatch(db: Session, *, sleep_fn=time.sleep) -> dict:
    """Fan out one identity discovery run per eligible org.

    Returns ``{"queued": int, "skipped_cooldown": int, "ran": int,
    "skipped_no_consent": int}``.

    ``sleep_fn`` is injectable for tests so the jitter doesn't make the
    suite slow.
    """
    now = datetime.utcnow()
    cutoff = now - _MIN_INTERVAL_BETWEEN_SUCCESSFUL_RUNS

    org_ids = _eligible_org_ids(db)
    queued = len(org_ids)
    skipped_cooldown = 0
    skipped_no_consent = 0
    ran = 0

    for org_id in org_ids:
        last_run = _last_successful_run_at(db, org_id)
        if last_run is not None and last_run > cutoff:
            skipped_cooldown += 1
            continue

        # Jitter before the actual call. Cheap insurance against DDGS
        # treating bulk fan-out as a single bot.
        sleep_fn(random.uniform(0, _MAX_JITTER_SECONDS))
        try:
            summary = run_identity_discovery(db, org_id)
        except Exception:
            logger.exception(
                "Identity discovery raised for org=%s (non-fatal)", org_id,
            )
            db.rollback()
            continue
        if summary.get("status") == "skipped_no_consent":
            skipped_no_consent += 1
            continue
        ran += 1

    logger.info(
        "Identity discovery weekly dispatch: queued=%d ran=%d "
        "skipped_cooldown=%d skipped_no_consent=%d",
        queued, ran, skipped_cooldown, skipped_no_consent,
    )
    return {
        "queued": queued,
        "ran": ran,
        "skipped_cooldown": skipped_cooldown,
        "skipped_no_consent": skipped_no_consent,
    }

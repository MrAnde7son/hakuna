"""Deterministic feed-card emitters for ingest events.

The activity feed (``OrgFeedEntry``) is normally populated by agents through
the ``post_feed_entry`` tool. That depends on an agent being configured for
the org and an LLM key being available — neither is guaranteed.

These helpers post a *deterministic* card (no agent, no LLM) so that every
file import (Nessus, Qualys, Rapid7, OpenVAS) and every integration run
shows up in the feed regardless of agent state. Agent narrators still run
in parallel and can post richer cards on top; the deterministic card is
the floor, not the ceiling.

Each helper is best-effort and swallows its own exceptions — feed posting
must never break the ingest path.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models.models import Integration, IntegrationRun, OrgFeedEntry, Scan

logger = logging.getLogger(__name__)

SCAN_INGESTED_EVENT_TYPE = "scan_ingested"
INTEGRATION_RUN_EVENT_TYPE = "integration_run"

# Skip the deterministic card if an agent-authored entry for the same
# scan/run already landed in this window — keeps the feed from
# double-posting when a triage agent is configured.
_DEDUP_WINDOW = timedelta(minutes=5)


def post_scan_ingest_card(
    db: Session,
    *,
    org_id: int,
    scan: Scan,
    source_type: str,
    total_assets: int,
    total_findings: int,
    crit_high: int,
    filename: Optional[str] = None,
) -> Optional[int]:
    """Post an ``observation`` card summarizing a completed file-import scan.

    Returns the new entry id, or ``None`` if skipped (dedup hit or error).
    """
    if not org_id or scan is None:
        return None

    try:
        if _has_recent_entry_for_ref(
            db, org_id=org_id,
            event_type=SCAN_INGESTED_EVENT_TYPE, ref_key="scan_id", ref_value=scan.id,
        ):
            return None

        label = _humanize_source(source_type)
        scan_name = scan.scan_name or filename or f"scan #{scan.id}"
        severity = "high" if crit_high > 0 else "info"

        crit_clause = f", {crit_high} critical/high" if crit_high else ""
        headline = (
            f"Ingested {label} scan '{scan_name}': "
            f"{total_assets} assets, {total_findings} findings{crit_clause}"
        )

        body_md = (
            f"- **Source:** {label}\n"
            f"- **Assets:** {total_assets}\n"
            f"- **Findings:** {total_findings}\n"
            f"- **Critical / high:** {crit_high}\n"
        )

        actions = [
            {"kind": "navigate", "label": "View findings",
             "href": f"/findings?scan_id={scan.id}"},
            {"kind": "navigate", "label": "View assets",
             "href": f"/assets?scan_id={scan.id}"},
        ]

        entry = OrgFeedEntry(
            org_id=org_id,
            kind="observation",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=SCAN_INGESTED_EVENT_TYPE,
            event_ref={
                "scan_id": scan.id,
                "source_type": source_type,
                "assets": total_assets,
                "findings": total_findings,
                "critical_high": crit_high,
            },
            proposed_actions=actions,
            severity=severity,
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception("post_scan_ingest_card failed for scan=%s", scan.id if scan else None)
        return None


def post_integration_run_card(
    db: Session,
    *,
    integration: Integration,
    run: IntegrationRun,
) -> Optional[int]:
    """Post a card summarizing a completed integration-builder run.

    Covers both ``pull`` and ``push`` directions and all transport types.
    Severity is driven by run status: ``error`` → high, ``partial`` →
    medium, ``success`` → info.
    """
    if integration is None or run is None:
        return None
    org_id = integration.org_id
    if not org_id:
        return None

    try:
        if _has_recent_entry_for_ref(
            db, org_id=org_id,
            event_type=INTEGRATION_RUN_EVENT_TYPE, ref_key="run_id", ref_value=run.id,
        ):
            return None

        direction = (integration.direction or "").lower()
        verb = {"pull": "Pulled", "push": "Pushed"}.get(direction, "Ran")
        status = (run.status or "").lower()

        severity = {"error": "high", "partial": "medium"}.get(status, "info")
        kind = "action" if status == "error" else "observation"

        fetched = run.records_fetched or 0
        inserted = run.records_inserted or 0
        updated = run.records_updated or 0
        skipped = run.records_skipped or 0

        name = integration.name or integration.id

        if status == "error":
            headline = f"{verb} via '{name}' failed"
        elif direction == "pull":
            headline = (
                f"{verb} {fetched} records via '{name}' "
                f"(+{inserted} new, ~{updated} updated)"
            )
        else:
            headline = f"{verb} {fetched} records via '{name}'"

        body_lines = [
            f"- **Integration:** {name}",
            f"- **Direction:** {direction or 'unknown'}",
            f"- **Entity:** {integration.entity or 'unknown'}",
            f"- **Status:** {status or 'unknown'}",
            f"- **Records:** {fetched} fetched, {inserted} inserted, "
            f"{updated} updated, {skipped} skipped",
        ]
        if run.error_message:
            body_lines.append(f"- **Error:** {run.error_message}")
        body_md = "\n".join(body_lines)

        actions = [
            {"kind": "navigate", "label": "Open integration",
             "href": f"/integrations/{integration.id}"},
        ]

        entry = OrgFeedEntry(
            org_id=org_id,
            kind=kind,
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=INTEGRATION_RUN_EVENT_TYPE,
            event_ref={
                "integration_id": integration.id,
                "run_id": run.id,
                "direction": direction,
                "status": status,
                "records_fetched": fetched,
                "records_inserted": inserted,
                "records_updated": updated,
            },
            proposed_actions=actions,
            severity=severity,
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception(
            "post_integration_run_card failed for integration=%s run=%s",
            getattr(integration, "id", None), getattr(run, "id", None),
        )
        return None


def _has_recent_entry_for_ref(
    db: Session, *, org_id: int, event_type: str, ref_key: str, ref_value,
) -> bool:
    """Return True if any feed entry with the same (org, event_type,
    event_ref[ref_key]) already exists in the dedup window."""
    if ref_value is None:
        return False
    cutoff = datetime.utcnow() - _DEDUP_WINDOW
    rows = (
        db.query(OrgFeedEntry.event_ref)
        .filter(
            OrgFeedEntry.org_id == org_id,
            OrgFeedEntry.event_type == event_type,
            OrgFeedEntry.created_at >= cutoff,
        )
        .all()
    )
    for (ref,) in rows:
        if isinstance(ref, dict) and ref.get(ref_key) == ref_value:
            return True
    return False


def _humanize_source(source_type: str) -> str:
    return {
        "nessus": "Nessus",
        "qualys": "Qualys",
        "rapid7": "Rapid7",
        "openvas": "OpenVAS",
        "easm": "EASM",
        "vm_scanner": "VM scanner",
    }.get((source_type or "").lower(), source_type or "scanner")


def _clip_headline(s: str) -> str:
    s = (s or "").strip()
    if len(s) > 280:
        return s[:277] + "…"
    return s

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

from models.models import Campaign, Integration, IntegrationRun, OrgFeedEntry, Scan, Tag

logger = logging.getLogger(__name__)

SCAN_INGESTED_EVENT_TYPE = "scan_ingested"
INTEGRATION_RUN_EVENT_TYPE = "integration_run"
WELCOME_EVENT_TYPE = "welcome"
TAG_CREATED_EVENT_TYPE = "tag_created"
TAG_ASSIGNED_EVENT_TYPE = "tag_assigned"
CAMPAIGN_CREATED_EVENT_TYPE = "campaign_created"
CAMPAIGN_UPDATED_EVENT_TYPE = "campaign_updated"
CAMPAIGN_RUN_EVENT_TYPE = "campaign_run"

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


def post_welcome_card(db: Session, *, org_id: int) -> Optional[int]:
    """Seed a first-run welcome card so a brand-new org doesn't land on a
    dead-end empty feed. Idempotent on ``event_type='welcome'`` for the
    lifetime of the org — never re-posts.
    """
    if not org_id:
        return None
    try:
        existing = (
            db.query(OrgFeedEntry.id)
            .filter(
                OrgFeedEntry.org_id == org_id,
                OrgFeedEntry.event_type == WELCOME_EVENT_TYPE,
            )
            .first()
        )
        if existing:
            return None

        headline = "Welcome to Hakuna — here's how your feed works"
        body_md = (
            "Your activity feed is where your agents post **observations**, "
            "ask for **approvals** on risky actions, and propose **one-click fixes**.\n\n"
            "Three ways to get value fast:\n\n"
            "- **Connect a scanner** so findings start flowing in.\n"
            "- **Review your agents** — they triage scans, narrate attack chains, and draft remediations.\n"
            "- **Use the chat above** — it knows your recent feed and can summarize, prioritize, "
            "or draft a campaign for you. Reference any entry by its `#id`.\n"
        )
        actions = [
            {
                "kind": "navigate", "intent": "integrate",
                "label": "Connect a scanner", "href": "/settings",
            },
            {"kind": "navigate", "label": "See your agents", "href": "/agents"},
        ]
        entry = OrgFeedEntry(
            org_id=org_id,
            kind="brief",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=WELCOME_EVENT_TYPE,
            event_ref={},
            proposed_actions=actions,
            severity="info",
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception("post_welcome_card failed for org=%s", org_id)
        return None


def post_tag_created_card(
    db: Session, *, tag: Tag,
) -> Optional[int]:
    """Post an observation card when a new tag is created."""
    if tag is None or not tag.org_id:
        return None
    try:
        if _has_recent_entry_for_ref(
            db, org_id=tag.org_id,
            event_type=TAG_CREATED_EVENT_TYPE, ref_key="tag_id", ref_value=tag.id,
        ):
            return None

        label = f"{tag.category}:{tag.value}"
        headline = f"New tag created: {label}"
        body_lines = [
            f"- **Tag:** {label}",
            f"- **Color:** {tag.color or '—'}",
        ]
        if tag.description:
            body_lines.append(f"- **Description:** {tag.description}")
        body_md = "\n".join(body_lines)

        actions = [
            {"kind": "navigate", "label": "View tags", "href": "/tags"},
        ]

        entry = OrgFeedEntry(
            org_id=tag.org_id,
            kind="observation",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=TAG_CREATED_EVENT_TYPE,
            event_ref={"tag_id": tag.id, "category": tag.category, "value": tag.value},
            proposed_actions=actions,
            severity="info",
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception("post_tag_created_card failed for tag=%s", getattr(tag, "id", None))
        return None


def post_tag_assigned_card(
    db: Session, *,
    org_id: int,
    tag_labels: list[str],
    asset_count: int,
    finding_count: int,
    request_id: Optional[str] = None,
) -> Optional[int]:
    """Post an observation card summarizing a bulk tag-assignment request.

    ``request_id`` is a caller-provided dedup key so identical bulk requests
    in the dedup window don't double-post; if absent we fall back to a
    composite of (tag set, counts).
    """
    if not org_id:
        return None
    total = (asset_count or 0) + (finding_count or 0)
    if total == 0:
        return None
    try:
        dedup_value = request_id or "|".join(sorted(tag_labels or [])) + f":{asset_count}:{finding_count}"
        if _has_recent_entry_for_ref(
            db, org_id=org_id,
            event_type=TAG_ASSIGNED_EVENT_TYPE, ref_key="dedup", ref_value=dedup_value,
        ):
            return None

        labels = ", ".join(tag_labels or []) or "(unknown)"
        targets = []
        if asset_count:
            targets.append(f"{asset_count} asset{'s' if asset_count != 1 else ''}")
        if finding_count:
            targets.append(f"{finding_count} finding{'s' if finding_count != 1 else ''}")
        targets_str = " and ".join(targets)

        headline = f"Tagged {targets_str} with {labels}"
        body_md = (
            f"- **Tags:** {labels}\n"
            f"- **Assets tagged:** {asset_count}\n"
            f"- **Findings tagged:** {finding_count}\n"
        )

        actions = []
        if asset_count:
            actions.append({"kind": "navigate", "label": "View assets", "href": "/assets"})
        if finding_count:
            actions.append({"kind": "navigate", "label": "View findings", "href": "/findings"})

        entry = OrgFeedEntry(
            org_id=org_id,
            kind="observation",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=TAG_ASSIGNED_EVENT_TYPE,
            event_ref={
                "dedup": dedup_value,
                "tag_labels": tag_labels,
                "asset_count": asset_count,
                "finding_count": finding_count,
            },
            proposed_actions=actions,
            severity="info",
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception("post_tag_assigned_card failed for org=%s", org_id)
        return None


def post_campaign_created_card(
    db: Session, *, campaign: Campaign,
) -> Optional[int]:
    """Post an observation card when a new campaign is created."""
    if campaign is None or not campaign.org_id:
        return None
    try:
        if _has_recent_entry_for_ref(
            db, org_id=campaign.org_id,
            event_type=CAMPAIGN_CREATED_EVENT_TYPE, ref_key="campaign_id", ref_value=campaign.id,
        ):
            return None

        headline = f"New campaign created: '{campaign.name}'"
        body_lines = [
            f"- **Campaign:** {campaign.name}",
            f"- **Status:** {campaign.status or 'draft'}",
        ]
        if campaign.description:
            body_lines.append(f"- **Description:** {campaign.description}")
        body_md = "\n".join(body_lines)

        actions = [
            {"kind": "navigate", "label": "Open campaign",
             "href": f"/campaigns/{campaign.id}"},
        ]

        entry = OrgFeedEntry(
            org_id=campaign.org_id,
            kind="observation",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=CAMPAIGN_CREATED_EVENT_TYPE,
            event_ref={"campaign_id": campaign.id, "name": campaign.name, "status": campaign.status},
            proposed_actions=actions,
            severity="info",
            status="open",
        )
        db.add(entry)
        db.commit()
        return entry.id
    except Exception:
        db.rollback()
        logger.exception("post_campaign_created_card failed for campaign=%s",
                         getattr(campaign, "id", None))
        return None


def post_campaign_updated_card(
    db: Session, *,
    campaign: Campaign,
    old_status: Optional[str],
    new_status: Optional[str],
) -> Optional[int]:
    """Post a card when a campaign's status transitions.

    Non-status edits (name/description/query) are intentionally not
    surfaced here — they generate audit-log entries but would be too
    noisy in the feed.
    """
    if campaign is None or not campaign.org_id:
        return None
    if not new_status or old_status == new_status:
        return None
    try:
        ref_value = f"{campaign.id}:{old_status}->{new_status}"
        if _has_recent_entry_for_ref(
            db, org_id=campaign.org_id,
            event_type=CAMPAIGN_UPDATED_EVENT_TYPE, ref_key="transition", ref_value=ref_value,
        ):
            return None

        severity = "info"
        if new_status == "completed":
            severity = "info"
        elif new_status == "paused":
            severity = "medium"

        headline = f"Campaign '{campaign.name}' moved from {old_status or 'draft'} to {new_status}"
        body_md = (
            f"- **Campaign:** {campaign.name}\n"
            f"- **Previous status:** {old_status or 'draft'}\n"
            f"- **New status:** {new_status}\n"
        )
        actions = [
            {"kind": "navigate", "label": "Open campaign",
             "href": f"/campaigns/{campaign.id}"},
        ]

        entry = OrgFeedEntry(
            org_id=campaign.org_id,
            kind="observation",
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=CAMPAIGN_UPDATED_EVENT_TYPE,
            event_ref={
                "campaign_id": campaign.id,
                "transition": ref_value,
                "old_status": old_status,
                "new_status": new_status,
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
        logger.exception("post_campaign_updated_card failed for campaign=%s",
                         getattr(campaign, "id", None))
        return None


def post_campaign_run_card(
    db: Session, *,
    campaign: Campaign,
    finding_count: int,
    asset_count: int,
) -> Optional[int]:
    """Post a card summarizing a campaign execution."""
    if campaign is None or not campaign.org_id:
        return None
    try:
        # Dedup on the campaign's last_run_at timestamp so retried runs in
        # the same minute don't double-post; distinct runs (different
        # last_run_at) post cleanly.
        run_marker = campaign.last_run_at.isoformat() if campaign.last_run_at else str(finding_count)
        ref_value = f"{campaign.id}:{run_marker}"
        if _has_recent_entry_for_ref(
            db, org_id=campaign.org_id,
            event_type=CAMPAIGN_RUN_EVENT_TYPE, ref_key="run_marker", ref_value=ref_value,
        ):
            return None

        severity = "high" if finding_count > 0 else "info"
        kind = "action" if finding_count > 0 else "observation"

        if finding_count == 0:
            headline = f"Campaign '{campaign.name}' ran — no matching findings"
        else:
            headline = (
                f"Campaign '{campaign.name}' matched {finding_count} "
                f"finding{'s' if finding_count != 1 else ''} across {asset_count} "
                f"asset{'s' if asset_count != 1 else ''}"
            )

        body_md = (
            f"- **Campaign:** {campaign.name}\n"
            f"- **Findings matched:** {finding_count}\n"
            f"- **Assets affected:** {asset_count}\n"
            f"- **Status:** {campaign.status or 'unknown'}\n"
        )
        actions = [
            {"kind": "navigate", "label": "Open campaign",
             "href": f"/campaigns/{campaign.id}"},
        ]

        entry = OrgFeedEntry(
            org_id=campaign.org_id,
            kind=kind,
            headline=_clip_headline(headline),
            body_md=body_md,
            event_type=CAMPAIGN_RUN_EVENT_TYPE,
            event_ref={
                "campaign_id": campaign.id,
                "run_marker": ref_value,
                "finding_count": finding_count,
                "asset_count": asset_count,
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
        logger.exception("post_campaign_run_card failed for campaign=%s",
                         getattr(campaign, "id", None))
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

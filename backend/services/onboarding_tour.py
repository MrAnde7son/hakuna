"""Onboarding tour — deterministic feed cards seeded right after the wizard.

The ``welcome_narrator`` agent posts the hero card (LLM-generated, branches
on EASM scan state). This module posts the *next-action* cards under it:
"try the copilot", "connect tools", "invite teammates", and an optional
"here's what got provisioned" card.

These are written as plain ``OrgFeedEntry`` rows — no agent, no LLM, no
keys required. Determinism matters for the first thing a new user sees,
and these cards still render even when the welcome agent fails.

Idempotent on ``(org_id, event_type='onboarding_tour')``: a second call
for the same org is a no-op, so re-running the wizard or replaying the
emit doesn't spam the feed.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from models.models import OrgFeedEntry

logger = logging.getLogger(__name__)

_TOUR_EVENT_TYPE = "onboarding_tour"


def seed_onboarding_tour(
    db: Session, *, org_id: int, payload: dict[str, Any] | None = None,
) -> dict:
    """Insert the onboarding tour feed cards for ``org_id``.

    Returns ``{"seeded": N}`` on first call, ``{"seeded": 0, "reason":
    "already_seeded"}`` on subsequent calls. Never raises — onboarding
    success can't depend on the tour.
    """
    if not org_id:
        return {"seeded": 0, "reason": "missing_org_id"}

    payload = payload or {}

    try:
        already = (
            db.query(OrgFeedEntry.id)
            .filter(
                OrgFeedEntry.org_id == org_id,
                OrgFeedEntry.event_type == _TOUR_EVENT_TYPE,
            )
            .first()
        )
        if already is not None:
            return {"seeded": 0, "reason": "already_seeded"}

        entries = _build_tour_entries(payload)

        for spec in entries:
            db.add(OrgFeedEntry(
                org_id=org_id,
                kind=spec["kind"],
                headline=spec["headline"],
                body_md=spec["body_md"],
                event_type=_TOUR_EVENT_TYPE,
                event_ref={},
                proposed_actions=spec["proposed_actions"],
                severity="info",
                status="open",
            ))
        db.commit()
        return {"seeded": len(entries)}
    except Exception:
        db.rollback()
        logger.exception("seed_onboarding_tour failed for org=%d", org_id)
        return {"seeded": 0, "reason": "error"}


def _build_tour_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the ordered list of tour cards to seed.

    Cards are static text by design — the user's first feed needs to be
    predictable. The only dynamic piece is the "what got provisioned"
    card, which references actual counts from ``payload['provisioning']``
    so the user can see what the wizard set up for them.
    """
    cards: list[dict[str, Any]] = [
        {
            "kind": "question",
            "headline": "Try the copilot — ask it to triage your top risks",
            "body_md": (
                "I can summarize what's risky, build campaigns, draft tickets, "
                "and explain any finding in plain English. A few prompts to start with:\n\n"
                "- *What should I fix first this week?*\n"
                "- *Show me critical assets without an owner.*\n"
                "- *Draft a campaign for KEV-listed CVEs on internet-facing hosts.*\n\n"
                "Anything you'd normally type into a SIEM, ask me first — I'll do the joins."
            ),
            "proposed_actions": [
                {"kind": "navigate", "label": "Open the copilot", "href": "/agents"},
            ],
        },
        {
            "kind": "action",
            "headline": "Connect Jira, Slack, or a scanner so I can pull data automatically",
            "body_md": (
                "Hakuna gets sharper the more it sees. The high-leverage integrations:\n\n"
                "- **Scanner imports** (Nessus, Qualys, Rapid7, OpenVAS) — auto-ingest findings.\n"
                "- **Jira / ServiceNow** — bidirectional ticket sync on campaigns.\n"
                "- **Slack / Teams** — route alerts to the right channel.\n\n"
                "Each takes about a minute to wire up."
            ),
            "proposed_actions": [
                {
                    "kind": "navigate",
                    "label": "Connect an integration",
                    "href": "/settings?tab=integrations",
                    "intent": "integrate",
                },
            ],
        },
        {
            "kind": "action",
            "headline": "Invite teammates so I can route findings to the right owners",
            "body_md": (
                "Ownership inference and SLA notifications work better when "
                "analysts, asset owners, and managers are in the system. "
                "Invite by email, set a role (Analyst, Viewer, Org Admin), "
                "and they'll get an activation link."
            ),
            "proposed_actions": [
                {"kind": "navigate", "label": "Invite teammates", "href": "/settings?tab=users"},
            ],
        },
    ]

    provisioning_card = _build_provisioning_card(payload.get("provisioning") or {})
    if provisioning_card is not None:
        cards.append(provisioning_card)

    return cards


def _build_provisioning_card(provisioning: dict[str, Any]) -> dict[str, Any] | None:
    """Optional card summarizing what the wizard auto-provisioned. Skipped
    when nothing was created (a wizard-skipper or a stripped-down profile).
    """
    counts = {k: len(v) for k, v in provisioning.items() if isinstance(v, list)}
    if not any(counts.values()):
        return None

    parts: list[str] = []
    for label, key, route in (
        ("campaigns", "campaigns", "/campaigns"),
        ("agents", "agents", "/agents"),
        ("reports", "reports", "/reports"),
        ("tags", "tags", "/tags"),
    ):
        n = counts.get(key, 0)
        if n:
            parts.append(f"**{n}** {label}")

    if not parts:
        return None

    summary = ", ".join(parts[:-1]) + (f", and {parts[-1]}" if len(parts) > 1 else parts[0])

    primary_route = "/campaigns"
    if not counts.get("campaigns"):
        primary_route = "/agents" if counts.get("agents") else "/reports"

    return {
        "kind": "brief",
        "headline": "Here's what I set up for you — take a look",
        "body_md": (
            f"Based on your objectives, I provisioned {summary}. "
            "You can edit, disable, or delete any of them. "
            "Nothing here is locked in — treat it as a starting point."
        ),
        "proposed_actions": [
            {"kind": "navigate", "label": "Show me", "href": primary_route},
        ],
    }

"""Campaign collaboration invite delivery.

Sends the passcode-gated-link email for an external collaborator. Thin wrapper
around the generic `send_email` connector so the org's configured SMTP (or
Brevo fallback) is used automatically.
"""
import logging
import os
from typing import Optional

from sqlalchemy.orm import Session

from services.integrations import send_email

logger = logging.getLogger(__name__)


# The origin of the public collaboration page — configurable per deployment.
# Falls back to app.hakunahq.com so invites still carry a working URL in
# production environments where PUBLIC_APP_URL isn't explicitly set.
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "https://app.hakunahq.com").rstrip("/")


def build_share_url(share_token: str) -> str:
    return f"{PUBLIC_APP_URL}/c/{share_token}"


INVITE_BODY_TEMPLATE = """Hi {invitee_name},

{inviter_name} from {org_name} has invited you to collaborate on a remediation
campaign in Hakuna: "{campaign_name}"

Open the campaign page:
  {share_url}

Your passcode (needed to unlock the page):
  {passcode}

Keep this passcode confidential — anyone with the link AND the passcode can see
and act on this campaign.

The link expires on {expires_at}.

If you weren't expecting this invite, just ignore this email.

— Hakuna
"""


def send_campaign_invite_email(
    db: Session,
    *,
    to_email: str,
    invitee_name: Optional[str],
    inviter_name: str,
    org_name: str,
    campaign_name: str,
    share_token: str,
    passcode: str,
    expires_at_iso: Optional[str] = None,
) -> dict:
    """Send the campaign collaboration invite email.

    Raises ConnectionError if no email path is configured (no org SMTP + no
    system Brevo). Callers should catch this and fall back to the "copy link"
    path in the wizard — the share URL + passcode are always shown in the UI
    regardless of email success.
    """
    share_url = build_share_url(share_token)
    body = INVITE_BODY_TEMPLATE.format(
        invitee_name=invitee_name or "there",
        inviter_name=inviter_name,
        org_name=org_name,
        campaign_name=campaign_name,
        share_url=share_url,
        passcode=passcode,
        expires_at=expires_at_iso or "in 30 days",
    )
    subject = f"[Hakuna] Campaign invite: {campaign_name}"
    config = {
        "to": to_email,
        "subject": subject,
        "body_template": body,
        "include_findings_table": False,
    }
    try:
        return send_email(db, config, items=[])
    except Exception as e:
        logger.warning("Campaign invite email delivery failed: %s", e)
        raise

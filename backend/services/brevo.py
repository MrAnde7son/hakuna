"""Brevo (formerly Sendinblue) SMTP email service.

Used as the system-level email sender for password resets and as a fallback
for workflow alert emails when no custom SMTP integration is configured.

Required env vars:
  BREVO_SMTP_PASS     — Brevo SMTP API key (required to enable)
  BREVO_SMTP_USER     — Brevo SMTP login (default: a58580001@smtp-brevo.com)
  BREVO_SMTP_HOST     — SMTP host (default: smtp-relay.brevo.com)
  BREVO_SMTP_PORT     — SMTP port (default: 587)
  BREVO_FROM_ADDRESS  — Sender address (default: BREVO_SMTP_USER)
  APP_URL             — Frontend URL used to build reset links (default: http://localhost:5173)
"""
import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

BREVO_SMTP_HOST = os.environ.get("BREVO_SMTP_HOST", "smtp-relay.brevo.com")
BREVO_SMTP_PORT = int(os.environ.get("BREVO_SMTP_PORT", "587"))
BREVO_SMTP_USER = os.environ.get("BREVO_SMTP_USER", "a58580001@smtp-brevo.com")
BREVO_SMTP_PASS = os.environ.get("BREVO_SMTP_PASS", "")
BREVO_FROM_ADDRESS = os.environ.get("BREVO_FROM_ADDRESS", BREVO_SMTP_USER)
APP_URL = os.environ.get("APP_URL", "http://localhost:5173").rstrip("/")


def is_configured() -> bool:
    """Return True if Brevo credentials are present in environment."""
    return bool(BREVO_SMTP_PASS)


def send_email(to: "str | list[str]", subject: str, body_text: str, body_html: str = None) -> None:
    """Send an email via Brevo SMTP. Raises on failure."""
    if not is_configured():
        raise RuntimeError("Brevo SMTP not configured — set BREVO_SMTP_PASS env var")

    recipients = [to] if isinstance(to, str) else to

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = BREVO_FROM_ADDRESS
    msg["To"] = ", ".join(recipients)

    msg.attach(MIMEText(body_text, "plain"))
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    with smtplib.SMTP(BREVO_SMTP_HOST, BREVO_SMTP_PORT, timeout=15) as server:
        server.starttls()
        server.login(BREVO_SMTP_USER, BREVO_SMTP_PASS)
        server.sendmail(BREVO_FROM_ADDRESS, recipients, msg.as_string())

    logger.info(f"Brevo email sent to {recipients}: {subject}")


def send_password_reset(to: str, display_name: str, token: str) -> None:
    """Send a password reset email with the given token."""
    reset_url = f"{APP_URL}/reset-password?token={token}"
    subject = "Reset your Hakuna password"

    body_text = (
        f"Hello {display_name},\n\n"
        "You requested a password reset for your Hakuna account.\n\n"
        f"Click the link below to reset your password (expires in 1 hour):\n"
        f"{reset_url}\n\n"
        "If you didn't request this, you can safely ignore this email.\n\n"
        "— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">Reset your password</h2>
  <p>Hello <strong>{display_name}</strong>,</p>
  <p>You requested a password reset for your Hakuna account.</p>
  <p style="margin:24px 0">
    <a href="{reset_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Reset Password
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{reset_url}" style="color:#590202">{reset_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_org_admin_activation(to: str, org_name: str, token: str) -> None:
    """Send an account activation email to a newly created org admin."""
    activate_url = f"{APP_URL}/reset-password?token={token}"
    subject = f"Activate your Hakuna account — {org_name}"

    body_text = (
        f"Hello,\n\n"
        f"An account has been created for you as the admin of {org_name} on Hakuna.\n\n"
        f"Click the link below to set your password and activate your account (expires in 24 hours):\n"
        f"{activate_url}\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">Activate your Hakuna account</h2>
  <p>An account has been created for you as the admin of <strong>{org_name}</strong> on Hakuna.</p>
  <p style="margin:24px 0">
    <a href="{activate_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Set Password &amp; Activate
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This link expires in 24 hours. If you didn't expect this, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{activate_url}" style="color:#590202">{activate_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_email_verification(to: str, display_name: str, token: str) -> None:
    """Send an email verification link to a newly registered user."""
    verify_url = f"{APP_URL}/verify-email?token={token}"
    subject = "Verify your Hakuna email address"

    body_text = (
        f"Hello {display_name},\n\n"
        "Thanks for signing up for Hakuna! Please verify your email address "
        "by clicking the link below (expires in 24 hours):\n\n"
        f"{verify_url}\n\n"
        "If you didn't create this account, you can safely ignore this email.\n\n"
        "— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">Verify your email address</h2>
  <p>Hello <strong>{display_name}</strong>,</p>
  <p>Thanks for signing up for Hakuna! Please verify your email address to activate your account.</p>
  <p style="margin:24px 0">
    <a href="{verify_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Verify Email
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This link expires in 24 hours. If you didn't create this account, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{verify_url}" style="color:#590202">{verify_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_user_invite(to: str, display_name: str, org_name: str, token: str) -> None:
    """Send an invite email to a new user so they can set their password."""
    activate_url = f"{APP_URL}/reset-password?token={token}"
    subject = f"You've been invited to {org_name} on Hakuna"

    body_text = (
        f"Hello {display_name},\n\n"
        f"You've been invited to join {org_name} on Hakuna.\n\n"
        f"Click the link below to set your password and activate your account (expires in 24 hours):\n"
        f"{activate_url}\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">You've been invited to Hakuna</h2>
  <p>Hello <strong>{display_name}</strong>,</p>
  <p>You've been invited to join <strong>{org_name}</strong> on Hakuna's vulnerability management platform.</p>
  <p style="margin:24px 0">
    <a href="{activate_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Set Password &amp; Get Started
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This link expires in 24 hours. If you didn't expect this, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{activate_url}" style="color:#590202">{activate_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_campaign_collaborator_invite(
    to: str,
    campaign_name: str,
    invited_by_name: str,
    org_name: str,
    accept_url: str,
    expires_in_days: int = 7,
) -> None:
    """Invite an external (non-Hakuna) collaborator into one specific campaign.

    The accept_url carries a single-use magic-link token. After acceptance the
    collaborator can only see/edit findings, workflows, and integrations
    attached to this campaign.
    """
    subject = f"You've been invited to collaborate on '{campaign_name}'"

    body_text = (
        f"Hello,\n\n"
        f"{invited_by_name} ({org_name}) invited you to collaborate on the "
        f"remediation campaign '{campaign_name}' on Hakuna.\n\n"
        f"You don't need a Hakuna account — click the link below to accept "
        f"and you'll get scoped access to this campaign only "
        f"(expires in {expires_in_days} days):\n"
        f"{accept_url}\n\n"
        f"If you didn't expect this, you can safely ignore this email.\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">You've been invited to collaborate</h2>
  <p><strong>{invited_by_name}</strong> ({org_name}) invited you to collaborate on the campaign <strong>{campaign_name}</strong> on Hakuna.</p>
  <p style="font-size:13px;color:#71717a">
    You don't need a Hakuna account. Accepting this invite gives you scoped
    access to this campaign only — its findings, workflows, and integrations.
  </p>
  <p style="margin:24px 0">
    <a href="{accept_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Accept Invitation
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This link expires in {expires_in_days} days. If you didn't expect this, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{accept_url}" style="color:#590202">{accept_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_domain_join_request_to_admin(
    to: str,
    admin_display_name: str,
    org_name: str,
    requester_email: str,
    requester_display_name: str,
) -> None:
    """Notify an org admin that someone with their corporate email domain has
    requested to join. Admin must approve in the app."""
    review_url = f"{APP_URL}/settings?tab=domain-join"
    subject = f"New join request for {org_name}"

    body_text = (
        f"Hello {admin_display_name},\n\n"
        f"{requester_display_name} ({requester_email}) has requested to join "
        f"{org_name} on Hakuna.\n\n"
        f"Review and approve or deny the request here:\n"
        f"{review_url}\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">New join request for {org_name}</h2>
  <p>Hello <strong>{admin_display_name}</strong>,</p>
  <p><strong>{requester_display_name}</strong> ({requester_email}) has requested to join your Hakuna organization.</p>
  <p style="margin:24px 0">
    <a href="{review_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Review Request
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    They'll receive an email once you approve or deny their request.
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_domain_join_approved(to: str, display_name: str, org_name: str) -> None:
    """Tell the requester their join request was approved and they can now log in."""
    login_url = f"{APP_URL}/login"
    subject = f"You're in — welcome to {org_name}"

    body_text = (
        f"Hello {display_name},\n\n"
        f"Your request to join {org_name} on Hakuna has been approved.\n\n"
        f"Sign in with the email and password you used to sign up:\n"
        f"{login_url}\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">Welcome to {org_name}</h2>
  <p>Hello <strong>{display_name}</strong>,</p>
  <p>Your request to join <strong>{org_name}</strong> on Hakuna has been approved.</p>
  <p style="margin:24px 0">
    <a href="{login_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Sign In
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    Use the email and password you provided when you signed up.
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_domain_join_denied(to: str, display_name: str, org_name: str, reason: str = None) -> None:
    """Tell the requester their join request was denied."""
    subject = f"Your request to join {org_name} was not approved"
    reason_line = f"\n\nReason: {reason}\n" if reason else ""
    reason_html = (
        f'<p style="font-size:13px;color:#71717a"><strong>Reason:</strong> {reason}</p>'
        if reason else ""
    )

    body_text = (
        f"Hello {display_name},\n\n"
        f"Your request to join {org_name} on Hakuna was not approved.{reason_line}\n"
        f"If you believe this was a mistake, please contact your organization's administrator.\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">Request not approved</h2>
  <p>Hello <strong>{display_name}</strong>,</p>
  <p>Your request to join <strong>{org_name}</strong> on Hakuna was not approved.</p>
  {reason_html}
  <p style="font-size:13px;color:#71717a">
    If you believe this was a mistake, please contact your organization's administrator.
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)


def send_client_invite(to: str, mssp_org_name: str, invite_url: str, client_org_name: str = None) -> None:
    """Send an MSSP client onboarding invite email."""
    subject = f"You've been invited to join {mssp_org_name} on Hakuna"
    org_hint = f" for {client_org_name}" if client_org_name else ""

    body_text = (
        f"Hello,\n\n"
        f"You've been invited by {mssp_org_name} to create your organization{org_hint} on Hakuna.\n\n"
        f"Click the link below to set up your account (expires in 7 days):\n"
        f"{invite_url}\n\n"
        f"— The Hakuna Team"
    )

    body_html = f"""<html>
<body style="font-family:sans-serif;color:#1a1a1a;max-width:480px;margin:auto;padding:32px">
  <h2 style="margin-bottom:8px">You've been invited to Hakuna</h2>
  <p><strong>{mssp_org_name}</strong> has invited you to create your organization{org_hint} on Hakuna's vulnerability management platform.</p>
  <p style="margin:24px 0">
    <a href="{invite_url}"
       style="background:#590202;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">
      Accept Invitation
    </a>
  </p>
  <p style="font-size:13px;color:#71717a">
    This invite expires in 7 days. If you didn't expect this, you can safely ignore this email.
  </p>
  <p style="font-size:13px;color:#71717a">
    Or copy and paste this URL into your browser:<br/>
    <a href="{invite_url}" style="color:#590202">{invite_url}</a>
  </p>
  <hr style="border:none;border-top:1px solid #e4e4e7;margin:24px 0"/>
  <p style="font-size:12px;color:#a1a1aa">The Hakuna Team</p>
</body>
</html>"""

    send_email(to, subject, body_text, body_html)

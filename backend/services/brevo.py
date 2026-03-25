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

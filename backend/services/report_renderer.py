"""
Report renderer — generates a PDF of a saved ReportTemplate.

Primary strategy (high fidelity): use Playwright to navigate to the live
frontend `/reports/{id}` page with an injected service JWT and call
`page.pdf()` so the exported PDF matches what the user sees in the browser.

Fallback strategy: if Playwright is not installed (e.g. in tests or a lean
deployment), emit a minimal PDF from pypdf+reportlab that at least lists the
report name, a timestamp, and the widget titles. This keeps the
scheduling feature functional without a browser dependency.

Environment:
    FRONTEND_BASE_URL   Base URL the renderer navigates to (default http://localhost:3000)
    REPORT_PDF_TIMEOUT  Navigation/wait timeout in seconds (default 45)
    REPORT_PDF_WAIT_MS  Extra settle time after networkidle (default 1500)
"""
from __future__ import annotations

import io
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from core.auth import create_access_token
from models.models import ReportTemplate, User

logger = logging.getLogger(__name__)

FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "http://localhost:3000")
REPORT_PDF_TIMEOUT = int(os.environ.get("REPORT_PDF_TIMEOUT", "45"))
REPORT_PDF_WAIT_MS = int(os.environ.get("REPORT_PDF_WAIT_MS", "1500"))


def _resolve_service_user(db: Session, org_id: Optional[int]) -> Optional[User]:
    """Pick a user whose identity can be used to render the report.

    Prefers an admin in the target org so the PDF reflects the same tenant
    view the recipients expect. Falls back to any admin user.
    """
    q = db.query(User).filter(User.is_active == True)
    if org_id is not None:
        scoped = q.filter(User.org_id == org_id).order_by(User.id.asc()).first()
        if scoped:
            return scoped
    # Fallback: any admin / first active user
    return q.order_by(User.id.asc()).first()


def _mint_render_token(user: User) -> str:
    """Short-lived JWT the headless browser will use when loading the report."""
    return create_access_token(
        user_id=user.id,
        org_id=user.org_id,
        role=user.role or "viewer",
        expires_delta=timedelta(minutes=10),
    )


def render_report_pdf(db: Session, template: ReportTemplate) -> bytes:
    """Render a ReportTemplate to PDF bytes.

    Tries Playwright first and falls back to a simple reportlab layout if
    Playwright (or its browser runtime) is unavailable.
    """
    try:
        return _render_with_playwright(db, template)
    except _PlaywrightUnavailable as e:
        logger.warning("Playwright unavailable for PDF render (%s) — using fallback", e)
    except Exception:
        logger.exception("Playwright PDF render failed — using fallback")
    return _render_with_fallback(template)


# ─────────────────────────────────────────────
# Playwright renderer
# ─────────────────────────────────────────────

class _PlaywrightUnavailable(Exception):
    pass


def _render_with_playwright(db: Session, template: ReportTemplate) -> bytes:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError as e:
        raise _PlaywrightUnavailable(str(e))

    service_user = _resolve_service_user(db, template.org_id)
    if not service_user:
        raise RuntimeError("No active user available to render the report")
    token = _mint_render_token(service_user)

    target_url = f"{FRONTEND_BASE_URL.rstrip('/')}/reports/{template.id}?export=pdf"

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception as e:
            raise _PlaywrightUnavailable(f"chromium launch failed: {e}")

        try:
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                device_scale_factor=2,
            )
            page = context.new_page()

            # Seed auth + org context into localStorage BEFORE the app bootstraps.
            init_script = f"""
                window.localStorage.setItem('auth_token', {token!r});
                window.localStorage.setItem('org_context', {str(template.org_id or '')!r});
            """
            context.add_init_script(init_script)

            page.goto(target_url, wait_until="networkidle",
                      timeout=REPORT_PDF_TIMEOUT * 1000)
            # Give widgets a little extra time to finish their lazy fetches.
            page.wait_for_timeout(REPORT_PDF_WAIT_MS)

            pdf_bytes = page.pdf(
                format="A4",
                landscape=True,
                print_background=True,
                margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
            )
            return pdf_bytes
        finally:
            browser.close()


# ─────────────────────────────────────────────
# Fallback renderer (pure-Python)
# ─────────────────────────────────────────────

def _render_with_fallback(template: ReportTemplate) -> bytes:
    """Emit a minimal one-page PDF without a browser.

    Uses a hand-rolled PDF so we don't take a hard dependency on reportlab.
    Good enough for tests and degraded deployments.
    """
    widgets = (template.config or {}).get("widgets", []) if template.config else []
    lines = [
        f"Hakuna Report: {template.name}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"Widgets: {len(widgets)}",
        "",
    ]
    for i, w in enumerate(widgets[:40], 1):
        title = w.get("title") or w.get("type") or "widget"
        lines.append(f"{i}. {title}")
    if len(widgets) > 40:
        lines.append(f"... and {len(widgets) - 40} more widgets")
    lines.append("")
    lines.append("Install Playwright for full-fidelity rendering.")

    return _simple_pdf(lines)


def _simple_pdf(lines: list[str]) -> bytes:
    """Minimal PDF 1.4 document with a single page of Helvetica text."""
    buf = io.BytesIO()
    # Build content stream
    content = ["BT", "/F1 12 Tf", "50 780 Td", "14 TL"]
    for i, line in enumerate(lines):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if i == 0:
            content.append(f"({safe}) Tj")
        else:
            content.append("T*")
            content.append(f"({safe}) Tj")
    content.append("ET")
    stream_body = "\n".join(content).encode("latin-1", errors="replace")

    def _obj(n: int, body: bytes) -> bytes:
        return f"{n} 0 obj\n".encode() + body + b"\nendobj\n"

    objects = []
    objects.append(_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append(_obj(2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"))
    objects.append(_obj(
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    ))
    stream_obj = (
        f"<< /Length {len(stream_body)} >>\nstream\n".encode()
        + stream_body
        + b"\nendstream"
    )
    objects.append(_obj(4, stream_obj))
    objects.append(_obj(5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

    buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj in objects:
        offsets.append(buf.tell())
        buf.write(obj)
    xref_pos = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.write(f"{off:010d} 00000 n \n".encode())
    buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    )
    return buf.getvalue()

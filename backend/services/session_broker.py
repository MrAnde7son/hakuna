"""Playwright-driven session broker for authenticated VM scans.

Drives a login flow defined on an AuthProfile, captures the resulting
cookies and scraped response headers, and hands them to the VM scanner
dispatch path as a merged ScanCredentials payload.

Caching is inline on the auth_profiles row (encrypted blob + expires_at +
credential hash). Rotating the underlying IntegrationCredential changes
the hash and invalidates the cached session on next read — no explicit
invalidation needed.

Scope (MVP, see plan): form-login only. Steps are {goto, fill, click,
wait_for_url}. Success conditions are {url_matches, cookie_present,
element_visible}. No TOTP, no OAuth redirect capture, no SSO.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from services import credential_manager, credential_vault


logger = logging.getLogger(__name__)

_MAX_TTL_SECONDS = 3600          # hard cap regardless of profile setting
_DEFAULT_STEP_TIMEOUT_MS = 30000  # per-step timeout fallback — heavy SPAs
                                  # (Tenable, Okta) need 10–20s for React to
                                  # hydrate before the first input selector
                                  # resolves. Playwright auto-waits inside
                                  # fill/click, so this is the effective
                                  # budget for "form is ready to interact".


class SessionBrokerError(Exception):
    """Raised when a login flow cannot produce a valid session."""


@dataclass
class SessionBundle:
    """Headers-only projection of a logged-in Playwright context."""
    cookie_header: str           # serialized as "name=value; name2=value2"
    headers: dict[str, str]      # scraped response headers (CSRF tokens, etc.)
    expires_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "cookie_header": self.cookie_header,
            "headers": dict(self.headers or {}),
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SessionBundle":
        return cls(
            cookie_header=d.get("cookie_header") or "",
            headers=dict(d.get("headers") or {}),
            expires_at=datetime.fromisoformat(d["expires_at"]),
        )


def _hash_credential(values: dict) -> str:
    """Stable fingerprint of the decrypted credential values for cache keying.

    Only the keys the login flow can reference (username/password/token/etc.)
    contribute — internal metadata like `_auth_type` is excluded so that
    re-decorating the dict doesn't falsely invalidate the cache.
    """
    payload = {k: v for k, v in values.items() if not k.startswith("_") and k != "instance_url"}
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_flow_value(step: dict, creds: dict) -> str:
    """Resolve `value` or `value_from` on a step against the credential dict."""
    if "value" in step:
        return str(step.get("value") or "")
    src = step.get("value_from")
    if not src:
        return ""
    return str(creds.get(src) or "")


async def get_or_create_session(
    db: Session, org_id: int, auth_profile_id: str,
) -> SessionBundle:
    """Return a valid session for the profile, driving Playwright if needed.

    Cache hit: decrypts cached_session_blob and returns it. Cache miss or
    expired / credential rotated: runs the login flow, persists the new
    blob, and returns it. Raises SessionBrokerError on login failure.
    """
    from models.models import AuthProfile  # local to avoid import cycles

    profile = db.query(AuthProfile).filter(
        AuthProfile.id == auth_profile_id,
        AuthProfile.org_id == org_id,
    ).first()
    if not profile:
        raise SessionBrokerError(f"AuthProfile {auth_profile_id} not found for org {org_id}")

    creds = await credential_manager.load_credentials(db, profile.credential_id, org_id)
    if not creds:
        raise SessionBrokerError(f"Credential {profile.credential_id} not found or empty")

    cred_hash = _hash_credential(creds)
    now = datetime.utcnow()

    if (
        profile.cached_session_blob
        and profile.session_expires_at
        and profile.session_expires_at > now
        and profile.session_credential_hash == cred_hash
    ):
        try:
            bundle = SessionBundle.from_dict(
                credential_vault.decrypt(profile.cached_session_blob)
            )
            logger.info(
                "session_broker cache hit profile=%s org=%s expires=%s",
                auth_profile_id, org_id, bundle.expires_at.isoformat(),
            )
            return bundle
        except Exception:
            logger.exception(
                "session_broker: failed to decrypt cached session — rebuilding"
            )

    bundle = await _run_login_flow(
        login_url=profile.login_url,
        login_flow=profile.login_flow or [],
        success_condition=profile.success_condition or {},
        creds=creds,
        ttl_seconds=min(profile.session_ttl_seconds or 900, _MAX_TTL_SECONDS),
    )

    profile.cached_session_blob = credential_vault.encrypt(bundle.to_dict())
    profile.session_expires_at = bundle.expires_at
    profile.session_credential_hash = cred_hash
    profile.updated_at = datetime.utcnow()
    db.add(profile)
    db.commit()

    logger.info(
        "session_broker cache miss profile=%s org=%s expires=%s cookies=%d headers=%d",
        auth_profile_id, org_id, bundle.expires_at.isoformat(),
        len(bundle.cookie_header.split("; ")) if bundle.cookie_header else 0,
        len(bundle.headers or {}),
    )
    return bundle


async def test_login(db: Session, org_id: int, auth_profile_id: str) -> dict:
    """Run the login flow and report captured session metadata (redacted).

    Never returns the actual cookie or header values — only names — so a UI
    can render a green "login succeeded" affordance without exposing secrets.
    """
    try:
        bundle = await get_or_create_session(db, org_id, auth_profile_id)
    except SessionBrokerError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.exception("test_login failed")
        return {"success": False, "error": f"unexpected: {type(e).__name__}"}

    cookie_names = [
        part.split("=", 1)[0].strip()
        for part in bundle.cookie_header.split("; ")
        if part and "=" in part
    ]
    return {
        "success": True,
        "captured_cookies": cookie_names,
        "captured_headers": list((bundle.headers or {}).keys()),
        "expires_at": bundle.expires_at.isoformat(),
    }


def invalidate(db: Session, auth_profile_id: str) -> None:
    """Clear the cached session blob — called when a profile is edited."""
    from models.models import AuthProfile

    profile = db.query(AuthProfile).filter(AuthProfile.id == auth_profile_id).first()
    if not profile:
        return
    profile.cached_session_blob = None
    profile.session_expires_at = None
    profile.session_credential_hash = None
    profile.updated_at = datetime.utcnow()
    db.add(profile)
    db.commit()


# ─────────────────────────────────────────────
# Playwright driver
# ─────────────────────────────────────────────

class _PlaywrightUnavailable(Exception):
    pass


async def _run_login_flow(
    login_url: str,
    login_flow: list[dict],
    success_condition: dict,
    creds: dict,
    ttl_seconds: int,
) -> SessionBundle:
    """Drive Playwright through the flow and return a SessionBundle."""
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError as e:
        raise SessionBrokerError(f"Playwright not installed: {e}")

    scraped_headers: dict[str, str] = {}

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        except Exception as e:
            raise SessionBrokerError(f"chromium launch failed: {e}")

        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,
            )
            page = await context.new_page()

            # Capture a narrow set of response headers from the login origin —
            # CSRF tokens, anti-forgery headers, etc. — that the scanner may
            # need to replay alongside the cookie jar.
            def _on_response(response):
                try:
                    for name, value in (response.headers or {}).items():
                        lname = name.lower()
                        if lname in ("x-csrf-token", "x-xsrf-token", "csrf-token", "x-requested-with"):
                            scraped_headers[name] = value
                except Exception:
                    pass

            page.on("response", _on_response)

            # Steps default to starting at login_url; if the first step is
            # an explicit `goto`, use it; otherwise prepend one.
            steps = list(login_flow or [])
            if not steps or steps[0].get("action") != "goto":
                steps = [{"action": "goto", "url": login_url}] + steps

            for step in steps:
                await _execute_step(page, step, creds)

            await _assert_success(page, success_condition)

            cookies = await context.cookies()
            cookie_header = "; ".join(
                f"{c['name']}={c['value']}" for c in cookies if c.get("name")
            )

            return SessionBundle(
                cookie_header=cookie_header,
                headers=scraped_headers,
                expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
            )
        finally:
            try:
                await browser.close()
            except Exception:
                pass


async def _execute_step(page, step: dict, creds: dict) -> None:
    action = (step.get("action") or "").lower()
    timeout = int(step.get("timeout_ms") or _DEFAULT_STEP_TIMEOUT_MS)

    if action == "goto":
        url = step.get("url") or ""
        if not url:
            raise SessionBrokerError("goto step missing url")
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        # SPA hydration pass: give React/Vue/etc. a moment to render the form
        # before the next step tries to interact with it. networkidle can
        # hang forever on long-polling apps, so cap it and swallow timeouts —
        # Playwright's per-action auto-wait still covers the selector itself.
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass
    elif action == "fill":
        selector = step.get("selector") or ""
        value = _resolve_flow_value(step, creds)
        if not selector:
            raise SessionBrokerError("fill step missing selector")
        await page.fill(selector, value, timeout=timeout)
    elif action == "click":
        selector = step.get("selector") or ""
        if not selector:
            raise SessionBrokerError("click step missing selector")
        await page.click(selector, timeout=timeout)
    elif action == "wait_for_url":
        pattern = step.get("pattern") or ""
        if not pattern:
            raise SessionBrokerError("wait_for_url step missing pattern")
        await page.wait_for_url(re.compile(pattern), timeout=timeout)
    elif action == "wait_for_selector":
        selector = step.get("selector") or ""
        if not selector:
            raise SessionBrokerError("wait_for_selector step missing selector")
        await page.wait_for_selector(selector, timeout=timeout)
    else:
        raise SessionBrokerError(f"unknown step action: {action!r}")


async def _assert_success(page, condition: dict) -> None:
    ctype = (condition.get("type") or "").lower()
    timeout = int(condition.get("timeout_ms") or _DEFAULT_STEP_TIMEOUT_MS)

    if not ctype:
        # No explicit success condition — assume whatever the last step did is
        # sufficient. This is lax by design; the UI warns users to set one.
        return

    if ctype == "url_matches":
        pattern = condition.get("pattern") or ""
        if not pattern:
            raise SessionBrokerError("url_matches condition missing pattern")
        # page may already be at the target URL after the last step
        if not re.search(pattern, page.url or ""):
            try:
                await page.wait_for_url(re.compile(pattern), timeout=timeout)
            except Exception as e:
                raise SessionBrokerError(
                    f"login did not reach url matching {pattern!r}: {e}"
                )
    elif ctype == "cookie_present":
        name = condition.get("name") or ""
        if not name:
            raise SessionBrokerError("cookie_present condition missing name")
        cookies = await page.context.cookies()
        if not any(c.get("name") == name for c in cookies):
            raise SessionBrokerError(f"expected cookie {name!r} not present after login")
    elif ctype == "element_visible":
        selector = condition.get("selector") or ""
        if not selector:
            raise SessionBrokerError("element_visible condition missing selector")
        try:
            await page.wait_for_selector(selector, state="visible", timeout=timeout)
        except Exception as e:
            raise SessionBrokerError(
                f"expected element {selector!r} not visible after login: {e}"
            )
    else:
        raise SessionBrokerError(f"unknown success condition type: {ctype!r}")

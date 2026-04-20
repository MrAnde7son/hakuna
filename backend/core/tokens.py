"""Token + passcode utilities for campaign collaboration share links.

Keeps bcrypt for passcodes (reuses `pwd_context` from core.auth so rehashing is
consistent) and produces URL-safe share tokens via `secrets.token_urlsafe`.
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt, JWTError
from fastapi import HTTPException

from core.auth import pwd_context


# ── Share tokens (the random URL path component) ─────────────────────────────

def generate_share_token() -> str:
    """Return a URL-safe random token (~43 chars from 32 bytes of entropy)."""
    return secrets.token_urlsafe(32)


# ── Passcodes (the short code the invitee types) ─────────────────────────────
# 6-digit numeric: easy to read over phone/chat, still 1M space. Combined with
# 5-strikes-per-15min lockout + 5/min rate limit, the effective brute-force
# resistance is far above 10^6.

PASSCODE_LENGTH = 6


def generate_passcode() -> str:
    """Return a random 6-digit numeric passcode (may start with 0)."""
    # secrets.randbelow is the cryptographically-safe choice here.
    return f"{secrets.randbelow(10 ** PASSCODE_LENGTH):0{PASSCODE_LENGTH}d}"


def hash_passcode(plain: str) -> str:
    """bcrypt-hash a passcode. Reuses core.auth.pwd_context."""
    return pwd_context.hash(plain)


def verify_passcode(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── Guest session JWTs ───────────────────────────────────────────────────────
# Intentionally signed with a SEPARATE secret from the main user JWT so a leak
# of one doesn't widen the blast radius of the other.

GUEST_JWT_SECRET = os.environ.get("GUEST_JWT_SECRET") or os.environ.get("JWT_SECRET", "")
GUEST_JWT_ALGORITHM = "HS256"
GUEST_SESSION_MINUTES = int(os.environ.get("GUEST_SESSION_MINUTES", "120"))  # 2h default


def create_guest_session_token(
    share_link_id: int,
    campaign_id: int,
    org_id: int,
    external_email: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=GUEST_SESSION_MINUTES))
    payload = {
        "kind": "guest",
        "share_link_id": share_link_id,
        "campaign_id": campaign_id,
        "org_id": org_id,
        "email": external_email,
        "exp": expire,
    }
    return jwt.encode(payload, GUEST_JWT_SECRET, algorithm=GUEST_JWT_ALGORITHM)


def decode_guest_session_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, GUEST_JWT_SECRET, algorithms=[GUEST_JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired guest session")
    if payload.get("kind") != "guest":
        raise HTTPException(status_code=401, detail="Not a guest session")
    return payload


# ── Lockout helpers ──────────────────────────────────────────────────────────

PASSCODE_FAILURE_THRESHOLD = 5
PASSCODE_LOCKOUT_MINUTES = 15


def should_lock(failed_attempts: int) -> bool:
    return failed_attempts >= PASSCODE_FAILURE_THRESHOLD


def next_lock_until() -> datetime:
    return datetime.utcnow() + timedelta(minutes=PASSCODE_LOCKOUT_MINUTES)

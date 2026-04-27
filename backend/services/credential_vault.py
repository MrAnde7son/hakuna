"""AES-256-GCM encryption for integration credentials."""

import json
import os
import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


import logging as _logging
_logger = _logging.getLogger(__name__)
_dev_key = None

_DEV_KEY_PATH = Path(
    os.environ.get("HAKUNA_DEV_KEY_FILE")
    or Path(__file__).resolve().parents[2] / ".dev_secret_key"
)


class CredentialDecryptError(RuntimeError):
    """Decryption failed — most likely INTEGRATION_SECRET_KEY differs from the
    key used at encrypt time. Callers can catch this specifically to prompt
    the user to re-enter the credential rather than report a generic crash."""


def _is_production() -> bool:
    """True unless ENVIRONMENT is explicitly set to a non-prod value."""
    env = os.environ.get("ENVIRONMENT", "production").lower()
    return env not in ("development", "dev", "test", "testing", "local")


def _load_or_create_dev_key() -> str:
    """Persist the auto-generated dev key on disk so it survives restarts.

    Without this, every backend restart with INTEGRATION_SECRET_KEY unset
    mints a fresh key, silently rendering every previously-stored credential
    un-decryptable. Caller already enforced we're in non-prod.
    """
    try:
        if _DEV_KEY_PATH.exists():
            existing = _DEV_KEY_PATH.read_text().strip()
            if len(existing) == 64 and all(c in "0123456789abcdefABCDEF" for c in existing):
                return existing
    except OSError:
        pass

    import secrets
    key = secrets.token_hex(32)
    try:
        _DEV_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DEV_KEY_PATH.write_text(key)
        os.chmod(_DEV_KEY_PATH, 0o600)
        _logger.warning(
            "INTEGRATION_SECRET_KEY not set — generated and persisted a dev key at %s. "
            "Set ENVIRONMENT=production (and INTEGRATION_SECRET_KEY) for real deployments.",
            _DEV_KEY_PATH,
        )
    except OSError as e:
        _logger.warning(
            "INTEGRATION_SECRET_KEY not set and could not persist dev key to %s (%s) — "
            "falling back to in-memory key. Credentials will not survive restart.",
            _DEV_KEY_PATH, e,
        )
    return key


def _get_key() -> bytes:
    """Load 32-byte encryption key from environment.

    In production, fails fast if not set — a rotating key would break
    decryption of all previously-stored credentials on every restart.
    In development, auto-generates a key and persists it to disk so it
    survives across restarts.
    """
    global _dev_key
    raw = os.environ.get("INTEGRATION_SECRET_KEY")
    if not raw:
        if _is_production():
            raise RuntimeError(
                "INTEGRATION_SECRET_KEY is required in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\" "
                "and store it in Secret Manager. A rotating key would render all stored "
                "integration credentials un-decryptable."
            )
        if _dev_key is None:
            _dev_key = _load_or_create_dev_key()
        raw = _dev_key
    key = bytes.fromhex(raw)
    if len(key) != 32:
        raise RuntimeError("INTEGRATION_SECRET_KEY must be exactly 64 hex characters (32 bytes).")
    return key


def encrypt(values: dict) -> str:
    """Encrypt a dict to a base64-encoded string (nonce + ciphertext)."""
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    plaintext = json.dumps(values).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Store as base64(nonce + ciphertext)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt(encrypted: str) -> dict:
    """Decrypt a base64-encoded string back to a dict."""
    key = _get_key()
    aesgcm = AESGCM(key)
    raw = base64.b64decode(encrypted)
    nonce = raw[:12]
    ciphertext = raw[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise CredentialDecryptError(
            "Failed to decrypt credentials — the encryption key has changed. "
            "Set a stable INTEGRATION_SECRET_KEY env var and re-enter your credentials."
        )
    return json.loads(plaintext.decode("utf-8"))


def encrypt_string(value: str) -> str:
    """Encrypt a single string value."""
    return encrypt({"_v": value})


def decrypt_string(encrypted: str) -> str:
    """Decrypt a single string value."""
    return decrypt(encrypted)["_v"]

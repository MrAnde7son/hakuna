"""AES-256-GCM encryption for integration credentials."""

import json
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


import logging as _logging
_logger = _logging.getLogger(__name__)
_dev_key = None


def _get_key() -> bytes:
    """Load 32-byte encryption key from environment.
    In development, auto-generates and persists a key if not set."""
    global _dev_key
    raw = os.environ.get("INTEGRATION_SECRET_KEY")
    if not raw:
        # Auto-generate for development — log a warning
        if _dev_key is None:
            import secrets
            _dev_key = secrets.token_hex(32)
            _logger.warning(
                "INTEGRATION_SECRET_KEY not set — auto-generated a dev key. "
                "Set this env var in production: %s", _dev_key
            )
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
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def encrypt_string(value: str) -> str:
    """Encrypt a single string value."""
    return encrypt({"_v": value})


def decrypt_string(encrypted: str) -> str:
    """Decrypt a single string value."""
    return decrypt(encrypted)["_v"]

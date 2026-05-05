"""Tests for CredentialVault encrypt/decrypt."""

import os
import secrets
import pytest


@pytest.fixture(autouse=True)
def set_secret_key(monkeypatch):
    """Set a test encryption key for all tests."""
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


def test_round_trip():
    from services.credential_vault import encrypt, decrypt
    values = {"api_key": "sk-abc123", "secret": "top-secret"}
    encrypted = encrypt(values)
    assert isinstance(encrypted, str)
    assert "sk-abc123" not in encrypted  # not plaintext
    decrypted = decrypt(encrypted)
    assert decrypted == values


def test_round_trip_string():
    from services.credential_vault import encrypt_string, decrypt_string
    original = "my-refresh-token-xyz"
    encrypted = encrypt_string(original)
    assert original not in encrypted
    assert decrypt_string(encrypted) == original


def test_different_nonces_produce_different_ciphertext():
    from services.credential_vault import encrypt
    values = {"key": "value"}
    e1 = encrypt(values)
    e2 = encrypt(values)
    assert e1 != e2  # different nonces


def test_empty_dict():
    from services.credential_vault import encrypt, decrypt
    assert decrypt(encrypt({})) == {}


def test_nested_values():
    from services.credential_vault import encrypt, decrypt
    values = {"oauth": {"access_token": "at", "refresh_token": "rt"}, "scopes": ["read", "write"]}
    assert decrypt(encrypt(values)) == values


def test_missing_key_auto_generates(monkeypatch, tmp_path):
    monkeypatch.delenv("INTEGRATION_SECRET_KEY")
    monkeypatch.setenv("HAKUNA_DEV_KEY_FILE", str(tmp_path / "dev_key"))
    import services.credential_vault as vault
    vault._dev_key = None  # reset cached dev key
    monkeypatch.setattr(vault, "_DEV_KEY_PATH", tmp_path / "dev_key")
    from services.credential_vault import encrypt, decrypt
    # Should auto-generate a key and work (dev mode)
    encrypted = encrypt({"key": "val"})
    assert decrypt(encrypted) == {"key": "val"}


def test_dev_key_persists_across_resets(monkeypatch, tmp_path):
    """Dev key must survive process restarts so previously-encrypted
    credentials remain decryptable when INTEGRATION_SECRET_KEY is unset."""
    monkeypatch.delenv("INTEGRATION_SECRET_KEY")
    import services.credential_vault as vault
    monkeypatch.setattr(vault, "_DEV_KEY_PATH", tmp_path / "dev_key")
    vault._dev_key = None
    encrypted = vault.encrypt({"key": "val"})
    # Simulate a restart — clear in-memory key, re-read from disk.
    vault._dev_key = None
    assert vault.decrypt(encrypted) == {"key": "val"}


def test_wrong_key_raises_credential_decrypt_error(monkeypatch):
    from services.credential_vault import encrypt, decrypt, CredentialDecryptError
    encrypted = encrypt({"key": "val"})
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))
    with pytest.raises(CredentialDecryptError):
        decrypt(encrypted)


def test_bad_key_length_raises(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", "abcd")  # too short
    from services.credential_vault import encrypt
    with pytest.raises(RuntimeError, match="64 hex characters"):
        encrypt({"key": "val"})


def test_tampered_ciphertext_raises():
    from services.credential_vault import encrypt, decrypt
    encrypted = encrypt({"key": "val"})
    # Flip a character in the middle
    chars = list(encrypted)
    mid = len(chars) // 2
    chars[mid] = "A" if chars[mid] != "A" else "B"
    tampered = "".join(chars)
    with pytest.raises(Exception):  # InvalidTag from cryptography
        decrypt(tampered)


def test_wrong_key_raises(monkeypatch):
    from services.credential_vault import encrypt, decrypt
    encrypted = encrypt({"key": "val"})
    # Change the key
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))
    with pytest.raises(Exception):
        decrypt(encrypted)

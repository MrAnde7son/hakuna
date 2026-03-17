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


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("INTEGRATION_SECRET_KEY")
    from services.credential_vault import encrypt
    with pytest.raises(RuntimeError, match="INTEGRATION_SECRET_KEY"):
        encrypt({"key": "val"})


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

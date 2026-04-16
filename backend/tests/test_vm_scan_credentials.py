"""Tests for VM scan credential resolution.

Covers the happy path where a basic-auth credential stored in the vault is
decrypted, shaped into the scanner's ScanCredentials payload, and forwarded
to the scanner via the _vm_request HTTP call. Decrypted values are verified
to travel in the POST body only (never in the Scan record's metadata).
"""

import asyncio
import secrets
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = "sqlite:///:memory:"


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("INTEGRATION_SECRET_KEY", secrets.token_hex(32))


@pytest.fixture
def db_session():
    from core.database import Base
    from models.models import Organization

    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = Organization(name="Test Org", slug="test-org")
    session.add(org)
    session.flush()

    yield session, org
    session.close()


class TestStartVmScanWithCredentials:
    """Exercises services.vm_scanner.start_vm_scan(credential_id=…)."""

    def test_basic_credential_resolved_and_shaped(self, db_session):
        """A basic-auth credential is decrypted, mapped to type=basic, and
        forwarded to the scanner. The scan record stores only the id."""
        session, org = db_session

        from models.models import IntegrationCredential
        from services import credential_vault

        cred = IntegrationCredential(
            org_id=org.id,
            name="test-basic",
            connector_id="generic-http",
            auth_type="basic",
            encrypted_values=credential_vault.encrypt({
                "username": "scan-user",
                "password": "super-secret-password",
            }),
        )
        session.add(cred)
        session.flush()

        with patch("services.vm_scanner._vm_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {
                "job_ids": ["job-1"],
                "assets_queued": 0,
                "targets_queued": 1,
            }

            from services.vm_scanner import start_vm_scan
            result = _run(start_vm_scan(
                session, org,
                targets=["https://example.com"],
                credential_id=cred.id,
            ))

        assert result is not None
        assert result["job_ids"] == ["job-1"]

        # Exactly one POST to /vm/scans/ with the shaped credentials block.
        assert mock_req.call_count == 1
        args, kwargs = mock_req.call_args
        assert args[0] == "POST"
        assert args[1] == "/vm/scans/"

        body = kwargs["json"]
        assert body["targets"] == ["https://example.com"]
        assert body["credentials"] == {
            "type": "basic",
            "username": "scan-user",
            "password": "super-secret-password",
        }

        # Scan record persists only a credential id reference — never the
        # decrypted values. This is load-bearing; do not relax this check.
        from models.models import Scan
        scan = session.query(Scan).filter(Scan.id == result["scan_id"]).first()
        assert scan is not None
        meta = scan.raw_metadata or {}
        assert meta.get("credential_id") == cred.id
        serialized = repr(meta)
        assert "super-secret-password" not in serialized
        assert "scan-user" not in serialized

    def test_missing_credential_raises_404(self, db_session):
        """A credential_id that doesn't exist (or belongs to another org)
        causes start_vm_scan to raise HTTPException(404) before any HTTP
        call goes out to the scanner."""
        session, org = db_session

        from fastapi import HTTPException

        with patch("services.vm_scanner._vm_request", new_callable=AsyncMock) as mock_req:
            from services.vm_scanner import start_vm_scan
            with pytest.raises(HTTPException) as exc_info:
                _run(start_vm_scan(
                    session, org,
                    targets=["https://example.com"],
                    credential_id="00000000-0000-0000-0000-000000000000",
                ))
            assert exc_info.value.status_code == 404
            mock_req.assert_not_called()

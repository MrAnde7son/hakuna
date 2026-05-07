"""Credential loading with OAuth2 auto-refresh."""

import re
import os
import logging
from datetime import datetime, timedelta

import httpx

from services import credential_vault

logger = logging.getLogger(__name__)


async def load_credentials(db, credentials_id: str, org_scope) -> dict:
    """Decrypt credentials, auto-refreshing OAuth2 tokens if expired or near expiry.

    `org_scope` accepts either a single org_id (legacy callers) or a list of
    accessible org IDs (preferred — narrows by `org_id IN (...)`). Pass `None`
    only for trusted internal callers (e.g. background workers) that have
    already validated tenancy themselves.

    Handles two refresh strategies:
      - refresh_token grant (standard OAuth2)
      - client_credentials re-issue (machine-to-machine, e.g. CrowdStrike)
    """
    from models.models import IntegrationCredential

    q = db.query(IntegrationCredential).filter(IntegrationCredential.id == credentials_id)
    if isinstance(org_scope, (list, tuple, set)):
        q = q.filter(IntegrationCredential.org_id.in_(list(org_scope)))
    elif org_scope is not None:
        q = q.filter(IntegrationCredential.org_id == org_scope)
    cred = q.first()
    if not cred:
        return {}

    # Auto-refresh if OAuth2 token is expired or within 60s of expiry
    if (
        cred.auth_type == "oauth2"
        and cred.expires_at
        and cred.expires_at <= datetime.utcnow() + timedelta(seconds=60)
    ):
        try:
            current_values = credential_vault.decrypt(cred.encrypted_values)

            if cred.encrypted_refresh_token:
                await _refresh_with_token(db, cred, current_values)
            elif current_values.get("_client_id") and current_values.get("_client_secret"):
                await _refresh_client_credentials(db, cred, current_values)

        except Exception as e:
            logger.warning("Auto-refresh failed for credential %s: %s", credentials_id, e)

    credentials = credential_vault.decrypt(cred.encrypted_values)
    credentials["_auth_type"] = cred.auth_type
    credentials["instance_url"] = cred.instance_url or ""
    return credentials


async def _refresh_with_token(db, cred, current_values: dict):
    """Refresh using a stored refresh_token."""
    from integrations.connector_loader import get_connector

    refresh_token_val = credential_vault.decrypt_string(cred.encrypted_refresh_token)

    connector = get_connector(cred.connector_id)
    acq = (connector.get("credential_acquisition", {}) if connector else {})
    token_url = acq.get("token_url") or current_values.get("_token_url", "")
    client_id = acq.get("client_id") or current_values.get("_client_id", "")
    client_id = re.sub(r'\{\{env\.(\w+)\}\}', lambda m: os.environ.get(m.group(1), ""), client_id)

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(token_url, data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_val,
            "client_id": client_id,
        })

    if resp.status_code >= 400:
        logger.warning("Token refresh HTTP %s: %s", resp.status_code, resp.text[:200])
        return

    tokens = resp.json()
    new_access = tokens.get("access_token", "")
    new_refresh = tokens.get("refresh_token", refresh_token_val)
    expires_in = tokens.get("expires_in")

    current_values["access_token"] = new_access
    cred.encrypted_values = credential_vault.encrypt(current_values)
    cred.encrypted_refresh_token = credential_vault.encrypt_string(new_refresh)
    if expires_in:
        cred.expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
    db.commit()
    logger.info("Auto-refreshed OAuth2 token (refresh_token) for credential %s", cred.id)


async def _refresh_client_credentials(db, cred, current_values: dict):
    """Re-issue an access token using stored client_id + client_secret."""
    token_url = current_values.get("_token_url", "")
    token_data = {
        "grant_type": "client_credentials",
        "client_id": current_values["_client_id"],
        "client_secret": current_values["_client_secret"],
    }
    scopes = current_values.get("_scopes", [])
    if scopes:
        token_data["scope"] = " ".join(scopes)

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(token_url, data=token_data)

    if resp.status_code >= 400:
        logger.warning("Client credentials re-issue HTTP %s: %s", resp.status_code, resp.text[:200])
        return

    tokens = resp.json()
    new_access = tokens.get("access_token", "")
    expires_in = tokens.get("expires_in")

    current_values["access_token"] = new_access
    cred.encrypted_values = credential_vault.encrypt(current_values)
    if expires_in:
        cred.expires_at = datetime.utcnow() + timedelta(seconds=int(expires_in))
    db.commit()
    logger.info("Auto-reissued client_credentials token for credential %s", cred.id)

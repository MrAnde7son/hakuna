"""Relay transport — proxies transport operations to an on-prem relay agent via WebSocket."""

import logging
from typing import AsyncIterator, Optional

from .base import BaseTransport, ConnectResult, PushResult
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


class RelayTransport(BaseTransport):
    """Delegates API calls to a relay agent connected over WebSocket.

    The agent runs ApiTransport locally in the customer's network and
    streams results back. All field mapping, upsert, and scheduling
    remain on the cloud side.
    """

    def __init__(self, agent_id: str, credentials_mode: str = "agent_local"):
        self.agent_id = agent_id
        self.credentials_mode = credentials_mode

    def _prepare_credentials(self, credentials: dict) -> Optional[dict]:
        """Only send credentials if the integration uses cloud-managed mode."""
        if self.credentials_mode == "cloud_managed":
            return credentials
        # agent_local: agent loads creds from its own env — don't send secrets
        return None

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        broker = get_relay_broker()
        if not broker.is_connected(self.agent_id):
            return ConnectResult(success=False, error="Relay agent is offline")

        try:
            result = await broker.send_task(
                self.agent_id, "connect", config,
                credentials=self._prepare_credentials(credentials),
            )
            return ConnectResult(
                success=result.get("success", False),
                sample_records=result.get("sample_records", []),
                raw_response=result.get("raw_response"),
                error=result.get("error"),
                detected_records_path=result.get("detected_records_path"),
            )
        except Exception as e:
            logger.exception("RelayTransport.connect failed for agent %s", self.agent_id)
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        broker = get_relay_broker()
        if not broker.is_connected(self.agent_id):
            raise ConnectionError(f"Relay agent {self.agent_id} is offline")

        async for batch in broker.send_streaming_task(
            self.agent_id, config,
            credentials=self._prepare_credentials(credentials),
            params=params,
        ):
            for record in batch:
                yield record

    async def push(self, config: dict, credentials: dict, payload: dict) -> PushResult:
        broker = get_relay_broker()
        if not broker.is_connected(self.agent_id):
            return PushResult(success=False, error="Relay agent is offline")

        try:
            result = await broker.send_task(
                self.agent_id, "push", config,
                credentials=self._prepare_credentials(credentials),
                payload=payload,
            )
            return PushResult(
                success=result.get("success", False),
                response=result.get("response"),
                status_code=result.get("status_code"),
                error=result.get("error"),
            )
        except Exception as e:
            logger.exception("RelayTransport.push failed for agent %s", self.agent_id)
            return PushResult(success=False, error=str(e))

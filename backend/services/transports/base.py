"""Base transport interface."""

from dataclasses import dataclass, field
from typing import List, Optional, Any, AsyncIterator


@dataclass
class ConnectResult:
    success: bool
    sample_records: List[dict] = field(default_factory=list)
    raw_response: Any = None
    error: Optional[str] = None
    detected_records_path: Optional[str] = None


@dataclass
class PushResult:
    success: bool
    response: Any = None
    status_code: Optional[int] = None
    error: Optional[str] = None


class BaseTransport:
    """All transports implement this interface."""

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        raise NotImplementedError

    async def fetch_all(self, config: dict, credentials: dict, params: dict) -> AsyncIterator:
        raise NotImplementedError
        yield  # make it an async generator

    async def push(self, config: dict, credentials: dict, payload: dict) -> PushResult:
        raise NotImplementedError

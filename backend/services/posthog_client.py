"""PostHog product analytics client.

Thin wrapper around posthog-python that:
  - No-ops cleanly when POSTHOG_API_KEY is unset (dev, tests).
  - Identifies users and groups organizations for B2B group analytics.
  - Captures product events (scan_started, remediation_executed,
    integration_connected, etc.) without ever blocking the request path.
  - Never raises — analytics failures must not break the product.

Env vars:
  POSTHOG_API_KEY   — required to enable (project API key, starts with `phc_`)
  POSTHOG_HOST      — defaults to https://us.i.posthog.com
  ENVIRONMENT       — attached to every event as `$environment`
"""
import os
import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)

_POSTHOG_API_KEY = os.environ.get("POSTHOG_API_KEY", "").strip()
_POSTHOG_HOST = os.environ.get("POSTHOG_HOST", "https://us.i.posthog.com").strip()
_ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

_client = None

if _POSTHOG_API_KEY:
    try:
        from posthog import Posthog
        _client = Posthog(
            project_api_key=_POSTHOG_API_KEY,
            host=_POSTHOG_HOST,
        )
        logger.info("PostHog analytics enabled (host=%s)", _POSTHOG_HOST)
    except Exception as e:
        logger.warning("PostHog init failed (non-fatal): %s", e)
        _client = None


def is_enabled() -> bool:
    return _client is not None


def identify(user_id: Any, properties: Optional[dict] = None) -> None:
    """Associate a distinct_id with user properties (email, role, org, etc.)."""
    if _client is None or user_id is None:
        return
    try:
        _client.identify(distinct_id=str(user_id), properties=properties or {})
    except Exception as e:
        logger.debug("PostHog identify failed: %s", e)


def group_identify(group_type: str, group_key: Any, properties: Optional[dict] = None) -> None:
    """Register/update a group (e.g. `company`) with properties — for B2B analytics."""
    if _client is None or group_key is None:
        return
    try:
        _client.group_identify(
            group_type=group_type,
            group_key=str(group_key),
            properties=properties or {},
        )
    except Exception as e:
        logger.debug("PostHog group_identify failed: %s", e)


def capture(
    user_id: Any,
    event: str,
    properties: Optional[dict] = None,
    org_id: Optional[Any] = None,
) -> None:
    """Capture an event. `org_id`, if provided, attaches the company group."""
    if _client is None or user_id is None:
        return
    props = {"$environment": _ENVIRONMENT, **(properties or {})}
    groups = {"company": str(org_id)} if org_id is not None else None
    try:
        _client.capture(
            distinct_id=str(user_id),
            event=event,
            properties=props,
            groups=groups,
        )
    except Exception as e:
        logger.debug("PostHog capture failed (%s): %s", event, e)


def shutdown() -> None:
    """Flush queued events before process exit."""
    if _client is None:
        return
    try:
        _client.shutdown()
    except Exception:
        pass

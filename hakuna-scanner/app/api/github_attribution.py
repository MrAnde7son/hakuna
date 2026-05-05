"""GitHub/npm attribution endpoint.

Synchronously runs the EASM GitHub/npm engine for a target domain and
returns the unified DiscoveryResult JSON. The backend calls this from its
EASM completion path to ingest discovered repos / orgs / users / npm
packages as first-class assets.

Discovery mode is bounded by the engine's own per-API-call timeouts and
result caps (max_users / max_packages / max_keyword_results), so a single
request typically completes in seconds-to-low-minutes. Callers should set
their HTTP client timeout accordingly.
"""

import logging
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ingest.github_npm.engine import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    EASMEngine,
    Mode,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/orgs/{org_id}/github-attribution",
    tags=["github-attribution"],
)


class GitHubAttributionRequest(BaseModel):
    target_domain: str = Field(..., min_length=1)
    mode: str = Mode.DISCOVERY.value
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    enable_keyword_search: bool = True
    org_login_hints: list[str] | None = None


@router.post("")
async def run_github_attribution(
    org_id: uuid.UUID,
    body: GitHubAttributionRequest,
) -> dict:
    if body.mode not in (Mode.DISCOVERY.value, Mode.FULL.value):
        raise HTTPException(
            400,
            f"mode must be one of: {Mode.DISCOVERY.value}, {Mode.FULL.value} "
            f"(scan-only mode is handled by hakuna-vm-scanner)",
        )

    engine = EASMEngine(
        confidence_threshold=body.confidence_threshold,
        enable_keyword_search=body.enable_keyword_search,
        org_login_hints=body.org_login_hints or [],
    )
    try:
        result = await engine.run(body.target_domain, mode=Mode(body.mode))
    except Exception as exc:
        logger.exception(
            "github attribution failed for org=%s domain=%s",
            org_id, body.target_domain,
        )
        raise HTTPException(500, f"github attribution failed: {exc}") from exc

    payload = result.to_dict()
    payload["org_id"] = str(org_id)
    logger.info(
        "github attribution org=%s domain=%s: orgs=%d users=%d repos=%d npm=%d errors=%d",
        org_id, body.target_domain,
        payload["stats"].get("orgs_kept", 0),
        payload["stats"].get("users_kept", 0),
        payload["stats"].get("repos_kept", 0),
        payload["stats"].get("npm_kept", 0),
        payload["stats"].get("errors", 0),
    )
    return payload

"""API tokens — long-lived credentials customers paste into MCP clients,
CI scripts, and other agents.

Endpoints:
    POST   /api/auth/tokens          — mint a new token (plaintext shown ONCE)
    GET    /api/auth/tokens          — list the caller's tokens (no plaintext)
    DELETE /api/auth/tokens/{id}     — revoke a token

Tokens are scoped to the creating user + their org_context at creation time.
Calls authenticated with a token inherit that user's role and org.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import generate_api_token, require_auth
from core.database import get_db
from models.models import ApiToken, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth/tokens", tags=["api-tokens"])

VALID_SCOPES = {"mcp:read", "mcp:write", "api:read", "api:write"}
DEFAULT_SCOPES = ["mcp:read"]


class CreateTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=lambda: list(DEFAULT_SCOPES))
    expires_in_days: Optional[int] = Field(None, ge=1, le=365 * 5)


def _serialize(t: ApiToken) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "token_prefix": t.token_prefix,
        "scopes": t.scopes or [],
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
    }


@router.post("")
async def create_token(
    body: CreateTokenRequest,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Mint a new API token. The plaintext value is returned ONCE in this
    response under `token`. Subsequent listings only show the prefix."""
    bad = [s for s in body.scopes if s not in VALID_SCOPES]
    if bad:
        raise HTTPException(400, f"Unknown scope(s): {bad}. Valid: {sorted(VALID_SCOPES)}")
    if not body.scopes:
        raise HTTPException(400, "At least one scope is required")

    plaintext, token_hash, prefix = generate_api_token()
    expires_at = (
        datetime.utcnow() + timedelta(days=body.expires_in_days)
        if body.expires_in_days is not None
        else None
    )

    row = ApiToken(
        user_id=user.id,
        org_id=user.org_id,
        name=body.name,
        token_hash=token_hash,
        token_prefix=prefix,
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {**_serialize(row), "token": plaintext}


@router.get("")
async def list_tokens(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """List the caller's tokens (no plaintext — only prefixes for display)."""
    rows = (
        db.query(ApiToken)
        .filter(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )
    return {"tokens": [_serialize(t) for t in rows]}


@router.delete("/{token_id}")
async def revoke_token(
    token_id: int,
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    row = db.query(ApiToken).filter(
        ApiToken.id == token_id,
        ApiToken.user_id == user.id,
    ).first()
    if not row:
        raise HTTPException(404, "Token not found")
    if row.revoked_at is None:
        row.revoked_at = datetime.utcnow()
        db.commit()
    return {"revoked": True, "id": token_id}

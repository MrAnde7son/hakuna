"""
AI token quota enforcement for Pro plan.

Pro plan: 5,000,000 tokens/month (shared across agents + copilot).
Free plan: AI features are fully disabled (gated by require_pro).

Quota resets lazily — when a request arrives after current_period_end
has passed, usage is zeroed and the reset timestamp is updated.
"""
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from models.models import Organization

logger = logging.getLogger(__name__)

PRO_TOKEN_LIMIT = 5_000_000  # 5M tokens/month
WARN_THRESHOLD = 0.8         # 80% — surface warning to frontend


def _maybe_reset(org: Organization, db: Session) -> None:
    """Reset token counter if the billing period has rolled over."""
    now = datetime.utcnow()

    # If current_period_end exists and we've passed it, reset
    if org.current_period_end and now >= org.current_period_end:
        org.ai_tokens_used = 0
        org.ai_tokens_reset_at = now
        db.flush()
        logger.info("Org %d token counter reset (period ended %s)", org.id, org.current_period_end)
        return

    # If no reset timestamp yet, initialize it
    if not org.ai_tokens_reset_at:
        org.ai_tokens_reset_at = now
        db.flush()


def check_token_quota(org_id: int, db: Session) -> None:
    """Raise 429 if the org has exhausted its monthly AI token quota.

    Called before each LLM API call in the agent engine.
    """
    from fastapi import HTTPException

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return

    # Superadmin orgs or non-pro: skip (non-pro is already blocked by require_pro)
    tier = org.subscription_tier or "free"
    if tier != "pro":
        return

    _maybe_reset(org, db)

    used = org.ai_tokens_used or 0
    if used >= PRO_TOKEN_LIMIT:
        raise HTTPException(
            429,
            f"Monthly AI token quota exceeded ({used:,} / {PRO_TOKEN_LIMIT:,} tokens). "
            f"Quota resets at the start of your next billing period."
        )


def increment_token_usage(org_id: int, tokens: int, db: Session) -> int:
    """Add tokens to the org's monthly usage. Returns new total."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return 0

    _maybe_reset(org, db)

    org.ai_tokens_used = (org.ai_tokens_used or 0) + tokens
    db.flush()
    return org.ai_tokens_used


def get_token_usage(org_id: int, db: Session) -> dict:
    """Return current token usage stats for an org."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        return {"used": 0, "limit": PRO_TOKEN_LIMIT, "percentage": 0, "warning": False}

    tier = org.subscription_tier or "free"
    if tier != "pro":
        return {"used": 0, "limit": 0, "percentage": 0, "warning": False, "tier": "free"}

    _maybe_reset(org, db)

    used = org.ai_tokens_used or 0
    pct = round(used / PRO_TOKEN_LIMIT * 100, 1) if PRO_TOKEN_LIMIT > 0 else 0
    return {
        "used": used,
        "limit": PRO_TOKEN_LIMIT,
        "percentage": min(pct, 100),
        "warning": pct >= WARN_THRESHOLD * 100,
        "exceeded": used >= PRO_TOKEN_LIMIT,
        "resets_at": org.current_period_end.isoformat() if org.current_period_end else None,
        "tier": "pro",
    }

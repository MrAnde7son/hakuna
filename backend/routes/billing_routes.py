"""
Billing & subscription routes.
Prefix: /api/billing
"""
import os
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.database import get_db
from core.auth import require_auth, require_role
from models.models import Organization, User
from services.billing import (
    create_checkout_session,
    create_portal_session,
    handle_webhook_event,
    sync_subscription_status,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/billing", tags=["billing"])


# ── Request schemas ──────────────────────────────────────

class CheckoutRequest(BaseModel):
    price_id: str
    success_url: str
    cancel_url: str


class PortalRequest(BaseModel):
    return_url: str


# ── Helpers ──────────────────────────────────────────────

def _get_org(db: Session, user: User) -> Organization:
    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return org


# ── Routes ───────────────────────────────────────────────

FREE_FEATURES = [
    "Dashboard & reports",
    "Findings & assets",
    "3 scans total",
    "3 users",
    "3 campaigns",
    "Integrations",
    "Workflows",
    "SBOM & EASM",
    "Threat intelligence",
    "NLP search",
]

PRO_FEATURES = [
    "Everything in Free",
    "Unlimited scans",
    "Unlimited users",
    "Unlimited campaigns",
    "AI agents",
]


@router.get("/plans")
def get_plans():
    """Public — return plan details for both tiers."""
    return {
        "plans": [
            {
                "tier": "free",
                "name": "Free",
                "price_monthly": 0,
                "price_annual": 0,
                "features": FREE_FEATURES,
            },
            {
                "tier": "pro",
                "name": "Pro",
                "price_monthly": 200,
                "price_annual": 2000,
                "price_id_monthly": os.getenv("STRIPE_PRICE_ID_MONTHLY", ""),
                "price_id_annual": os.getenv("STRIPE_PRICE_ID_ANNUAL", ""),
                "features": PRO_FEATURES,
            },
        ]
    }


@router.post("/checkout")
def billing_checkout(
    body: CheckoutRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Create a Stripe Checkout Session for upgrading to Pro."""
    org = _get_org(db, user)
    url = create_checkout_session(
        org=org,
        price_id=body.price_id,
        success_url=body.success_url,
        cancel_url=body.cancel_url,
        admin_email=user.email,
        db=db,
    )
    return {"checkout_url": url}


@router.post("/portal")
def billing_portal(
    body: PortalRequest,
    user: User = Depends(require_role("superadmin", "org_admin")),
    db: Session = Depends(get_db),
):
    """Create a Stripe Customer Portal session for managing billing."""
    org = _get_org(db, user)
    if not org.stripe_customer_id:
        raise HTTPException(400, "No billing account found. Subscribe first.")
    url = create_portal_session(org, body.return_url)
    return {"portal_url": url}


@router.get("/status")
def billing_status(
    user: User = Depends(require_auth),
    db: Session = Depends(get_db),
):
    """Return the org's current subscription status."""
    org = _get_org(db, user)
    return {
        "subscription_tier": org.subscription_tier or "free",
        "subscription_status": org.subscription_status,
        "current_period_end": org.current_period_end.isoformat() if org.current_period_end else None,
        "trial_ends_at": org.trial_ends_at.isoformat() if org.trial_ends_at else None,
    }


@router.post("/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)):
    """Stripe webhook handler — NO auth, uses signature verification."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = handle_webhook_event(payload, sig_header)
    except Exception as e:
        logger.warning(f"Webhook signature verification failed: {e}")
        raise HTTPException(400, "Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]
    logger.info(f"Stripe webhook: {event_type}")

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data, db)
    elif event_type == "invoice.paid":
        _handle_invoice_paid(data, db)
    elif event_type == "invoice.payment_failed":
        _handle_payment_failed(data, db)
    elif event_type == "customer.subscription.updated":
        _handle_subscription_updated(data, db)
    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data, db)

    return {"status": "ok"}


# ── Webhook handlers (idempotent) ────────────────────────

def _find_org_by_customer(customer_id: str, db: Session) -> Organization | None:
    return db.query(Organization).filter(Organization.stripe_customer_id == customer_id).first()


def _handle_checkout_completed(session: dict, db: Session):
    """checkout.session.completed → set tier to pro, status to active."""
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")
    org = _find_org_by_customer(customer_id, db)
    if not org:
        # Try metadata fallback
        org_id = (session.get("metadata") or {}).get("org_id")
        if org_id:
            org = db.query(Organization).filter(Organization.id == int(org_id)).first()
            if org:
                org.stripe_customer_id = customer_id
    if not org:
        logger.warning(f"Checkout completed but no org found for customer {customer_id}")
        return

    # Idempotent: only update if not already pro+active
    if org.subscription_tier == "pro" and org.subscription_status == "active":
        return

    org.subscription_tier = "pro"
    org.subscription_status = "active"
    org.stripe_subscription_id = subscription_id
    db.commit()
    logger.info(f"Org {org.id} upgraded to Pro via checkout")


def _handle_invoice_paid(invoice: dict, db: Session):
    """invoice.paid → update current_period_end."""
    import stripe as stripe_mod
    customer_id = invoice.get("customer")
    org = _find_org_by_customer(customer_id, db)
    if not org or not org.stripe_subscription_id:
        return

    try:
        sub = stripe_mod.Subscription.retrieve(org.stripe_subscription_id)
        sync_subscription_status(org, sub)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to sync subscription after invoice.paid: {e}")


def _handle_payment_failed(invoice: dict, db: Session):
    """invoice.payment_failed → set status to past_due."""
    customer_id = invoice.get("customer")
    org = _find_org_by_customer(customer_id, db)
    if not org:
        return

    if org.subscription_status == "past_due":
        return  # idempotent

    org.subscription_status = "past_due"
    db.commit()
    logger.info(f"Org {org.id} payment failed, status → past_due")


def _handle_subscription_updated(subscription: dict, db: Session):
    """customer.subscription.updated → sync tier + status."""
    customer_id = subscription.get("customer")
    org = _find_org_by_customer(customer_id, db)
    if not org:
        return

    # Use the dict directly to build a simple namespace
    class _Sub:
        def __init__(self, d):
            self.id = d.get("id")
            self.status = d.get("status")
            self.current_period_end = d.get("current_period_end")
            self.trial_end = d.get("trial_end")

    sync_subscription_status(org, _Sub(subscription))
    db.commit()
    logger.info(f"Org {org.id} subscription updated: tier={org.subscription_tier} status={org.subscription_status}")


def _handle_subscription_deleted(subscription: dict, db: Session):
    """customer.subscription.deleted → set tier to free, status to canceled."""
    customer_id = subscription.get("customer")
    org = _find_org_by_customer(customer_id, db)
    if not org:
        return

    if org.subscription_tier == "free" and org.subscription_status == "canceled":
        return  # idempotent

    org.subscription_tier = "free"
    org.subscription_status = "canceled"
    db.commit()
    logger.info(f"Org {org.id} subscription canceled, tier → free")

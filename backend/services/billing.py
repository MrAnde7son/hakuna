"""
Stripe billing service — wraps Stripe API for subscription management.
"""
import os
import logging
from datetime import datetime

import stripe

from models.models import Organization

logger = logging.getLogger(__name__)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")


def get_or_create_stripe_customer(org: Organization, admin_email: str, db) -> str:
    """Return existing Stripe customer ID or create one and persist it."""
    if org.stripe_customer_id:
        return org.stripe_customer_id

    customer = stripe.Customer.create(
        email=admin_email,
        name=org.name,
        metadata={"org_id": str(org.id), "org_slug": org.slug},
    )
    org.stripe_customer_id = customer.id
    db.commit()
    logger.info(f"Created Stripe customer {customer.id} for org {org.id}")
    return customer.id


def create_checkout_session(org: Organization, price_id: str, success_url: str, cancel_url: str, admin_email: str, db) -> str:
    """Create a Stripe Checkout Session and return its URL."""
    customer_id = get_or_create_stripe_customer(org, admin_email, db)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"org_id": str(org.id)},
    )
    return session.url


def create_portal_session(org: Organization, return_url: str) -> str:
    """Create a Stripe Customer Portal session and return its URL."""
    if not org.stripe_customer_id:
        raise ValueError("Organization has no Stripe customer")

    session = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=return_url,
    )
    return session.url


def handle_webhook_event(payload: bytes, sig_header: str) -> dict:
    """Verify webhook signature and return the parsed event.

    Fails fast if STRIPE_WEBHOOK_SECRET is missing — an empty secret would
    cause construct_event to accept any signature silently in some SDK
    versions, enabling subscription forgery.
    """
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not webhook_secret:
        logger.error("STRIPE_WEBHOOK_SECRET is not configured; rejecting webhook")
        raise ValueError("Billing webhook is not configured")
    if not sig_header:
        raise ValueError("Missing Stripe signature header")
    event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    return event


def sync_subscription_status(org: Organization, subscription) -> None:
    """Update org columns from a Stripe subscription object."""
    org.stripe_subscription_id = subscription.id

    # Map Stripe status to our tier
    if subscription.status in ("active", "trialing"):
        org.subscription_tier = "pro"
    elif subscription.status == "canceled":
        org.subscription_tier = "free"
    # past_due keeps current tier but updates status

    org.subscription_status = subscription.status

    if subscription.current_period_end:
        org.current_period_end = datetime.utcfromtimestamp(subscription.current_period_end)

    if subscription.trial_end:
        org.trial_ends_at = datetime.utcfromtimestamp(subscription.trial_end)

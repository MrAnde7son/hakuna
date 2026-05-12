"""Correlate discovered identities with known domain breaches.

When an org's monitored domain shows up in HIBP (``domain_breaches`` table),
the people who work there with that corporate email are statistically
likely to have had credentials exposed in those breaches. We can't prove
it without an authenticated per-email HIBP lookup (paid API, ToS-sensitive
to use at scale), but we can produce an actionable Medium-severity finding
that says *"likely exposed — rotate this credential"*, which is the right
fix regardless of certainty.

Pipeline:

1. For the org's ``easm_domain``, read all ``DomainBreach`` rows. If zero,
   there's nothing to correlate and we exit fast.
2. For each ``asset_type='identity'`` asset just discovered, derive the
   plausible corporate email addresses from the display name + domain.
3. Emit one ``Finding`` per (identity, breach), keyed on plugin_id so
   re-runs are idempotent.

Implementation is deliberately conservative — no external lookups, no
per-email API calls. The signal is "your domain was in this breach AND
this person works there" — strong enough to act on, weak enough that we
phrase it as "likely exposed" rather than "definitely pwned".
"""

from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy.orm import Session

from models.models import Asset, Finding, Organization
from models.threat_intel_models import BreachRecord, DomainBreach
from services.asset_observations import record_finding_observation
from services.post_ingest import _recompute_asset_severity_counts
from .email_permutations import permute_corporate_emails

logger = logging.getLogger(__name__)

_PLUGIN_ID = "EASM-IDENTITY-BREACHED-CORPORATE-EMAIL"
_PLUGIN_FAMILY = "EASM: Identity Exposure"

# Severity keys map to (severity_int, label, risk_factor, priority_score).
# Mirror the values used by _GH_SEVERITY_MAP in services/easm.py so the
# prioritizer treats these the same as other EASM findings.
_SEVERITY_MAP = {
    "critical": (4, "Critical", "Critical", 9.5),
    "high":     (3, "High", "High", 7.5),
    "medium":   (2, "Medium", "Medium", 5.0),
    "low":      (1, "Low", "Low", 2.5),
    "info":     (0, "Informational", "None", 0.5),
}


def _classify_severity(breach: BreachRecord | None) -> str:
    """Pick a severity for a breach-identity correlation.

    The base is Medium ("credentials may be exposed"); we bump on signals
    that increase the blast radius:
    - Passwords in ``data_classes`` → High (a password cleared the breach,
      not just an email; brute force / credential stuffing risk is real).
    - ``is_sensitive`` flag → High (HIBP marks sites where simple
      membership is itself harmful, e.g. AshleyMadison).
    - ``is_fabricated`` or ``is_spam_list`` → Low (low signal data).
    """
    if breach is None:
        return "medium"
    if breach.is_fabricated or breach.is_spam_list:
        return "low"
    classes = breach.data_classes or []
    has_passwords = any(
        "password" in (c or "").lower() for c in classes
    )
    if has_passwords or breach.is_sensitive:
        return "high"
    return "medium"


def correlate_breaches_for_identities(
    db: Session, *, org_id: int, scan_id: int, identity_asset_ids: list[int],
) -> dict:
    """Emit identity-exposure findings for the assets in ``identity_asset_ids``.

    Returns ``{"created": int, "updated": int, "breaches_checked": int,
    "identities_checked": int}``. Re-runs are idempotent — same (asset_id,
    plugin_id) pair updates the existing finding rather than duplicating.
    """
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org or not org.easm_domain:
        return {"created": 0, "updated": 0, "breaches_checked": 0, "identities_checked": 0}

    domain = org.easm_domain
    breaches = (
        db.query(DomainBreach)
        .filter(DomainBreach.org_id == org_id, DomainBreach.domain == domain)
        .all()
    )
    if not breaches:
        return {
            "created": 0, "updated": 0,
            "breaches_checked": 0,
            "identities_checked": len(identity_asset_ids),
        }

    # Hydrate matching BreachRecord rows once so we can read severity inputs
    # (data_classes, is_sensitive, ...) without a per-finding lookup.
    breach_names = [b.breach_name for b in breaches]
    breach_records = {
        r.name: r
        for r in db.query(BreachRecord)
        .filter(BreachRecord.name.in_(breach_names))
        .all()
    }

    assets = (
        db.query(Asset)
        .filter(Asset.id.in_(identity_asset_ids), Asset.asset_type == "identity")
        .all()
    )

    existing_findings: dict[tuple[int, str], Finding] = {
        (f.asset_id, f.plugin_id): f
        for f in (
            db.query(Finding)
            .filter(Finding.asset_id.in_([a.id for a in assets]))
            .filter(Finding.plugin_id.like(f"{_PLUGIN_ID}%"))
            .all()
        )
    }

    now = datetime.utcnow()
    created = 0
    updated = 0
    touched_finding_ids: list[int] = []

    for asset in assets:
        display_name = (asset.asset_attributes or {}).get("display_name")
        if not display_name:
            continue
        emails = permute_corporate_emails(display_name, domain)
        if not emails:
            continue

        for db_breach in breaches:
            breach_record = breach_records.get(db_breach.breach_name)
            severity_key = _classify_severity(breach_record)
            sev, sev_label, risk, priority = _SEVERITY_MAP[severity_key]

            # plugin_id includes the breach slug so each (identity, breach)
            # pair is its own finding — closing one doesn't suppress another.
            pid = f"{_PLUGIN_ID}:{db_breach.breach_name}"
            plugin_name = (
                f"Likely corporate-email exposure in {breach_record.title}"
                if breach_record else
                f"Likely corporate-email exposure in {db_breach.breach_name}"
            )
            breach_date = breach_record.breach_date if breach_record else "unknown"
            data_classes = breach_record.data_classes if breach_record else []

            synopsis = (
                f"{display_name}'s corporate email at {domain} may have been "
                f"exposed in the {db_breach.breach_name} breach ({breach_date})."
            )
            description = (
                f"The domain {domain} appears in the {db_breach.breach_name} "
                f"breach catalogued by HIBP. {display_name} is a discovered "
                f"identity at this org, so any corporate email account they "
                f"hold may have been part of the {db_breach.exposed_count:,} "
                f"accounts compromised in that incident. This correlation is "
                f"probabilistic — we did not query HIBP per-email, only the "
                f"domain. Treat it as a credential rotation prompt."
            )
            solution = (
                "Rotate the credentials for the likely corporate email "
                "addresses below. If the account uses SSO/SAML, also force "
                "re-authentication on any standing sessions. Enroll the "
                "user in MFA if not already enforced."
            )
            plugin_output = "\n".join([
                f"Identity: {display_name}",
                f"Source: {(asset.asset_identity or {}).get('source')}",
                f"Profile: {(asset.asset_attributes or {}).get('profile_url') or '—'}",
                f"Breach: {db_breach.breach_name} ({breach_date})",
                f"Exposed accounts on domain: {db_breach.exposed_count:,}",
                "Data classes: " + (", ".join(data_classes) if data_classes else "unknown"),
                "Candidate emails (most → least likely):",
                *[f"  - {e}" for e in emails],
            ])

            raw_fields = {
                "identity": display_name,
                "identity_source": (asset.asset_identity or {}).get("source"),
                "profile_url": (asset.asset_attributes or {}).get("profile_url"),
                "domain": domain,
                "breach_name": db_breach.breach_name,
                "breach_title": breach_record.title if breach_record else None,
                "breach_date": breach_date,
                "exposed_count": db_breach.exposed_count,
                "data_classes": data_classes,
                "candidate_emails": emails,
                "is_sensitive": bool(breach_record.is_sensitive) if breach_record else None,
                "is_fabricated": bool(breach_record.is_fabricated) if breach_record else None,
                "is_spam_list": bool(breach_record.is_spam_list) if breach_record else None,
            }

            existing = existing_findings.get((asset.id, pid))
            if existing:
                existing.severity = sev
                existing.severity_label = sev_label
                existing.risk_factor = risk
                existing.priority_score = priority
                existing.last_seen = now
                existing.plugin_output = plugin_output
                finding_id = existing.id
                updated += 1
            else:
                finding = Finding(
                    scan_id=scan_id, asset_id=asset.id,
                    source_type="easm", source_vuln_id=pid,
                    plugin_id=pid,
                    plugin_name=plugin_name,
                    plugin_family=_PLUGIN_FAMILY,
                    severity=sev, severity_label=sev_label, risk_factor=risk,
                    priority_score=priority, effort_level="low",
                    owner_suggestion="IAM",
                    synopsis=synopsis,
                    description=description,
                    solution=solution,
                    plugin_output=plugin_output,
                    first_seen=now, last_seen=now,
                )
                db.add(finding)
                db.flush()
                finding_id = finding.id
                created += 1

            touched_finding_ids.append(finding_id)
            record_finding_observation(
                db, finding_id=finding_id, source_system="hibp",
                raw_fields=raw_fields, scan_id=scan_id,
            )

    # Recompute critical/high/medium/low_count on touched identity assets so
    # the Assets list "Findings" column and risk scores reflect the new
    # breach-exposure findings. The main ingest pipeline does this via
    # finalize_scan, but identity-discovery runs outside that pipeline.
    if touched_finding_ids:
        _recompute_asset_severity_counts(
            db, scan_id, new_finding_ids=touched_finding_ids,
        )

    logger.info(
        "Identity breach correlation org=%s domain=%s identities=%d "
        "breaches=%d created=%d updated=%d",
        org_id, domain, len(assets), len(breaches), created, updated,
    )
    return {
        "created": created,
        "updated": updated,
        "breaches_checked": len(breaches),
        "identities_checked": len(assets),
    }

"""Trufflehog secrets scanning — result parsing and finding creation.

Scans katana-discovered JS bundles for leaked secrets (API keys, tokens,
credentials) and stores them as findings.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.ingest.managed_ai_keys import classify_trufflehog_detector

logger = logging.getLogger(__name__)

# Trufflehog detector types that are high-confidence
CRITICAL_DETECTORS = {
    "AWS", "GCP", "Azure", "Slack", "GitHub", "GitLab", "Stripe",
    "Twilio", "SendGrid", "Mailgun", "PrivateKey", "JWT",
}


async def store_trufflehog_results(
    db: AsyncSession,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    results: list[dict],
    source_url: str | None = None,
) -> dict:
    """Parse trufflehog output and store as findings.

    Trufflehog v3 JSON output per line:
    {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/path/to/file.js"}}},
        "SourceID": 0,
        "SourceType": 15,
        "SourceName": "trufflehog - filesystem",
        "DetectorType": 1,
        "DetectorName": "AWS",
        "DecoderName": "PLAIN",
        "Verified": true,
        "Raw": "AKIA...",
        "RawV2": "...",
        "Redacted": "AKIA********",
        "ExtraData": {"account": "...", "resource_type": "Access key"}
    }

    Returns {"secrets_found": int, "verified": int, "unverified": int}.
    """
    now = datetime.now(timezone.utc)
    secrets_found = 0
    verified_count = 0
    seen_hashes: set[str] = set()

    for entry in results:
        detector = entry.get("DetectorName") or entry.get("detector_name") or "Unknown"
        verified = entry.get("Verified", False)
        raw = entry.get("Raw") or entry.get("raw") or ""
        redacted = entry.get("Redacted") or entry.get("redacted") or _redact(raw)
        source_file = ""
        source_meta = entry.get("SourceMetadata") or entry.get("source_metadata") or {}
        if isinstance(source_meta, dict):
            data = source_meta.get("Data") or source_meta.get("data") or {}
            fs = data.get("Filesystem") or data.get("filesystem") or {}
            source_file = fs.get("file") or ""

        # Dedup key: detector + redacted value hash per asset
        dedup_key = hashlib.sha256(f"{asset_id}:{detector}:{raw[:32]}".encode()).hexdigest()[:16]
        if dedup_key in seen_hashes:
            continue
        seen_hashes.add(dedup_key)

        severity = 4 if verified else 3  # critical if verified, high if not
        if detector in CRITICAL_DETECTORS and verified:
            severity = 4

        # Phase 3.5 slice 4 — managed-AI providers get reclassified with a
        # provider-specific plugin_id and admin-scope severity bump. This
        # runs *before* the generic trufflehog finding shape so the plugin
        # family/title reflect the AI-governance angle rather than a
        # generic "OpenAI secret".
        managed_ai = classify_trufflehog_detector(detector, raw)
        if managed_ai is not None:
            ai_provider, ai_severity, ai_plugin_id = managed_ai
            # Admin-scope keys are critical regardless of trufflehog's
            # verification status — the scope is the threat, not the
            # current liveness.
            if ai_severity > severity:
                severity = ai_severity
        else:
            ai_provider = None
            ai_plugin_id = None

        finding_title = f"Leaked {detector} secret in JS bundle"
        if verified:
            finding_title += " (verified)"
        if ai_provider:
            finding_title = f"Leaked managed-AI key ({ai_provider}) in JS bundle"
            if verified:
                finding_title += " (verified)"

        description = (
            f"Trufflehog detected a {detector} secret in a JavaScript bundle "
            f"served by this asset.\n\n"
            f"**Verified:** {'Yes — secret was confirmed active' if verified else 'No — requires manual verification'}\n"
            f"**Redacted value:** `{redacted}`\n"
        )
        if source_file:
            description += f"**Source file:** {source_file}\n"
        if source_url:
            description += f"**JS bundle URL:** {source_url}\n"

        solution = (
            f"1. Immediately rotate the {detector} credential\n"
            f"2. Remove the secret from the JavaScript source code\n"
            f"3. Use environment variables or a secrets manager instead\n"
            f"4. Review access logs for unauthorized usage"
        )

        finding_id = uuid.uuid4()
        plugin_id = (
            f"{ai_plugin_id}-{dedup_key}"
            if ai_plugin_id
            else f"trufflehog-{detector.lower()}-{dedup_key}"
        )
        plugin_family = "AI Governance" if ai_provider else "Secret Detection"
        await db.execute(
            text("""
                INSERT INTO findings (
                    id, org_id, asset_id, source_type, plugin_id, plugin_name,
                    severity, severity_label, description, solution,
                    plugin_family, plugin_output,
                    first_seen, last_seen, times_seen, workflow_status
                ) VALUES (
                    :id, :org_id, :asset_id, 'easm', :plugin_id, :plugin_name,
                    :severity, :severity_label, :description, :solution,
                    :plugin_family, :plugin_output,
                    :now, :now, 1, 'open'
                )
                ON CONFLICT DO NOTHING
            """),
            {
                "id": finding_id,
                "org_id": org_id,
                "asset_id": asset_id,
                "plugin_id": plugin_id,
                "plugin_name": finding_title,
                "severity": severity,
                "severity_label": "Critical" if severity == 4 else "High",
                "description": description,
                "solution": solution,
                "plugin_family": plugin_family,
                "plugin_output": f"Detector: {detector}, Verified: {verified}, Redacted: {redacted}",
                "now": now,
            },
        )
        secrets_found += 1
        if verified:
            verified_count += 1

    await db.commit()
    logger.info(
        "org=%s asset=%s trufflehog: found=%d verified=%d",
        org_id, asset_id, secrets_found, verified_count,
    )
    return {
        "secrets_found": secrets_found,
        "verified": verified_count,
        "unverified": secrets_found - verified_count,
    }


def _redact(raw: str) -> str:
    """Redact a secret value, keeping first 4 chars."""
    if len(raw) <= 4:
        return "****"
    return raw[:4] + "*" * min(len(raw) - 4, 12)

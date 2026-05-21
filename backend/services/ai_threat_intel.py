"""Model-derived ('mythos') threat intelligence.

The classic feeds — NVD, CISA KEV, EPSS, MITRE ATT&CK — are observational:
they describe exploitation that has already been seen. AI threat signals
augment them with a forecasting layer that synthesizes a weaponization
outlook from a CVE's intrinsic attributes, so a high-pressure CVE can be
flagged *before* it lands on KEV.

The synthesizer here is deterministic: the stochastic component of a model
inference is replaced with a stable hash of the CVE id so demo output is
reproducible. The function boundary (`synthesize`) is the seam where a live
LLM call would be substituted.
"""

import hashlib
import logging
from typing import Optional

from sqlalchemy.orm import Session

from core.time_utils import iso_utc
from models.threat_intel_models import AIThreatSignal

logger = logging.getLogger(__name__)

MODEL_ID = "mythos-threat-lm-v1"
SOURCE = "mythos"
SIGNAL_TYPE = "weaponization_forecast"


def _stable_factor(cve_id: str) -> float:
    """Deterministic 0..1 value derived from the CVE id — stands in for the
    stochastic component of a model inference so demo output is reproducible."""
    digest = hashlib.sha256(cve_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def synthesize(
    cve_id: str,
    *,
    cvss: float = 0.0,
    in_kev: bool = False,
    has_public_exploit: bool = False,
    product: Optional[str] = None,
    description: Optional[str] = None,
) -> dict:
    """Produce a model-derived weaponization forecast for one CVE.

    Returns a plain dict (not persisted) — the shape of one AIThreatSignal."""
    factor = _stable_factor(cve_id)
    cvss = cvss or 5.0

    # Exploitation pressure — how hard the threat landscape is pushing on
    # this CVE. Severity sets the floor; public exploit code and active KEV
    # listing raise it; the per-CVE factor adds model variance.
    pressure = cvss / 10.0
    if has_public_exploit:
        pressure += 0.18
    if in_kev:
        pressure += 0.22
    pressure = min(1.0, pressure + factor * 0.22)

    predicted_exploitation = pressure >= 0.6
    predicted_score = round(min(10.0, cvss * 0.6 + pressure * 4.0), 1)
    confidence = max(0.45, min(0.97, 0.55 + 0.4 * pressure - 0.1 * (1.0 - factor)))
    confidence = round(confidence, 2)
    horizon_days = max(3, int(round(45 - 38 * pressure)))

    target = product or "the affected component"
    ahead_of_kev = predicted_exploitation and not in_kev

    if ahead_of_kev:
        title = f"{cve_id}: weaponization likely within {horizon_days} days"
        summary = (
            f"Model forecasts active exploitation of {cve_id} in {target} "
            f"within ~{horizon_days} days. Not yet on CISA KEV — this signal "
            f"leads the classic feeds."
        )
    elif in_kev:
        title = f"{cve_id}: sustained exploitation expected"
        summary = (
            f"{cve_id} is already KEV-listed; the model expects continued, "
            f"broadening exploitation of {target} over the next {horizon_days} days."
        )
    else:
        title = f"{cve_id}: low near-term weaponization pressure"
        summary = (
            f"Model sees limited near-term exploitation pressure on {cve_id} "
            f"in {target}; routine patch cadence is sufficient."
        )

    reasoning_bits = [
        f"base CVSS {cvss:.1f}",
        "public exploit code observed" if has_public_exploit else "no public exploit yet",
        "KEV-listed" if in_kev else "not on KEV",
        f"exploitation pressure {pressure:.2f}",
    ]
    reasoning = (
        f"Forecast derived from {', '.join(reasoning_bits)}. "
        f"Predicted weaponization horizon {horizon_days} days at "
        f"{int(confidence * 100)}% confidence."
    )

    indicators = []
    if has_public_exploit:
        indicators.append("public_exploit_code")
    if cvss >= 9.0:
        indicators.append("critical_cvss")
    if ahead_of_kev:
        indicators.append("leads_kev")
    if "remote" in (description or "").lower():
        indicators.append("remote_unauthenticated")

    return {
        "cve_id": cve_id,
        "source": SOURCE,
        "signal_type": SIGNAL_TYPE,
        "title": title,
        "summary": summary,
        "reasoning": reasoning,
        "confidence": confidence,
        "predicted_score": predicted_score,
        "predicted_exploitation": predicted_exploitation,
        "horizon_days": horizon_days,
        "generated_by_model": MODEL_ID,
        "indicators": indicators,
    }


def upsert_signal(db: Session, payload: dict) -> AIThreatSignal:
    """Persist a synthesized signal, keyed by (cve_id, source, signal_type)."""
    sig = (
        db.query(AIThreatSignal)
        .filter(
            AIThreatSignal.cve_id == payload["cve_id"],
            AIThreatSignal.source == payload["source"],
            AIThreatSignal.signal_type == payload["signal_type"],
        )
        .first()
    )
    if sig is None:
        sig = AIThreatSignal(
            cve_id=payload["cve_id"],
            source=payload["source"],
            signal_type=payload["signal_type"],
        )
        db.add(sig)

    for field in (
        "title", "summary", "reasoning", "confidence", "predicted_score",
        "predicted_exploitation", "horizon_days", "generated_by_model", "indicators",
    ):
        setattr(sig, field, payload[field])
    return sig


def generate_signals(db: Session, cve_specs: list[dict]) -> int:
    """Synthesize and persist signals for a batch of CVEs.

    `cve_specs` items: {cve_id, cvss, in_kev, has_public_exploit, product,
    description}. Returns the number of signals written."""
    written = 0
    for spec in cve_specs:
        cve_id = spec.get("cve_id")
        if not cve_id:
            continue
        try:
            payload = synthesize(
                cve_id,
                cvss=spec.get("cvss", 0.0) or 0.0,
                in_kev=bool(spec.get("in_kev")),
                has_public_exploit=bool(spec.get("has_public_exploit")),
                product=spec.get("product"),
                description=spec.get("description"),
            )
            upsert_signal(db, payload)
            written += 1
        except Exception:
            logger.exception("AI threat signal synthesis failed for %s", cve_id)
    if written:
        db.flush()
    return written


def signal_to_dict(sig: AIThreatSignal) -> dict:
    return {
        "id": sig.id,
        "cve_id": sig.cve_id,
        "source": sig.source,
        "signal_type": sig.signal_type,
        "title": sig.title,
        "summary": sig.summary,
        "reasoning": sig.reasoning,
        "confidence": sig.confidence,
        "predicted_score": sig.predicted_score,
        "predicted_exploitation": sig.predicted_exploitation,
        "horizon_days": sig.horizon_days,
        "generated_by_model": sig.generated_by_model,
        "indicators": sig.indicators or [],
        "created_at": iso_utc(sig.created_at),
        "updated_at": iso_utc(sig.updated_at),
    }


def get_signals_for_cves(db: Session, cve_ids: list[str]) -> list[dict]:
    """Return all persisted signals for the given CVE ids."""
    cve_ids = [c for c in cve_ids if c]
    if not cve_ids:
        return []
    rows = (
        db.query(AIThreatSignal)
        .filter(AIThreatSignal.cve_id.in_(cve_ids))
        .all()
    )
    return [signal_to_dict(r) for r in rows]

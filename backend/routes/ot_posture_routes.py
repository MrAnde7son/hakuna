"""OT Posture Dashboard — read + manage per-asset OT audit consent.

Surfaces the data needed by the Phase 5 follow-on UX slice
(``frontend/src/pages/OTPostureDashboard.jsx``):

* Asset × OT-protocol matrix with consent state, freshness, finding count.
* Org-level rollups: opted-in asset count, IEC 62443 / METI v3 coverage %.
* Grant / revoke endpoints that write to ``Asset.easm_data["ot_audit_consent"]``
  with a 90-day TTL (the same record consumed by ``_has_fresh_consent``
  in ``services.audit_auto_trigger`` and the manual-dispatch gate in
  ``services.audit_runner``).

Prefix: /api/ot-posture
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.auth import get_accessible_org_ids, require_auth
from core.database import get_db
from core.time_utils import iso_utc
from models.models import Asset, Finding, Organization, Scan, User

router = APIRouter(prefix="/api/ot-posture", tags=["ot-posture"])


# ── Configuration ────────────────────────────────────────────────────

# Mirror of the AutoTriggerRule port lists in audit_auto_trigger; kept here
# rather than imported because the dashboard's "OT-relevant" filter is a
# UX heuristic (which assets to show) and shouldn't drift if the rules
# are renamed. Update both together when a new OT protocol family lands.
_OT_PROTOCOLS = {
    "ot_protocol": {
        "label": "Active read-only (Modbus, S7, BACnet, EtherNet/IP, OPC UA, SLMP, FINS, IEC-104, PROFINET)",
        "plugin_family": "Audit: OT (active read-only)",
        "ports_tcp": (502, 102, 44818, 4840, 5007, 2404),
        "ports_udp": (47808, 9600, 34962),
        "iec_62443_controls": ("SR_1.1", "SR_1.2", "SR_2.1", "SR_2.4", "SR_3.1"),
        "meti_v3_controls": ("L3-CPS-PE-1", "L3-CPS-IT-2"),
    },
    "ot_passive": {
        "label": "Passive listen (Yokogawa Vnet/IP, CC-Link IE)",
        "plugin_family": "Audit: OT (passive listen)",
        "ports_tcp": (),
        "ports_udp": (12289, 61450, 47808, 9600, 34962),
        "iec_62443_controls": ("SR_1.1", "SR_3.1"),
        "meti_v3_controls": ("L3-CPS-PE-1",),
    },
}

_OT_TCP_PORT_SET: set[int] = set()
_OT_UDP_PORT_SET: set[int] = set()
for _meta in _OT_PROTOCOLS.values():
    _OT_TCP_PORT_SET.update(_meta["ports_tcp"])
    _OT_UDP_PORT_SET.update(_meta["ports_udp"])

_CONSENT_TTL_DAYS = 90


# ── Helpers ──────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _consent_state(record: Optional[dict], now: datetime) -> dict:
    """Normalize a single consent record to a UI-friendly shape."""
    if not isinstance(record, dict) or not record.get("granted_at"):
        return {"status": "missing", "granted_at": None, "expires_at": None,
                "granted_by": None, "days_remaining": None}
    granted_raw = record.get("granted_at")
    try:
        granted = datetime.fromisoformat(str(granted_raw))
    except (TypeError, ValueError):
        return {"status": "missing", "granted_at": None, "expires_at": None,
                "granted_by": None, "days_remaining": None}
    if granted.tzinfo is None:
        granted = granted.replace(tzinfo=timezone.utc)
    age_days = (now - granted).days
    days_remaining = _CONSENT_TTL_DAYS - age_days
    expires = granted + timedelta(days=_CONSENT_TTL_DAYS)
    if days_remaining <= 0:
        status = "expired"
    elif days_remaining <= 14:
        status = "expiring_soon"
    else:
        status = "fresh"
    return {
        "status": status,
        "granted_at": iso_utc(granted),
        "expires_at": iso_utc(expires),
        "granted_by": record.get("granted_by"),
        "days_remaining": max(0, days_remaining),
    }


def _asset_has_ot_signal(asset: Asset) -> bool:
    """True iff the asset's enrichment data exposes any OT-relevant port,
    or already has an existing consent record (so revocations stay visible)."""
    easm = asset.easm_data or {}
    if not isinstance(easm, dict):
        return False
    if isinstance(easm.get("ot_audit_consent"), dict) and easm["ot_audit_consent"]:
        return True
    open_tcp = easm.get("open_ports") or []
    open_udp = easm.get("open_udp_ports") or []
    try:
        tcp_set = {int(p) for p in open_tcp}
        udp_set = {int(p) for p in open_udp}
    except (TypeError, ValueError):
        return False
    return bool(tcp_set & _OT_TCP_PORT_SET) or bool(udp_set & _OT_UDP_PORT_SET)


def _asset_label(asset: Asset) -> str:
    return asset.fqdn or asset.hostname or asset.ip or f"asset-{asset.id}"


# ── Schemas ──────────────────────────────────────────────────────────

class ConsentGrantRequest(BaseModel):
    asset_id: int
    protocol: str = Field(..., description="ot_protocol | ot_passive")
    note: Optional[str] = Field(default=None, max_length=500,
                                 description="Optional operator note (free text)")


class ConsentRevokeRequest(BaseModel):
    asset_id: int
    protocol: str


# ── Endpoints ────────────────────────────────────────────────────────

@router.get("/overview")
def get_ot_posture_overview(
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
    org_ids: list | None = Depends(get_accessible_org_ids),
):
    """Asset × OT-protocol consent matrix + IEC 62443 / METI v3 coverage."""
    # Honor the X-Org-Context sidebar selector so superadmin/MSSP users see
    # the selected child org's posture instead of their home org's.
    org_id = org_ids[0] if org_ids and len(org_ids) == 1 else user.org_id
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    # Pull the org's assets that have any OT signal. Cap at 500 to keep the
    # dashboard payload bounded — most plant networks will have far fewer
    # OT-eligible assets, and >500 would need a paged UI anyway.
    candidates = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Scan.org_id == org_id, Asset.easm_data.isnot(None))
        .limit(2000)
        .all()
    )
    ot_assets = [a for a in candidates if _asset_has_ot_signal(a)]

    # Per-(asset, protocol) finding counts in two batched queries — O(1)
    # round-trips regardless of asset count.
    asset_ids = [a.id for a in ot_assets]
    finding_counts: dict[tuple[int, str], int] = {}
    if asset_ids:
        from sqlalchemy import func
        # Tenant isolation rides on the asset_id allowlist (already org-scoped
        # via the join above) — Finding.org_id isn't always populated on
        # legacy rows, so filtering by asset_id alone is the safer narrow.
        for protocol, meta in _OT_PROTOCOLS.items():
            rows = (
                db.query(Finding.asset_id, func.count(Finding.id))
                .filter(
                    Finding.asset_id.in_(asset_ids),
                    Finding.plugin_family == meta["plugin_family"],
                )
                .group_by(Finding.asset_id)
                .all()
            )
            for asset_id, count in rows:
                finding_counts[(asset_id, protocol)] = int(count)

    now = _utcnow()
    auto_audit_ot_enabled = bool((org.settings or {}).get("auto_audit_ot"))

    # Build per-asset rows.
    rows = []
    consent_totals = {p: {"fresh": 0, "expiring_soon": 0, "expired": 0, "missing": 0}
                      for p in _OT_PROTOCOLS}
    for asset in ot_assets:
        easm = asset.easm_data or {}
        consent_map = easm.get("ot_audit_consent") if isinstance(easm, dict) else None
        consent_map = consent_map if isinstance(consent_map, dict) else {}
        per_protocol = {}
        for protocol in _OT_PROTOCOLS:
            state = _consent_state(consent_map.get(protocol), now)
            per_protocol[protocol] = {
                **state,
                "findings_count": finding_counts.get((asset.id, protocol), 0),
            }
            consent_totals[protocol][state["status"]] += 1
        open_tcp = sorted({int(p) for p in (easm.get("open_ports") or []) if isinstance(p, (int, str))
                           and str(p).isdigit()})
        open_udp = sorted({int(p) for p in (easm.get("open_udp_ports") or []) if isinstance(p, (int, str))
                           and str(p).isdigit()})
        ot_tcp_observed = sorted(set(open_tcp) & _OT_TCP_PORT_SET)
        ot_udp_observed = sorted(set(open_udp) & _OT_UDP_PORT_SET)
        rows.append({
            "asset_id": asset.id,
            "label": _asset_label(asset),
            "ip": asset.ip,
            "hostname": asset.hostname,
            "fqdn": asset.fqdn,
            "device_type": asset.device_type,
            "ot_tcp_ports_observed": ot_tcp_observed,
            "ot_udp_ports_observed": ot_udp_observed,
            "consent": per_protocol,
        })

    # Stable sort: assets with at least one fresh consent first, then ones
    # with expiring/expired (operator should re-grant), then untouched.
    def _sort_key(row):
        statuses = [row["consent"][p]["status"] for p in _OT_PROTOCOLS]
        rank = (
            -sum(1 for s in statuses if s == "fresh"),
            -sum(1 for s in statuses if s == "expiring_soon"),
            -sum(1 for s in statuses if s == "expired"),
            row["label"],
        )
        return rank
    rows.sort(key=_sort_key)

    # IEC 62443 / METI v3 coverage: union of controls covered by any
    # protocol with at least one fresh consent in the org.
    iec_universe: set[str] = set()
    meti_universe: set[str] = set()
    iec_covered: set[str] = set()
    meti_covered: set[str] = set()
    for protocol, meta in _OT_PROTOCOLS.items():
        iec_universe.update(meta["iec_62443_controls"])
        meti_universe.update(meta["meti_v3_controls"])
        if consent_totals[protocol]["fresh"] > 0:
            iec_covered.update(meta["iec_62443_controls"])
            meti_covered.update(meta["meti_v3_controls"])

    def _pct(part: int, whole: int) -> int:
        return round(100 * part / whole) if whole else 0

    return {
        "auto_audit_ot_enabled": auto_audit_ot_enabled,
        "consent_ttl_days": _CONSENT_TTL_DAYS,
        "protocols": [
            {
                "protocol": protocol,
                "label": meta["label"],
                "ports_tcp": list(meta["ports_tcp"]),
                "ports_udp": list(meta["ports_udp"]),
                "iec_62443_controls": list(meta["iec_62443_controls"]),
                "meti_v3_controls": list(meta["meti_v3_controls"]),
                "consent_summary": consent_totals[protocol],
            }
            for protocol, meta in _OT_PROTOCOLS.items()
        ],
        "ot_asset_count": len(ot_assets),
        "iec_62443_coverage": {
            "covered": sorted(iec_covered),
            "total": sorted(iec_universe),
            "percent": _pct(len(iec_covered), len(iec_universe)),
        },
        "meti_v3_coverage": {
            "covered": sorted(meti_covered),
            "total": sorted(meti_universe),
            "percent": _pct(len(meti_covered), len(meti_universe)),
        },
        "rows": rows,
    }


def _load_asset_for_consent(db: Session, asset_id: int, org_id: int) -> Asset:
    asset = (
        db.query(Asset)
        .join(Scan, Asset.scan_id == Scan.id)
        .filter(Asset.id == asset_id, Scan.org_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@router.post("/consent")
def grant_consent(
    body: ConsentGrantRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Grant per-asset consent for an OT audit. 90-day TTL — operators
    must re-grant after expiry. The auto-trigger and manual-dispatch
    paths both check freshness, so revocation also takes immediate
    effect on subsequent scan runs."""
    if body.protocol not in _OT_PROTOCOLS:
        raise HTTPException(400, f"Unknown OT protocol: {body.protocol}")
    asset = _load_asset_for_consent(db, body.asset_id, user.org_id)
    easm = dict(asset.easm_data or {})
    consent_map = dict(easm.get("ot_audit_consent") or {})
    consent_map[body.protocol] = {
        "granted_at": iso_utc(_utcnow()),
        "granted_by": user.email or str(user.id),
        "note": body.note or None,
    }
    easm["ot_audit_consent"] = consent_map
    asset.easm_data = easm
    db.commit()

    from core.audit import log_audit
    log_audit(
        db, "grant", "ot_consent", entity_id=asset.id,
        entity_name=_asset_label(asset),
        changes={"protocol": body.protocol, "ttl_days": _CONSENT_TTL_DAYS},
        actor=user,
    )
    db.commit()

    return {
        "asset_id": asset.id,
        "protocol": body.protocol,
        "consent": _consent_state(consent_map[body.protocol], _utcnow()),
    }


@router.delete("/consent")
def revoke_consent(
    asset_id: int,
    protocol: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Revoke per-asset consent for an OT audit. The next dispatch call
    (auto or manual) will refuse with the standard ``ot_audit_consent``
    error, regardless of cooldown."""
    if protocol not in _OT_PROTOCOLS:
        raise HTTPException(400, f"Unknown OT protocol: {protocol}")
    asset = _load_asset_for_consent(db, asset_id, user.org_id)
    easm = dict(asset.easm_data or {})
    consent_map = dict(easm.get("ot_audit_consent") or {})
    if protocol in consent_map:
        consent_map.pop(protocol)
        easm["ot_audit_consent"] = consent_map
        asset.easm_data = easm
        db.commit()

        from core.audit import log_audit
        log_audit(
            db, "revoke", "ot_consent", entity_id=asset.id,
            entity_name=_asset_label(asset),
            changes={"protocol": protocol},
            actor=user,
        )
        db.commit()

    return {"asset_id": asset.id, "protocol": protocol, "revoked": True}

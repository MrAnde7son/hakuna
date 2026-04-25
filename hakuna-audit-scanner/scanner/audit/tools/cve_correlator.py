"""``correlate_software_to_cves`` — pluggable CVE correlation.

The backend's correlator (``services.cve_correlator.correlate_asset``)
is 280 LOC of SQLAlchemy + custom version-range matching against the
threat-intel CVE DB and the MSRC patch catalog. Porting the whole
thing to asyncpg would duplicate substantial domain logic that the
backend is the canonical owner of.

Instead the audit-scanner ships:

  - A ``CveCorrelator`` Protocol with one method, ``correlate(asset_id,
    top_n, include_eol)``.
  - A ``NullCveCorrelator`` default that returns a useful "not
    configured" result so the LLM can adjust strategy (e.g., fall back
    to per-package CPE lookups via its own tools).
  - A module-level ``set_correlator()`` swap point for the backend to
    install ``SqlAlchemyCveCorrelator`` at startup that wraps
    ``services.cve_correlator.correlate_asset``.

This is the same plug-in pattern used for ``QuotaProvider`` and
``RelayTransport`` — keeps OSS callable, lets the backend layer in
its full implementation without forking the engine.
"""

from __future__ import annotations

import logging
from typing import Protocol

from scanner.audit.agent_context import AuditContext
from scanner.audit.audit_engine import agent_tool

logger = logging.getLogger(__name__)


class CveCorrelator(Protocol):
    def correlate(
        self,
        asset_id: str | int,
        *,
        top_n: int = 40,
        include_eol: bool = True,
        org_id: str | int | None = None,
    ) -> dict: ...


class NullCveCorrelator:
    """No-op default. Returns an empty candidate list with a note that
    the LLM can read — explicit "not configured" beats silent zero
    results that look like "no CVEs found" (a much stronger claim)."""

    def correlate(self, asset_id, *, top_n=40, include_eol=True, org_id=None) -> dict:
        return {
            "candidate_cves": [],
            "summary": {
                "total_candidate_cves": 0,
                "kev_candidates": 0,
                "high_epss_candidates": 0,
            },
            "eol_components": [],
            "note": (
                "CVE correlator not configured in this deployment. Use the "
                "protocol's package/inventory tools (e.g. ssh_list_installed_packages, "
                "wmi_get_installed_software) to enumerate software, then run a "
                "per-package CPE lookup if your environment supports it."
            ),
        }


_correlator: CveCorrelator = NullCveCorrelator()


def get_correlator() -> CveCorrelator:
    return _correlator


def set_correlator(correlator: CveCorrelator) -> None:
    """Backend wires this at startup::

        from scanner.audit.tools.cve_correlator import set_correlator
        from backend.services.audit_runner import SqlAlchemyCveCorrelator
        set_correlator(SqlAlchemyCveCorrelator())
    """
    global _correlator
    _correlator = correlator
    logger.info("cve_correlator: set to %s", type(correlator).__name__)


@agent_tool(
    "correlate_software_to_cves",
    "Correlate the asset's installed software inventory against the "
    "threat-intel CVE database and return a ranked candidate CVE list. "
    "This is the deterministic coverage pass; pair it with your protocol's "
    "audit tools to triage which candidates are actually exploitable on "
    "this host. Candidates are sorted by KEV → EPSS → CVSS, capped at "
    "`top_n` (default 40, max 100). Also returns end-of-life components — "
    "an EOL OS or package is a finding regardless of CVE status.",
    {
        "asset_id": {
            "type": ["string", "integer"],
            "description": "Target asset id (default: the run's asset)",
        },
        "top_n": {
            "type": "integer",
            "description": "Max candidates in the sampled list (default 40, max 100)",
        },
        "include_eol": {
            "type": "boolean",
            "description": "Include EOL lifecycle check (default true)",
        },
    },
)
def correlate_software_to_cves(ctx: AuditContext, params: dict) -> dict:
    aid = params.get("asset_id")
    if aid is None and ctx.asset:
        aid = ctx.asset.get("id")
    if aid is None:
        return {"error": "asset_id is required"}
    top_n = min(int(params.get("top_n") or 40), 100)
    include_eol = bool(params.get("include_eol", True))
    return get_correlator().correlate(
        aid, top_n=top_n, include_eol=include_eol, org_id=ctx.org_id,
    )

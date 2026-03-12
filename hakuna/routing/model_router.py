"""
ModelRouter — deterministic model selection based on task type and complexity.

Usage:
    from hakuna.routing.model_router import ModelRouter

    router = ModelRouter()
    model = router.select_model("risk_scoring", complexity="low")   # → haiku
    model = router.select_model("remediation_planning")             # → sonnet

Routing rules (per spec):
    normalization            → claude-haiku-4-5-20251001
    ticket_formatting        → claude-haiku-4-5-20251001
    field_mapping            → claude-haiku-4-5-20251001
    risk_scoring + low       → claude-haiku-4-5-20251001
    risk_scoring + high      → claude-sonnet-4-6
    remediation_planning     → claude-sonnet-4-6
    executive_summary        → claude-sonnet-4-6
    exploit_correlation      → claude-sonnet-4-6
    default                  → claude-sonnet-4-6

Complexity is determined by:
    - number of affected assets (>50 = high)
    - number of CVEs (>100 = high)
    - presence of zero-days
    - MSSP multi-tenant context
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# ── Model IDs ─────────────────────────────────────────────────────────

SONNET = "claude-sonnet-4-6"
HAIKU = "claude-haiku-4-5-20251001"

# ── Routing table ─────────────────────────────────────────────────────

# task_type → (default_model, can_route_to_haiku_on_low_complexity)
_TASK_ROUTING: Dict[str, Dict[str, Any]] = {
    # Deterministic tasks — Haiku always sufficient
    "normalization":       {"model": HAIKU,   "complexity_routing": False},
    "ticket_formatting":   {"model": HAIKU,   "complexity_routing": False},
    "field_mapping":       {"model": HAIKU,   "complexity_routing": False},
    # Complexity-dependent tasks
    "risk_scoring":        {"model": SONNET,  "complexity_routing": True},
    # Reasoning-heavy tasks — Sonnet required
    "remediation_planning": {"model": SONNET, "complexity_routing": False},
    "executive_summary":   {"model": SONNET,  "complexity_routing": False},
    "exploit_correlation": {"model": SONNET,  "complexity_routing": False},
    # Additional task types inferred from agent templates
    "triage":              {"model": SONNET,  "complexity_routing": True},
    "patch_planning":      {"model": SONNET,  "complexity_routing": False},
    "attack_surface":      {"model": SONNET,  "complexity_routing": False},
    "campaign_planning":   {"model": SONNET,  "complexity_routing": False},
    "threat_intel":        {"model": SONNET,  "complexity_routing": False},
    "asset_classification": {"model": HAIKU,  "complexity_routing": False},
    "data_extraction":     {"model": HAIKU,   "complexity_routing": False},
    "sla_check":           {"model": HAIKU,   "complexity_routing": True},
}

# ── Complexity thresholds ─────────────────────────────────────────────

_COMPLEXITY_HIGH_THRESHOLDS = {
    "asset_count": 50,
    "cve_count": 100,
    "finding_count": 500,
}


class ModelRouter:
    """Selects the appropriate model for a given task type and complexity.

    Can be instantiated once and reused throughout a pipeline run.
    All methods are stateless (no instance state required).
    """

    def select_model(
        self,
        task_type: str,
        complexity: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Return the model ID for a given task type and complexity.

        Args:
            task_type: One of the task type strings in _TASK_ROUTING.
                       Defaults to "default" (→ sonnet) if unknown.
            complexity: "low" | "high" | None.
                        If None, inferred from context dict.
            context: Optional dict with complexity signals:
                     - asset_count (int)
                     - cve_count (int)
                     - finding_count (int)
                     - has_zero_day (bool)
                     - is_mssp (bool)

        Returns:
            Model ID string.
        """
        task_cfg = _TASK_ROUTING.get(task_type)
        if task_cfg is None:
            # Unknown task → safe default
            return SONNET

        base_model = task_cfg["model"]
        if not task_cfg.get("complexity_routing"):
            # Task is not complexity-routable — always use base model
            return base_model

        # Resolve complexity
        resolved = self._resolve_complexity(complexity, context or {})

        if resolved == "low":
            return HAIKU
        else:
            return base_model  # high or unknown → use configured model

    def _resolve_complexity(
        self,
        complexity: Optional[str],
        context: Dict[str, Any],
    ) -> str:
        """Resolve 'low' or 'high' from explicit flag or context signals."""
        if complexity in ("low", "high"):
            return complexity

        # Infer from context signals
        if context.get("has_zero_day"):
            return "high"
        if context.get("is_mssp"):
            return "high"
        if context.get("asset_count", 0) > _COMPLEXITY_HIGH_THRESHOLDS["asset_count"]:
            return "high"
        if context.get("cve_count", 0) > _COMPLEXITY_HIGH_THRESHOLDS["cve_count"]:
            return "high"
        if context.get("finding_count", 0) > _COMPLEXITY_HIGH_THRESHOLDS["finding_count"]:
            return "high"

        return "low"

    def get_routing_table(self) -> List[Dict[str, Any]]:
        """Return the full routing table as a list of dicts (for introspection/docs)."""
        rows = []
        for task_type, cfg in _TASK_ROUTING.items():
            if cfg.get("complexity_routing"):
                rows.append({
                    "task_type": task_type,
                    "complexity_low": HAIKU,
                    "complexity_high": cfg["model"],
                    "complexity_routing": True,
                })
            else:
                rows.append({
                    "task_type": task_type,
                    "model": cfg["model"],
                    "complexity_routing": False,
                })
        rows.append({"task_type": "default", "model": SONNET, "complexity_routing": False})
        return rows


# ── Module-level singleton ────────────────────────────────────────────

_router = ModelRouter()


def select_model(
    task_type: str,
    complexity: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """Module-level shortcut to ModelRouter.select_model()."""
    return _router.select_model(task_type, complexity=complexity, context=context)

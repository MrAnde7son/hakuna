"""Scanner registry — pluggable scanner interface with capability declaration.

Each existing scanner (tlsx, httpx, katana, etc.) gets a ScannerSpec that
declares what it needs (inputs), what it produces (outputs), and its
dependencies on other scanners. The orchestrator uses this to build the
enrichment DAG dynamically instead of hardcoding step_groups.

Existing BaseRunner subclasses are NOT modified — they're wrapped in specs.
This is a pure refactor: the default output of build_step_groups() should
match today's hardcoded step_groups exactly.

Guarded behind settings.use_scanner_registry (default False) until parity
is verified against the existing literal.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class ScannerSpec:
    """Declarative description of a scanner's capabilities + placement in the pipeline.

    Fields use loose semantics — the orchestrator inspects them when building
    the DAG but nothing is strictly enforced. The intent is to make scanner
    capabilities inspectable so new scanners self-describe.
    """

    name: str
    """Stable identifier used in step_groups and event_bridge filters."""

    stage: str
    """'discovery' | 'enrichment' | 'vm' — which orchestration chain owns it."""

    group: int
    """Index of the parallel group within the stage (0-based)."""

    stage_fn: Callable | None = None
    """Async function `_do_<name>(sf, org_id, target_scope) -> dict`.

    For registry-driven orchestration, the stage_fn is the entry point.
    If None (e.g., 'nmap_dispatch'), the orchestrator falls back to its
    own hardcoded handling for that step name.
    """

    runner_class: type | None = None
    """Optional BaseRunner subclass. Informational — used by tool_health
    and future introspection. Not needed if stage_fn invokes runners directly.
    """

    inputs: list[str] = field(default_factory=list)
    """Required asset fields: e.g. ['hostname', 'open_ports']. Informational."""

    outputs: list[str] = field(default_factory=list)
    """Fields this scanner writes to assets: e.g. ['tls_cert', 'jarm_hash']."""

    depends_on: list[str] = field(default_factory=list)
    """Scanner names that MUST complete before this runs. Used for topological
    sort when building groups from the registry.
    """

    port_filter: set[int] | None = None
    """If set, scanner only runs on assets with these ports open. Informational."""

    cdn_safe: bool = True
    """Whether the scanner is safe to run on CDN-fronted assets."""

    internet_facing_only: bool = False
    """If True, scanner skips non-internet-facing assets."""

    estimated_cost: str = "medium"
    """'low' | 'medium' | 'high' — heuristic for future scheduling/prioritization."""

    enabled: bool = True
    """Per-scanner enable flag. Allows disabling via config without unregistering."""


# Registry: scanner name → spec. Populated by adapters.py on import.
SCANNER_REGISTRY: dict[str, ScannerSpec] = {}


def register_scanner(spec: ScannerSpec) -> None:
    """Register a scanner spec. Idempotent — re-registering overwrites."""
    if spec.name in SCANNER_REGISTRY:
        logger.debug("Scanner %s re-registered (overwriting prior spec)", spec.name)
    SCANNER_REGISTRY[spec.name] = spec


def get_scanner(name: str) -> ScannerSpec | None:
    return SCANNER_REGISTRY.get(name)


def list_scanners(stage: str | None = None) -> list[ScannerSpec]:
    """List registered scanners, optionally filtered by stage."""
    specs = list(SCANNER_REGISTRY.values())
    if stage:
        specs = [s for s in specs if s.stage == stage]
    return specs


_adapters_registered = False


def _ensure_adapters_registered() -> None:
    """Lazy adapter registration.

    Adapters import from app.tasks.enrichment, which imports from
    app.runner.tools — registering eagerly at app.runner package import
    time would create a circular import. We register on first use instead.
    """
    global _adapters_registered
    if _adapters_registered:
        return
    from app.runner.adapters import register_all
    register_all()
    _adapters_registered = True


def build_step_groups(stage: str) -> list[list[tuple[str, Any]]]:
    """Build ordered, parallel step groups from the registry for a stage.

    Groups are indexed by `spec.group`; within a group, scanners run in
    parallel. Groups run sequentially.

    depends_on is used as a sanity check — if A depends on B, A's group
    must be > B's group. We log a warning (don't fail) if the ordering
    is inconsistent, since the explicit `group` field is authoritative.

    Returns list of groups, each a list of (name, stage_fn) tuples.
    Matches the shape of the existing hardcoded step_groups in enrichment.py.
    """
    _ensure_adapters_registered()
    specs = [s for s in SCANNER_REGISTRY.values() if s.stage == stage and s.enabled]

    # Validate depends_on ordering
    name_to_group: dict[str, int] = {s.name: s.group for s in specs}
    for spec in specs:
        for dep in spec.depends_on:
            dep_group = name_to_group.get(dep)
            if dep_group is None:
                logger.warning(
                    "Scanner %s declares dependency on unregistered scanner %s",
                    spec.name, dep,
                )
                continue
            if dep_group >= spec.group:
                logger.warning(
                    "Scanner %s (group %d) declares dependency on %s (group %d) — "
                    "dependency should be in an earlier group",
                    spec.name, spec.group, dep, dep_group,
                )

    # Bucket by group
    buckets: dict[int, list[ScannerSpec]] = defaultdict(list)
    for spec in specs:
        buckets[spec.group].append(spec)

    # Emit groups in order, preserving registration order within a group
    groups: list[list[tuple[str, Any]]] = []
    for group_idx in sorted(buckets.keys()):
        group_entries: list[tuple[str, Any]] = [
            (s.name, s.stage_fn) for s in buckets[group_idx]
        ]
        groups.append(group_entries)

    return groups

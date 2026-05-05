"""Edge type taxonomy for `AssetRelationship`.

Every producer (EASM, VM scanner, audit agents, parsers, knowledge graph,
inventory) writes edges using one of the constants below. The list is
closed — adding a new edge family is a code change here, not a config
change. See `docs/cross-scan-chain-coordinator-plan.md` (F1) for the
families and their producers.
"""

from __future__ import annotations


# ── Infrastructure (knowledge_graph.py — pre-existing values) ────────
RESOLVES_TO            = "resolves_to"
ALIAS_OF               = "alias_of"
HOSTS_SERVICE          = "hosts_service"
RUNS_TECHNOLOGY        = "runs_technology"
SHARES_CERTIFICATE     = "shares_certificate"
SAME_JARM_CLUSTER      = "same_jarm_cluster"
SAME_IP                = "same_ip"
SHARED_IP_RANGE        = "shared_ip_range"
EXPOSES_ENDPOINT       = "exposes_endpoint"
AUTHENTICATES_VIA      = "authenticates_via"

# ── Reachability ─────────────────────────────────────────────────────
# src=NULL → asset edge. Replaces the boolean `Asset.is_internet_facing`
# at chain-traversal time (the flag still drives a lot of UI; the edge
# is what BFS walks).
INTERNET_TO_ASSET      = "internet_to_asset"
# src→dst by port — sourced from inventory (InventoryNetConn).
ASSET_TO_ASSET_PORT    = "asset_to_asset_port"

# ── Authentication / identity ────────────────────────────────────────
USER_TO_ASSET          = "user_to_asset"
ASSET_TO_ASSET_AUTH    = "asset_to_asset_auth"

# ── Coercion (kill-chain edge from SMB / RPC audits) ─────────────────
# Reachability of a coercion primitive — PrinterBug (spoolss),
# PetitPotam (efsrpc/lsarpc), DFSCoerce (netdfs), WebDAV (DAV RPC
# Service). dst=NULL means "an attacker-controlled relay target" —
# the agent emits the edge as src=asset, dst=NULL with the pipe name
# in properties.
ASSET_TO_ASSET_COERCE  = "asset_to_asset_coerce"

# ── Same-host privilege escalation ───────────────────────────────────
LOCAL_ROOT             = "local_root"

# ── DCSync / domain-takeover ─────────────────────────────────────────
PRINCIPAL_TO_DOMAIN    = "principal_to_domain"

# ── Exploit anchor (VM scanner, parsers, SBOM correlator) ────────────
# Attached to one asset (src=NULL, dst=asset). `properties.cve` carries
# the CVE id; `enabled_by_findings` carries the finding row that
# surfaced it. Coordinator weights asset traversal by these.
CVE_ON_ASSET           = "cve_on_asset"


# Closed family taxonomy used by `emit_edge` validation.
EDGE_TYPES: frozenset[str] = frozenset({
    RESOLVES_TO, ALIAS_OF, HOSTS_SERVICE, RUNS_TECHNOLOGY,
    SHARES_CERTIFICATE, SAME_JARM_CLUSTER, SAME_IP, SHARED_IP_RANGE,
    EXPOSES_ENDPOINT, AUTHENTICATES_VIA,
    INTERNET_TO_ASSET, ASSET_TO_ASSET_PORT,
    USER_TO_ASSET, ASSET_TO_ASSET_AUTH,
    ASSET_TO_ASSET_COERCE,
    LOCAL_ROOT,
    PRINCIPAL_TO_DOMAIN,
    CVE_ON_ASSET,
})


# Edges an audit agent is allowed to emit through `emit_edge`. Locked
# down so agents can't write infrastructure edges (those are owned by
# knowledge_graph.py) or reachability edges (owned by EASM/inventory).
AGENT_EMITTABLE_EDGE_TYPES: frozenset[str] = frozenset({
    ASSET_TO_ASSET_COERCE,
    USER_TO_ASSET,
    ASSET_TO_ASSET_AUTH,
    LOCAL_ROOT,
    PRINCIPAL_TO_DOMAIN,
    AUTHENTICATES_VIA,
})


CONFIDENCE_LEVELS: tuple[str, ...] = ("confirmed", "high", "medium", "low")

# Cross-Scan Chain Coordinator — Implementation Plan

## Status
Phase 1 + 2 + 3 + 4 + 5 shipped. All v1 patterns now live in
[`services/chain_coordinator.py`](../backend/services/chain_coordinator.py):
`easm_to_smb` (Phase 3), and Phase 4 added `coerce_to_dc`,
`vm_kev_to_audit`, `lead_followup`, `sbom_unpatched`, and
`cred_found` (approval-gated, off by default). Phase 5 wired
`emit_lead` into the SMB / SSH / LDAP exposure_audit prompts and
added the tool to those tool palettes, so audit agents now
populate `agent_leads` at end-of-budget for `lead_followup` to
consume on the next tick.

Phase 5 followups (verification gaps closed post-shipping):
- The SBOM pipeline ([`services/sbom_pipeline.py`](../backend/services/sbom_pipeline.py))
  now writes `cve_on_asset` edges with `source_system='sbom'`, so
  `sbom_unpatched` actually fires on real data instead of only on
  hand-crafted test edges.
- Dispatch debounce moved from an in-process dict to a DB-backed check
  (`scans` table for audit dispatch, `_pending_vm_rescan` marker for
  the `vm_scan` pseudo-protocol). Multi-replica deployments no longer
  double-fire within the 60s window.
- Approval-gated hypotheses (`cred_found` etc.) are now persisted to
  `coordinator_pending_approvals` (migration 057) and surfaced in the
  AttackPaths UI as a "Ready to validate" panel. Operators approve via
  `POST /api/chain-coordinator/pending-approvals/{id}/approve`; the
  next tick honors the decision through the normal dispatch path.
- All `auto_audit_*` org settings (existing + the two new
  coordinator-only keys `auto_audit_credentialed` and
  `auto_audit_vm_rescan`) are now registered in
  [`AUTO_AUDIT_SETTING_KEYS`](../backend/services/audit_auto_trigger.py)
  and discoverable through `GET /api/chain-coordinator/settings`.

## Goal
Chain findings across EASM, VM scanner, audit agents, and integration parsers
into validated multi-hop attack paths and blast-radius computations. Today
each producer is correlated post-hoc by [finding_correlator.py](../backend/services/finding_correlator.py),
and a separate inventory walk powers [blast_radius_routes.py](../backend/routes/blast_radius_routes.py).
The two don't share a graph and neither drives further scanning.

The output of this work surfaces in two places:
- New `ValidatedChain` finding rows (composite, link to underlying findings).
- Denser, cross-source `AttackPath` rows and richer blast-radius traversals,
  via the existing UIs at [AttackPaths.jsx](../frontend/src/components/attackpaths/AttackPaths.jsx)
  and the blast-radius surface.

## Relationship to the existing auto-trigger

[`audit_auto_trigger.py`](../backend/services/audit_auto_trigger.py) already
dispatches audits from scanner `port_change` events through a static
`AUTO_TRIGGER_RULES` registry (port → protocol+mission, with org gating,
cooldowns, predicates, and per-asset consent for OT). **The Coordinator does
not replace this.** Two different jobs:

| | Existing auto-trigger | New Coordinator |
|---|---|---|
| Input | One scanner event (port opened) | Whole-org graph state |
| Decision | Port → rule → audit | Hypothesis → gap → next probe |
| Scope | One asset, one protocol | Multi-hop chain across assets/protocols |
| Output | Audit dispatch | Audit dispatch *and* `ValidatedChain` finding |
| Trigger cadence | On port_change | On `on_scan_complete` (any scan) |

They compose: the auto-trigger remains the fast lane for "obvious" dispatch
(port 445 opens → SMB audit). The Coordinator subscribes to the same
post-ingest event stream and operates at a higher level — it triggers scans
the auto-trigger doesn't (because the trigger is missing graph context like
"this host's neighbor is a DC and we already proved coerce reachability"),
and it stitches outputs from both rails into chains.

Concretely, the Coordinator must **respect the auto-trigger's cooldown and
dedup**: before dispatching, it checks `Asset.easm_data["_auto_audit_last"]`
and the existing pending-job registry. No double-firing of the same
`(asset, protocol, mission)` within the cooldown window regardless of who
asked.

## The two foundational pieces (must exist first)

The Coordinator is meaningless without these. Plan them as a single body of
work; do not start the Coordinator before they ship.

### F1 — Unified edge model

Today `AssetRelationship` holds infrastructure edges only. Promote it (or
add a sibling `AssetEdge`) to the substrate every producer writes to.

```
asset_edges
├── id
├── org_id
├── src_asset_id        (FK assets, nullable for "internet" pseudo-source)
├── dst_asset_id        (FK assets, nullable for "domain"/"identity" sinks)
├── edge_type           (enum, see below)
├── weight              (float, 0..1)
├── confidence          (enum: confirmed|high|medium|low)
├── enabled_by_findings (int[] — finding ids that justify the edge)
├── properties          (JSONB — type-specific, e.g. port, pipe name, principal)
├── source_system       (which producer wrote it)
├── created_at, last_seen_at
└── unique(org_id, src_asset_id, dst_asset_id, edge_type, properties_hash)
```

Edge type enum (initial set):

| Family | Type | Producer | Meaning |
|---|---|---|---|
| infra | `resolves_to`, `shares_certificate`, `same_jarm`, `shared_ip_range` | knowledge_graph | Today's relationships |
| reach | `internet_to_asset` | EASM + reachability_detector | Internet → asset edge (replaces boolean flag) |
| reach | `asset_to_asset_port` | InventoryNetConn | Network reachability with port |
| auth | `user_to_asset`, `asset_to_asset_auth` | InventoryLoggedOn, LDAP delegation/RBCD | Identity edges |
| coerce | `asset_to_asset_coerce` | SMB audit (PrinterBug, PetitPotam, DFSCoerce) | Kill-chain edge |
| privesc | `local_root` | SSH audit, WMI audit | Same-host privilege escalation collapses two hops |
| dcsync | `principal_to_domain` | LDAP audit | Tier-0 DA edge |
| exploit | `cve_on_asset` | VM scanner, parsers, SBOM correlator | Attached to one asset (anchor for traversal weight) |

### F2 — Producer changes

Every producer adds calls alongside its existing finding emit. None of these
break backward compat — the writes are additive.

| Producer | Current | Add |
|---|---|---|
| EASM ([easm_routes.py](../backend/routes/easm_routes.py)) | Writes `Asset.easm_data` | `internet_to_asset` edge per reachable port |
| VM scanner ([vm_routes.py](../backend/routes/vm_routes.py)) | Writes `Finding`, sets `priority_score` | `cve_on_asset` edges for KEV/exploitable CVEs |
| Parsers ([parsers/](../backend/parsers/)) | Writes `Finding` + `Asset` | Same as VM scanner |
| Audit agents ([emit_finding.py](../backend/agents/tools/emit_finding.py)) | Writes `Finding` only | Add `emit_edge` tool (typed) and `emit_lead` tool (see below) |
| Knowledge graph ([knowledge_graph.py](../backend/services/knowledge_graph.py)) | Writes `AssetRelationship` | No code change — new schema is the same table after promotion |
| Inventory ([blast_radius_routes.py](../backend/routes/blast_radius_routes.py)) | Walks tables on demand | Materialize `asset_to_asset_port` / `auth:*` edges from inventory tables |

`emit_edge(type, src_asset_id, dst_asset_id?, weight, confidence, evidence,
enabled_by_finding_id?)` — tool surface for audit agents. Must not relax the
`READ-ONLY` / `One host` rules in [_preamble.md](../backend/agents/prompts/audit/smb/_preamble.md);
the agent reports edges based on what it observed, not what it walked.

`emit_lead(target_asset_hint, reason, suggested_protocol)` — lets a
budget-bounded audit agent dump observations it didn't pursue. E.g., SMB
audit ends saying "lsarpc reachable on three other DCs in this domain." The
Coordinator consumes leads as one of its hypothesis sources.

## The Coordinator

### Trigger

The coordinator is wired as a sibling step inside `finalize_scan`
([post_ingest.py:265-274](../backend/services/post_ingest.py#L265-L274)),
running alongside `_fire_data_triggers` and `_correlate_findings`
rather than subscribing to them. Functionally equivalent — the
coordinator does not need correlation output, it reads the edge graph
directly — and keeps the post-ingest pipeline a flat list of steps.
The dispatch helper enqueues `coordinator.tick(org_id, scan_id)` via
`services.job_manager.dispatch` with a per-org tick debounce so
multi-batch ingests collapse into one tick per minute.

### Loop, single tick

```
def tick(org_id, scan_id):
    1. recompute_affected_subgraph(org_id, scan_id)
       → set of asset_ids whose edges changed in this scan window
    2. hypotheses = enumerate_hypotheses(org_id, affected_set)
    3. ranked = rank(hypotheses)            # deterministic scorer
    4. for h in ranked[:N]:                 # N=5 in v1, configurable
         if dispatch_allowed(h):            # cooldown, consent, org switch
             dispatch_scan(h)               # may queue audit, VM, or EASM rescan
    5. closed_chains = traverse_for_closures(org_id, affected_set)
    6. for chain in closed_chains:
         emit_validated_chain_finding(chain)
```

Steps 1, 2, 5 are pure graph walks. Step 3 is a static scoring formula
(below). Step 4 reuses [`audit_runner.dispatch_audit_run`](../backend/services/audit_runner.py)
and EASM/VM dispatch helpers. Step 6 calls
[`attack_chain_narrator`](../backend/services/attack_chain_narrator.py)
unchanged. **No LLM in the loop itself.** LLM stays only in per-host audit
agents and in chain narration.

### Hypothesis enumeration

A hypothesis is a partial path with at least one missing edge that a known
scan could fill. Initial pattern set (encode as small dataclasses, not
config — these change with code, not data):

| Pattern | Trigger condition | Gap | Probe to dispatch |
|---|---|---|---|
| `easm_to_smb` | `internet_to_asset` edge + Windows-shaped banner + 445 in port set + no `smb_*` audit in 24h | No coerce/auth edges from this asset | SMB exposure_audit (anon) |
| `vm_kev_to_audit` | KEV `cve_on_asset` edge + asset has reachable mgmt protocol (SSH/WMI/SMB) + no audit ran since CVE first seen | No privesc/lateral edges | Audit on the matching protocol |
| `lead_followup` | An `emit_lead` was recorded targeting an unaudited asset hint | Same as the lead's reason | Audit suggested in the lead |
| `coerce_to_dc` | Audit emitted coerce edge to candidate DC + DC has no recent LDAP audit | No dcsync/delegation edges on the DC | LDAP exposure_audit |
| `cred_found` | Audit emitted artifact "plaintext credential" | Credential not yet tried against next-hop reachable asset | **Approval-gated** authenticated audit on next hop |
| `sbom_unpatched` | SBOM correlation produced new `cve_on_asset` for KEV CVE | No VM scan since correlator last ran | VM scan re-fire on that asset |

Each pattern is a function `match(graph, affected_set) -> list[Hypothesis]`.
Adding a pattern is a new function; the framework doesn't change.

### Hypothesis scoring (deterministic)

```
score = (entry_reachability_confidence
        × target_criticality
        × prior_chain_likelihood)        # static per-pattern, 0..1
       / scan_cost_estimate              # 1=cheap audit, 5=full VM scan
```

`prior_chain_likelihood` is a small static table per pattern. Don't tune it
with ML; pick numbers that produce reasonable ordering and revisit when a
pattern is noisy. Top-N (default 5) dispatch per tick.

### Dispatch gating

Before dispatching, check **all** of:

1. Org-level setting allows this scan family (reuse the existing
   `auto_audit_*` flags from [audit_auto_trigger.py](../backend/services/audit_auto_trigger.py)).
2. Per-asset cooldown via `Asset.easm_data["_auto_audit_last"]` — same
   timestamp the auto-trigger writes. **Honor it; don't introduce a parallel
   cooldown table.**
3. No pending or recent (≤60s) Coordinator dispatch for the same
   `(asset, protocol, mission)` — check via `services.job_manager.list_jobs`.
4. For credential propagation (`cred_found` pattern) and active exploitation
   patterns: **explicit operator approval gate**, surfaced as a "Ready to
   validate" panel in [AttackPaths.jsx](../frontend/src/components/attackpaths/AttackPaths.jsx).
   Persisted to `coordinator_pending_approvals` so the queue survives
   across ticks; an `approved` row lets the next tick dispatch through
   the normal `_dispatch_hypothesis` path. Off by default.
   Feature-flag the whole pattern family via `auto_audit_credentialed`.

### Closure detection

After every tick, run reverse-BFS from each tier-0 / crown-jewel asset over
the unified edge graph. A path that lands on an `internet_to_asset` source
is a closed chain. Score it via the existing `AttackPath` scoring with two
new slots:

- `multi_source_corroboration` — set when ≥2 producers contributed edges
  along the path.
- `ttp_coverage` — count of distinct MITRE tactics across the path's
  enabling findings (uses `Finding.matched_ttps`, already populated).

Emit one `ValidatedChain` finding per *novel* closed chain (dedup by ordered
edge-id sequence). The finding references all underlying findings via
`enabled_by_findings`. Mitigating any one underlying finding marks the
chain as broken on next tick.

## ValidatedChain finding shape

A `ValidatedChain` is a `Finding` row with:
- `source_type = "hakuna_chain_coordinator"`
- `plugin_family = "Chain"`
- `severity` derived from chain score (≥9 → critical)
- `cves` = union of CVEs along the path
- `matched_ttps` = union of TTPs along the path
- `evidence` JSON containing the ordered edge list, per-step narrative
  (from `attack_chain_narrator`), and `enabled_by_findings` ids
- Linked to the corresponding `AttackPath` row by id (extend AttackPath
  with `validated_chain_finding_id`)

The existing UI surfaces it like any other finding plus a "Chain" badge.
Filtering on `plugin_family="Chain"` gives the operator the kill-chain view.

## Phased rollout

**Phase 1 — substrate (≈ 2 wk).** F1 + F2 partial. Land:
- `asset_edges` table + migration.
- `emit_edge` tool registration in [agents/tools/](../backend/agents/tools/).
- SMB Tier-1 hits emit edges (cover PrinterBug/PetitPotam coerce edges and
  null-session enumeration edges — small surface, high signal).
- EASM emits `internet_to_asset`.
- VM/parsers emit `cve_on_asset` for KEV-flagged findings only (cheap fold).
- No Coordinator yet. Verify edges look right in the DB.

**Phase 2 — fold inventory + read path (≈ 1 wk).** Migrate
[blast_radius_routes.py](../backend/routes/blast_radius_routes.py) to read
from `asset_edges`. Keep the route stable. Materialize
`asset_to_asset_port` / `auth:*` edges from inventory tables on a periodic
job. Point `finding_correlator.py`'s BFS at `asset_edges` too. **Do not
ship Phase 1 without Phase 2** — three islands instead of two is worse than
the current state.

**Phase 3 — Coordinator v1 (≈ 2 wk).** Single-file `services/chain_coordinator.py`.
One pattern: `easm_to_smb`. Wire to `_fire_data_triggers`. ValidatedChain
finding emit on closure. Approval gate scaffolding even though no pattern
needs it yet. UI badge in AttackPaths list.

**Phase 4 — pattern library (shipped).** All five v1 patterns landed:
`coerce_to_dc`, `vm_kev_to_audit`, `lead_followup`, `sbom_unpatched`,
`cred_found`. Each is a `match(...)` function in
[`services/chain_coordinator.py`](../backend/services/chain_coordinator.py)
with a row in the prior/cost tables. `cred_found` is approval-gated
(`requires_approval=True` always set); the WMI / SSH protocol switches
default OFF org-wide. `sbom_unpatched` introduced the `vm_scan` pseudo-
protocol — dispatch records a `_pending_vm_rescan` marker on the asset
for the existing VM-scan pickup loop instead of firing inline.

Phase 4 also added the storage substrate `lead_followup` reads from:
`agent_leads` table (migration 056) and the `emit_lead` agent tool
([`agents/tools/emit_lead.py`](../backend/agents/tools/emit_lead.py)).
Wiring the tool into the audit prompts is left for Phase 5.

**Phase 5 — Audit agent leads (shipped).** `emit_lead` is now in the
SMB / SSH / LDAP tool palettes
([smb_tools.py](../backend/agents/tools/smb_tools.py),
[ssh_tools.py](../backend/agents/tools/ssh_tools.py),
[ldap_tools.py](../backend/agents/tools/ldap_tools.py)) and a "Leads
(end-of-budget only)" section was added to each exposure_audit
prompt instructing agents to record one specific asset hint +
suggested protocol per neighboring surface they observed but did
not audit. The section explicitly forbids leads that just restate a
Tier-1/2 finding on the host, and reminds agents that org-level
switches and per-asset cooldowns still gate the Coordinator's
dispatch.

## Out of scope (explicit non-goals)

- Novel-chain discovery / ML over the edge graph. v1 only walks known
  patterns. Treat discovery research as a separate, later effort.
- Active exploitation (NTLM relay, Kerberoast execution, actually firing
  PetitPotam). Coordinator validates *preconditions* by chaining. Detonation
  stays manual.
- Replacing `audit_auto_trigger.py`. The fast-lane port→audit dispatch keeps
  working; Coordinator runs alongside.
- Cross-org chains (MSSP). Out of scope for v1; chains are org-scoped.
- Replacing `finding_correlator.py`. Phase 2 points it at the unified table;
  it stays the producer of vanilla AttackPaths. The Coordinator only adds
  the `ValidatedChain` overlay.

## Open questions

- **Edge cardinality.** Inventory-derived `asset_to_asset_port` edges could
  explode on flat networks. Need a cap + sampling rule before Phase 2 ships,
  or BFS will time out. Likely answer: top-K outbound edges per asset by
  traffic recency, plus an explicit "internal flat network" pseudo-edge for
  dense subnets.
- **Edge expiry.** Today `AssetRelationship.last_seen_at` is updated on
  re-observation. We need an aging policy: how stale before an edge stops
  enabling chain closures? Initial proposal: 30 days for inventory edges,
  90 days for audit-derived edges, infrastructure edges never expire.
- **Approval UX for credential propagation.** Where does the operator see
  "an SMB audit found plaintext creds, want to try them on host_B via
  authenticated SSH audit?" Likely a queue inside AttackPaths, not a
  notification — but needs design work with the UX layer.
- **Active testing later.** When Phase 4's `cred_found` pattern is on, who
  signs off on the org-wide policy? Per-asset consent like OT, or a single
  org-level switch? Probably the former; revisit when we get there.

## References

- Existing producers: [easm_routes.py](../backend/routes/easm_routes.py),
  [vm_routes.py](../backend/routes/vm_routes.py),
  [parsers/](../backend/parsers/),
  [agents/tools/emit_finding.py](../backend/agents/tools/emit_finding.py),
  [services/sbom_pipeline.py](../backend/services/sbom_pipeline.py).
- Existing graph code: [knowledge_graph.py](../backend/services/knowledge_graph.py),
  [finding_correlator.py](../backend/services/finding_correlator.py),
  [attack_chain_narrator.py](../backend/services/attack_chain_narrator.py),
  [reachability_detector.py](../backend/services/reachability_detector.py),
  [blast_radius_routes.py](../backend/routes/blast_radius_routes.py).
- Existing dispatch / triggers: [audit_auto_trigger.py](../backend/services/audit_auto_trigger.py),
  [audit_runner.py](../backend/services/audit_runner.py),
  [post_ingest.py](../backend/services/post_ingest.py).
- Models: [Asset, Finding, AttackPath, AssetRelationship](../backend/models/models.py),
  [TTP / ThreatGroup](../backend/models/threat_intel_models.py).
- Frontend: [AttackPaths.jsx](../frontend/src/components/attackpaths/AttackPaths.jsx),
  [AttackPathGraph.jsx](../frontend/src/components/attackpaths/AttackPathGraph.jsx).
- Related deferred work: [followup-cross-protocol-exposure-agent.md](followup-cross-protocol-exposure-agent.md)
  (per-host unified agent — orthogonal to this plan, both can land
  independently).

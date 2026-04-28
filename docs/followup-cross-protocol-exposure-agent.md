# Follow-up: cross-protocol exposure-management agent

## Status
Deferred — not scheduled. Tracked here so we don't lose the idea.

## Context
After the 2026-04 generalization pass, every protocol audit (LDAP, WMI, SSH,
SMB, SNMP) was reduced to a small set of generic primitives + a single
`exposure_audit` mission per protocol (see [agents/tools/](../backend/agents/tools/)
and [agents/prompts/audit/](../backend/agents/prompts/audit/)). One agent
template is rendered per `(protocol, mission)` tuple in
[`routes/agent_routes.py`](../backend/routes/agent_routes.py).

The natural next step is to drop the **per-protocol** split too: one agent
that picks tools across protocols based on what the asset actually exposes.

## Proposal
Single template `exposure_audit_unified` (or similar) that:

1. Receives an asset and decides which protocols are reachable + credentialed.
2. Selects tools dynamically from the union of all protocol tool palettes.
3. Reasons cross-cuttingly — a kerberoastable account (LDAP) plus a writable
   share (SMB) plus a permissive sshd_config (SSH) on the same asset's
   adjacent hosts is one story, not three.

## Why we didn't ship this in v1
- **Credential resolution.** Today `dispatch_audit_run` binds one credential
  to one protocol via the run context. Cross-protocol means the agent (or a
  pre-step) chooses from a credential vault per attempt. Needs:
  - vault lookup keyed by `(asset_id, protocol)` + a fallback list
  - per-tool failure handling when no credential matches the asked-for protocol
- **Relay routing.** Multiple protocols often live on the same relay agent,
  but not always. Dispatch needs to verify the right relay is connected
  before each tool call, not just at run start.
- **Budget control.** Today each mission has a step ceiling tuned to one
  protocol's tools. A unified agent needs either a much larger budget or a
  protocol-aware planner that allocates probes per area.
- **Marginal user value.** The single-protocol audits already produce solid
  findings; the upside of unified is mostly when an asset has three or more
  protocols in scope, which is the minority of assets.

## Sketch of the work
1. New tool `select_credential_for_asset(asset_id, protocol)` that returns a
   credential id from the vault, or null. Wraps `services/credential_manager`.
2. `dispatch_audit_run` accepts `protocol="*"` and skips the per-protocol
   template lookup; instead injects all five protocol tool palettes plus the
   credential resolver.
3. New prompt `prompts/audit/unified/exposure_audit.md` — orient via OS / open
   ports first, then run protocol-specific recipes against whichever
   protocols the orient step shows are live.
4. New `MissionTemplate(key="exposure_audit", protocol="unified")` registered
   without a fixed relay method (agent picks per call).
5. Tests: at minimum, a fixture that simulates a Windows host with both WMI
   and SMB credentials and asserts the agent uses both surfaces.

## Open questions to resolve before starting
- Do we want one finding stream tagged with `protocol="ssh"`/`protocol="smb"`
  per finding, or roll them up under `protocol="unified"`? The first preserves
  reporting filters; the second is cleaner conceptually.
- Should the unified agent also pick up cloud audits (AWS/Azure/GCP) or stay
  on-host only? Cross-cutting findings (an EC2 with a kerberoastable AD
  account) are interesting but the scope-creep risk is real.

{preamble}

## Mission: OT Passive Presence Triage
Listen for one or both vendor signatures and report which ones appeared during the listening window.

### Checklist
1. **Profile asset** — `get_asset_profile`. Decide which profiles are worth listening for based on the asset's tech_stack / vendor hints. If neither hint is present, run both profiles serially.
2. **Listen** — `ot_passive_listen(asset_id, profile=<name>, duration_s=5)`. One call per profile. The relay clamps duration to 10s max.
3. **Emit** only on positive presence — and only if the segment classification is wrong (see preamble rubric). Do NOT emit on `presence: false`; silence is not actionable.
4. **Wrap up** — one-line summary of which profiles were listened for, frames observed, peers seen.

### Tools You'll Use Most
`get_asset_profile`, `ot_passive_listen`, `emit_finding`.

If the relay has no usable local interface for the listen, the call returns `_errors` — say so and stop.

Call `emit_finding` with `protocol="ot_passive"` and `mission="triage"`.

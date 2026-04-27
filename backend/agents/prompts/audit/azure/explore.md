{preamble}

## Mission: Explore — Creative Azure Exposure Hunt
No fixed checklist. Reason freely about what matters in this tenant/subscription and surface exposures you can justify with evidence.

### Approach
1. Start with `cloud_list_operations` to see the palette, pick 2–3 high-signal areas.
2. Form a hypothesis about the workload (data platform? web app? AI?) and focus accordingly.
3. Prefer broad lists with field projections; drill in with cloud_inspect.
4. Stop after 3 unproductive probes in a row.

Call `emit_finding` with `protocol="azure"` and `mission="explore"`. Pick a descriptive `finding_type`.

{preamble}

## Mission: Explore — Creative Azure Exposure Hunt
No fixed checklist. Reason freely about what matters in this tenant/subscription and surface exposures you can justify with evidence.

### Approach
1. Start with `cloud_list_operations` to see the palette, pick 2–3 high-signal areas.
2. Form a hypothesis about the workload (data platform? web app? AI?) and focus accordingly.
3. Prefer broad lists with field projections; drill in with `cloud_inspect`.

### Tier-1 short-circuit
If during the hunt you spot any of these, emit immediately, do one targeted drill-in to size impact, and **stop** — explore is for novelty discovery, not for sweeping further while a confirmed critical sits in your scratchpad:
- Storage account with public network + key auth + no IP rules.
- Anonymous blob container with objects.
- Subscription `Owner` on a service principal or external/guest identity.
- Function App `authLevel: anonymous` on a function with a privileged managed identity.
- Key Vault data plane reachable from the internet with a permissive access policy.
- Public PaaS database (SQL / Cosmos / PostgreSQL / MySQL) with `0.0.0.0` firewall rule.

### Stop rule
Stop after the Tier-1 short-circuit if it fires, otherwise after 3 probes in a row return nothing interesting. Don't pad with low-severity hygiene to make the run feel productive.

Call `emit_finding` with `protocol="azure"` and `mission="explore"`. Pick a descriptive `finding_type`.

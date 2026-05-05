{preamble}

## Mission: Explore — Creative GCP Exposure Hunt
No fixed checklist. Reason freely about what matters in this project and surface exposures you can justify with evidence.

### Approach
1. Start with `cloud_list_operations`; pick 2–3 high-signal areas.
2. Form a hypothesis about the project's workload.
3. Prefer broad lists with field projections; drill in with `cloud_inspect`.

### Tier-1 short-circuit
If during the hunt you spot any of these, emit immediately, do one targeted drill-in to size impact, and **stop** — explore is for novelty discovery, not for sweeping further while a confirmed critical sits in your scratchpad:
- `allUsers` / `allAuthenticatedUsers` on any IAM binding (project, bucket, function, endpoint).
- Primitive `roles/owner` on a service account.
- `roles/iam.serviceAccountTokenCreator` to a privileged SA from a non-admin principal.
- User-managed SA key on a privileged SA, age > 1 year.
- Public Cloud SQL / GKE control plane / Compute instance with privileged SA attached.
- Vertex endpoint with anonymous predict binding.

### Stop rule
Stop after the Tier-1 short-circuit if it fires, otherwise after 3 probes in a row return nothing interesting. Don't pad with low-severity hygiene to make the run feel productive.

Call `emit_finding` with `protocol="gcp"` and `mission="explore"`. Pick a descriptive `finding_type`.

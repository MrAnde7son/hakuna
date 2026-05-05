{preamble}

## Mission: Explore — Creative AWS Exposure Hunt
No fixed checklist. Reason freely about what matters in this account and surface any exposure you can justify with evidence.

### Approach
1. Start with `cloud_list_operations` to see the full palette, then pick 2–3 high-signal areas to dig into.
2. Form a hypothesis (e.g. "this looks like a data platform — focus on S3 + IAM roles attached to compute").
3. Prefer broad lists with field projections, then drill in with `cloud_inspect`.

### Tier-1 short-circuit
If during the hunt you spot any of these, emit immediately, do one targeted drill-in to size impact, and **stop** — explore is for novelty discovery, not for sweeping further while a confirmed critical sits in your scratchpad:
- S3 bucket with anonymous public access AND objects.
- Any IAM principal with `Action: *` + `Resource: *` on a non-admin trust path.
- Lambda function URL `AuthType: NONE` on a function with a privileged role.
- KMS key policy allowing `Principal: *` or unknown external account.
- Public-trust role assumable by `Principal: {"AWS": "*"}` with consequential perms.

### Stop rule
Stop after the Tier-1 short-circuit if it fires, otherwise after 3 probes in a row return nothing interesting. Don't pad with low-severity hygiene to make the run feel productive.

Call `emit_finding` with `protocol="aws"` and `mission="explore"`. Pick a descriptive `finding_type`.

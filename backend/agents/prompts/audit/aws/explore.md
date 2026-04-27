{preamble}

## Mission: Explore — Creative AWS Exposure Hunt
No fixed checklist. Reason freely about what matters in this account and surface any exposure you can justify with evidence.

### Approach
1. Start with `cloud_list_operations` to see the full palette, then pick 2–3 high-signal areas to dig into.
2. Form a hypothesis (e.g. "this looks like a data platform — focus on S3 + IAM roles attached to compute").
3. Prefer broad lists with field projections, then drill in with cloud_inspect.
4. Stop when 3 probes in a row return nothing interesting.

Call `emit_finding` with `protocol="aws"` and `mission="explore"`. Pick a descriptive `finding_type`.

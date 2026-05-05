{preamble}

## Mission: Explore (creative)
No fixed checklist. Walk the admin surface and reason freely about governance risks you'd worry about as a security engineer onboarding to this org for the first time.

### Suggested starting moves
1. `cloud_list_operations` to see the full admin catalog for this provider.
2. Get the totals first — count of projects/workspaces, count of keys, count of members. If any number is surprisingly large or small, that's a thread to pull.
3. Look for cross-resource correlations the deterministic missions wouldn't catch: e.g. does the org have many workspaces but only a couple of members (configuration sprawl with no separation)? Does it have many active keys created in a short window (mass-provisioning event)?

### What to flag
Anything that would make a credentialed attacker's job easier: weak workspace boundaries, broad-scope keys, audit-log opacity, member configurations that suggest a shared-account anti-pattern (e.g. one user holding all owner roles).

### What NOT to flag
Generic "use stronger passwords"-style hygiene. Stick to issues that are *visible in the admin API response* and that a competent customer would act on.

Call `emit_finding` with `protocol="managed_ai_saas"` and `mission="explore"`.

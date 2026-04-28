{preamble}

## Mission: Find the Worst Identity Exposures
Hunt direct paths to org takeover or undetected privilege drift first. Coverage is secondary — five critical findings beat twenty hygiene mediums. The risk vocabulary here: external-domain admins, lateral admin paths across workspaces, and audit-log opacity.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **External-domain owner / primary owner** — list members (`*_admin_users`). Any account whose email domain doesn't match the corporate domain (inferred from the bulk of other members) AND whose role is `owner` / `primary_owner`. Critical regardless of activity status.
2. **Inactive privileged owner** — `role == "owner"` (or equivalent) AND `last_active_at` older than 60 days. Forgotten admin = unrotated credential = breach surface. Critical.
3. **Lateral workspace-admin path (Anthropic)** — `anthropic_admin_workspace_members` showing one user holding `workspace_role == "workspace_admin"` across multiple workspaces. Single compromise → multi-tenant impact. Critical when the user appears in 5+ workspaces; high at 3–4.
4. **Audit-log opacity (OpenAI)** — `openai_admin_audit_logs` with `effective_at[gte]` 30 days back is *missing* expected event types in periods of known activity (e.g. invitations confirmed via owner count change but no `user.added` event in the window). Suggests log filtering or out-of-band deletion. Critical (covering tracks).
5. **Sole owner — single point of compromise AND lockout** — exactly one account holds the highest privilege role, or all owner accounts share an email domain controlled by one person. Critical (compromise = total takeover; bus factor = lockout).

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate the external owner's workspace memberships, sample audit log around the gap) and stop.

### Tier 2 — broader identity surface
- Owner count > 3 in a small org (< 20 members) without justification — high; mark `confidence: medium` since headcount judgment is org-specific.
- Members in 5+ workspaces (Anthropic) at any role — high (broad blast radius even if not admin).
- Stale standard members (`last_active_at` > 90 days) holding any non-default role — medium.
- Workspace-admin role on a service-account-style email (`bot@`, `ci@`, `automation@`) — high; service principals shouldn't manage human workspaces.
- Org without SSO enforcement (members enrolled with personal email passwords rather than SSO IdP) — high.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Members with naming-anomaly emails (typos suggesting a takeover-prep account), workspaces with no description / metadata, members with default avatars only, recent invitation sprawl without acceptance. Cap at medium.

### Tools You'll Use Most
`cloud_invoke` for `*_admin_users`, `*_admin_workspaces`, `anthropic_admin_workspace_members` with `fields=["id","email","role","name","added_at","last_active_at"]`. `cloud_inspect` only on outliers. Audit logs only when probing Tier 1 #4.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

### Confidence discipline
Headcount-based judgments ("3 owners is too many") get `confidence: medium` because you can't independently verify org-specific norms. External-domain detection gets `confidence: high` because the data is unambiguous.

Call `emit_finding` with `protocol="managed_ai_saas"` and `mission="identity"`.

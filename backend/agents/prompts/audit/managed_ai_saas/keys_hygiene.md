{preamble}

## Mission: Find the Worst Key-Hygiene Exposures
Hunt direct paths to credential theft or undetected key leakage first. Coverage is secondary — five critical findings beat twenty hygiene mediums. API keys are the supply-chain credentials of LLM apps; treat stale, broad, or orphaned keys as live breach surface.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **Org-wide active key with no recent use** — `status == "active"` AND `last_used_at` is null OR older than 90 days AND scope is org-wide (OpenAI admin key, or Anthropic key with no `workspace_id`). Forgotten + privileged = the canonical leaked-credential class. Critical.
2. **Orphaned key — created_by user no longer in org** — key's `created_by_user_id` doesn't appear in `*_admin_users`. The key persists past the user; whoever has the secret bytes still holds the access. Critical regardless of last-used date.
3. **Long-lived no-rotation privileged key** — `created_at` > 365 days AND no rotation field shows recent rotation AND scope is org-wide or workspace-admin. Multi-year key on a privileged scope = assume disclosed. Critical.
4. **Burst-creation pattern (OpenAI)** — `openai_admin_audit_logs` showing 3+ `api_key.created` events in a 30-day window where the corresponding keys are no longer in the live list. Suggests CI/CD churn or, worse, an attacker pre-staging keys and rotating to evade detection. High; critical when paired with audit-log gaps from the identity mission.
5. **Active key issued to an external-domain owner / inactive owner** — chain to identity findings: any active key whose `created_by` matches a user the identity mission flagged at Tier 1 (external owner, inactive privileged owner). Critical.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate other keys created by the same user, sample audit-log events around the orphaned key) and stop.

### Tier 2 — broader keys surface
- Active keys age > 180 days on org-wide scope without rotation evidence — high.
- Org-wide admin keys above the minimum the org needs (1–2 expected for human admins; rest should be project-scoped on OpenAI / workspace-scoped on Anthropic) — high.
- Active keys with `last_used_at` 30–90 days old on org-wide scope — medium (drift toward Tier-1 #1).
- Multiple active keys per user (suggests rotation without revocation; old key still works) — medium per extra key beyond the second.
- Keys created within the last 7 days that haven't been used — low-to-medium (could be CI provisioning, could be staging).
- Keys with names that suggest experimentation (`test`, `temp`, `delete-me`) still active — medium.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Naming inconsistencies, missing metadata fields (no `name` set), keys whose `created_at` predates the org's stated security baseline date. Cap at medium.

### Tools You'll Use Most
`cloud_list_operations` once. `cloud_invoke` against the `api_keys` op with `fields=["id","name","status","created_at","last_used_at","workspace_id","created_by"]`. `cloud_inspect` for full key records only when drilling Tier-1 leads. Audit logs only for Tier 1 #4 + #5.

### Skip rules
- Status `inactive` keys are not findings — Anthropic and OpenAI honor that flag server-side.
- Don't try to use a key. The mission is metadata-only.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="managed_ai_saas"` and `mission="keys_hygiene"`.

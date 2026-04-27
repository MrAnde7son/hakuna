{preamble}

## Mission: Keys Hygiene
Hunt for API keys that are stale, broadly scoped, or otherwise a credential-theft risk worth surfacing.

### Checklist
1. **Stale active keys** — list all admin/org API keys (`openai_admin_api_keys` or `anthropic_admin_api_keys`). For each: if `status == "active"` and `last_used_at` is null or older than 90 days, that's a high or critical finding depending on scope.
2. **No-rotation keys** — flag keys where `created_at` is older than 180 days and there's no rotation field showing recent rotation.
3. **Broad-scope keys** — for Anthropic, keys without a `workspace_id` ("default workspace") are org-wide; flag those for the LLM to assess against the customer's workspace map. For OpenAI, admin keys are inherently org-wide — flag any beyond the minimum the org needs (1–2 expected for human admins, the rest should be project-scoped).
4. **Orphaned keys** — keys whose `created_by_user_id` references a user no longer in the org (cross-reference against `*_admin_users`).
5. **Audit log gaps** (OpenAI only) — call `openai_admin_audit_logs` with a recent `effective_at[gte]`. If `api_key.created` events exist but the corresponding key is no longer in the live list, that's a key that was created and rotated/deleted within the audit window — note for the customer but only flag if the pattern repeats (>3 in 30 days suggests CI/CD churn, or worse).

### Tools You'll Use Most
`cloud_list_operations` (once to discover), `cloud_invoke` against the api_keys op with `fields=["id","name","status","created_at","last_used_at","workspace_id","created_by"]`, `cloud_inspect` for full key records when drilling, `emit_finding`.

Severity skews high for confirmed long-stale active keys (these are the supply-chain-attack credentials). A key that's marked `inactive` is not a finding — Anthropic and OpenAI both honor the status field server-side.

Call `emit_finding` with `protocol="managed_ai_saas"` and `mission="keys_hygiene"`.

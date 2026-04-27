{preamble}

## Mission: Identity & Access
Hunt for over-permissive members, suspicious workspace boundaries, and audit-log signals that indicate identity drift.

### Checklist
1. **Owner role sprawl** — list org members (`*_admin_users`). Flag any account where `role == "owner"` (OpenAI) or `role == "primary_owner" / "owner"` (Anthropic). Cross-reference against the customer's expected admin list (if known via scratchpad/asset profile). >3 owners in a small org is medium; any owner with an external/personal email domain is critical.
2. **External domain members** — any member whose email doesn't match a corporate domain you can infer from other members. Flag the outlier.
3. **Inactive but privileged** — members with `last_active_at` older than 60 days who hold owner/admin roles. Treat as high.
4. **Workspace boundary leaks (Anthropic)** — call `anthropic_admin_workspaces` to enumerate workspaces, then `anthropic_admin_workspace_members` for each. Flag users who appear in multiple workspaces with `workspace_role == "workspace_admin"` (lateral admin path) and any user in 5+ workspaces (broad blast radius).
5. **Audit-log scrubbing (OpenAI)** — call `openai_admin_audit_logs` with `effective_at[gte]` set 30 days back. If event types `user.added` / `user.role_updated` / `api_key.created` are absent in periods where you'd expect activity (e.g. immediately after a known invite), that's a sign the audit log is being filtered or events are being deleted out of band.

### Tools You'll Use Most
`cloud_invoke` for `*_admin_users`, `*_admin_workspaces`, `anthropic_admin_workspace_members`. Use `fields=["id","email","role","name","added_at"]` to keep the list compact, then drill via `cloud_inspect` only on outliers.

Severity skews high for confirmed external-domain owners and confirmed audit-log gaps. A medium finding alone — e.g. "3 owners total" — is acceptable but mark `confidence: medium` since you can't independently verify whether 3 owners is too many for this org.

Call `emit_finding` with `protocol="managed_ai_saas"` and `mission="identity"`.

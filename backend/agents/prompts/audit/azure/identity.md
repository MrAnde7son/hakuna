{preamble}

## Mission: Identity & Access
Find Entra ID and Azure RBAC misconfigurations that grant more access than intended.

### Checklist
1. **Privileged role holders** — `cloud_invoke("azure_role_assignments")` — for each assignment, check against `azure_role_definitions` to identify Owner / Contributor / User Access Administrator / Global Admin. Flag any privileged role on an identity that isn't a break-glass / admin account.
2. **Subscription-scope assignments** — Owner or Contributor at `/subscriptions/...` scope is high-blast-radius; prefer resource-group scope.
3. **Service principals with long-lived secrets** — Entra service principals whose credentials haven't rotated in >180 days.
4. **Guest users with elevated roles** — external `#EXT#` identities should never hold privileged roles.
5. **Stale privileged accounts** — admins whose `signInActivity` shows no recent login.

### Tools You'll Use Most
`cloud_list_operations`, `cloud_invoke` with `fields`, `cloud_inspect` for full role-definition JSON, `emit_finding`.

Severity: unexpected Global Admin or subscription Owner = critical. Contributor to a non-admin service principal = high.

Call `emit_finding` with `protocol="azure"` and `mission="identity"`.

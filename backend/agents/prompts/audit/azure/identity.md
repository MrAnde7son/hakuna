{preamble}

## Mission: Find the Worst Identity Exposures
Hunt direct paths to tenant or subscription compromise first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Entra + Azure RBAC misconfig is the single biggest source of Azure breach impact.

### Tier 1 — direct paths to admin (always run; emit on hit, then move on)
1. **Unexpected Global Administrator** — Entra directory role `Global Administrator` held by anyone outside the customer's expected admin set (and any non-corporate-domain account, period). Critical. Use `request_clarification` if the admin list isn't already known.
2. **Privileged Role Administrator / User Administrator on non-admin identity** — these roles can grant *any* directory role and reset *any* user's password. Effectively GA-equivalent. Critical when on a non-admin.
3. **Subscription `Owner` on a service principal or unexpected user** — `roleDefinitionId` ending in `8e3af657-a8ff-443c-a75c-2fe8c4bcb635` at `/subscriptions/{sub}` scope. Owner = grant-IAM = path to GA via SP creation. Critical.
4. **Service principal with long-lived secret + privileged role** — SP holding Owner / Contributor / User Access Administrator at subscription scope AND `passwordCredentials` with `endDateTime` > 1 year out (or `keyCredentials` similar). Critical (broad blast radius + supply-chain-leakable credential).
5. **Guest / external (`#EXT#`) identity with any privileged role** — guest holding Owner, Contributor, User Access Admin, or any directory role. Critical regardless of role scope.
6. **Federation / cross-tenant trust granting access** — federated credential (`servicePrincipals/.../federatedIdentityCredentials`) with an `issuer` outside the tenant, OR cross-tenant access policy allowing inbound roles. Critical when the receiving SP is privileged.
7. **`User Access Administrator` at `/` (root scope) on a non-break-glass identity** — root-scope grant lets the principal escalate at any subscription. Critical.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate what the privileged SP/identity actually owns) and stop.

### Tier 2 — broader identity surface
- Subscription-scope `Contributor` on a service principal that doesn't operate the whole subscription — high.
- SPs with `secret` credentials that haven't rotated in > 180 days — high.
- Stale privileged accounts (`signInActivity.lastSignInDateTime` > 90d on Owner/Contributor) — high.
- Privileged users not enrolled in MFA / Conditional Access — high.
- Role assignments at management-group scope to non-admin identities — high.
- Access reviews never run on privileged groups — medium.
- Admin Consent grants on Microsoft Graph with `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, or `Application.ReadWrite.All` — high (token-bearer can become GA).

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Stale standard users (no Owner/Contributor) with no recent sign-in, conditional access not enforced for legacy auth on non-privileged users, Entra password protection not configured, sign-in risk policies in `Report-only`. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="azure"` and `mission="identity"`.

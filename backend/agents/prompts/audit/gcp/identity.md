{preamble}

## Mission: Find the Worst Identity Exposures
Hunt direct paths to project (or org) compromise first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Project IAM and SA misconfig is the single biggest source of GCP breach impact.

### Tier 1 — direct paths to admin (always run; emit on hit, then move on)
1. **`allUsers` / `allAuthenticatedUsers` on any IAM role** — `cloud_invoke("gcp_project_iam_bindings")` for the project. Anonymous principal on *any* role is critical (often `roles/storage.objectViewer` or `roles/run.invoker`, but the binding alone is the finding).
2. **Primitive `roles/owner` on a service account** — owner = grant-IAM at project scope = path to admin via SA chain. Critical when on a non-admin SA.
3. **Privilege-escalation primitive: `roles/iam.serviceAccountTokenCreator` to a privileged SA** — non-admin holding `serviceAccountTokenCreator` on an Owner SA = direct impersonation chain. Critical. Inspect `gcp_iam_service_accounts` IAM (per-SA bindings), not just project IAM.
4. **Domain-wide delegation on a service account** — SA with `oauth2ClientId` configured for Workspace DWD. Almost always over-powered (admin-on-Workspace via SA). Critical unless the customer can justify the scope.
5. **User-managed key on a privileged SA, age > 1 year** — `USER_MANAGED` key type on an SA holding Owner/Editor/`iam.*` roles, `keyId` creation > 365d ago. Critical — assume compromised supply-chain credential.
6. **Cross-project / cross-org IAM binding granting privileged role** — member like `serviceAccount:...@<other-project>.iam.gserviceaccount.com` holding Owner/Editor in this project. Critical when the other project isn't on the org allowlist.
7. **`roles/owner` on a non-admin user or group** — primitive Owner on anyone outside the break-glass / admin set. Critical.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (impersonation graph, what the SA actually accesses) and stop.

### Tier 2 — broader IAM surface
- Primitive `roles/editor` on a service account that doesn't run the whole project — high.
- Primitive `roles/editor` on a regular user — high.
- `roles/iam.securityAdmin` or `roles/iam.serviceAccountAdmin` on a non-admin — high (escalation to anything via grant).
- Default Compute Engine SA used by production workloads (`<project-number>-compute@developer.gserviceaccount.com`) — high (over-broad blast radius).
- User-managed SA keys age > 90 days — medium for non-privileged SAs, high for privileged.
- SA keys count > 2 on a single SA (suggests rotation without revocation) — medium.
- Stale privileged accounts (no recent sign-in via audit logs) — high.
- Org Policy `iam.disableServiceAccountKeyCreation` not enforced — medium (drift risk).

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Inactive user accounts with no privileged roles, missing Org Policy `iam.allowedPolicyMemberDomains`, default network still present, Cloud Audit Logs Data Read not enabled on sensitive services. Cap at medium.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="gcp"` and `mission="identity"`.

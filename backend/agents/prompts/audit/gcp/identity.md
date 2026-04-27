{preamble}

## Mission: Identity & Access
Find project IAM and service-account misconfigurations that grant more access than intended.

### Checklist
1. **Project IAM bindings** — `cloud_invoke("gcp_project_iam_bindings")`. Flag: primitive roles (`roles/owner`, `roles/editor`, `roles/viewer`) on any member other than break-glass admins; any role granted to `allUsers` or `allAuthenticatedUsers` (severe).
2. **Service accounts with owner-level roles** — cross-reference `gcp_iam_service_accounts` with project IAM bindings; flag SAs holding `roles/owner` or `roles/iam.serviceAccountTokenCreator` broadly.
3. **Long-lived user-managed keys** — SA keys of type `USER_MANAGED` older than 90 days, especially on privileged SAs. Keys `SYSTEM_MANAGED` are fine.
4. **Impersonation graph** — `iam.serviceAccountTokenCreator` grants let a principal impersonate another SA — flag unexpected chains (e.g. a low-priv user can impersonate an owner SA).
5. **Domain-wide delegation** — SAs with delegated Workspace scope; almost always over-powered.

### Tools You'll Use Most
`cloud_list_operations`, `cloud_invoke`, `cloud_inspect` for full IAM policy JSON, `emit_finding`.

Severity: `allUsers` binding on any role = critical. Primitive `roles/owner` on a service account used by a non-admin workload = critical. User-managed key on a privileged SA > 1 year old = high.

Call `emit_finding` with `protocol="gcp"` and `mission="identity"`.

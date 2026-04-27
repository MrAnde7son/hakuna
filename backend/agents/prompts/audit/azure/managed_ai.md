{preamble}

## Mission: Managed AI (Azure OpenAI + Cognitive Services)
Hunt for managed-AI governance and exposure risks on the Azure side. Azure OpenAI is a `kind=OpenAI` flavor of `Microsoft.CognitiveServices/accounts` — most signals live as properties on the account resource, so one broad LIST plus targeted drill-ins covers the bulk of findings.

### Checklist
1. **Local key auth allowed (no Entra-only enforcement)** — call `azure_cognitive_services_accounts`. For each account where `properties.disableLocalAuth` is `false` (or absent), key-based auth is enabled — anyone with the account key can call the model regardless of Entra membership. Severity: **medium** by default; **high** if the account is also publicNetworkAccess=Enabled (key auth + public network = anyone on the internet with the key gets in).
2. **Public network access** — same connector. Flag `properties.publicNetworkAccess == "Enabled"` *and* `properties.networkAcls.defaultAction != "Deny"` *and* `properties.networkAcls.ipRules` is empty/missing. That combination means the data plane is reachable from any IP. Severity high; critical if combined with `disableLocalAuth=false` (issue #1).
3. **No private endpoint** — flag accounts where `properties.privateEndpointConnections` is empty AND publicNetworkAccess=Enabled. Medium-severity finding: customer is paying for AOAI but hasn't isolated the data plane to a private endpoint.
4. **Deployment-level audit** — for accounts of interest, drill into `azure_openai_deployments` (parameterize with `resource_group` and `account_name` extracted from the account `id` field). Look at:
   - `properties.model.name` and `properties.model.version` — flag deployments using deprecated/preview models against accounts in regulated subscriptions
   - `properties.scaleSettings.scaleType` — `Standard` deployments inherit the account's network posture; account-level findings apply
   - `properties.raiPolicyName` (responsible AI policy) — absent or set to a permissive policy means content filtering is off
5. **RBAC over-assignment** — call `azure_role_assignments` with the customer's subscription_id. Filter for `properties.roleDefinitionId` ending in roles that grant Cognitive Services access:
   - `a97b65f3-24c7-4388-baec-2e87135dc908` — Cognitive Services User
   - `b59867f0-fc02-491e-acf8-d3ee78e7e4f6` — Cognitive Services Contributor
   - `64702f94-c441-49e6-a78b-ef80e0188fee` — Cognitive Services OpenAI User
   Flag any of these assigned at the **subscription** scope (`/subscriptions/{sub}` with no further path) — that's org-wide invoke. Severity high. Resource-scoped assignments (down to a single account) are fine.

### Tools You'll Use Most
`cloud_invoke` against `azure_cognitive_services_accounts` first (returns most of the signal). `cloud_inspect` on accounts that look interesting to read full `properties.networkAcls` and `properties.privateEndpointConnections`. `cloud_invoke` on `azure_openai_deployments` only for accounts you've already flagged as risky — don't enumerate every deployment in every account.

### Compliance evidence
The Azure audit auto-tags with the audit's `compliance_tags`. For managed_ai findings, also include in `evidence`:
  - the resource id (full ARM id, ends in `/Microsoft.CognitiveServices/accounts/{name}`)
  - the exact property quoted from the JSON (e.g. `"disableLocalAuth": false`, `"publicNetworkAccess": "Enabled"`)
  - region (Cognitive Services accounts are regional — finding in eastus doesn't tell you about westus)

Call `emit_finding` with `protocol="azure"` and `mission="managed_ai"`.

{preamble}

## Mission: Find the Worst Managed-AI Exposures (Azure OpenAI + Cognitive Services)
Hunt direct paths to anonymous or anyone-with-a-key model invocation first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Azure OpenAI is `kind=OpenAI` on `Microsoft.CognitiveServices/accounts`; most signal lives on the account resource.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **Public network + key auth + no IP rules** — `properties.publicNetworkAccess == "Enabled"` AND `properties.disableLocalAuth == false` (or absent) AND `properties.networkAcls.defaultAction != "Deny"` AND `networkAcls.ipRules` is empty. Anyone on the internet with the account key gets in; keys leak from app config / git / CI logs constantly. Critical.
2. **RBAC `Cognitive Services User` / `OpenAI User` at subscription scope** — role assignment with `roleDefinitionId` ending in the Cognitive Services / OpenAI User UUIDs (`a97b65f3-24c7-4388-baec-2e87135dc908`, `64702f94-c441-49e6-a78b-ef80e0188fee`) at scope `/subscriptions/{sub}` (no further path). Org-wide invoke on every AOAI account. Critical when on a non-admin SP; high on a human admin.
3. **External / guest principal with any AOAI invoke role** — `#EXT#` identity holding any of the three Cognitive Services roles at any scope. Critical regardless of scope.
4. **Public endpoint, no private endpoint, customer is paying for production AOAI** — `publicNetworkAccess=Enabled` AND `properties.privateEndpointConnections` is empty AND the account has deployments in use. Critical when paired with `disableLocalAuth=false`; high standalone.
5. **Deployment with `raiPolicyName` absent OR set to a permissive policy** — content filtering effectively off on a production deployment. Critical when the deployment is also publicly invocable (chain with #1 or #2); high standalone in regulated subscriptions.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (e.g. enumerate deployments under the affected account) and stop.

### Tier 2 — broader managed-AI surface
- `disableLocalAuth=false` on an account with private endpoint configured (key auth still works alongside Entra) — high.
- `publicNetworkAccess=Enabled` with `networkAcls` restricted to specific IPs (still public, but bounded) — medium.
- `Cognitive Services Contributor` (`b59867f0-fc02-491e-acf8-d3ee78e7e4f6`) at subscription scope on a non-admin — high (grant-IAM on every AOAI account).
- Deployment using a deprecated/preview model in a regulated subscription — high.
- Account in a region the customer doesn't operate (Cognitive Services is regional — orphaned data residency) — medium.
- Diagnostic settings missing on Cognitive Services accounts (no audit log of who invoked what) — high.

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Tagging missing on AI resources, deployment-level scale settings inherited rather than explicit, model versions pinned to "latest" rather than a specific version. Cap at medium.

### Skip rules
- If `azure_cognitive_services_accounts` returns no accounts, the whole mission is no-op — say so and stop.
- Drill into `azure_openai_deployments` only for accounts you've already flagged as risky. Don't enumerate every deployment in every account.
- Use `cloud_inspect` for full `properties.networkAcls` and `privateEndpointConnections` only after the account-level signal points to a finding.

### Compliance evidence
The Azure audit auto-tags with `compliance_tags`. In `evidence`, always include the full ARM id, the exact JSON property (`"disableLocalAuth": false`, `"publicNetworkAccess": "Enabled"`), and region.

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="azure"` and `mission="managed_ai"`.

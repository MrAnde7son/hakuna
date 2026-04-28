{preamble}

## Mission: Find the Worst Managed-AI Exposures (Vertex AI)
Hunt direct paths to anonymous or anyone-with-a-Google-account model invocation first. Coverage is secondary — five critical findings beat twenty hygiene mediums. Vertex risk is endpoint-IAM-centric: who can call `aiplatform.endpoints.predict`.

### Tier 1 — direct compromise paths (always run; emit on hit, then move on)
1. **`allUsers` on a Vertex endpoint** — `gcp_vertex_endpoint_iam` returning a binding whose `members` list contains `"allUsers"` on any role that includes `aiplatform.endpoints.predict`. Anyone on the internet can invoke. Critical.
2. **`allAuthenticatedUsers` on a Vertex endpoint with predict** — same call, member `"allAuthenticatedUsers"` on a predict-bearing role. Any Google account can invoke. Critical.
3. **External-domain or unknown principal with `roles/aiplatform.user` or `roles/aiplatform.admin`** — `gcp_project_iam_bindings` showing a `user:` / `serviceAccount:` member outside the customer's domain (or unrecognized SA project) holding either role. Project-wide predict + admin reach. Critical; use `request_clarification` if the domain isn't established.
4. **Default Compute Engine SA used by a deployed Vertex model** — `deployedModels[].serviceAccount` matches `<project-number>-compute@developer.gserviceaccount.com` AND the project IAM binds that SA to broad roles. Over-broad blast radius for inference workload. Critical (model code can use the SA's project-wide permissions); high if the default SA has been scoped down.
5. **Public-trust workload principal can predict** — combine project IAM with workload identity bindings: any SA reachable from outside the project (e.g. via Workload Identity Federation with an open issuer) holding `aiplatform.endpoints.predict`. Critical.

If Tier 1 is fully probed and **clean**, continue to Tier 2. If Tier 1 produced a critical, do one Tier-2 enrichment pass (resolve which models the binding affects, snapshot deployedModels SA) and stop.

### Tier 2 — broader managed-AI surface
- `domain:<corporate-domain>` or `projectViewer:<project>` granted predict on a production endpoint — high (wider than necessary).
- `roles/aiplatform.user` granted at project scope to a service that doesn't operate the AI surface — high.
- Endpoint with no encryption-key configuration (no CMEK) in a project that uses CMEK elsewhere — medium (data residency / control inconsistency).
- Audit logs (Data Read/Data Write) disabled on `aiplatform.googleapis.com` — high (predict invocations unaudited).
- Vertex Workbench instances with `noProxyAccess=false` and a privileged SA — high (notebook escape into project).

### Tier 3 — hygiene (skip unless Tier 1+2 are exhausted and budget remains)
Models without `production` versionAlias when `default` exists, endpoints with no traffic split documentation, deprecated model versions still attached, missing tag taxonomy on Vertex resources. Cap at medium.

### Skip rules
- Don't enumerate every model version. `gcp_vertex_models` is for context only.
- Don't try to invoke a model. `aiplatform.endpoints.predict` is data-plane and the cloud audit catalog excludes it.
- If `gcp_vertex_endpoints` returns nothing in a region, skip that region's checklist.

### Compliance evidence
GCP audit auto-tags with `compliance_tags`. In `evidence`, always include full endpoint resource name, the exact binding (`"members": ["allUsers"]`, `"role": "roles/aiplatform.user"`), and location (Vertex is regional).

### Budget & stop rule
Ration by tier, not by category. Stop after one Tier-2 enrichment pass once Tier 1 produces a critical. Stop if Tier 1 and Tier 2 are clean and you're 3 probes into Tier 3 with nothing new.

Call `emit_finding` with `protocol="gcp"` and `mission="managed_ai"`.

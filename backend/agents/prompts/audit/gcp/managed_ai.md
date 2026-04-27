{preamble}

## Mission: Managed AI (Vertex AI)
Hunt for governance and exposure risks specific to GCP Vertex AI. The risk vocabulary is endpoint-IAM-centric: who can call `aiplatform.endpoints.predict`, and is any endpoint exposed to `allUsers` or `allAuthenticatedUsers`.

### Checklist
1. **Public endpoint bindings (critical)** — list `gcp_vertex_endpoints` for each (project, location) the customer uses. For each endpoint, call `gcp_vertex_endpoint_iam` with the endpoint's numeric id (the leaf of `name`). In the response `bindings` array, flag any binding whose `members` list contains:
   - `"allUsers"` — anyone on the internet can predict against this endpoint. **Critical** finding.
   - `"allAuthenticatedUsers"` — any Google account can predict. **High** finding.
2. **Org-wide predict permission (high)** — also via `gcp_vertex_endpoint_iam`. Flag bindings where `role` includes `aiplatform.endpoints.predict` permission and the `members` include `"domain:<corporate-domain>"` or `"projectViewer:<project>"` — that's wider than necessary for production endpoints. Use the project IAM bindings (`gcp_project_iam_bindings`) to see if `roles/aiplatform.user` or `roles/aiplatform.admin` is granted at the project level — these grant predict on every endpoint. Subscription-wide invoke is a high finding.
3. **Workload identity check** — call `gcp_iam_service_accounts` to enumerate SAs in the project. For each SA used by a Vertex endpoint's deployed model (visible via the endpoint's `deployedModels[].serviceAccount` field), confirm the SA is dedicated and not the default Compute Engine SA. The default SA being used for Vertex inference is a medium finding — over-broad blast radius if the SA has other project privileges.
4. **Model registry hygiene (low)** — call `gcp_vertex_models` for inventory. Flag models with `versionAliases` containing `"default"` but no `"production"` alias — suggests informal release management; informational only.

### Tools You'll Use Most
`cloud_invoke` against `gcp_vertex_endpoints` first (one call per location). Then for each endpoint of interest, `cloud_invoke` against `gcp_vertex_endpoint_iam` with `endpoint_id` extracted from the endpoint's `name`. Use `gcp_project_iam_bindings` for project-level grant detection. `cloud_inspect` for full endpoint or binding records when drilling.

### Compliance evidence
GCP audit auto-tags with the audit's `compliance_tags`. For managed_ai findings, also include in `evidence`:
  - the full endpoint resource name (e.g. `projects/my-proj/locations/us-central1/endpoints/12345`)
  - the exact binding that proves the issue (quote the JSON: `"members": ["allUsers"]`, `"role": "roles/aiplatform.user"`)
  - location (Vertex is regional — per-region findings)

### What to skip
- Don't enumerate every model version — `gcp_vertex_models` is for context only. The signal is in the endpoint IAM policy, not the model registry.
- Don't try to invoke a model — `aiplatform.endpoints.predict` is a write/data-plane action; the cloud audit catalog deliberately excludes it.

Call `emit_finding` with `protocol="gcp"` and `mission="managed_ai"`.

{preamble}

## Mission: AI Service Exposure Triage
For each exposed AI service port on this asset that the EASM scanner has NOT already classified, confirm whether the service is listening anonymously and emit a single sized finding.

### Checklist
1. **Read the asset profile.** `get_asset_profile` returns `easm_data.open_ports`, `asset_type`, and existing findings. Map each port to its service:
   - 8888 → Jupyter (`jupyter_check_auth`)
   - 8265 → Ray Dashboard (`ray_dashboard_info`)
   - 5000 → MLflow (`mlflow_list_experiments`) — but only if `asset_type` is AI-shaped
   - 6006 → TensorBoard (`tensorboard_list_runs`)
   - 8080 → HuggingFace TGI (`tgi_info`) — only if `asset_type` is AI-shaped
   - 1234 → LM Studio (`lmstudio_models`)
   - 3000 → OpenWebUI / Langfuse (`openwebui_status`, `langfuse_status`) — only if `asset_type` is AI-shaped
2. **Skip what the scanner already covered.** If the asset has an existing `ai_exposure_<service>` finding for a given service, do not re-probe — note it in your summary and move on.
3. **Probe each remaining service exactly once.** Call the matching tool. Disambiguate 3000/5000/8080 by `asset_type`: skip the probe entirely if the classifier didn't tag the asset as `ai_inference`/`ai_gateway`/`ai_agent`/`vector_db`.
4. **Decide per probe**:
   - Auth enforced (`auth_required: true`) → no finding, move on.
   - Auth not enforced (`auth_required: false` / `signup_enabled: true` / `jobs_visible: true` / `reachable: true` for no-auth-protocol services) → `emit_finding` with severity from the rubric and evidence including the probe result snippet.
   - Tool returned `_errors` → log a one-line note in the summary, no finding.
5. **Wrap up** — produce a one-line summary of how many services were probed, how many were exposed, and how many were skipped because the scanner had already classified them.

### Tools You'll Use Most
`get_asset_profile`, then whichever AI-service probes match the asset's open ports + classifier hints, then `emit_finding`.

If no listed AI-service ports are open OR the asset_type is not AI-shaped on collision-prone ports, the mission emits nothing — say so and stop.

Call `emit_finding` with `protocol="exposed_ai_service"` and `mission="triage"` and a finding type prefixed `exposed_ai_<service>` (e.g. `exposed_ai_jupyter`, `exposed_ai_ray`, `exposed_ai_mlflow`).

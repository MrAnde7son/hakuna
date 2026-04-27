{preamble}

## Mission: AI Capability Probe (consent-gated)
This mission goes one step deeper than triage: it sends one benign hardcoded canary prompt to confirm the service accepts arbitrary inference, and it enumerates MCP tool palettes when reachable. The canary prompt text is fixed at the relay — you cannot supply prompt text via these tools.

This mission is **per-asset consent gated**. The user has already approved this run for this asset; you do not need to ask again. But you must not pivot off the result to other hosts or invoke inference outside the canary tools.

### Checklist
1. **Run the triage checklist first.** Use the same probes as the triage mission to identify exposed services and skip anything the scanner already covered. Emit triage-shaped findings as you go.
2. **For Ollama (port 11434)** — if the scanner already emitted `ai_exposure_ollama`, run `ollama_capability_probe` to confirm anonymous inference works. A `canary_response_match: true` upgrades the existing finding's evidence; emit a new finding with type `exposed_ai_ollama_canary` referencing the canary result.
3. **For vLLM (port 8000)** — same pattern with `vllm_capability_probe` and finding type `exposed_ai_vllm_canary`.
4. **For MCP servers** — if the asset's open ports include a likely MCP port (3001, 3010, 8765, or any port the scanner labeled MCP) and the scanner emitted `ai_exposure_mcp`, run `mcp_enumerate_tools` with that port. Emit `exposed_ai_mcp_palette` with the tool palette as evidence — the palette IS the threat model, so include all surfaced tool names in the finding.
5. **Wrap up** — summary of canaries run, canary matches, MCP palettes enumerated.

### Tools You'll Use Most
`get_asset_profile`, the triage probes, then `ollama_capability_probe` / `vllm_capability_probe` / `mcp_enumerate_tools`, then `emit_finding`.

### Severity for canary findings
  - **critical** — Ollama or vLLM canary returns `canary_response_match: true` on a service the scanner already classified as exposed. This is proof, not inference: anyone can run unbounded completions through this endpoint.
  - **high** — MCP `tools` palette includes any tool whose description references "execute", "shell", "file", "fetch", "request" — those are the RCE/SSRF primitives an attacker reaches through any LLM that connects.
  - **medium** — MCP palette is exposed but consists only of read-only data tools.

Call `emit_finding` with `protocol="exposed_ai_service"` and `mission="prompt_injection_probe"`.

# Protocol Audit Coverage Expansion — Roadmap

**Last updated:** 2026-04-27
**Status:** Phase 0, 1a, 1b, 2, 3, 3.5, 4.0, 4.1, 4.2, 4.3, 5 shipped. Open relay-side prereqs: register local interfaces (gates 4.3 from firing in production); JP localization + OT Posture dashboard land in a follow-on UX slice.

## The big picture

Hakuna started with two anonymous-capable agentic audits (SMB null-session, SNMP default-community). The roadmap expands that to ~22 protocol audits across 6 families, covering: legacy enterprise, modern cloud-native datastores, AI/ML services, IPMI/legacy Tier 1, OT/ICS (with Japanese-vendor coverage), and a scanner-side EASM fingerprinter for banner-only protocols.

**Architectural backbone:** every new family is a `ProtocolAudit` registration that flows through the existing `dispatch_audit_run` pipeline. No parallel infrastructure.

**Safety model:** a tiered `safety_class` field (`credentialed` → `anon_*` → `ot_*`) drives credential gating, auto-trigger eligibility, cooldowns, per-asset consent, and frontend grouping. Single source of truth on the audit registration.

---

## Phase status overview

| Phase | Family | Status | Tests | Effort |
|---|---|---|---|---|
| 0 | Foundation refactors | ✅ shipped | 2611 backend | 1 PR |
| 1a | `exposed_datastore` (6 datastores) | ✅ shipped | 2628 backend + 14 relay | 1 PR |
| 1b | `exposed_datastore` (4 more) | ✅ shipped | 2636 backend + 23 relay | 1 PR |
| 2 | F: EASM fingerprinter (gap-fill only) | ✅ shipped | 49 (19 backend + 30 scanner) | ~3 days |
| 3 | B: `exposed_ai_service` (Option D: gap-fill only) | ✅ shipped | 56 (29 backend + 27 relay) | ~1 wk |
| 3.5 | B': Managed AI governance (saas + cloud + secrets) | ✅ shipped | 258 (235 backend + 23 scanner) | ~1 wk |
| 4.1 | D: `exposed_anon_protocol` (FTP/VNC/DNS-AXFR/Kerberos/TFTP) | ✅ shipped | 36 (18 backend + 18 relay) | ~2 days |
| 4.0 | Scanner UDP `port_change` events (transport-aware delta) | ✅ shipped | 9 (5 scanner + 4 backend) | ~1 day |
| 4.2 | C: `ipmi_bmc` (Cipher Zero + RAKP-3) | ✅ shipped | 31 (13 backend + 18 relay) | ~3 days |
| 4.3 | D': `netbios_local` (LAN-local, relay subnet predicate) | ✅ shipped | 26 (15 backend + 11 relay) | ~2 days |
| 5 | E: OT/ICS (`ot_protocol` + `ot_passive`, JP wedge included) | ✅ shipped | 61 (25 backend + 36 relay) | ~3 days |

### Pre-existing scanner coverage (audit 2026-04-26)

Before scoping new work, an audit of `hakuna-scanner/app/ingest/` found significant pre-existing coverage that shrinks Phase 2/3/5:

| Roadmap item | Already shipped in |
|---|---|
| TLS testssl-grade cipher list (P2) | [tls_deep_audit.py](../hakuna-scanner/app/ingest/tls_deep_audit.py) — sslyze cipher enum, weak-cipher regex, deprecated TLS versions, chain validation, OCSP, CAA |
| AI-port asset-type disambiguation (P3 prereq) | [asset_classifier.py](../hakuna-scanner/app/ingest/asset_classifier.py) + [endpoint_probe_db.json](../hakuna-scanner/app/ingest/endpoint_probe_db.json) — `ai_inference`/`ai_gateway`/`ai_agent`/`vector_db` already set per asset |
| AI unauthenticated-exposure findings (P3 core) | [ai_exposure_probe.py](../hakuna-scanner/app/ingest/ai_exposure_probe.py) — emits `ai_exposure_*` Findings for Ollama, vLLM, Qdrant, Milvus, LangServe, MCP |
| Modbus, S7, BACnet, EtherNet/IP, OPC-UA, MQTT, RTSP, DNP3, Niagara Fox (P5) | [protocol_probe.py](../hakuna-scanner/app/ingest/protocol_probe.py) — read-only identification PDUs, OT-safe |

**Resolved 2026-04-27 (Phase 3 shipped — Option D):** AI exposure findings continue to flow scanner → DB direct-insert. The audit's tool palette is gap-fill only — services scanner doesn't probe (Jupyter, Ray, MLflow, TensorBoard, TGI, LM Studio, OpenWebUI, Langfuse) plus consent-gated capability probes for Ollama/vLLM/MCP. Finding-type prefixes are disjoint (`ai_exposure_*` from scanner vs `exposed_ai_*` from audit) so no dedup logic is needed. The triage prompt instructs the agent to read `Asset.findings` and skip services already classified by the scanner.

---

## ✅ Phase 0 — Foundational refactors

**Status:** shipped. Zero behavior change in production.

### What changed
- New fields on `ProtocolAudit`: `safety_class`, `mode`, `cooldown_hours`, `auto_trigger_policy`, `compliance_tags`
- New methods: `is_anonymous_capable()`, `requires_per_asset_consent()`
- Removed `_ANON_CAPABLE_PROTOCOLS` literal set; cred check now reads `audit.safety_class != "credentialed"` — single source of truth on the registration
- Replaced `_PORT_TO_ANON_AUDIT` dict with `AutoTriggerRule` dataclass + `AUTO_TRIGGER_RULES` list. Per-rule fields: `cooldown`, `enabled_setting_key`, `requires_per_asset_consent`, `predicate`, `transport`
- 90-day TTL on per-asset OT consent records (helper in audit_auto_trigger)
- SMB and SNMP migrated to the new model with `safety_class="anon_standard"`, `auto_trigger_policy="auto_org_opt_in"`

### Files touched
- [backend/agents/audit_registry.py](../backend/agents/audit_registry.py)
- [backend/agents/tools/smb_tools.py](../backend/agents/tools/smb_tools.py)
- [backend/agents/tools/snmp_tools.py](../backend/agents/tools/snmp_tools.py)
- [backend/services/audit_runner.py](../backend/services/audit_runner.py)
- [backend/services/audit_auto_trigger.py](../backend/services/audit_auto_trigger.py)
- [backend/tests/test_audit_auto_trigger.py](../backend/tests/test_audit_auto_trigger.py)

### `safety_class` hierarchy

| Class | Meaning | Auto-trigger gate |
|---|---|---|
| `credentialed` | Needs creds (WMI, LDAP, SSH, WinRM, cloud) | N/A |
| `anon_standard` | Anonymous OK, normal blast radius (SMB, SNMP) | Org-level switch |
| `anon_datastore` | Anonymous OK, target is a data store | Org-level switch |
| `anon_ai_exposure` | Anonymous OK, target is an AI/ML service | Org-level switch |
| `anon_ipmi` | Anonymous OK, BMC/IPMI Cipher Zero class | Org-level switch |
| `anon_lan_local` | Anon OK, only valid when relay on same broadcast domain | Org switch + subnet predicate |
| `ot_safe` | OT/ICS, read-only PDUs only | **Per-asset consent + org switch** |
| `ot_passive_only` | OT/ICS, fingerprint via banner only — never craft a PDU | **Per-asset consent + org switch** |

---

## ✅ Phase 1a — `exposed_datastore` family (initial 6)

**Status:** shipped. 2628 backend + 14 relay tests pass.

Single audit registration, single relay method (`datastore_probe`), single mission (`triage`), op-allowlisted at the relay.

| Port | Service | Decisive field |
|---|---|---|
| 6379 | Redis | `auth_required` |
| 27017 | MongoDB | `auth_required` |
| 9200 | Elasticsearch | `auth_required` |
| 2375 | Docker Engine API | `reachable` (TCP-without-TLS = critical by itself) |
| 6443 | Kubernetes API | `anon_namespaces` |
| 2379 | etcd | `auth_enabled` |

### Files added
- [backend/agents/tools/exposed_datastore_tools.py](../backend/agents/tools/exposed_datastore_tools.py)
- [hakuna-relay-agent/agent/datastore_probe.py](../hakuna-relay-agent/agent/datastore_probe.py)
- [backend/tests/test_exposed_datastore_audit.py](../backend/tests/test_exposed_datastore_audit.py)
- [hakuna-relay-agent/tests/test_datastore_probe.py](../hakuna-relay-agent/tests/test_datastore_probe.py)

### Activation
```python
org.settings = {**(org.settings or {}), "auto_audit_datastore": True}
```

### Defense in depth
- **Backend tool layer**: each tool only exposes one `op` value. No `KEYS`, `SCAN`, `find()`, `_search`, `/exec` paths exist in the palette.
- **Relay allowlist** (`_OP_HANDLERS` in `datastore_probe.py`): unknown ops raise `DatastoreProbeError` before any network code runs.
- **Per-call timeout**: 8s default, capped at handler level.
- **Anonymous by spec**: `credentials={}` always — even if a credential is in the run context, it's never forwarded.

---

## ✅ Phase 1b — `exposed_datastore` completion (4 more)

**Status:** shipped. 2636 backend + 23 relay tests pass. Pure mechanical extension.

| Port | Service | Decisive field |
|---|---|---|
| 11211 | Memcached | `reachable` (no auth in protocol) |
| 5601 | Kibana | `auth_required` |
| 10250 | kubelet | `anon_pods` (anon-auth on kubelet = critical) |
| 5984 | CouchDB | `auth_required` (admin-party mode) |

**No new files, no new dependencies** — Memcached uses stdlib socket; Kibana/kubelet/CouchDB use existing httpx.

### Family A final — 10 datastores, 1 audit registration

PostgreSQL/MySQL deferred to Phase 2 — they're auth-required-by-spec, so they're a banner→CVE problem (Family F's job) not an auth-misconfig problem.

---

## 📋 Phase 2 — Family F: EASM fingerprinter extension (gap-fill scope)

**Why next:** scanner-only work, no LLM cost, no relay changes. Enriches the existing CVE correlator. The pre-existing scanner audit (above) **removes the Phase 3 hard dependency** — port 3000/5000/8000 disambiguation already works via `asset_classifier.py`. Phase 2 is now pure CVE-correlation enrichment for protocols where banner version matters and no signal currently exists.

### Scope (revised — gap-fill only)

Adds banner depth in `hakuna-scanner/app/ingest/` for:
- **SSH** 22 — full version exchange line (`SSH-2.0-OpenSSH_8.4p1` etc.)
- **RDP** 3389 — NLA enforcement probe (no full handshake) + TLS cert via existing tls_deep_audit
- **SMTP/IMAP/POP3** 25/587/143/110/993/995 — banner + STARTTLS capability + VRFY/EXPN test
- **IPP/LPD** 631/515 — printer model via IPP `Get-Printer-Attributes`
- **TR-069/UPnP** 7547/1900 — SOAP/SSDP descriptor fetch
- **Postgres/MySQL** 5432/3306 — banner version (deferred from Phase 1)

**Dropped from original Phase 2 scope:**
- TLS testssl-grade list — superseded by `tls_deep_audit.py`
- AI-port disambiguation — superseded by `asset_classifier.py` + `endpoint_probe_db.json`

### Output
Writes to `assets.easm_data.banner_findings` (new sub-key). No agent involvement. CVE correlator consumes this field.

### New code (delivered)
- ✅ One module per protocol family in `hakuna-scanner/app/ingest/`: [`ssh_banner.py`](../hakuna-scanner/app/ingest/ssh_banner.py), [`rdp_nla_probe.py`](../hakuna-scanner/app/ingest/rdp_nla_probe.py), [`mail_banner.py`](../hakuna-scanner/app/ingest/mail_banner.py), [`printer_banner.py`](../hakuna-scanner/app/ingest/printer_banner.py), [`tr069_upnp_probe.py`](../hakuna-scanner/app/ingest/tr069_upnp_probe.py), [`db_banner.py`](../hakuna-scanner/app/ingest/db_banner.py)
- ✅ Pipeline step `_do_banner_grab` in [`enrichment.py`](../hakuna-scanner/app/tasks/enrichment.py), registered in both the hardcoded step_groups (group 1) and [`adapters.py`](../hakuna-scanner/app/runner/adapters.py)
- ✅ `ProtocolAudit(protocol="easm_fingerprint", mode="fingerprint", ...)` registered in [`backend/agents/tools/easm_fingerprint_tools.py`](../backend/agents/tools/easm_fingerprint_tools.py); dispatch refuses fingerprint-mode in [`audit_runner.py`](../backend/services/audit_runner.py)

### Tests (delivered)
- ✅ [`backend/tests/test_easm_fingerprint_audit.py`](../backend/tests/test_easm_fingerprint_audit.py) — 19 tests covering audit registration, dispatch guard, banner→component extraction across all 4 mappable protocols + skip cases for the 5 free-form ones; caught a real isinstance-guard bug in `_banner_components`
- ✅ [`hakuna-scanner/tests/test_banner_grab.py`](../hakuna-scanner/tests/test_banner_grab.py) — 30 tests: SSH banner regex (OpenSSH/Dropbear/libssh/legacy/non-SSH), RDP X.224 builder + 5 selectedProtocol parser cases, mail regexes + dispatch-table coverage, IPP request builder + tag parser, UPnP descriptor field extraction, Postgres SSLRequest packet + StartupMessage build + ErrorResponse parser, MySQL dispatch
- ✅ Updated [`backend/tests/test_audit_runner.py`](../backend/tests/test_audit_runner.py) `list_audits()` exact-set assertion to include `easm_fingerprint`
- All 108 backend tests pass; all 30 new scanner tests pass

### Frontend (delivered)
- ✅ [`ScanManagement.jsx`](../frontend/src/components/scans/ScanManagement.jsx) — `auditProtocols` and `AuditPanel.protocols` now filter `mode === 'fingerprint'` audits out of the kickoff picker. Scanner-driven audits can't be selected for dispatch (would be refused by `audit_runner` anyway, but failing closed at the UI layer is cleaner). Build verified.

### Still pending
- `_do_banner_grab` end-to-end test (mocked sf + asyncio.gather) — deferred as low-signal vs. the parser unit tests
- Multi-tier kickoff grouping by `safety_class` (5 tiers per cross-cutting section) — deferred to Phase 3+ when AI/IPMI/OT families ship and the binary cloud-vs-host split actually has more than two real tiers

### CVE correlator wired (delivered)
- ✅ [`cve_correlator.py`](../backend/services/cve_correlator.py) — `_banner_components()` maps SSH (OpenSSH/Dropbear/libssh), PostgreSQL, MySQL, and TR-069 RomPager banners to `(component, version)` tuples; fed into `_query_threat_intel_cves` alongside InventorySoftware
- Banner-derived candidates tagged `source="banner"` and never marked `mitigated` (banners don't carry patch state); inventory wins on dedup conflicts
- New report fields: `banner_components_scanned`, `banner_components_with_cves`, `banner_only_cves`, plus per-candidate `sources`/`banner_protocol`/`banner_port`
- Free-form banners (RDP, SMTP/IMAP/POP3 software, IPP, UPnP) intentionally skipped — false-positive rate too high for substring matching against `ThreatCVE.affected_products`

### Compliance
- SMTP open relay / VRFY exposure → `nist_csf_pr_ds`
- RDP NLA disabled → `cis_benchmarks`

### Risks
- Banner-grab false positives on honeypots → stamp `confidence: low` when banner is the only signal

---

## ✅ Phase 3 — Family B: `exposed_ai_service` (competitive wedge)

**Status:** shipped 2026-04-27. 29 backend + 27 relay tests pass.

**Scope landed: Option D (gap-fill only).** Scanner stays primary for the 8 services it already covers (ollama, qdrant, milvus, chroma, vllm, mcp, litellm, langserve). Audit's tool palette is *only* the services scanner doesn't probe — Jupyter, Ray, MLflow, TensorBoard, OpenWebUI, Langfuse, LMStudio, TGI — plus a consent-gated `prompt_injection_probe` mission for deeper LLM-shaped checks. Zero finding-type overlap, no dedup logic needed, LLM cost is purely additive.

### Audit (delivered)
`protocol="exposed_ai_service"`, `safety_class="anon_ai_exposure"`, missions `triage` + `prompt_injection_probe` (latter consent-gated at the auto-trigger layer — `requires_per_asset_consent` is False on the rule, but the mission is intentionally not in the auto-trigger registration; it's manual-dispatch only).

Single relay method `ai_service_probe` handles all 11 ops (8 triage + 3 capability probes). Allowlist enforced relay-side in `_OP_HANDLERS`.

### Tools delivered

**Triage (gap-fill — services scanner doesn't already cover):**
- `jupyter_check_auth(asset_id)` — `GET /api/status` + `GET /api/kernels` reachability
- `ray_dashboard_info(asset_id)` — `GET /api/version`, `/api/jobs/` — `jobs_visible:true` is critical
- `mlflow_list_experiments(asset_id)` — `GET /api/2.0/mlflow/experiments/search`
- `tensorboard_list_runs(asset_id)` — `GET /data/runs`
- `tgi_info(asset_id)` — `/v1/models` OpenAI-compat (HuggingFace TGI)
- `lmstudio_models(asset_id)` — `/v1/models` OpenAI-compat
- `openwebui_status(asset_id)` — `GET /api/config`, surfaces `signup_enabled` + auth state
- `langfuse_status(asset_id)` — `GET /api/public/health` + `/api/public/projects`

**Deeper-than-scanner reasoning (consent-gated mission only):**
- `ollama_capability_probe(asset_id)` — benign **hardcoded** canary prompt at relay (LLM cannot supply prompt text)
- `mcp_enumerate_tools(asset_id, port)` — tries `GET /tools` then JSON-RPC `tools/list`; caps result at 25 tools
- `vllm_capability_probe(asset_id)` — same hardcoded canary against vLLM `/v1/completions`, `temperature=0`

### Files added
- [`backend/agents/tools/exposed_ai_service_tools.py`](../backend/agents/tools/exposed_ai_service_tools.py)
- [`hakuna-relay-agent/agent/ai_service_probe.py`](../hakuna-relay-agent/agent/ai_service_probe.py)
- [`backend/agents/prompts/audit/exposed_ai_service/_preamble.md`](../backend/agents/prompts/audit/exposed_ai_service/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/exposed_ai_service/triage.md), [`prompt_injection_probe.md`](../backend/agents/prompts/audit/exposed_ai_service/prompt_injection_probe.md)
- [`backend/tests/test_exposed_ai_service_audit.py`](../backend/tests/test_exposed_ai_service_audit.py) — 29 tests
- [`hakuna-relay-agent/tests/test_ai_service_probe.py`](../hakuna-relay-agent/tests/test_ai_service_probe.py) — 27 tests including assertion that canary prompts are hardcoded and op_params-supplied prompt text is ignored

### Auto-trigger (delivered)
Ports {8888, 8265, 5000, 6006, 8080, 1234, 3000} → `("exposed_ai_service","triage")`. 11434 / 8000 deliberately excluded — scanner's `ai_exposure_*` covers them.

**Disambiguation predicate** `_ai_service_predicate` in [`audit_auto_trigger.py`](../backend/services/audit_auto_trigger.py): unambiguous AI ports (8888/8265/6006/1234) fire regardless of asset_type; collision-prone ports (5000/8080/3000) require `Asset.asset_type ∈ {ai_inference, ai_gateway, ai_agent, vector_db}`. Tested for both column and `easm_data` fallback paths.

### Coexistence with scanner (delivered)
- Scanner finding types stay `ai_exposure_<service>`; audit finding types use `exposed_ai_<service>` prefix — disjoint namespaces
- Triage prompt instructs the agent to read `Asset.findings` and skip any service that already has an `ai_exposure_*` finding so the LLM loop doesn't re-emit
- The `prompt_injection_probe` mission goes deeper *intentionally* (it's the canary path), and emits `exposed_ai_<service>_canary` / `exposed_ai_mcp_palette` to preserve traceability vs scanner findings

### Compliance
`nist_ai_rmf`, `iso_42001`. Wired in registration's `compliance_tags`.

### Defense-in-depth
- Backend tool layer exposes one `op` per probe — no general "send arbitrary prompt" tool exists
- Relay allowlist (`_OP_HANDLERS` in `ai_service_probe.py`) rejects unknown ops before any network code
- Canary prompt is constants `_CANARY_PROMPT`/`_CANARY_EXPECTED_SUBSTRING` at the relay; the backend tool passes empty `op_params` and the relay ignores any `op_params.prompt` an attacker might smuggle through
- MCP enumerate caps at 25 tools to defang malicious / huge palettes

---

## 📋 Phase 3.5 — Family B': Managed AI governance (cloud + secrets)

**Why this is its own phase:** Phase 3 covers self-hosted AI services that have a *network port* to probe. Hosted/managed services (OpenAI, Anthropic, Bedrock, Vertex AI, Azure OpenAI, SageMaker, Cohere, Mistral) have **no asset surface** — the risk lives in IAM policies and leaked API keys. Forcing them into `exposed_ai_service` would conflate two unrelated threat models. Coverage lands as targeted additions in three existing families plus one new SaaS-LLM audit.

### Scope (one new audit family — `managed_ai_saas`)

**0. SaaS LLM provider governance** — new `managed_ai_saas` ProtocolAudit. Multi-provider via the existing connector-id prefix mechanism (`openai_*`, `anthropic_*`; structurally extensible to `cohere_*`, `mistral_*` when those vendors expose comparable admin APIs). Reuses [cloud_tools.py](../backend/agents/tools/cloud_tools.py) verbatim — only the prefix-matching logic changes.

| Provider | New connectors | Missions surface |
|---|---|---|
| OpenAI | `openai_admin_projects`, `openai_admin_api_keys`, `openai_admin_users`, `openai_admin_audit_logs` | stale/never-used keys, projects with no usage cap, members with `owner` role outside expected list, audit-log scrub gaps |
| Anthropic | `anthropic_admin_workspaces`, `anthropic_admin_api_keys`, `anthropic_admin_users` | unused workspace API keys, primary org members without explicit role scoping, workspace sprawl |
| Groq / Mistral / Replicate / Cohere | (deferred — vendors lack comparable admin APIs) | leaked-key detection only via Slice 4 |

**Auth:** Bearer-token via existing `_inject_auth` path. **Custody warning:** an OpenAI/Anthropic *admin* API key has org-wide visibility — far more sensitive than a read-only AWS key. Onboarding copy must flag this explicitly and the credential acquisition flow gates behind a "I understand this key has org-wide visibility" confirmation step.

Missions: `keys_hygiene` (stale, unused, no-expiry, broad-scope keys), `identity` (members, roles, workspace boundary leaks), `explore` (free-form). `usage_anomaly` deferred until baseline-usage signal exists.

**1. Cloud audit extensions** — added to existing `aws`/`azure`/`gcp` Cloud Posture audits. Each provider gets new tools + missions, no new ProtocolAudit registration.

| Provider | New connectors | Findings emitted |
|---|---|---|
| AWS ✅ | `aws_bedrock_invocation_logging`, `aws_bedrock_foundation_models`, `aws_bedrock_guardrails`, `aws_sagemaker_endpoints`, `aws_sagemaker_endpoint_configs` (+ `managed_ai` mission on existing `aws` audit; IAM-walking reuses `aws_iam_policies` / `aws_iam_roles`) | "Bedrock invocation logging disabled", "Bedrock account has no guardrails configured", "IAM policy grants `bedrock:*` at wildcard scope", "SageMaker endpoint without VPC isolation", "SageMaker `InvokeEndpoint` granted to public principal" |
| Azure ✅ | `azure_cognitive_services_accounts`, `azure_openai_deployments` (+ `managed_ai` mission on existing `azure` audit; RBAC walking reuses `azure_role_assignments`) | "Azure OpenAI key auth allowed (no Entra)", "Cognitive Services account publicly reachable + key auth = critical", "Cognitive Services User / OpenAI User RBAC granted at subscription scope", "AOAI account has no privateEndpointConnections" |
| GCP ✅ | `gcp_vertex_endpoints`, `gcp_vertex_models`, `gcp_vertex_endpoint_iam` (+ `managed_ai` mission on existing `gcp` audit; project IAM walks reuse `gcp_project_iam_bindings`) | "Vertex endpoint `allUsers` / `allAuthenticatedUsers` binding (critical/high)", "`aiplatform.endpoints.predict` granted at project scope", "Default Compute SA used by Vertex inference" |

**2. Secrets-scan extension** ✅ — new module [`managed_ai_keys.py`](../hakuna-scanner/app/ingest/managed_ai_keys.py) wired into [`secrets.py`](../hakuna-scanner/app/ingest/secrets.py) trufflehog post-processing. Two entry points:

- `scan_for_managed_ai_keys(text)` — pure regex scan over arbitrary text. Catches providers trufflehog doesn't natively cover (Groq) and edge cases like the latest admin-key formats.
- `classify_trufflehog_detector(detector_name, raw)` — re-tags trufflehog hits with provider-specific plugin_id (`leaked_managed_ai_key_<provider>`) and bumps severity for admin-scope variants.

Patterns shipped:
- `sk-[A-Za-z0-9]{48,}` — OpenAI user
- `sk-proj-[A-Za-z0-9_-]{40,}` — OpenAI project key
- `sk-admin-[A-Za-z0-9_-]{40,}` — OpenAI admin (severity 4 — org-wide visibility)
- `sk-ant-api\d{2}-[A-Za-z0-9_-]{93}` — Anthropic API
- `sk-ant-admin\d{2}-[A-Za-z0-9_-]{93}` — Anthropic admin (severity 4)
- `csk_[A-Za-z0-9]{50,}` — Cohere
- `cohere-[A-Za-z0-9-]{40}` — Cohere legacy
- `r8_[A-Za-z0-9]{40}` — Replicate
- `hf_[A-Za-z0-9]{34}` — HuggingFace
- `gsk_[A-Za-z0-9]{52}` — Groq (no upstream trufflehog detector)

Severity scale: provider key without admin scope = high (3); admin/org-scope key = critical (4) regardless of trufflehog's `Verified` status — scope is the threat, liveness can't be untracked.

Findings emitted as `plugin_family="AI Governance"` with `plugin_id=leaked_managed_ai_key_<provider>` so they group with cloud audit findings instead of the generic Secret Detection family.

**Deferred (not blocking GA):** AWS Bedrock-only IAM scope post-processor and GCP service-account-Vertex-only role detector. Both require an inline cloud API call from the scanner to the customer's account, which adds a credential-vault dependency to the scanner pipeline that the cloud audit (Slice 1/3) already covers from the credentialed side. Re-evaluate after first 30 days of customer findings.

**3. Defer the LLM-driven `managed_ai_governance` audit** until customers explicitly ask for cross-account narrative ("walk every Bedrock model invocation across our 12 accounts"). Until then, deterministic findings from the cloud audits + secrets scan are enough. Re-evaluate at GA + 90 days.

### Compliance
- All findings auto-tag with `nist_ai_rmf`, `iso_42001`
- Cloud-IAM findings additionally tag with `cis_benchmarks` (AWS/Azure/GCP profiles already exist)
- Secrets-scan findings tag with `pci_dss_4` (key handling)

### Effort
~1 wk — three thin additions to existing surface vs. one greenfield family. No new audit registration, no relay handler changes, no UI work (cloud audits already render via `cloud-picker`).

### Prerequisite
- AWS/Azure/GCP audits must already have IAM-walking missions wired (they do — `cloud_inspect_tool` covers it)
- Trufflehog custom rule loading needs to support per-org additions (verify before starting)

---

## ✅ Phase 4.1 — Family D slice: `exposed_anon_protocol` bundle

**Status:** shipped. 18 backend + 18 relay tests pass.

Single audit registration covering five legacy anon-misconfig protocols, mirroring the Phase 1 datastore-bundle pattern (one audit, one relay method, one mission, op-dispatch). The `kerberos_anon` AS-REP-roast scope from the original roadmap was deliberately narrowed to **reachability + realm fingerprint** — actual username enumeration / roasting belongs in a separate consent-gated mission, not in `triage`.

| Port | Protocol | Decisive field |
|---|---|---|
| 21 | FTP | `anonymous_login_allowed` (USER anonymous → 230) |
| 5900 | VNC | `auth_required` (RFB security type 1 = None) |
| 53 | DNS | `axfr_allowed` (zone-transfer materialized) |
| 88 | Kerberos | `kdc_reachable` + best-effort `realm` from KRB-ERROR scan |
| UDP 69 | TFTP | `readable_files` (hardcoded common-filename list at relay) |

### Files added
- [`backend/agents/tools/exposed_anon_protocol_tools.py`](../backend/agents/tools/exposed_anon_protocol_tools.py)
- [`hakuna-relay-agent/agent/anon_protocol_probe.py`](../hakuna-relay-agent/agent/anon_protocol_probe.py)
- [`backend/agents/prompts/audit/exposed_anon_protocol/_preamble.md`](../backend/agents/prompts/audit/exposed_anon_protocol/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/exposed_anon_protocol/triage.md)
- [`backend/tests/test_exposed_anon_protocol_audit.py`](../backend/tests/test_exposed_anon_protocol_audit.py) — 18 tests
- [`hakuna-relay-agent/tests/test_anon_protocol_probe.py`](../hakuna-relay-agent/tests/test_anon_protocol_probe.py) — 18 tests including TFTP-filename-injection guard

### Defense in depth
- Backend tool layer exposes one `op` per protocol; the agent cannot smuggle paths or realms.
- Relay allowlist (`_OP_HANDLERS` in `anon_protocol_probe.py`) rejects unknown ops before any network code.
- TFTP filename list is `_TFTP_COMMON_FILES` at the relay — `op_params.filenames` is ignored. Tested explicitly.
- Kerberos probe is fingerprint-only: malformed AS-REQ-shaped TCP message + best-effort realm extraction. **No** AS-REQ for real principals, no AS-REP roasting.
- DNS AXFR uses dnspython if available; the probe degrades gracefully (returns `_errors`) when not installed.

### Auto-trigger (delivered)
Ports {21, 53, 88, 5900} → `("exposed_anon_protocol", "triage")`. Gated by new family switch `auto_audit_anon_protocol`. UDP 69 (TFTP) deliberately excluded from auto-trigger until Phase 4.0 lands UDP `port_change` events; the audit can still be dispatched manually with TFTP probing in scope.

### Compliance
`cis_benchmarks`, `nist_csf_pr_ac`, `pci_dss_4`. Wired in registration's `compliance_tags`.

---

## ✅ Phase 4.0 — Scanner UDP `port_change` events (transport-aware delta)

**Status:** shipped. Alembic migration 014 + delta diff + auto-trigger transport filter.

### What changed
- **Scanner schema**: new `assets.open_udp_ports` Integer array column ([migration 014](../hakuna-scanner/alembic/versions/014_add_open_udp_ports.py)). Mirrors `assets.open_ports` but holds UDP ports populated from the existing nmap UDP scan.
- **Enrichment**: `store_nmap_results` ([enrichment.py](../hakuna-scanner/app/ingest/enrichment.py)) now extracts UDP services from nmap's per-port output and writes them to `assets.open_udp_ports`. TCP-only nmap runs leave the column untouched.
- **Snapshot capture**: `_get_asset_snapshot` ([tasks/enrichment.py](../hakuna-scanner/app/tasks/enrichment.py)) reads both arrays so the post-scan delta has both transports' previous state.
- **Delta diffing**: `detect_changes` ([delta.py](../hakuna-scanner/app/ingest/delta.py)) diffs TCP and UDP separately and emits one `port_change` event per (asset, transport) with `payload.transport ∈ {"tcp", "udp"}`. Same asset with simultaneous TCP+UDP changes produces two distinct events.
- **Auto-trigger filter**: [`audit_auto_trigger.py`](../backend/services/audit_auto_trigger.py) `_match_rules(new_ports, transport)` rejects rules whose declared `transport` doesn't match the event transport. Legacy events with no `transport` field default to `"tcp"` — historical SMB/datastore/anon-protocol behavior preserved.

### Backwards compatibility
- Pre-4.0 `port_change` events without a `transport` field default to TCP at the matcher.
- Snapshots without `open_udp_ports` (taken before migration) are tolerated by `detect_changes` — UDP diffs default to empty.

### What this unlocked
- **SNMP rule** (declared `transport='udp'` since Phase 0) starts firing for the first time — historically the matcher ignored transport, so the rule actually didn't match TCP-shape events. New tests pin the correct UDP-only behavior.
- **IPMI rule** (Phase 4.2) and **NetBIOS rule** (Phase 4.3) auto-fire on UDP-tagged events.
- **TFTP** in the `exposed_anon_protocol` family (Phase 4.1) — auto-trigger still excludes UDP 69 deliberately (the rule is TCP-only) since the TFTP probe is opportunistic; the audit can still be dispatched manually with TFTP probing in scope.

---

## ✅ Phase 4.2 — Family C: `ipmi_bmc` (Cipher Zero + RAKP-3)

**Status:** shipped. 13 backend + 18 relay tests pass.

Single-protocol audit registration with two ops, both UDP/623, RMCP+ packet-construction at the relay (no `pyipmi`/`pyghmi` dependency — neither library exposes the low-level control we need for cipher-zero and deliberately-incomplete RAKP-3).

| Op | Detection | Severity (when fired) |
|---|---|---|
| `cipher_zero` | RMCP+ Open Session Request with auth/integ/conf=0; BMC accepts → critical | always **critical** (any user, no password → full host control) |
| `rakp_hash` | RAKP-1 with username `admin`/`root`; BMC returns RAKP-2 with status=0 + non-zero KEAC → hash leak (CVE-2013-4786) | **high**/**medium** depending on network position |

### Files added
- [`backend/agents/tools/ipmi_tools.py`](../backend/agents/tools/ipmi_tools.py)
- [`hakuna-relay-agent/agent/ipmi_probe.py`](../hakuna-relay-agent/agent/ipmi_probe.py) — hand-rolled RMCP+ session header + Open Session Req/Resp + RAKP-1/RAKP-2 parsers
- [`backend/agents/prompts/audit/ipmi_bmc/_preamble.md`](../backend/agents/prompts/audit/ipmi_bmc/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/ipmi_bmc/triage.md)
- [`backend/tests/test_ipmi_bmc_audit.py`](../backend/tests/test_ipmi_bmc_audit.py) — 13 tests (registration, dispatch, auto-trigger, transport-filter)
- [`hakuna-relay-agent/tests/test_ipmi_probe.py`](../hakuna-relay-agent/tests/test_ipmi_probe.py) — 18 tests covering packet builders + parsers + cipher-zero verdict matrix + RAKP-2 keac handling

### Auto-trigger (delivered)
UDP 623 → `("ipmi_bmc", "triage")`. Gated by family switch `auto_audit_ipmi`. Rule declares `transport="udp"`; only fires on UDP-tagged port_change events from Phase 4.0.

### Defense-in-depth
- Op-allowlist (`_OP_HANDLERS` in `ipmi_probe.py`) restricts the relay to exactly two ops — no chassis power, no virtual-media, no SOL.
- `_build_rakp1` clamps username to 16 bytes per IPMI spec — no buffer-overrun smuggling.
- Triage prompt limits username probing to `admin` then `root` (only if first returns "name unknown"). The agent is told **not** to enumerate vendor-default usernames.

### Compliance
`nist_csf_pr_ac`, `cis_benchmarks`.

---

## ✅ Phase 4.3 — Family D': `netbios_local` (LAN-local)

**Status:** shipped. 15 backend + 11 relay tests pass.

Single audit registration covering three LAN-local name-resolution / service-discovery protocols. All probes are unicast UDP queries sent directly to the asset (not multicast solicitations) — the auto-trigger's subnet predicate ensures the relay shares a broadcast domain with the asset so the unicast probes land.

| Op | Port | Detection |
|---|---|---|
| `nbns` | UDP 137 | NBSTAT query (`*` name) — response = NBT-NS enabled, name table reveals workgroup + signed-on user |
| `llmnr` | UDP 5355 | Unicast LLMNR query for the host's short name — any reply = LLMNR enabled (Responder/poisoning vector) |
| `mdns` | UDP 5353 | Unicast DNS-SD `_services._dns-sd._udp.local` PTR — response = mDNS enabled, advertised services exposed |

### New: `_lan_local_predicate` (relay/asset same-subnet gate)
[`audit_auto_trigger.py`](../backend/services/audit_auto_trigger.py) — predicate signature widened to `Callable[[Asset, RelayAgent | None], bool]`. The LAN-local rule's predicate reads `RelayAgent.labels["local_interfaces"]` (a list of CIDR strings) and accepts only when the asset's IP falls inside one of them. Missing labels = predicate rejects (defensive default).

### Files added
- [`backend/agents/tools/netbios_local_tools.py`](../backend/agents/tools/netbios_local_tools.py)
- [`hakuna-relay-agent/agent/netbios_probe.py`](../hakuna-relay-agent/agent/netbios_probe.py) — RFC 1002 NetBIOS-name encoder, NBSTAT response parser, DNS-format query builder shared between LLMNR and mDNS, DNS-SD service-name scanner
- [`backend/agents/prompts/audit/netbios_local/_preamble.md`](../backend/agents/prompts/audit/netbios_local/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/netbios_local/triage.md)
- [`backend/tests/test_netbios_local_audit.py`](../backend/tests/test_netbios_local_audit.py) — 15 tests
- [`hakuna-relay-agent/tests/test_netbios_probe.py`](../hakuna-relay-agent/tests/test_netbios_probe.py) — 11 tests covering encoders + parsers + per-op silent-host vs responding-host vs mismatched-tid behavior

### Auto-trigger
UDP {137, 5355, 5353} → `("netbios_local", "triage")`. Family switch `auto_audit_netbios`. Predicate-gated on relay-asset same subnet.

### Open prerequisite
The relay-agent registration code does not yet populate `RelayAgent.labels["local_interfaces"]`. Until it does, the predicate defensively rejects every event and the audit only fires via manual dispatch. **Next steps**: extend the relay's startup to enumerate local interfaces (Python `psutil.net_if_addrs()` or stdlib `socket.if_nameindex`+`fcntl`) and include them in the registration handshake; update the backend relay-registration route to persist into `labels`. Out of scope for this slice — the predicate, audit, prompts, and tests are ready to consume the data the moment it lands.

### Defense-in-depth
- Probes are unicast-only — the relay never multicasts, never poisons, never spoofs Responder-style replies.
- DNS-SD service-list parser dedupes and caps at 50 services.
- LLMNR query uses just the short hostname (RFC compliance) — confirmed by test that fqdn input gets stripped.

---

## ✅ Phase 5 — Family E: OT/ICS (`ot_protocol` + `ot_passive`)

**Status:** shipped. 25 backend + 36 relay tests pass. Two audit registrations covering ten active read-only fingerprints + one passive UDP listener. Per-asset OT consent enforced at BOTH the auto-trigger gate AND the manual-dispatch path (the latter is new in this slice — see [audit_runner.py](../backend/services/audit_runner.py) `_has_fresh_ot_consent`).

**Deferred to a follow-on UX slice (not blocking GA):** JP-first localization (`frontend/src/locales/ja/audit.json`), OT Posture Dashboard page, METI v3 control-mapping UI. Phase 5 ships the audit machinery and compliance tags; the Japanese UX surface lands separately so it can iterate with design-partner factories.

### What landed

**Active audit `ot_protocol` (`safety_class="ot_safe"`)** — single registration, single relay handler `ot_protocol_probe`, op-allowlisted, ten read-only ops:

| Op | Port | Family | What it asks |
|---|---|---|---|
| `modbus_read_device_id` | TCP 502 | Modbus | FC 43 / MEI 14: vendor + product + revision |
| `modbus_read_holding` | TCP 502 | Modbus | FC 3: ≤16 registers, unit_id ≤247 |
| `s7_read_szl` | TCP 102 | Siemens S7 | COTP CR + Setup + Read SZL 0x0011 (CPU/MLFB) |
| `enip_list_identity` | TCP 44818 | EtherNet/IP CIP | ListIdentity → vendor/product/revision |
| `bacnet_read_property` | UDP 47808 | BACnet/IP | ReadProperty Object-Name on Device 0 |
| `opcua_hello` | TCP 4840 | OPC UA | Hello + ACK; deeper GetEndpoints intentionally deferred |
| `melsec_read_cpu_info` | TCP 5007 | Mitsubishi SLMP (JP) | Cmd 0x0101 / Sub 0x0000: CPU model |
| `omron_fins_read_cpu_unit` | UDP 9600 | Omron FINS (JP) | MRC/SRC 0x05/0x01: CPU unit data read |
| `iec104_interrogate` | TCP 2404 | IEC 60870-5-104 | U-format STARTDT + I-format C_IC_NA_1 (type 100) |
| `profinet_dcp_unicast` | UDP 34962 | PROFINET DCP | Best-effort unicast IDENTIFY (canonically L2 — opportunistic) |

**Passive audit `ot_passive` (`safety_class="ot_passive_only"`)** — single registration, single relay handler `ot_passive_probe`. Sole op: `passive_listen` with a closed allowlist of profiles (`yokogawa_vnetip` UDP 12289, `cclink_ie` UDP 61450). Receive-only socket; the test suite explicitly asserts the relay never calls `sendto`/`sendall`/`send`.

### Defense-in-depth

- **Op-allowlist** at the relay (`_OP_HANDLERS`) — unknown ops rejected before any byte hits the wire. Mirrors the IPMI/datastore/anon-protocol pattern.
- **Read-only enforcement at the relay** (not just the tool palette): every op's request bytes are constants in the relay file or built from clamped parameters. SLMP command code is hardcoded `0x0101` (Read CPU Type); FINS MRC/SRC hardcoded `0x05/0x01`; IEC-104 type ID hardcoded 100. The LLM can never supply a write op via crafted op_params.
- **Rate limiter** at the relay — `_RateLimiter` with ≥2-second inter-PDU floor and 1 RPS default; `HAKUNA_OT_RPS` env var allows down-tuning to 0.2 RPS for cautious JP factories. Process-global, so concurrent ops across protocol handlers can't gang up.
- **Modbus FC3 clamping** — `count` capped at 16, `unit_id` capped at 247 (spec ceiling) at BOTH tool and relay layers; tested with a 99999-input that should clamp to 16.
- **PROFINET DCP** — clearly documented as INCONCLUSIVE on negative; the LLM is instructed never to claim absence based on this op. The error message itself includes the word "inconclusive."
- **Per-asset OT consent gate at manual dispatch** — `services.audit_runner.dispatch_audit_run` now refuses any `ot_*` audit run without a fresh `Asset.easm_data['ot_audit_consent'][protocol]` (90-day TTL). Same gate applied to `rescan_audit_scan`. Auto-trigger had this already; the manual API path was an open hole and is now closed.

### Auto-trigger (delivered)

Two rules per protocol, split by transport (Phase 4.0's transport-aware delta):

- TCP {502, 102, 44818, 4840, 5007, 2404} → `("ot_protocol", "triage")`
- UDP {47808, 9600, 34962} → `("ot_protocol", "triage")` AND `("ot_passive", "triage")` (both fire when consent for both protocols is present)

Both gated by `auto_audit_ot` org switch (defense-in-depth master kill — same shape as every other family) AND `requires_per_asset_consent=True`. 7-day cooldown per (asset, protocol).

### Compliance

`iec_62443_3_3`, `meti_ot_security_guideline_v3`, plus `nist_csf_pr_ac` for the active audit. Wired in registration's `compliance_tags`. Findings emit these tags for the existing compliance evaluator.

### Files added

- [`backend/agents/tools/ot_protocol_tools.py`](../backend/agents/tools/ot_protocol_tools.py)
- [`backend/agents/tools/ot_passive_tools.py`](../backend/agents/tools/ot_passive_tools.py)
- [`backend/agents/prompts/audit/ot_protocol/_preamble.md`](../backend/agents/prompts/audit/ot_protocol/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/ot_protocol/triage.md)
- [`backend/agents/prompts/audit/ot_passive/_preamble.md`](../backend/agents/prompts/audit/ot_passive/_preamble.md), [`triage.md`](../backend/agents/prompts/audit/ot_passive/triage.md)
- [`backend/tests/test_ot_protocol_audit.py`](../backend/tests/test_ot_protocol_audit.py) — 18 tests
- [`backend/tests/test_ot_passive_audit.py`](../backend/tests/test_ot_passive_audit.py) — 7 tests
- [`hakuna-relay-agent/agent/ot_protocol_probe.py`](../hakuna-relay-agent/agent/ot_protocol_probe.py) — 10 hand-rolled byte protocols + rate limiter
- [`hakuna-relay-agent/agent/ot_passive_probe.py`](../hakuna-relay-agent/agent/ot_passive_probe.py) — receive-only listener with closed profile allowlist
- [`hakuna-relay-agent/tests/test_ot_protocol_probe.py`](../hakuna-relay-agent/tests/test_ot_protocol_probe.py) — 30 tests including rate-limiter floor + read-only-FC enforcement
- [`hakuna-relay-agent/tests/test_ot_passive_probe.py`](../hakuna-relay-agent/tests/test_ot_passive_probe.py) — 6 tests including "never sends" contract
- [`backend/services/audit_runner.py`](../backend/services/audit_runner.py) — `_has_fresh_ot_consent` helper + dispatch gate
- [`backend/services/audit_auto_trigger.py`](../backend/services/audit_auto_trigger.py) — three new OT rules

### Library choices

Hand-rolled byte parsers for every protocol (~50–100 LoC each) — no `pymodbus`/`python-snap7`/`bacpypes3`/`asyncua`/`pyipmi` dependencies. Each protocol's request packet is a constant or clamped-parameter builder; reading 100 LoC of explicit byte construction is cheaper to audit than verifying a third-party lib's "does this *actually* never write?" guarantees.

### Still pending (follow-on UX slice)

- JP-first localization (`frontend/src/locales/ja/audit.json` + Japanese vendor names 三菱電機 / オムロン / 横河 in OT kickoff card)
- OT Posture Dashboard page (`frontend/src/pages/OTPostureDashboard.tsx`) — asset × protocol matrix, per-asset consent state, IEC 62443 coverage %
- Multi-tier kickoff grouping by `safety_class` now that there are 8 tiers (the binary cloud-vs-host split outgrew its design)

---

## (archived) Phase 5 plan, pre-shipping

**Why last:** highest safety stakes, JP localization gating sales, longest QA cycle. By now `safety_class` infrastructure has been exercised across four families.

### Scope

**Pre-existing in `protocol_probe.py`** (already shipped, read-only ID PDUs): Modbus, S7, BACnet, EtherNet/IP, OPC-UA, MQTT, RTSP, DNP3, Niagara Fox. Phase 5 wraps these in agentic `ot_safe` audits but does not re-implement the network-layer probes.

**`safety_class="ot_safe"`** — wraps existing scanner probes + adds new ones:
- **Modbus** 502 — wrap existing probe; add FC 1–4 read for diagnostics
- **EtherNet/IP CIP** 44818 — wrap existing `ListIdentity`
- **BACnet/IP** UDP 47808 — wrap existing `ReadProperty`; add `WhoIs`
- **OPC UA** 4840 — wrap existing Hello; add `GetEndpoints` for `SecurityPolicy=None` detection
- **Siemens S7** 102 — wrap existing COTP+Setup; add `Read SZL`
- **MELSEC SLMP** 5007/5562 (Mitsubishi, JP — NEW — read-only commands `0x0401`, `0x0619`)
- **Omron FINS** UDP 9600 (JP — NEW — MRC `{0x01, 0x05}` only)
- **IEC 60870-5-104** 2404 (NEW — interrogation only, no control commands)
- **ProfiNet** 34962/34964 (NEW — DCP Identify-All)

**`safety_class="ot_passive_only"`** (banner-fingerprint only, never craft PDUs):
- **Yokogawa Vnet/IP** (JP DCS) — UDP broadcast presence check
- **CC-Link IE** (JP) — passive L2 signal from scanner

### Auto-trigger gating
- `auto_trigger_policy="per_asset_consent"` — never fires without fresh `Asset.easm_data["ot_audit_consent"]`
- Even with org consent, dispatch refuses without the per-asset record
- 7-day cooldown per (asset, protocol)
- 90-day TTL on consent records (forces re-approval)

### Defense-in-depth
- **Read-only function codes enforced at the relay layer**, not just tool palette — a buggy/prompt-injected LLM tool call cannot reach a write FC
- Min 2-second inter-request delay encoded in relay handler
- Relay-side rate limiter (1 RPS default, configurable down to 0.2 RPS for cautious JP factories)

### Compliance
- **`iec_62443_3_3`** — international, JP-adopted
- **`meti_ot_security_guideline_v3`** — JP customers will diff against METI's 制御システムのセキュリティリスク分析ガイド v3.0
- Map MELSEC/FINS findings to `L3-CPS-PE-1` (PLC integrity), `L3-CPS-IT-2` (control protocol authentication absence)

### Localization
**JP-first** — `frontend/src/locales/ja/audit.json` ships with full coverage before `en/`. OT kickoff card displays JP vendor names natively (三菱電機, オムロン, 横河). Sales-grade copy drafted by humans, not auto-translated.

### Library choices
- `pymodbus` (Modbus), `cpppo`/handrolled (EtherNet/IP), `bacpypes3` (BACnet), `python-snap7` (S7), `asyncua` (OPC UA `GetEndpoints` only)
- **MELSEC SLMP, Omron FINS, Yokogawa Vnet/IP, CC-Link IE → hand-rolled byte parsers** (~200 LoC each), no maintained Python lib worth trusting on a PLC

### Handoff gates
- **End P5.1:** behind `ot_audits_enabled` flag, internal only
- **End P5.2:** limited GA to 2 design-partner JP factories, auto-trigger still off
- **End P5.3:** GA, two-flag opt-in auto-trigger, OT Posture report in compliance pack

### Frontend
New page `frontend/src/pages/OTPostureDashboard.tsx`. Shows asset → protocol matrix, opt-in status, last-fingerprint timestamp, IEC 62443 coverage %.

---

## Cross-cutting infrastructure

### Per-family org switches
| Switch | Family | Status |
|---|---|---|
| `auto_audit_anon` | SMB, SNMP (legacy) | shipped |
| `auto_audit_datastore` | Family A | shipped |
| `auto_audit_ai` | Family B (self-hosted) | shipped |
| `auto_audit_anon_protocol` | Family D bundle (FTP/VNC/DNS/Kerberos/TFTP) | shipped (Phase 4.1) |
| `auto_audit_ipmi` | Family C (IPMI BMC) | shipped (Phase 4.2) |
| `auto_audit_netbios` | Family D' (NetBIOS/LLMNR/mDNS) | shipped (Phase 4.3) |
| `auto_audit_ot` | Family E (`ot_protocol` + `ot_passive`) | shipped (Phase 5) |

Family B' (Phase 3.5, managed AI governance) does NOT get its own switch — coverage rides on the existing cloud audits' kickoff cadence and the always-on secrets-scan stage.

OT (Family E, Phase 5) follows the same pattern as the rest — `auto_audit_ot` org switch + per-asset consent. Both gates must pass to auto-fire. The earlier roadmap text proposed "per-asset only" with no org switch, but defense-in-depth + consistency with the other families won out: master-kill switches are cheap and the consent record is still the per-asset signal.

### Per-asset consent record
`Asset.easm_data["ot_audit_consent"]` keyed by protocol with 90-day TTL. Helper functions live in [audit_auto_trigger.py](../backend/services/audit_auto_trigger.py). Reused by any future high-touch family.

### Compliance auto-tagging
Each audit declares `compliance_tags`:
- Datastores: `("cis_benchmarks", "nist_csf_pr_ac")`
- AI: `("nist_ai_rmf", "iso_42001")`
- OT: `("iec_62443_3_3", "meti_ot_security_guideline_v3")`
- IPMI: `("nist_csf_pr_ac", "cis_benchmarks")`

Findings emit these tags for the existing compliance evaluator to consume.

### Frontend grouping
Kickoff menu groups by `safety_class`, not alphabetically. Tiers:
- "Datastore exposures"
- "AI services"
- "OT (read-only)"
- "Legacy anon"
- "Credentialed"

22 audits become 5 visible navigation tiers.

---

## Open prerequisites by phase

| Prereq | Blocks | Where |
|---|---|---|
| ~~Scanner UDP `port_change` events~~ | ~~Phase 4 (IPMI/TFTP/NetBIOS)~~ | ✅ Phase 4.0 (migration 014 + transport-aware delta) |
| Relay registration carries local interfaces | Family D' `netbios_local` predicate fires in production | hakuna-relay-agent registration handshake — read by `_lan_local_predicate` |
| ~~Relay-side method allowlist + rate limiter~~ | ~~Phase 5 (OT)~~ | ✅ Phase 5 (`_OP_HANDLERS` + `_RateLimiter` in `ot_protocol_probe.py`) |
| Compliance YAML loader supports per-finding tag→control | Compliance auto-tagging across all phases | [backend/services/compliance_loader.py](../backend/services/compliance_loader.py) |

---

## Counts at full rollout

- **~23 `ProtocolAudit` registrations** (Phase 3.5 adds *one* — `managed_ai_saas` for OpenAI/Anthropic admin APIs; cloud arm extends existing aws/azure/gcp audits without new registrations)
- **~50 LLM tools** for self-hosted/host audits + **~12 new cloud-AI tools** in Phase 3.5, all read-only with parameter bounds
- **4 org-level family switches** + 1 per-asset consent flag (OT). Phase 3.5 deliberately rides existing cloud-audit cadence — no new switch.
- **~10 managed-AI key regex patterns** added to secrets-scan in Phase 3.5
- **6 `safety_class` tiers** driving dispatch validation, cooldowns, gating, and UI grouping
- **1 dispatch pipeline** (`dispatch_audit_run`), 1 auto-trigger evaluator, 1 relay handler per protocol family

**Total estimated effort remaining:** ~3 weeks for Phases 4 → 5 (Phase 2, 3, 3.5 ✅ shipped; ~1 wk for 4; ~2 wk for 5). Handoff gates between phases (internal flag → design partners → GA per family).

---

## Quick reference — adding a new family

1. Decide `safety_class` (drives credential gating, cooldown defaults, UI group)
2. Write tool palette in `backend/agents/tools/<family>_tools.py` with `register_audit(ProtocolAudit(...))`
3. Add mission prompt to `backend/agents/agent_prompts.py` (`_<family>_audit_preamble` + mission key); add family to `_resolve_audit_preambles` loop
4. Side-effect import in `backend/agents/tools/__init__.py`
5. Write relay handler in `hakuna-relay-agent/agent/<family>_probe.py` with `@register_method` and op-allowlist dict
6. Wire handler import in `hakuna-relay-agent/agent/executor.py`
7. Add `AutoTriggerRule` entries to `backend/services/audit_auto_trigger.py` if family supports auto-fire
8. Add new family switch key to `Organization.settings` (no migration — JSON column)
9. Tests: backend (mocked relay broker), relay-side (mocked clients) — never real hardware in CI
10. Update [docs/protocol-audit-coverage-roadmap.md](protocol-audit-coverage-roadmap.md) phase status

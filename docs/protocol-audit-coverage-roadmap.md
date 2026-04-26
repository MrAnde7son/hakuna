# Protocol Audit Coverage Expansion — Roadmap

**Last updated:** 2026-04-26
**Status:** Phase 0, 1a, 1b shipped. Phase 2–5 planned.

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
| 2 | F: EASM fingerprinter | 📋 planned | — | ~1 wk |
| 3 | B: `exposed_ai_service` | 📋 planned | — | ~1 wk |
| 4 | C+D: IPMI + small anon | 📋 planned | — | ~1 wk |
| 5 | E: OT/ICS (JP-flavored) | 📋 planned | — | ~3 wk |

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

## 📋 Phase 2 — Family F: EASM fingerprinter extension

**Why next:** scanner-only work, no LLM cost, no relay changes. Enriches the existing CVE correlator. **Phase 3 depends on this** for port 3000/5000/8000 disambiguation.

### Scope
Extends [hakuna-scanner](../hakuna-scanner/) for deeper banners on:
- **SSH** 22 — full version exchange line
- **RDP** 3389 — NLA enforcement probe (no full handshake), TLS cert
- **SMTP/IMAP/POP3** 25/587/143/110/993/995 — banner + STARTTLS capability + VRFY/EXPN test
- **HTTPS** 443 — testssl-grade cipher list (gap-fill on existing `tls_cert`)
- **IPP/LPD** 631/515 — printer model via IPP `Get-Printer-Attributes`
- **TR-069/UPnP** 7547/1900 — SOAP/SSDP descriptor fetch
- **Postgres/MySQL** 5432/3306 — banner version (deferred from Phase 1)

### Output
Writes to `assets.easm_data.banner_findings`, `assets.easm_data.tls_posture` (new sub-keys). No agent involvement. CVE correlator consumes these fields.

### New code
- `hakuna-scanner/app/tasks/banner_grab.py` — protocol-specific deeper banners than `-sV` provides
- `ProtocolAudit(protocol="easm_fingerprint", mode="fingerprint", ...)` registered with empty tools/missions — purely metadata for the audit list

### Compliance
- TLS posture → `pci_dss_4`, `cis_benchmarks`
- SMTP open relay → `nist_csf_pr_ds`

### Risks
- Banner-grab false positives on honeypots → stamp `confidence: low` when banner is the only signal

---

## 📋 Phase 3 — Family B: `exposed_ai_service` (competitive wedge)

**Why third:** product-differentiation value, but nascent threat model — wait until A's pattern is proven.

### Audit
`protocol="exposed_ai_service"`, `safety_class="anon_ai_exposure"`, missions `triage` + `prompt_injection_probe` (latter requires explicit consent — never auto-triggered).

### Tools
- `ollama_list_models(asset_id)` — `GET /api/tags`
- `ollama_capability_probe(asset_id)` — single benign hardcoded prompt to confirm inference is open
- `jupyter_check_auth(asset_id)` — `GET /api/status`, classify token requirement
- `ray_dashboard_info(asset_id)` — `GET /api/version`, `/api/jobs/`
- `mlflow_list_experiments(asset_id)`
- `tensorboard_list_runs(asset_id)`
- `vllm_models(asset_id)`, `tgi_info(asset_id)`, `lmstudio_models(asset_id)` — `/v1/models` OpenAI-compat
- `openwebui_status(asset_id)`, `langfuse_status(asset_id)`

### Auto-trigger
Ports {11434, 8888, 8265, 5000, 6006, 8000, 1234, 3000} → `("exposed_ai_service","triage")`.

**Disambiguation predicate** on `AutoTriggerRule`: ports 3000/5000/8000 only fire if Phase 2's banner-grabber tagged the service as AI. Hard dependency on Phase 2.

### Compliance
`nist_ai_rmf`, `iso_42001`. Findings auto-tag.

---

## 📋 Phase 4 — Families C + D: IPMI + small anon protocols

**Why fourth:** small surface area, drop in alongside whichever release window is open.

### Audits
- **`ipmi_bmc`** (UDP 623, `safety_class="anon_ipmi"`) — Cipher Zero + RAKP hash test. Devastating in legacy DCs.
- **`kerberos_anon`** (88) — username enum + AS-REP roast
- **`dns_axfr`** (53) — zone transfer
- **`tftp_anon`** (UDP 69) — common-filename probe with hardcoded list
- **`netbios_local`** (UDP 137/5355/5353, `safety_class="anon_lan_local"`) — auto-fires only when relay reports same /24 as asset
- **`ftp_anon`** (21), **`vnc_anon`** (5900) — auth-disabled checks

### Compliance
IPMI → `nist_csf_pr_ac`, `cis_benchmarks`. AXFR → `cis_benchmarks`. FTP anon → `pci_dss_4`.

### Prerequisite
**Phase 0.4** — UDP `port_change` events from the scanner. Currently TCP-only. See [hakuna-scanner/app/ingest/delta.py](../hakuna-scanner/app/ingest/delta.py).

---

## 📋 Phase 5 — Family E: OT/ICS (highest stakes, JP-flavored)

**Why last:** highest safety stakes, JP localization gating sales, longest QA cycle. By now `safety_class` infrastructure has been exercised across four families.

### Scope

**`safety_class="ot_safe"`** (read-only function codes only):
- **Modbus** 502 (FC 1–4 only — read coils, discrete inputs, holding registers, input registers)
- **EtherNet/IP CIP** 44818 (`ListIdentity` only)
- **BACnet/IP** UDP 47808 (`WhoIs`, `ReadProperty`)
- **OPC UA** 4840 (`GetEndpoints` only — flags `SecurityPolicy=None`)
- **Siemens S7** 102 (`Read SZL` — read-only diagnostics)
- **MELSEC SLMP** 5007/5562 (Mitsubishi, JP — read-only commands `0x0401`, `0x0619`)
- **Omron FINS** UDP 9600 (JP — MRC `{0x01, 0x05}` only)
- **IEC 60870-5-104** 2404 (interrogation only, no control commands)
- **ProfiNet** 34962/34964 (DCP Identify-All)

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
| `auto_audit_ai` | Family B | planned |
| `auto_audit_ipmi` | Family C | planned |

OT explicitly does NOT get an org switch — per-asset only.

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
| Scanner UDP `port_change` events | Phase 4 (IPMI/TFTP/NetBIOS) | [hakuna-scanner/app/ingest/delta.py](../hakuna-scanner/app/ingest/delta.py) |
| Relay registration carries local interfaces | Family D `netbios_local` subnet predicate | hakuna-relay-agent registration |
| Relay-side method allowlist + rate limiter | Phase 5 (OT) | hakuna-relay-agent executor |
| Compliance YAML loader supports per-finding tag→control | Compliance auto-tagging across all phases | [backend/services/compliance_loader.py](../backend/services/compliance_loader.py) |

---

## Counts at full rollout

- **~22 `ProtocolAudit` registrations**
- **~50 LLM tools**, all read-only with parameter bounds
- **4 org-level family switches** + 1 per-asset consent flag (OT)
- **6 `safety_class` tiers** driving dispatch validation, cooldowns, gating, and UI grouping
- **1 dispatch pipeline** (`dispatch_audit_run`), 1 auto-trigger evaluator, 1 relay handler per protocol family

**Total estimated effort remaining:** ~6 weeks for Phases 2 → 5, with handoff gates between phases (internal flag → design partners → GA per family).

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

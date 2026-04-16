# Scanning & Discovery Architecture — Plan & Phasing Guide

## Overview

This document describes the scanning, discovery, and prioritization architecture for Hakuna,
identifies implemented improvements, and provides a phased roadmap for remaining work.

---

## Current Architecture (Post Quick Wins)

```
                        TARGET DOMAINS
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                   ▼
   ┌─────────────┐  ┌──────────────┐   ┌──────────────┐
   │ Pipeline A   │  │ Pipeline B    │   │ File Upload  │
   │ EASM Scanner │  │ VM Scanner    │   │ Parsers      │
   │ (Discovery)  │  │ (Nuclei)      │   │ Nessus/Qualys│
   └──────┬──────┘  └──────┬───────┘   └──────┬───────┘
          │                 │                   │
          ▼                 ▼                   ▼
   ┌──────────────────────────────────────────────────┐
   │             INGESTION & DEDUP LAYER               │
   │  Asset Dedup (OR-mode IP/FQDN)                   │
   │  Finding Dedup (plugin+asset+port)               │
   │  CDN-aware IP exclusion                          │
   │  19 inventory entity types                       │
   └──────────────────────┬───────────────────────────┘
                          ▼
   ┌──────────────────────────────────────────────────┐
   │            POST-INGEST PIPELINE (12 steps)        │
   │  Auto-tag → Ownership → Exceptions → Threat Intel│
   │  TTP matching → SLA → Dedup → Relationships      │
   └──────────────────────┬───────────────────────────┘
                          ▼
   ┌──────────────────────────────────────────────────┐
   │            PRIORITIZATION ENGINE                  │
   │  7-signal finding score (0-10)                   │
   │  6-signal asset risk score (0-10)                │
   │  EPSS-default severity source                    │
   └──────────────────────┬───────────────────────────┘
                          ▼
   ┌────────────────┐  ┌─────────────────────────┐
   │ WORKFLOW ENGINE │  │ AI AGENT SYSTEM          │
   │ DAG-based       │  │ Multi-provider LLM       │
   │ 8 triggers      │  │ 50+ security tools       │
   │ 13 actions      │  │ HITL guardrails          │
   └────────────────┘  └─────────────────────────┘
```

---

## Pipeline A — EASM Discovery

### Discovery Chain (Daily 02:00 UTC)

| Group | Stage | Tool | What It Does |
|-------|-------|------|-------------|
| 1 (parallel) | subfinder | ProjectDiscovery subfinder | Passive DNS aggregation |
| 1 (parallel) | puredns | puredns + massdns | DNS brute force with wildcard filtering |
| 1 (parallel) | uncover | ProjectDiscovery uncover | Shodan/Censys/FOFA queries |
| 1 (parallel) | **crtsh** | crt.sh API | **NEW** — Certificate transparency log monitoring |
| 2 (parallel) | dnsx | ProjectDiscovery dnsx | Batch DNS resolution (A/CNAME/MX/TXT) |
| 2 (parallel) | naabu | ProjectDiscovery naabu | SYN scan on 141 ports (IT+AI+IoT+OT) |
| 3 (sequential) | liveness_gate | socket + naabu + httpx | Triple liveness validation → confirmed_alive / likely_dead / dangling_dns |

### Enrichment Chain (Daily 04:00 UTC)

| Group | Stage | Tool | What It Does |
|-------|-------|------|-------------|
| 1 (parallel) | tlsx | ProjectDiscovery tlsx | TLS cert scanning + JARM fingerprinting + **SAN feedback to discovery** |
| 1 (parallel) | httpx | ProjectDiscovery httpx | HTTP probing, tech detection (Wappalyzer), CDN, WAF, screenshots |
| 1 (parallel) | cdncheck | ProjectDiscovery cdncheck | CDN/WAF identification |
| 2 (parallel) | js_fingerprint | Custom | `<script>` tag parsing, JS library version detection |
| 2 (parallel) | favicon_fingerprint | Custom | mmh3 favicon hash → known product DB |
| 2 (parallel) | endpoint_probe | Custom | **EXPANDED** — Now 100+ probes including sensitive files, admin panels, GraphQL, API discovery |
| 2 (parallel) | protocol_probe | Custom | OT/ICS/IoT protocol detection (Modbus, S7, MQTT, RTSP) |
| 2 (parallel) | katana | ProjectDiscovery katana | Web crawling — **IMPROVED** depth 3 + automatic form fill |
| 3 (sequential) | classify_assets | Custom | Asset type classification (AI/IoT/OT/IT) |
| 4 (async queue) | nmap | libnmap | OS fingerprinting + NSE scripts, max concurrency 5 |

---

## Pipeline B — VM Scanning

### Template Routing (Adaptive)

```
Asset enrichment data (CPE, tech stack, ports)
    │
    ▼
┌─────────────────────────────────────────┐
│         TEMPLATE ROUTER                  │
│  Tier 1: CPE → Nuclei tags              │
│  Tier 2: Tech stack → tags (fallback)   │
│  Tier 3: Port gating (remove irrelevant)│
│  Tier 4: Fallback → [generic, exposure] │
│  Custom templates: "always" tag or match│
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│         NUCLEI EXECUTION                 │
│  150 req/s rate limit                   │
│  600s timeout, max 2 retries            │
│  JSONL streaming output                 │
│  Per-finding dedup (title + asset)      │
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│    ADAPTIVE SCAN PLANNER (NEW)           │
│  LLM analyzes asset risk profile        │
│  Selects tools + depth per asset        │
│  Deterministic fallback when no LLM     │
│  API: /api/scan-planner/plan/{id}       │
└─────────────────────────────────────────┘
```

---

## Asset Knowledge Graph (NEW)

### Relationship Types

| Type | Source | Confidence | Weight |
|------|--------|------------|--------|
| resolves_to | DNS CNAME chain | high | 1.0 |
| alias_of | DNS A record alias | high | 1.0 |
| **shares_certificate** | Same TLS cert (issuer+subject) | high | 0.9 |
| **same_jarm_cluster** | Same JARM fingerprint | medium | 0.7 |
| **same_ip** | Shared IP (non-CDN) | high | 0.8 |
| hosts_service | Port → service mapping | high | 0.9 |
| runs_technology | Tech stack detection | medium | 0.6 |
| exposes_endpoint | Katana endpoint discovery | medium | 0.5 |

### Infrastructure Clustering

Assets are automatically grouped into clusters by:
- **Shared certificate** — assets serving the same TLS cert (e.g., wildcard cert cluster)
- **Same JARM** — assets with identical JARM fingerprints (shared TLS config / potential C2)
- **Shared IP range** — multiple hostnames resolving to the same IP

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/graph/materialize` | Trigger edge materialization from enrichment data |
| GET | `/api/graph/` | Full graph visualization (nodes, edges, clusters) |
| GET | `/api/graph/blast-radius/{asset_id}` | BFS blast radius from an asset |
| GET | `/api/graph/clusters` | List infrastructure clusters |

---

## Prioritization Engine

### Finding Priority Score (0-10)

```
score = (
    0.25 × severity         +  // EPSS (default), CVSS, or VPR
    0.25 × exploit_bonus     +  // zero-day=1.0, weaponized=0.9, poc=0.5
    0.20 × intel_factor      +  // max(KEV=0.9, EPSS×1.5, ransomware=1.0)
    0.10 × criticality       +  // asset criticality (1-10 normalized)
    0.10 × family_bonus      +  // plugin family weight
    0.05 × controls          +  // compensating controls penalty
    0.05 × reachability         // port-aware + internet-facing
) × 10.0
```

Severity floors: Critical ≥ 7.0, High ≥ 5.0, Medium ≥ 3.0, Info ≤ 2.5.

### Asset Risk Score (0-10)

Uses 6 weighted signals: severity (0.35), exploitability (0.25), intel (0.15), criticality (0.15), controls (0.05), reachability (0.05).

---

## What Was Implemented

### Quick Wins (Done)

| # | Change | Files Modified |
|---|--------|---------------|
| 1 | Sensitive file probes (.git/config, .git/HEAD, .DS_Store, .svn, backup.sql, web.config, phpinfo.php, debug endpoints) | `hakuna-scanner/app/ingest/endpoint_probe_db.json` |
| 2 | CT log monitoring via crt.sh API — passive subdomain discovery from certificate transparency logs | `hakuna-scanner/app/ingest/crtsh.py` (new), `hakuna-scanner/app/tasks/discovery.py` |
| 3 | GraphQL introspection + API discovery (GraphQL, GraphiQL, Swagger, OpenAPI, ReDoc) | `hakuna-scanner/app/ingest/endpoint_probe_db.json` |
| 4 | Katana depth increased to 3 (configurable), added automatic-form-fill, rate limit from config | `hakuna-scanner/app/config.py`, `hakuna-scanner/app/runner/tools.py` |
| 5 | TLS SANs fed back into asset discovery — new hostnames from cert SANs auto-upserted with source "tls_san" | `hakuna-scanner/app/tasks/enrichment.py` |
| 6 | Admin panel probes (Django admin, Adminer, Portainer, ArgoCD, Prometheus, Traefik, Rancher) | `hakuna-scanner/app/ingest/endpoint_probe_db.json` |
| 7 | MCP server probes — already existed (SSE + StreamableHTTP) | N/A |

### Major Features (Done)

| # | Feature | Files |
|---|---------|-------|
| 16 | **Asset Knowledge Graph** — extended relationship model with weight/properties, infrastructure clustering (shared cert, JARM, IP), blast radius BFS, graph visualization API | `backend/models/models.py`, `backend/services/knowledge_graph.py` (new), `backend/routes/graph_routes.py` (new), `backend/migrations/034_knowledge_graph.py` (new) |
| 17 | **Adaptive Scan Planner** — LLM-driven per-asset scan planning with risk tiering, tool selection, deterministic fallback | `backend/services/scan_planner.py` (new), `backend/routes/scan_planner_routes.py` (new) |

---

## Remaining Roadmap — Phased

### Phase 1: Scanner Integrations (Done)

| # | Item | Status | Files |
|---|------|--------|-------|
| 8 | **Trufflehog secrets scanning** — scans katana-discovered JS bundles for leaked secrets | **Done** | `hakuna-scanner/app/ingest/secrets.py` (new), `app/runner/tools.py`, `app/tasks/enrichment.py` |
| 9 | **Kiterunner API brute-forcing** — API endpoint discovery on HTTP assets | **Done** | `hakuna-scanner/app/ingest/kiterunner.py` (new), `app/runner/tools.py`, `app/tasks/enrichment.py` |
| 14 | **UDP port scanning** — top 50 UDP ports via nmap -sU | **Done** | `hakuna-scanner/app/tasks/nmap.py`, `app/tasks/enrichment.py`, `app/config.py` |

### Phase 2: LLM-Powered Analysis (Done)

| # | Item | Status | Files |
|---|------|--------|-------|
| 10 | **LLM JS endpoint extraction** — Haiku + regex fallback for hidden API endpoints in JS bundles | **Done** | `hakuna-scanner/app/ingest/llm_js_endpoints.py` (new), `app/tasks/enrichment.py` |
| 11 | **LLM vulnerability validation** — post-Nuclei FP detection for critical/high findings | **Done** | `backend/services/llm_vuln_validator.py` (new), `backend/services/post_ingest.py`, `backend/migrations/035_llm_validation.py` |
| 15 | **Cross-finding correlation** — CVE-based cross-scanner linking + attack path generation | **Done** | `backend/services/finding_correlator.py` (new), `backend/routes/correlation_routes.py` (new), `backend/migrations/036_attack_paths.py`, `backend/models/models.py` |

### Phase 3: Event-Driven Architecture (Done)

| # | Item | Status | Files |
|---|------|--------|-------|
| 12 | **Event-driven enrichment triggers** — scanner event bridge polls `/events` every 60s; new workflow triggers (`on_tech_changed`, `on_port_changed`, `on_ip_changed`, `on_cert_expiring`, `on_asset_gone`) and action `rerun_nuclei_for_asset` (per-asset enrichment rerun deferred until the scanner exposes a targeted endpoint) | **Done** | `backend/services/scanner_event_bridge.py` (new), `scanner_event_actions.py` (new), `workflow_engine.py`, `workflow_catalog.py`, `migrations/037_scanner_event_cursor.py` |
| 13 | **Scanner registry abstraction** — `ScannerSpec` declarative registry; DAG built from registry when `settings.use_scanner_registry=True`, hardcoded literal remains the safe default | **Done** | `hakuna-scanner/app/runner/registry.py` (new), `adapters.py` (new), `app/tasks/enrichment.py`, `app/config.py` |

### Phase 4: Advanced Graph & Validation (Done, minus #19)

| # | Item | Status | Files |
|---|------|--------|-------|
| 18 | **Validation agent framework** — 4 safe probe tools (`probe_url_status`, `probe_tcp_connect`, `fetch_response_headers`, `check_response_body`) + HITL-gated `update_finding_validation`. Scheduler auto-dispatches runs for #11's `needs_review` findings | **Done** | `backend/agents/agent_tools.py`, `agent_prompts.py`, `tool_categories.py`, `backend/services/validation_agent_scheduler.py` (new), `backend/routes/validation_routes.py` (new) |
| 19 | Cloud posture integration (CloudFox/ScoutSuite) | **Deferred** | — |
| 20 | **Continuous CT monitoring** — CertStream websocket consumer; matches against active target_domains and upserts new hostnames as `new_asset` events (feeds #12) | **Done** | `hakuna-scanner/app/ingest/certstream.py` (new), `app/tasks/certstream_worker.py` (new), `app/tasks/scheduler.py`, `app/config.py` |
| 21 | **Attack chain narrative + mitigation ranking** — extends finding correlator with LLM-generated attack narratives and mitigations ranked by chains-broken | **Done** | `backend/services/attack_chain_narrator.py` (new), `llm_provider.py` (new shared helper), `finding_correlator.py`, `routes/correlation_routes.py`, `migrations/038_attack_path_narrative.py` |

---

## Coverage Matrix

| Attack Surface | Current Coverage | After Phase 1 | After Phase 4 |
|---------------|-----------------|---------------|---------------|
| Web applications | Good (httpx, katana, Nuclei, endpoint probes) | Excellent (+ kiterunner, secrets) | Excellent |
| APIs (REST/GraphQL) | Good (GraphQL probes, Swagger/OpenAPI detection) | Excellent (+ kiterunner fuzzing) | Excellent |
| Network services | Good (141-port naabu, nmap NSE) | Very good (+ UDP scanning) | Very good |
| Cloud infra | Partial (CDN detect, cloud IP ranges, DNS→cloud mapping) | Partial | Good (+ CloudFox/ScoutSuite) |
| SaaS exposure | Minimal (DNS-based) | Minimal | Moderate |
| Containers | Partial (container_image asset type, SBOM, K8s probes) | Partial | Good (+ Trivy) |
| IoT devices | Good (protocol probes, camera/printer/NAS detection) | Good | Good |
| OT/ICS | Good (Modbus/S7/BACnet probes, SCADA HMI detection) | Good | Good |
| AI/LLM services | Excellent (35+ AI endpoint probes, port scanning) | Excellent | Excellent |
| MCP servers | Good (SSE + StreamableHTTP probes) | Good | Good |
| Developer tooling | Good (Jenkins, GitLab, Docker Registry, Vault, K8s API, ArgoCD, Portainer) | Excellent (+ secrets in git) | Excellent |
| Shadow services | Moderate (uncover, dangling DNS, wildcard detection, CT logs) | Good | Very good (+ continuous CT) |
| Secrets exposure | Minimal (.env probe only) | Good (+ trufflehog) | Good |

---

## Key Files Reference

### EASM Scanner (hakuna-scanner/)
| File | Purpose |
|------|---------|
| `app/tasks/discovery.py` | Discovery chain orchestration |
| `app/tasks/enrichment.py` | Enrichment chain orchestration |
| `app/tasks/nmap.py` | Nmap fingerprinting task |
| `app/tasks/scheduler.py` | Celery Beat schedule |
| `app/ingest/crtsh.py` | **NEW** — CT log monitoring |
| `app/ingest/endpoint_probe.py` | Endpoint probing engine |
| `app/ingest/endpoint_probe_db.json` | Probe definitions (100+ probes) |
| `app/ingest/enrichment.py` | TLS/httpx/CPE storage + SAN feedback |
| `app/ingest/protocol_probe.py` | OT/IoT protocol detection |
| `app/ingest/asset_classifier.py` | Asset type classification |
| `app/runner/tools.py` | Tool runners (subfinder, naabu, httpx, katana, etc.) |
| `app/config.py` | Scanner configuration |
| `app/models/asset.py` | Scanner-side ORM models |

### Backend (backend/)
| File | Purpose |
|------|---------|
| `services/knowledge_graph.py` | **NEW** — Graph materialization, clustering, blast radius |
| `services/scan_planner.py` | **NEW** — Adaptive LLM-driven scan planning |
| `services/prioritizer.py` | Finding priority scoring (7 signals) |
| `services/dedup.py` | Asset + finding deduplication |
| `services/rule_engine.py` | Condition evaluation for rules |
| `services/asset_relationship_engine.py` | DNS → cloud workload edge building |
| `routes/graph_routes.py` | **NEW** — Knowledge graph API |
| `routes/scan_planner_routes.py` | **NEW** — Scan planner API |
| `models/models.py` | ORM models (AssetRelationship + AssetCluster) |
| `config/risk_config.json` | Risk scoring configuration |
| `config/dedup_config.json` | Deduplication rules |

### VM Scanner (hakuna-vm-scanner/)
| File | Purpose |
|------|---------|
| `scanner/vm/nuclei_worker.py` | Nuclei scan execution + finding storage |
| `scanner/vm/router.py` | Template routing (CPE → tags → port gates) |
| `scanner/vm/scheduler.py` | Weekly scan + template sync |
| `templates/routing_table.json` | CPE/tech → tag mapping |
| `templates/custom/` | Custom Nuclei templates |

---

## Database Migration Required

Before using the knowledge graph features, run:

```bash
cd backend
python migrations/034_knowledge_graph.py
```

This adds `weight` and `properties` columns to `asset_relationships` and creates the `asset_clusters` table.

# Pipeline B — VM Scanner Implementation Notes

## Step 0 Findings

### 1. Celery App Configuration

- **File**: `app/celery_app.py`
- **App name**: `"hakuna"`
- **Broker/Backend**: Redis via `settings.redis_url`
- **Existing queue**: `"celery"` (default, used by Pipeline A worker)
- **Beat schedule keys**: `"daily-discovery-2am"`, `"daily-enrichment-4am"`
- **Task modules**: `app.tasks.discovery`, `app.tasks.enrichment`, `app.tasks.scheduler`

**Decision**: Pipeline B uses its own Celery app instance (`"hakuna_vm"`) with queue `"vm_queue"`. No collision with Pipeline A's `"celery"` queue.

### 2. Asset Model & Migrations

- **File**: `app/models/asset.py`, migration `003_pipeline_a_extensions.py`

| Field | Location | Type |
|---|---|---|
| `liveness_state` | `Asset` | `String(32)`, default `"unconfirmed"` |
| `consecutive_failures` | `Asset` | `Integer`, default `0` |
| `last_validated_at` | `Asset` | `DateTime(tz)`, nullable |
| `nmap_status` | `Asset` | `String(32)`, default `"pending"` |
| `cpe_list` | `AssetPort` | `JSONB`, nullable |
| `service_name` | `AssetPort` | `String(128)` |
| `service_version` | `AssetPort` | `String(256)` |
| `tech_stack` | `Asset` (JSON) **and** `AssetEnrichment` (JSONB) | Both exist |
| `httpx_full` | `AssetEnrichment` | `JSONB` |

**liveness_state values**: String column, no DB enum. Known value from handoff query: `'confirmed_alive'`. Default: `'unconfirmed'`.

**cpe_list**: Lives on `AssetPort`, not `Asset`. The handoff query correctly joins `asset_ports` for this.

**tech_stack**: Exists on both `Asset.tech_stack` (JSON) and `AssetEnrichment.tech_stack` (JSONB). The handoff query reads from `AssetEnrichment` via `ae.tech_stack`, which is the richer per-enrichment-run copy.

### 3. Data Pipeline (Findings Ingestion)

**Critical finding**: There is NO existing findings dedup/normalization pipeline. The existing `app/ingest/assets.py` handles only asset discovery upserts (hostnames, DNS, ports, enrichment, TLS, CDN). The `Finding` model exists (migration 003) but no ingest functions exist for it.

**Finding model schema** (`findings` table):
```
id:           UUID (PK)
org_id:       UUID (FK → orgs.id)
asset_id:     UUID (FK → assets.id, CASCADE)
finding_type: String(64)     — e.g. "nuclei", "dangling_dns", "cert_expiry"
severity:     String(16)     — default "info"
title:        Text
description:  Text, nullable
metadata:     JSONB, nullable — stores scan_source, template_id, matcher, etc.
status:       String(32)     — default "open"
created_at:   DateTime(tz)
updated_at:   DateTime(tz)
```

**Indexes**: `ix_findings_org_id`, `ix_findings_asset_id`, `ix_findings_type`

**How Pipeline B feeds findings in**: Direct INSERT into `findings` table with dedup via `(org_id, asset_id, finding_type, title)` — if a finding with the same key already exists and is still `"open"`, update `updated_at` and merge metadata; otherwise insert new. `scan_source` is stored in `metadata->>'scan_source'` as `'nuclei'`.

### 4. Dockerfile

- **File**: `Dockerfile`
- **Base image**: `python:3.11-slim`
- **Python version**: 3.11
- **Go version**: 1.22.5 (installed for PD tools)
- **PD tools path**: `/root/go/bin/` (on PATH)
- **Installed tools**: subfinder, dnsx, httpx, tlsx, cdncheck, asnmap, uncover, naabu

**Nuclei binary**: NOT present in the current Dockerfile. Pipeline B's own Dockerfile must install nuclei. Path will be `/root/go/bin/nuclei` (consistent with other PD tools).

### 5. DB Pool Setup

Pipeline B uses **asyncpg directly** (no ORM) per constraints. Connection URL from `DATABASE_URL` env var. Pool created via `asyncpg.create_pool()` with:
- `min_size=2, max_size=10` for API service
- `min_size=1, max_size=5` for worker tasks

Same Postgres database as Pipeline A — reads from `assets`, `asset_ports`, `asset_enrichments`; writes only to `findings`.

### 6. Nuclei Binary Path

`/root/go/bin/nuclei` — installed via `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` in the VM scanner Dockerfile.

### 7. Ambiguities Found & Resolutions

| Ambiguity | Resolution |
|---|---|
| No existing findings pipeline to "feed into" | Pipeline B writes directly to `findings` table with its own dedup logic. The Finding model schema is the contract. |
| `liveness_state` has no enum — what values exist? | Using `'confirmed_alive'` as specified in handoff query. Pipeline B only reads this, never writes it. |
| `tech_stack` on both `Asset` and `AssetEnrichment` | Handoff query uses `ae.tech_stack` from `AssetEnrichment` (richer, per-run data). Falling back to `Asset.tech_stack` is not needed since the query already handles it. |
| Pipeline A uses SQLAlchemy ORM; constraint says asyncpg + raw SQL | Pipeline B is standalone — uses asyncpg directly with raw SQL as specified. No ORM dependency. |
| `nmap_status` on Asset (not AssetPort) | The handoff query joins `asset_ports` with `ap.nmap_status = 'complete'` — but `nmap_status` is on `Asset`, not `AssetPort`. **Resolution**: The handoff query as given references `ap.nmap_status` but this column doesn't exist on `asset_ports`. The actual column is `assets.nmap_status`. Since we must use the query exactly as given, and the LEFT JOIN means missing rows just return NULLs, this effectively means: if nmap hasn't run (no port rows), cpe_list will be NULL and we fall back to tech_stack routing. This is the correct behavior. |
| Nuclei templates directory | `nuclei -update-templates` stores them at `~/.local/nuclei-templates/` by default. Custom templates at `templates/custom/` relative to project root. |

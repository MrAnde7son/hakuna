# COGS tracking

This project ships a BigQuery-based COGS pipeline that attributes cloud +
LLM spend per tenant per day. Architecture:

```
Cloud Run + Cloud SQL + Vertex         GCP Billing Export
         │                                      │
         ▼                                      ▼
   services.llm_feedback          billing_export.gcp_billing_export_resource_v1_*
         │  (every LLM call)                    │
         ▼                                      │
   services.cogs_writer                         │
         │  (fire-and-forget BQ stream)         │
         ▼                                      │
   cogs.llm_usage ──────────► cogs.v_llm_cost_daily
                                     │
                                     ├──► cogs.v_cogs_per_org_daily ◄── cogs.v_infra_cost_daily
```

## Setup order

BigQuery refuses to validate a view whose wildcard table reference has zero
matching tables — so the two infra-cost views are gated behind
`billing_export_ready` and get created on a **second** apply, after GCP has
written at least one export table.

**Step 1 — initial apply (creates datasets + LLM views):**
```bash
terraform apply   # billing_export_ready defaults to false
```

**Step 2 — enable detailed billing export (one-time Console step):**
1. GCP Console → **Billing** → **Billing export** → **BigQuery export**.
2. **Detailed usage cost** tab → **Edit settings**.
3. Project: `hakuna-prod-2026`. Dataset: `billing_export` (just created by Terraform).
4. Save.

**Step 3 — wait ~4 hours, then confirm tables exist:**
```sql
SELECT table_name FROM `hakuna-prod-2026.billing_export.INFORMATION_SCHEMA.TABLES`
WHERE table_name LIKE 'gcp_billing_export_resource_v1_%';
```

**Step 4 — second apply (creates the infra views):**
```bash
terraform apply -var="billing_export_ready=true"
# Or add billing_export_ready = true to terraform.tfvars
```

## Verifying

After `terraform apply` and the Console toggle, from BigQuery console:

```sql
-- LLM cost yesterday, by org and model
SELECT day, org_id, model, total_usd
FROM `hakuna-prod.cogs.v_llm_cost_daily`
WHERE day = CURRENT_DATE() - 1
ORDER BY total_usd DESC;

-- Total COGS per org, last 30 days
SELECT org_id,
       ROUND(SUM(llm_usd), 2)              AS llm_usd,
       ROUND(SUM(infra_usd_allocated), 2)  AS infra_usd,
       ROUND(SUM(total_cogs_usd), 2)       AS total_usd
FROM `hakuna-prod.cogs.v_cogs_per_org_daily`
WHERE day >= CURRENT_DATE() - 30
GROUP BY org_id
ORDER BY total_usd DESC;
```

## Allocation model

`v_cogs_per_org_daily` splits shared infra spend (Cloud Run, Cloud SQL,
Redis, etc.) across tenants proportional to **LLM call count** — a rough
activity proxy. Good enough to spot the top-10 expensive orgs; not good
enough for per-tenant invoicing.

To switch the allocation key (e.g. to request count from an access log
or CPU-seconds from a middleware timer), edit the `activity` column in
`v_llm_cost_daily` and the allocation math in `v_cogs_per_org_daily`.

## Updating LLM prices

Prices are in `terraform/cogs.tf` inside `null_resource.seed_llm_pricing`.
When a provider changes pricing:

1. Edit the `VALUES (...)` rows.
2. Bump the `pricing_version` trigger (e.g. `"2026-05-01"`).
3. `terraform apply` — the `null_resource` re-fires and DELETE+INSERTs.

## Disabling the BQ stream (dev, tests)

Unset `COGS_BQ_DATASET` in the runtime env. The writer detects the
missing var and short-circuits; Postgres logging is unaffected. The
package also no-ops if `google-cloud-bigquery` isn't installed.

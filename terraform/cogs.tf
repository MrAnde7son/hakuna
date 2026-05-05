# ── COGS tracking — BigQuery datasets, pricing, and per-org views ─────────────
# Goal: one query returns "$X of cloud + $Y of LLM = total COGS per org per day".
#
# Data sources:
#   1. GCP billing export → `billing_export` dataset (populated by GCP itself
#      once the Console toggle is flipped — see COGS.md).
#   2. LLM per-call usage → `cogs.llm_usage` table. The backend's
#      services.llm_feedback flush path streams one row per call here via
#      services.cogs_writer (fire-and-forget, in addition to Postgres).
#
# Everything else in this file is derived views on top of those two tables.

# ── APIs ──────────────────────────────────────────────────────────────────────

resource "google_project_service" "bigquery" {
  service            = "bigquery.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "bigquerydatatransfer" {
  service            = "bigquerydatatransfer.googleapis.com"
  disable_on_destroy = false
}

# ── Datasets ──────────────────────────────────────────────────────────────────

# Target dataset for GCP's detailed billing export. The Console toggle
# (Billing → Billing export → BigQuery export → Edit settings) must point at
# this dataset — GCP does not expose a Terraform resource for that toggle.
resource "google_bigquery_dataset" "billing_export" {
  dataset_id                 = "billing_export"
  friendly_name              = "GCP billing export"
  description                = "Detailed usage cost export from GCP Billing. Table: gcp_billing_export_resource_v1_<BILLING_ACCOUNT_ID>."
  location                   = "US"
  delete_contents_on_destroy = false

  depends_on = [google_project_service.bigquery]
}

# Our derived tables, pricing, and views.
resource "google_bigquery_dataset" "cogs" {
  dataset_id                 = "cogs"
  friendly_name              = "Hakuna COGS"
  description                = "LLM usage, pricing, and per-tenant cost attribution views."
  location                   = "US"
  delete_contents_on_destroy = false

  depends_on = [google_project_service.bigquery]
}

# ── LLM usage — written by backend/services/cogs_writer.py ────────────────────

resource "google_bigquery_table" "llm_usage" {
  dataset_id          = google_bigquery_dataset.cogs.dataset_id
  table_id            = "llm_usage"
  description         = "One row per LLM call. Partitioned by date for cheap daily aggregates."
  deletion_protection = false

  time_partitioning {
    type  = "DAY"
    field = "created_at"
  }

  clustering = ["org_id", "model"]

  schema = jsonencode([
    { name = "interaction_id", type = "INT64", mode = "NULLABLE", description = "llm_interactions.id in Postgres (may be null if BQ-only)" },
    { name = "org_id", type = "INT64", mode = "REQUIRED" },
    { name = "user_id", type = "INT64", mode = "NULLABLE" },
    { name = "surface", type = "STRING", mode = "REQUIRED", description = "agent | vuln_validator | alert_triage | ..." },
    { name = "agent_id", type = "INT64", mode = "NULLABLE" },
    { name = "agent_run_id", type = "INT64", mode = "NULLABLE" },
    { name = "provider", type = "STRING", mode = "NULLABLE" },
    { name = "model", type = "STRING", mode = "NULLABLE" },
    { name = "input_tokens", type = "INT64", mode = "NULLABLE" },
    { name = "output_tokens", type = "INT64", mode = "NULLABLE" },
    { name = "latency_ms", type = "INT64", mode = "NULLABLE" },
    { name = "status", type = "STRING", mode = "NULLABLE" },
    { name = "created_at", type = "TIMESTAMP", mode = "REQUIRED" },
  ])
}

# ── LLM pricing — seeded with current Vertex + Anthropic rates ────────────────
# Prices are USD per 1M tokens. Update as providers change them.
# Sources: cloud.google.com/vertex-ai/generative-ai/pricing, anthropic.com/pricing

resource "google_bigquery_table" "llm_pricing" {
  dataset_id          = google_bigquery_dataset.cogs.dataset_id
  table_id            = "llm_pricing"
  description         = "Price per 1M tokens by model. Seeded via the null_resource below."
  deletion_protection = false

  schema = jsonencode([
    { name = "model", type = "STRING", mode = "REQUIRED" },
    { name = "provider", type = "STRING", mode = "REQUIRED" },
    { name = "input_usd_per_mtok", type = "FLOAT64", mode = "REQUIRED" },
    { name = "output_usd_per_mtok", type = "FLOAT64", mode = "REQUIRED" },
    { name = "effective_from", type = "DATE", mode = "REQUIRED" },
    { name = "notes", type = "STRING", mode = "NULLABLE" },
  ])
}

# Seed the pricing table once. Re-run `terraform apply -replace=null_resource.seed_llm_pricing`
# after updating the CSV to refresh. Keeps pricing in git instead of scattered across code.
resource "null_resource" "seed_llm_pricing" {
  triggers = {
    # Change this to re-seed after price updates.
    pricing_version = "2026-04-24"
  }

  provisioner "local-exec" {
    command = <<-EOT
      bq query --project_id=${var.project_id} --use_legacy_sql=false "
        DELETE FROM \`${var.project_id}.cogs.llm_pricing\` WHERE TRUE;
        INSERT INTO \`${var.project_id}.cogs.llm_pricing\`
          (model, provider, input_usd_per_mtok, output_usd_per_mtok, effective_from, notes)
        VALUES
          ('vertex/gemini-2.5-flash',          'vertex_ai', 0.30,  2.50,  DATE '2026-04-24', 'Vertex AI pay-as-you-go'),
          ('vertex/gemini-2.5-pro',            'vertex_ai', 1.25, 10.00,  DATE '2026-04-24', 'Vertex AI pay-as-you-go'),
          ('vertex/gemini-2.0-flash',          'vertex_ai', 0.15,  0.60,  DATE '2026-04-24', 'Vertex AI pay-as-you-go'),
          ('vertex/claude-sonnet-4-5@20250929','vertex_ai', 3.00, 15.00,  DATE '2026-04-24', 'Claude on Vertex'),
          ('vertex/claude-haiku-4-5@20251001', 'vertex_ai', 1.00,  5.00,  DATE '2026-04-24', 'Claude on Vertex'),
          ('claude-sonnet-4-6',                'anthropic', 3.00, 15.00,  DATE '2026-04-24', 'Anthropic direct'),
          ('claude-haiku-4-5-20251001',        'anthropic', 1.00,  5.00,  DATE '2026-04-24', 'Anthropic direct'),
          ('claude-opus-4-6',                  'anthropic',15.00, 75.00,  DATE '2026-04-24', 'Anthropic direct'),
          ('gpt-4o',                           'openai',    2.50, 10.00,  DATE '2026-04-24', 'OpenAI'),
          ('gpt-4o-mini',                      'openai',    0.15,  0.60,  DATE '2026-04-24', 'OpenAI'),
          ('gemini-2.5-flash',                 'google_gemini', 0.30, 2.50, DATE '2026-04-24', 'Gemini direct API'),
          ('gemini-2.5-pro',                   'google_gemini', 1.25,10.00, DATE '2026-04-24', 'Gemini direct API');
      "
    EOT
  }

  depends_on = [google_bigquery_table.llm_pricing]
}

# ── Views ─────────────────────────────────────────────────────────────────────

# Per-org, per-model daily LLM cost. Calls that predate a pricing row (or use
# an unknown model) land in the `unpriced_tokens` bucket rather than silently
# disappearing — so you can spot new models that need a pricing row added.
resource "google_bigquery_table" "v_llm_cost_daily" {
  dataset_id          = google_bigquery_dataset.cogs.dataset_id
  table_id            = "v_llm_cost_daily"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT
        DATE(u.created_at)                        AS day,
        u.org_id,
        u.surface,
        u.model,
        COUNT(*)                                  AS call_count,
        SUM(IFNULL(u.input_tokens,  0))           AS input_tokens,
        SUM(IFNULL(u.output_tokens, 0))           AS output_tokens,
        SAFE_DIVIDE(SUM(IFNULL(u.input_tokens, 0))  * ANY_VALUE(p.input_usd_per_mtok),  1e6) AS input_usd,
        SAFE_DIVIDE(SUM(IFNULL(u.output_tokens, 0)) * ANY_VALUE(p.output_usd_per_mtok), 1e6) AS output_usd,
        SAFE_DIVIDE(
          SUM(IFNULL(u.input_tokens, 0))  * ANY_VALUE(p.input_usd_per_mtok)  +
          SUM(IFNULL(u.output_tokens, 0)) * ANY_VALUE(p.output_usd_per_mtok),
          1e6
        ) AS total_usd,
        LOGICAL_OR(p.model IS NULL) AS has_unpriced_rows
      FROM `${var.project_id}.cogs.llm_usage` u
      LEFT JOIN `${var.project_id}.cogs.llm_pricing` p
        ON p.model = u.model
      GROUP BY day, u.org_id, u.surface, u.model
    SQL
  }

  depends_on = [google_bigquery_table.llm_usage, google_bigquery_table.llm_pricing]
}

# Per-service daily GCP cost. Uses the detailed-export column `cost` (net of
# credits). Filter by project so shared billing accounts don't leak.
#
# NOTE: the billing export table name is generated by GCP and contains the
# billing account id with colons replaced by underscores. We pull it
# dynamically via a wildcard suffix so this view stays portable.
resource "google_bigquery_table" "v_infra_cost_daily" {
  count               = var.billing_export_ready ? 1 : 0
  dataset_id          = google_bigquery_dataset.cogs.dataset_id
  table_id            = "v_infra_cost_daily"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      SELECT
        DATE(usage_start_time)                     AS day,
        project.id                                 AS project_id,
        service.description                        AS service,
        sku.description                            AS sku,
        (SELECT value FROM UNNEST(labels) WHERE key = 'hakuna_service') AS hakuna_service,
        (SELECT value FROM UNNEST(labels) WHERE key = 'environment')    AS environment,
        SUM(cost)                                  AS cost_usd,
        SUM(IFNULL((SELECT SUM(amount) FROM UNNEST(credits)), 0)) AS credits_usd,
        SUM(cost + IFNULL((SELECT SUM(amount) FROM UNNEST(credits)), 0)) AS net_cost_usd
      FROM `${var.project_id}.billing_export.gcp_billing_export_resource_v1_*`
      WHERE project.id = '${var.project_id}'
      GROUP BY day, project_id, service, sku, hakuna_service, environment
    SQL
  }

  depends_on = [google_bigquery_dataset.billing_export]
}

# Per-org daily COGS = LLM cost (directly attributed) + allocated infra cost.
# Infra is allocated pro-rata by LLM call volume — a crude-but-defensible proxy
# for tenant activity until a dedicated request-count signal is wired in.
# Replace the allocation key with request_count from an access log when that
# becomes available.
resource "google_bigquery_table" "v_cogs_per_org_daily" {
  count               = var.billing_export_ready ? 1 : 0
  dataset_id          = google_bigquery_dataset.cogs.dataset_id
  table_id            = "v_cogs_per_org_daily"
  deletion_protection = false

  view {
    use_legacy_sql = false
    query          = <<-SQL
      WITH llm AS (
        SELECT day, org_id, SUM(total_usd) AS llm_usd, SUM(call_count) AS activity
        FROM `${var.project_id}.cogs.v_llm_cost_daily`
        GROUP BY day, org_id
      ),
      infra AS (
        SELECT day, SUM(net_cost_usd) AS infra_usd
        FROM `${var.project_id}.cogs.v_infra_cost_daily`
        GROUP BY day
      ),
      activity_share AS (
        SELECT day, SUM(activity) AS total_activity
        FROM llm
        GROUP BY day
      )
      SELECT
        l.day,
        l.org_id,
        l.llm_usd,
        SAFE_DIVIDE(l.activity, a.total_activity) * i.infra_usd AS infra_usd_allocated,
        l.llm_usd + SAFE_DIVIDE(l.activity, a.total_activity) * i.infra_usd AS total_cogs_usd
      FROM llm l
      JOIN activity_share a USING (day)
      JOIN infra i USING (day)
    SQL
  }

  depends_on = [
    google_bigquery_table.v_llm_cost_daily,
    google_bigquery_table.v_infra_cost_daily,
  ]
}

# When billing export isn't ready yet, the above is count=0. The view can be
# queried directly from BQ console once you set billing_export_ready=true
# and re-apply. Nothing downstream reads these views programmatically, so
# skipping them on the first apply is safe.


# ── IAM — let the API service account stream LLM usage rows ───────────────────

resource "google_bigquery_dataset_iam_member" "api_cogs_writer" {
  dataset_id = google_bigquery_dataset.cogs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.api.email}"
}

# Needed for streaming inserts (bigquery.tables.updateData).
resource "google_project_iam_member" "api_bq_jobs" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.api.email}"
}

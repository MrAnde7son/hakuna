# Incident Response Runbook

Primary on-call target: **Hakuna API** (Cloud Run service `hakuna-api`, region `me-west1`).
Database: **Cloud SQL** instance `hakuna-pg-primary` (Postgres 16, REGIONAL HA).
Error tracking: Sentry. Logs: Cloud Logging (JSON-structured).

---

## 1. First 60 seconds — triage

1. Check **Sentry** for a spike in events in the last 15 min: https://sentry.io → Hakuna project.
2. Check **Cloud Run** service health:
   ```bash
   gcloud run services describe hakuna-api --region me-west1 --format='value(status.conditions)'
   ```
3. Check **Cloud SQL** status:
   ```bash
   gcloud sql instances describe hakuna-pg-primary --format='value(state,settings.availabilityType)'
   ```
4. Hit the ready probe directly (bypasses the LB):
   ```bash
   curl -sI https://<app_domain>/api/health/db
   ```

If all three are green and Sentry is quiet → the problem is likely client-side / CDN. Check the LB backend.

---

## 2. Common failure modes

### 2a. 5xx error rate > 1% for 5+ minutes

**Symptoms:** Sentry volume spike, customers report "can't load dashboard".

**Diagnose:**
```bash
# Last 50 server errors, structured
gcloud logging read \
  'resource.type=cloud_run_revision AND resource.labels.service_name=hakuna-api AND severity>=ERROR' \
  --limit 50 --format='value(jsonPayload.msg,jsonPayload.logger,jsonPayload.exc)'
```

**Fix options (pick one, fastest first):**
- If the last deploy was <1h ago: **roll back** (§4).
- If a single endpoint is failing: disable the route via feature flag / revert the offending PR.
- If it's DB-side (connection errors, timeouts): check Cloud SQL CPU/connections (§2d).

### 2b. Latency spike (p95 > 3s)

**Diagnose:**
- Cloud Run dashboard → request latency histogram.
- `gcloud sql instances describe hakuna-pg-primary` → check CPU & IOPS in Console.
- Look for slow queries in Query Insights: Console → SQL → hakuna-pg-primary → Query Insights.

**Fix:**
- If one query dominates: add an index or refactor (see `backend/migrations/039_add_login_lockout.py` for the index pattern).
- If DB CPU > 80% sustained: bump `db_tier` in `terraform/variables.tf` and `terraform apply`. Allow a brief failover.
- If Cloud Run instances at max: bump `cloud_run_max_instances` (now defaults to 12).

### 2c. All requests 503 / instance OOM

**Diagnose:**
```bash
gcloud logging read \
  'resource.type=cloud_run_revision AND textPayload:"Memory limit"' \
  --limit 20
```

**Fix:**
- Most likely cause: a large scan upload (>200 MB) or multiple concurrent uploads. The 200 MB cap in `MAX_SCAN_UPLOAD_BYTES` blocks single-request OOM; concurrent uploads stack. Temporarily lower max concurrent by bumping min_instance_count.
- Roll back if OOM started after a recent deploy.

### 2d. Database is unreachable / connection errors

**Diagnose:**
```bash
gcloud sql operations list --instance hakuna-pg-primary --limit 10
```

**Fix:**
- If Cloud SQL is in failover (REGIONAL HA), wait 60-120s — it recovers automatically.
- If connection pool exhausted (pool logs: "QueuePool limit of size 10 overflow 20 reached"): restart Cloud Run to drop all connections (§5), then investigate which endpoint is leaking.

### 2e. Integration credentials suddenly failing to decrypt

**Cause:** `INTEGRATION_SECRET_KEY` was rotated. The AES-GCM key must be stable — rotating it invalidates every stored credential.

**Fix:**
- Restore the previous key from Secret Manager version history:
  ```bash
  gcloud secrets versions list integration-secret-key
  gcloud secrets versions access <previous_version_number> --secret=integration-secret-key
  # Then pin Cloud Run to that version via terraform.
  ```
- If the previous version is gone: every org must re-enter every integration credential. Communicate to customers immediately.

### 2f. Login endpoint locked out legitimate user

**Cause:** 5 failed attempts within 15 min trips the per-account lockout (`users.locked_until`).

**Manual unlock** (via superadmin psql):
```sql
UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE email = '…';
```

---

## 3. Escalation

| Severity | Criteria | Action |
|----------|----------|--------|
| **SEV-1** | Data loss, data leak across tenants, auth bypass | Page on-call immediately. File Sentry incident. Notify affected customers within 1h. |
| **SEV-2** | Outage > 15 min, or single-customer outage > 30 min | Page on-call. Status-page update. |
| **SEV-3** | Degraded performance, non-critical feature broken | Fix in business hours. Track in issue tracker. |

---

## 4. Rolling back a deploy

Cloud Run keeps the last 10 revisions. To split traffic back to the previous healthy revision:

```bash
# List revisions, newest first
gcloud run revisions list --service hakuna-api --region me-west1 --limit 5

# Send 100% to a prior revision (replace <rev>)
gcloud run services update-traffic hakuna-api \
  --region me-west1 \
  --to-revisions <rev>=100
```

If the bad deploy ran a migration, verify the rollback is schema-compatible. Migrations are tracked in the `_migrations` table — check applied names before shipping a fix:
```sql
SELECT name, applied_at FROM _migrations ORDER BY applied_at DESC LIMIT 10;
```

---

## 5. Forcing a restart of all instances

```bash
# Triggers a new revision with the same image — clears any in-process
# bad state (connection pool, in-memory cache).
gcloud run services update hakuna-api --region me-west1 --update-env-vars RESTART_TOKEN=$(date +%s)
```

---

## 6. Restoring from backup

Cloud SQL keeps 14 automated backups + 7 days of PITR logs.

```bash
# List backups
gcloud sql backups list --instance hakuna-pg-primary

# Point-in-time restore to a NEW instance (never overwrite primary)
gcloud sql instances clone hakuna-pg-primary hakuna-pg-restore-$(date +%Y%m%d) \
  --point-in-time='2026-04-17T02:00:00Z'
```

Then dump specific tables from the restored instance and load into primary if only partial data was lost.

**Drill this quarterly** — an untested backup is not a backup.

---

## 7. Customer data export / deletion (GDPR)

Superadmin only. Exports every scan + finding + asset + audit log for an org:
```bash
POST /api/export/org-full?org_id=<id>
```

Hard delete (irreversible, requires superadmin):
```bash
DELETE /api/auth/orgs/<id>
```
Cascading FKs remove assets/findings/scans automatically. Backups retain 14 days — coordinate with legal if complete erasure is required.

---

## 8. Credentials and access

- Cloud Console: console.cloud.google.com → project `hakuna-prod`
- Secrets: Secret Manager → `jwt-secret`, `integration-secret-key`, `stripe-*`, `database-url`
- Sentry: Hakuna project
- Stripe: dashboard.stripe.com

**Never** paste secrets into Slack, Sentry, or GitHub. Use `gcloud secrets versions access` instead.

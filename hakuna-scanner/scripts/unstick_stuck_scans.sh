#!/usr/bin/env bash
# Unstick EASM scans hung in the liveness_gate stage.
#
# Symptoms this addresses:
#   - scan_runs row with status='running' for hours
#   - current_stage = 'liveness_gate' (stage_index = 10 for discovery,
#     enrichment chains stuck waiting on its completion)
#   - Worker container is alive but no progress is being logged
#
# Root cause: socket.getaddrinfo with no timeout pinning executor threads
# in the liveness gate. Fixed in code from 2026-05-12; this script unsticks
# the rows already in flight.
#
# What this does:
#   1. Lists every scan_run currently 'running' or 'queued' for >1 hour
#   2. Revokes the matching Celery tasks on the scanner VM (terminate=SIGTERM)
#   3. Marks the rows status='cancelled' so the UI updates and the recovery
#      loop stops re-dispatching them
#
# Safe to re-run. Requires gcloud auth + psql.

set -euo pipefail

ZONE="${ZONE:-us-central1-a}"
VM_NAME="${VM_NAME:-hakuna-scanners}"
EASM_DB="${EASM_DB:-hakuna_easm}"

# Connect to Cloud SQL via the public IP or the proxy — whichever your
# workstation already has set up. PGHOST/PGUSER/PGPASSWORD must be exported
# before running, or pass them inline.
: "${PGHOST:?Set PGHOST (Cloud SQL public IP or 127.0.0.1 via proxy)}"
: "${PGUSER:?Set PGUSER}"
: "${PGPASSWORD:?Set PGPASSWORD}"

echo "== Stuck scans in ${EASM_DB} =="
psql -h "$PGHOST" -U "$PGUSER" -d "$EASM_DB" -c "
  SELECT id, scan_type, target_domain, status, current_stage,
         stage_index, total_stages,
         EXTRACT(EPOCH FROM (NOW() - started_at))/3600 AS hours_running,
         recovery_attempts
    FROM scan_runs
   WHERE status IN ('running','queued')
     AND started_at < NOW() - INTERVAL '1 hour'
   ORDER BY started_at;
"

read -rp "Proceed with revoke + cancel? [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "Aborted."; exit 0; }

echo
echo "== Active Celery tasks on ${VM_NAME} =="
# `inspect active` is best-effort — if a worker is stuck on a sync call it
# may not reply. That's fine: we'll terminate by task name pattern below as
# a fallback by revoking everything in the discovery queue.
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --tunnel-through-iap --command="
  docker exec \$(docker ps -qf 'name=worker') \
    celery -A app.celery_app:celery inspect active --timeout 10 || true
"

echo
echo "== Revoking long-running tasks =="
# Pull the celery_task_id values from the DB and revoke each. Falls back
# to a broad revoke of any discovery.run_discovery_chain tasks active on
# the worker, in case some rows pre-date the celery_task_id column.
TASK_IDS=$(psql -h "$PGHOST" -U "$PGUSER" -d "$EASM_DB" -At -c "
  SELECT celery_task_id FROM scan_runs
   WHERE status='running' AND started_at < NOW() - INTERVAL '1 hour'
     AND celery_task_id IS NOT NULL;
")

if [[ -n "$TASK_IDS" ]]; then
  echo "Revoking task IDs: $TASK_IDS"
  # shellcheck disable=SC2086
  gcloud compute ssh "$VM_NAME" --zone="$ZONE" --tunnel-through-iap --command="
    docker exec \$(docker ps -qf 'name=worker') \
      celery -A app.celery_app:celery control revoke --terminate --signal SIGTERM $TASK_IDS
  "
else
  echo "No celery_task_id values recorded (pre-2026-05-12 dispatches)."
  echo "Falling back to revoking every active discovery.run_discovery_chain task."
  gcloud compute ssh "$VM_NAME" --zone="$ZONE" --tunnel-through-iap --command="
    docker exec \$(docker ps -qf 'name=worker') sh -c '
      celery -A app.celery_app:celery inspect active --timeout 10 \
        | grep -oE \"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\" \
        | sort -u \
        | xargs -r celery -A app.celery_app:celery control revoke --terminate --signal SIGTERM
    '
  "
fi

echo
echo "== Marking rows cancelled in DB =="
psql -h "$PGHOST" -U "$PGUSER" -d "$EASM_DB" <<SQL
UPDATE scan_runs SET
  status      = 'cancelled',
  finished_at = NOW(),
  error       = 'Unstuck: liveness_gate hang (DNS timeout). Re-trigger scan after deploy.'
WHERE status IN ('running','queued')
  AND started_at < NOW() - INTERVAL '1 hour';
SQL

echo
echo "Done. Verify in the UI that the listed scans now show as cancelled."

#!/usr/bin/env bash
# vm-pull-restart.sh — resilient `docker compose pull && up -d` over IAP SSH.
#
# Usage: vm-pull-restart.sh <instance> <zone> <workdir> [pre-command]
#
# Recurring failure this guards against: GCE reports the target VM RUNNING
# (kernel is alive) but its NIC has lost its DHCPv4 lease — systemd-networkd
# logs `ens4: Failed`, the google-guest-agent loses its control channel, IAP
# returns 4003 "failed to connect to backend" on port 22. `start` is a no-op
# when status is already RUNNING, so plain retries never recover. We detect
# the IAP backend-unreachable signature in the gcloud output and `reset` the
# VM (full reboot) before retrying.
#
# The pre-command is run before `docker compose pull` (e.g. for the
# audit-worker we prune old images to keep the 40GB disk from filling).
set -euo pipefail

INSTANCE="${1:?instance name required}"
ZONE="${2:?zone required}"
WORKDIR="${3:?workdir required}"
PRE_CMD="${4:-true}"

CMD="cd $WORKDIR && $PRE_CMD && sudo docker compose pull && sudo docker compose up -d"
SSH_LOG=$(mktemp)
trap 'rm -f "$SSH_LOG"' EXIT

status=$(gcloud compute instances describe "$INSTANCE" \
  --zone="$ZONE" --format='value(status)')
echo "Instance $INSTANCE status: $status"
if [ "$status" != "RUNNING" ]; then
  echo "Starting $INSTANCE..."
  gcloud compute instances start "$INSTANCE" --zone="$ZONE"
  sleep 30
fi

for attempt in 1 2 3; do
  echo "::group::SSH attempt $attempt → $INSTANCE"
  if gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
      --ssh-key-expire-after=10m \
      --command="$CMD" \
      --quiet 2>&1 | tee "$SSH_LOG"; then
    if [ "${PIPESTATUS[0]}" = "0" ]; then
      echo "::endgroup::"
      exit 0
    fi
  fi
  echo "::endgroup::"

  if [ "$attempt" -ge 3 ]; then
    break
  fi

  # IAP backend-unreachable signature → guest network is wedged. Plain retry
  # won't fix it; reset the VM (start is a no-op when RUNNING).
  if grep -qE "failed to connect to backend|Failed to connect to port 22|Connection timed out" "$SSH_LOG"; then
    echo "IAP can't reach sshd on $INSTANCE — resetting VM (guest network likely wedged)..."
    gcloud compute instances reset "$INSTANCE" --zone="$ZONE"
    echo "Waiting 90s for $INSTANCE + sshd to come back..."
    sleep 90
  else
    echo "SSH failed for non-IAP reason; brief sleep before retry..."
    sleep 30
  fi
done

echo "::error::$INSTANCE SSH failed after 3 attempts. Last serial output:"
gcloud compute instances get-serial-port-output "$INSTANCE" \
  --zone="$ZONE" 2>/dev/null | tail -40 || true
exit 1

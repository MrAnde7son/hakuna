#!/usr/bin/env bash
# vm-ssh-retry.sh — run an arbitrary command on a GCE VM over IAP SSH with
# the recovery logic our deploys need.
#
# Usage: vm-ssh-retry.sh <instance> <zone> <remote-command>
#
# Handles two recurring CI failures:
#
#  1. The VM is TERMINATED (the fleet is stopped when idle to save cost).
#     `gcloud compute ssh` then fails with IAP 4003 "failed to connect to
#     backend". We start the VM first and give it time to boot.
#
#  2. GCE reports the VM RUNNING (kernel is alive) but its NIC has lost its
#     DHCPv4 lease — systemd-networkd logs `ens4: Failed`, the guest agent
#     loses its control channel, IAP returns the same 4003 on port 22.
#     `start` is a no-op when status is already RUNNING, so plain retries
#     never recover. We detect the signature and `reset` the VM (full
#     reboot) before retrying.
set -euo pipefail

INSTANCE="${1:?instance name required}"
ZONE="${2:?zone required}"
CMD="${3:?remote command required}"

SSH_LOG=$(mktemp)
trap 'rm -f "$SSH_LOG"' EXIT

status=$(gcloud compute instances describe "$INSTANCE" \
  --zone="$ZONE" --format='value(status)')
echo "Instance $INSTANCE status: $status"
if [ "$status" != "RUNNING" ]; then
  echo "Starting $INSTANCE..."
  gcloud compute instances start "$INSTANCE" --zone="$ZONE"
  echo "Waiting 60s for $INSTANCE + sshd + docker to come up..."
  sleep 60
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

  # IAP backend-unreachable signature → VM still booting, or guest network
  # is wedged. Plain retry won't fix a wedged NIC; reset the VM (start is a
  # no-op when RUNNING).
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

#!/usr/bin/env bash
# vm-pull-restart.sh — resilient `docker compose pull && up -d` over IAP SSH.
#
# Usage: vm-pull-restart.sh <instance> <zone> <workdir> [pre-command]
#
# The pre-command is run before `docker compose pull` (e.g. for the
# audit-worker we prune old images to keep the 40GB disk from filling).
#
# Thin wrapper around vm-ssh-retry.sh, which owns the connection recovery
# logic (start a TERMINATED VM, reset one whose guest network has wedged,
# retry on IAP 4003 "failed to connect to backend").
set -euo pipefail

INSTANCE="${1:?instance name required}"
ZONE="${2:?zone required}"
WORKDIR="${3:?workdir required}"
PRE_CMD="${4:-true}"

CMD="cd $WORKDIR && $PRE_CMD && sudo docker compose pull && sudo docker compose up -d"

exec "$(dirname "$0")/vm-ssh-retry.sh" "$INSTANCE" "$ZONE" "$CMD"

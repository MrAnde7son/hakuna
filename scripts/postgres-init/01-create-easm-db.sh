#!/bin/sh
# Runs once on a fresh postgres-data volume (postgres image scans
# /docker-entrypoint-initdb.d on first init only). Creates the EASM scanner's
# database alongside the main `hakuna` DB so both stacks can share one
# Postgres instance in local dev. Production uses Cloud SQL where each scanner
# can have its own database/instance — this consolidation is dev-only.
#
# If your postgres-data volume already exists, this script will NOT run.
# Create the DB manually:
#   docker compose exec postgres createdb -U hakuna hakuna_easm
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE hakuna_easm;
    GRANT ALL PRIVILEGES ON DATABASE hakuna_easm TO $POSTGRES_USER;
EOSQL

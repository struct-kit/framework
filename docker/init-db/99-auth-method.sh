#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Rewrites pg_hba.conf so every host rule uses "md5" instead of the
# Postgres 14+ default of "scram-sha-256".  The framework's custom
# postgres driver implements md5 + cleartext password auth; scram is on
# the follow-up list but until then this ensures a first `docker compose
# up` boots all the way to a connectable server.
#
# The entrypoint runs /docker-entrypoint-initdb.d/*.sh once, only when
# $PGDATA has not been initialized yet — so existing data volumes are
# never touched by this script.
# ---------------------------------------------------------------------------
set -euo pipefail

HBA="${PGDATA}/pg_hba.conf"

if [ -f "${HBA}" ]; then
  echo "[init-db] Patching pg_hba.conf to prefer md5 auth..."
  sed -i -E \
    's/^host[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(scram-sha-256|peer|trust|md5)$/host \1 \2 \3 md5/' \
    "${HBA}"
  grep -E '^host[[:space:]]' "${HBA}" || true
fi

#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?Set DATABASE_URL before running restore}"
input="${1:?Usage: restore.sh backup.dump}"
pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" "$input"

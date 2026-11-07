#!/usr/bin/env sh
set -eu
: "${DATABASE_URL:?Set DATABASE_URL before running backup}"
output="${1:-ivm-backup-$(date -u +%Y%m%dT%H%M%SZ).dump}"
pg_dump "$DATABASE_URL" --format=custom --file "$output"
printf 'Backup written to %s\n' "$output"

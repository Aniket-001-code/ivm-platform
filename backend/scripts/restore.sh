#!/usr/bin/env sh
# Restore an IVM backup made by backup.sh. Stop the API first; restoring replaces all data.
set -eu
: "${DATABASE_URL:?Set DATABASE_URL before running restore}"
backup="${1:?Usage: restore.sh <backup-file>}"
[ -f "$backup" ] || { echo "Backup file not found: $backup" >&2; exit 1; }
case "$DATABASE_URL" in
  sqlite:*)
    db_path="${DATABASE_URL#sqlite:///}"
    cp "$backup" "$db_path"
    ;;
  postgresql*)
    pg_url="$(printf '%s' "$DATABASE_URL" | sed -E 's#^postgresql\+[a-z0-9]+://#postgresql://#')"
    pg_restore --clean --if-exists --no-owner --dbname "$pg_url" "$backup"
    ;;
  *)
    echo "Unsupported DATABASE_URL scheme" >&2
    exit 1
    ;;
esac
printf 'Restored %s\n' "$backup"

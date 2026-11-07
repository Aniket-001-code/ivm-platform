#!/usr/bin/env sh
# Back up the IVM database. PostgreSQL uses pg_dump (custom format); SQLite uses the online
# .backup command so a running application is not interrupted.
set -eu
: "${DATABASE_URL:?Set DATABASE_URL before running backup}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
case "$DATABASE_URL" in
  sqlite:*)
    db_path="${DATABASE_URL#sqlite:///}"
    output="${1:-ivm-backup-$stamp.sqlite}"
    sqlite3 "$db_path" ".backup '$output'"
    ;;
  postgresql*)
    # pg_dump does not understand SQLAlchemy driver suffixes such as +psycopg.
    pg_url="$(printf '%s' "$DATABASE_URL" | sed -E 's#^postgresql\+[a-z0-9]+://#postgresql://#')"
    output="${1:-ivm-backup-$stamp.dump}"
    pg_dump "$pg_url" --format=custom --file "$output"
    ;;
  *)
    echo "Unsupported DATABASE_URL scheme" >&2
    exit 1
    ;;
esac
sha256sum "$output" 2>/dev/null || shasum -a 256 "$output"
printf 'Backup written to %s\n' "$output"

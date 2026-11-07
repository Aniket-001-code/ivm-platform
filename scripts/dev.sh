#!/usr/bin/env bash
# Start the IVM demo locally on macOS/Linux without Docker: API on :8000, web app on :5173.
# First run installs dependencies; later runs reuse them. Stop with Ctrl+C.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  sed -e "s|^SECRET_KEY=.*|SECRET_KEY=${secret}|" \
      -e "s|^DATABASE_URL=.*|DATABASE_URL=sqlite:///./ivm_local_demo.sqlite|" .env.example > .env
  echo "Created .env with a random SECRET_KEY and a local SQLite database."
fi

if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 .venv
    uv pip install --python .venv/bin/python -e "backend[dev]"
  else
    PY="$(command -v python3.13 || command -v python3.12 || command -v python3.11 || true)"
    if [ -z "$PY" ]; then
      echo "Python 3.11-3.13 is required. Install uv (https://docs.astral.sh/uv/) or a newer Python." >&2
      exit 1
    fi
    "$PY" -m venv .venv
    .venv/bin/python -m pip install -e "backend[dev]"
  fi
fi

if [ ! -d frontend/node_modules ]; then
  (cd frontend && npm ci)
fi

# Load .env, but let variables already set in the shell win (e.g. LOGIN_RATE_LIMIT=100 ./scripts/dev.sh).
while IFS='=' read -r key value; do
  case "$key" in ''|\#*) continue ;; esac
  if [ -z "${!key+x}" ]; then export "$key=$value"; fi
done < .env

(cd backend && ../.venv/bin/alembic upgrade head)

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

(cd backend && exec ../.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000) &
(cd frontend && exec npm run dev -- --port 5173) &

echo
echo "IVM is starting:  web http://127.0.0.1:5173   API docs http://127.0.0.1:8000/docs"
echo "Sign in as user2@demo.bank / DemoPass!234 (first start seeds data; allow ~30 seconds)."
wait

#!/usr/bin/env bash
# Regenerate the quality, security and test evidence in docs/evidence/.
# Usage: scripts/collect_evidence.sh [--with-e2e]
#   --with-e2e  also run Playwright; needs the stack running (LOGIN_RATE_LIMIT=100 ./scripts/dev.sh)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/docs/evidence"
PY="$ROOT/.venv/bin/python"
mkdir -p "$OUT"
cd "$ROOT/backend"

run() { # run <file> <command...>: capture output and exit code without stopping
  local file="$1"; shift
  { echo "\$ $*"; echo "# collected $(date -u +%Y-%m-%dT%H:%M:%SZ)"; "$@"; echo "# exit code: $?"; } >"$OUT/$file" 2>&1
  tail -1 "$OUT/$file"
}

echo "Backend"
run backend-tests.txt "$PY" -m pytest -v --cov=app --cov-report=term --cov-fail-under=70 --junitxml="$OUT/backend-junit.xml"
run ruff.txt "$ROOT/.venv/bin/ruff" check app tests
run black.txt "$ROOT/.venv/bin/black" --check app tests
run mypy.txt "$ROOT/.venv/bin/mypy" app
run bandit.txt "$ROOT/.venv/bin/bandit" -r app
run pip-audit.txt "$ROOT/.venv/bin/pip-audit" --skip-editable
"$PY" - >"$OUT/openapi.json" <<'PY'
import json
from app.main import app
print(json.dumps(app.openapi(), indent=2))
PY
echo "  openapi.json written"
"$PY" - >"$OUT/success-criteria.json" <<'PY'
import json
from types import SimpleNamespace
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app import models  # noqa: F401
from app.db.base import Base
from app.db.seed import seed_demo
from app.services import reports
engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Base.metadata.create_all(engine)
db = Session(engine)
seed_demo(db)
admin = SimpleNamespace(role="platform_admin", business_unit_id=None, id=None)
print(json.dumps({
    "note": "Measured on a fresh seeded database (seed 42) at collection time.",
    "success_criteria": reports.success_criteria(db, admin),
    "automation_impact": reports.automation_impact(db),
    "ownership_accuracy": reports.ownership_accuracy(db, admin),
    "attack_path_impact": {k: v for k, v in reports.attack_path_impact(db, admin).items() if k != "findings"},
}, indent=2, default=str))
PY
echo "  success-criteria.json written"
if curl -sf http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; then
  run dashboard-latency.txt "$PY" scripts/measure_dashboard_latency.py
fi

echo "Frontend"
cd "$ROOT/frontend"
run frontend-tests.txt npx vitest run
run eslint.txt npm run lint
run frontend-build.txt npm run build
run npm-audit.txt npm audit --audit-level=high

if [[ "${1:-}" == "--with-e2e" ]]; then
  echo "End-to-end"
  cd "$ROOT"
  PLAYWRIGHT_BASE_URL="${PLAYWRIGHT_BASE_URL:-http://127.0.0.1:5173}" run e2e-results.txt npx playwright test --reporter=list
fi
# Keep evidence portable: replace the local checkout path with "." in every file.
for file in "$OUT"/*; do
  sed -i.bak "s#$ROOT#.#g" "$file" && rm -f "$file.bak"
done
echo "Evidence written to $OUT"

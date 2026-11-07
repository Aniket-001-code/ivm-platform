# Test Plan

## Purpose and scope

Verify deterministic synthetic generation, normalization/correlation, explainable risk, attack graph behavior, ownership/SLA/exception workflows, role controls, API validation, frontend accessibility basics, and Compose startup. Tests must never contact a vulnerability scanner or production service.

## Levels

1. **Unit:** pure normalization, fingerprint, scoring, scheduler decisions, and validation functions.
2. **Integration:** API login and workflow tests against PostgreSQL 15 after Alembic migration and seed.
3. **Frontend:** Vitest and React Testing Library verify login and common UI states.
4. **E2E:** Playwright runs the five operational journeys against a local Compose environment.
5. **Security/quality:** Ruff, Black, mypy, Bandit, pip-audit, npm audit, and gitleaks.
6. **Performance:** measure executive dashboard latency after seed; target p95 under 3 seconds on the test runner.

## Environment and data

Python 3.11 and Node 22 are used in CI. PostgreSQL 15 is created as a healthy service. The generator uses seed 42 and only fictional records. E2E tests run against `http://localhost:8080` after `docker compose up --build -d`.

## Entry/exit criteria

Entry: dependencies installed, migration applies, health endpoint reports the database, seed completes. Exit: required suites pass, coverage gate for risk/normalization is at least 70%, security scan results are reviewed, and every failure has a defect record. CI currently gates targeted core service coverage; full-application coverage is a follow-up before production.

## Commands

```powershell
docker compose up --build
cd backend; pip install -e ".[dev]"; pytest --cov=app.services.risk_engine --cov=app.services.normalization --cov-fail-under=70
cd frontend; npm install; npm test; npm run lint; npm run build
npx playwright install chromium
npm run e2e
```

## Evidence

Capture commit, environment, seed version, command, exit code, report path, timestamp, and defect references in `12_Test_Evidence_Template.md`. Do not attach real data or live secrets.

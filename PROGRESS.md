# Implementation progress

- [x] Read repository guidance and SPEC Sections 6, 7, 8, 9, and 11; no `AGENTS.md` was present.
- [x] Record initial endpoint/screen findings in `AUDIT.md`.
- [x] Replace role-string authorization with a nine-role permission map and scoped reads; extend owner/manager permissions based on browser tests.
- [x] Implement eight-factor max-point scoring, explanations, versioned configuration, what-if ranking, and base/path/final path feedback.
- [x] Add SQL-backed analytics and distinct role/dashboard endpoints, API health, and notifications.
- [x] Expand deterministic synthetic seed: 3,532 initial open findings, 156 Critical, 434 High, 109 paths, 26 weeks of risk history, 6 pending/4 approved exceptions, and level 1/2/3 escalations.
- [x] Add exception CSV, expiry behavior, SLA pauses, evidence-required task transitions, and role-aware escalation routing.
- [x] Remove selected fake frontend values; wire trend data, risk/status filters, finding picker, evidence input, factor list, and authenticated audit/exception CSV downloads.
- [x] Update vulnerable Python and frontend dependencies; `pip-audit` and `npm audit` report no known vulnerabilities.
- [x] Backend tests: 42 passed. CI-selected coverage gate: 100% for normalization and risk engine. Frontend Vitest: 1 passed, lint/build pass.
- [x] Ruff, Black, mypy (`--ignore-missing-imports`), Bandit, API smoke, and dashboard latency (<1 second p95) pass.
- [x] Playwright workflow suite: 5/5 flows passed in final Playwright run.
- [ ] Split backend API/model and frontend page monoliths into domain modules.
- [ ] Complete full frontend route guard coverage, sorting/pagination/exports, admin editors, complete AI source reporting/tool use, and dashboard page specialization.
- [ ] Add broad role-by-endpoint tests; whole-backend 70% coverage, gitleaks and Docker/PostgreSQL verification remain unavailable/incomplete.

See `KNOWN_ISSUES.md` for the remaining limitations.

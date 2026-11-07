# Initial implementation audit

Baseline was checked against the running SQLite demo API and current OpenAPI schema. “Works” means the screen/route is present and returned data in a representative read; route presence alone is not treated as proof that all write paths work.

| Endpoint or screen | Initial status | Evidence / gap |
|---|---|---|
| Auth login, refresh, logout, MFA, current user | Works / partial | Routes exist; successful local demo login. Rate limit and lockout coverage needs audit. |
| Users | Partial | List/create/update routes exist; delete route absent and role checks are hardcoded. |
| Assets, findings, imports | Partial | Main CRUD/list/detail and upload/retry routes exist; filters, pagination, dedup survivorship and error reporting need verification. |
| Risk config, scoring, what-if | Stubbed | Current scorer uses five fractional weights rather than SPEC’s eight max-point factors. |
| Attack paths | Partial | Graph/recalculate routes exist; before/after values need actual base/final scores and path influence. |
| Remediation, escalations, exceptions | Partial | Core routes exist; seed has no useful escalation/exception queue and escalation levels/expiry handling need work. |
| Dashboards | Stubbed / missing | One `/dashboards/{view}` returns a generic payload. `/heatmap`, `/trend`, `/mttr`, and `/sla-compliance` routes are missing. |
| AI | Partial | Ask/explain/summary/recommendation routes exist; must verify role-scoped tools, source data, fallback intents, and labeling. |
| Ticketing | Partial | Generic simulated ticket routes exist; task callback and system validation need verification. |
| Audit, users, ownership rules | Partial | Routes exist but authorization is string-based and exports/filters need validation. |
| Health and metrics | Partial | `/health` and `/api/v1/metrics` exist; required `/api/v1/health` is missing. |
| Frontend dashboard | Stubbed | Hardcoded chart/summary values and nav count; current component is a monolith. |
| Frontend filters and exports | Stubbed | Risk/status filters do not filter; “CSV” controls use print; exception requires pasted UUID; task close injects fixed evidence. |
| Frontend role views | Stubbed | Only one dashboard body, navigation and guards cover legacy roles, not all nine SPEC roles. |
| Backend tests / frontend build | Works (baseline) | 42 backend tests passed; frontend TypeScript/Vite production build passed before this feature audit. |



# Final verification update

| Endpoint or screen | Verified status | Evidence / remaining boundary |
|---|---|---|
| API health and login | Works | `/api/v1/health` returns ok; seeded analyst login succeeded on the final SQLite database. |
| Risk scoring and role enforcement | Works / partial | Eight max-point factors and nine canonical roles are implemented; full role-by-endpoint negative matrix remains untested. |
| Dashboards and analytics | Works / partial | Distinct executive/analyst/manager/auditor and heatmap/trend/MTTR/SLA endpoints return SQL-backed query results; final analyst dashboard returned 26 trend points. Full latency benchmark not run. |
| Seeded dataset | Works | 3,532 open findings, 156 Critical, 434 High, 109 paths, 6 pending and 4 approved exceptions, 9 escalations at each of levels 1–3. |
| Import, remediation, path, and exception workflows | Works / partial | Backend workflow suite passes; browser end-to-end set not run. |
| Frontend filters and evidence | Partial | Risk/status filters, finding picker, factor breakdown, and evidence input wired; detailed table pagination/sorting and pages remain incomplete. |
| Audit CSV | Works / partial | Authenticated download helper is wired; audit filters and other CSV exports remain incomplete. |
| Backend tests | Works / partial | 42 pass; risk engine + normalization measured 100% coverage, full backend is not 70% covered. |
| Frontend test/lint/build | Works | 1 Vitest test passes; lint and production build pass. |
| Docker/PostgreSQL | Not verified | Docker executable is unavailable. |
| Security and browser tests | Works / partial | Bandit, pip-audit, npm audit and all five Playwright flows pass. Gitleaks is not installed. |


## Updated quality and browser verification

- API latency helper: 10 dashboard samples, mean 0.832 s, p95 0.906 s.
- Backend: 42 tests pass; selected module coverage 100%. Ruff, Black, mypy with third-party missing imports ignored, and Bandit pass.
- Frontend: Vitest 1/1, ESLint, production build, and npm audit pass; npm audit reports zero vulnerabilities after dependency updates.
- `pip-audit` reports no known vulnerable installed packages.
- Playwright five-flow test passed (5/5).
- Docker configuration and Gitleaks could not be verified because those executables are unavailable.

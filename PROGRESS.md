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
- [x] Playwright workflow suite: all flows pass (13 as of 2026-11-07).
- [x] Split backend API/model and frontend page monoliths into domain modules.
- [x] Complete full frontend route guard coverage, sorting/pagination/exports, admin editors, AI source reporting, and dashboard page specialization. (Claude tool-use mode remains out of scope.)
- [x] Add broad role-by-endpoint tests and a whole-backend 70% coverage gate (now ≈82%).
- [ ] Gitleaks and Docker/PostgreSQL verification (tools unavailable locally; covered by CI jobs).

See `KNOWN_ISSUES.md` for the remaining limitations.

## 2026-11-06 pass

- Runs on macOS via `scripts/dev.sh`; CI workflow added.
- Fixed: assistant stuck on "Thinking…", three inconsistent data-scope rule sets (now `core/scope.py`), unscoped AI explain/recommendations, exception request/review/revoke/export scope gaps, crashes comparing naive and aware timestamps (overdue tasks, account lockout), CSV formula injection, unvalidated user roles and finding statuses, unaudited SLA/ownership changes, Swagger blocked by CSP, access tokens never refreshed (15-minute logout), admin weights shown as 2500%, task filter text sent as update comment.
- Tests: backend 79, frontend 12, Playwright 9 — all passing.

## 2026-11-07 pass — full SPEC coverage

- Implemented every remaining SPEC item: asset registration/criticality editing, survivorship and failed-row recovery,
  EASM source, threat-feed rescoring, single scoring path, ownership routing with groups/tags, policy-driven
  escalation with acknowledgement and inbox, task drawer/reassignment/tickets with signed webhook, MFA flow and
  password change, hash-chained append-only audit, forecasting (breach likelihood, trend), remediation sequencing,
  exception review packs, executive board report, success-criteria scorecard, Kubernetes manifests, graph export.
- Deliverables: all docs 01–20, evidence, demo video, presentation deck.
- Tests: backend 113 (85% coverage), frontend 12, Playwright 13 — all passing; 34 defects closed (`docs/13_Defect_Summary.md`).

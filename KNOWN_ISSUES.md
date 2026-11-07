# Remaining issues and verification gaps

Updated 2026-11-06.

## Not verified in this environment

- **Docker / PostgreSQL.** Docker is not installed on the development machine, so `docker compose up` and the PostgreSQL path have not been run. All verification used SQLite. The CI workflow (`.github/workflows/ci.yml`) includes `docker compose config` and `docker compose build` jobs, which will be the first real check.
- **Gitleaks** is not installed locally; it runs only in CI.
- **Optional Claude path.** With `ANTHROPIC_API_KEY` set, the assistant rewrites its summary with Claude. This path was not exercised (no key). It still uses `anthropic==0.42.0` and the default model `claude-haiku-4-5-20251001`; moving to a current model and SDK is a separate change.

## Prototype limits (by design)

- Business-unit scoping follows one documented rule set (`backend/app/core/scope.py`) and still needs stakeholder sign-off for real use.
- Audit rows are hash-chained and protected by database triggers; a database superuser could still drop the triggers, so production should also ship events to external write-once storage.
- Rate limits are per process and per client IP. Behind the Docker nginx proxy every user shares the proxy's IP, so the login limit is effectively shared.
- The assistant's offline mode answers a fixed set of 15 intents (with business-unit, asset, CVE and band filters and follow-ups); free-form reasoning needs the optional Claude path.
- Access tokens stay valid until expiry (15 min) after logout; only refresh tokens are revoked.

## Resolved in the 2026-11-07 pass

- Every SPEC use case, dashboard item and bonus item implemented; see `docs/20_Requirements_Traceability_Matrix.md`.
- Multi-replica scheduling: `SCHEDULER_ENABLED=false` on web replicas plus one scheduler (`deploy/k8s/scheduler.yaml`).
- Audit immutability: hash chain + append-only DB triggers (external WORM storage still recommended).

## Resolved in the 2026-11-06 pass

- API, model, and frontend monoliths split into domain modules.
- Permission-driven navigation and route guards on every page; role-specific dashboards.
- Server-side sorting, paging, filters and CSV export for findings, assets, tasks and audit.
- Editable scoring (with what-if preview), SLA, ownership-rule, and user-role administration.
- AI answers list source tables and row counts.
- Role-by-endpoint access matrix and scope tests; whole-backend coverage gate (≈82%).

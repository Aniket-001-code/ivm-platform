# Low-Level Design

## Backend modules

- `app.main`: constructs FastAPI, installs CORS/security middleware, mounts API v1, seeds an empty DB after migration, and starts/stops scheduled jobs.
- `app.core.config.Settings`: loads environment configuration with Pydantic Settings.
- `app.core.security`: creates request identifiers and Fernet-protects MFA secrets.
- `app.core.deps.get_db`: yields and closes a SQLAlchemy session per request.
- `app.api.v1.router`: Pydantic-validated route layer; dependencies validate JWTs and roles. It performs HTTP mapping and delegates business logic.
- `app.services.ingestion.parse_upload`: checks upload size/format and parses CSV/JSON.
- `app.services.ingestion.ingest_records`: maps source-specific fields, resolves assets/catalog rows, persists raw rows, deduplicates by fingerprint, records provenance, and scores new findings.
- `app.services.normalization`: normalizes severity and asset aliases and hashes identity fingerprints.
- `app.services.risk_engine.score_finding`: returns a 0–100 score, risk band, weighted points, and plain reason strings.
- `app.services.attack_path.recalculate_paths`: constructs a directed NetworkX graph, stores exposed-to-crown-jewel routes, and adjusts findings on those routes.
- `app.services.sla.check_overdue_tasks`: creates idempotent level-one and level-two escalation rows.
- `app.services.exceptions.expire_exceptions`: expires approved records and reopens their findings.
- `app.services.ai_assistant.answer_question`: classifies common intents, queries role-relevant aggregates, optionally calls Claude, and falls back on errors.
- `app.jobs.scheduler`: starts interval jobs using APScheduler in the backend process.
- `app.db.seed.seed_demo`: loads deterministic local fixtures only when the asset table is empty.

## Frontend modules

- `src/api/client.ts`: in-memory bearer token and JSON/FormData request helper.
- `src/App.tsx`: login, role-aware navigation, route pages, query/mutation orchestration, tables, chart, score breakdown, upload, and workflow controls.
- `src/styles.css`: responsive shell and page styles; badges include text labels so color is not the only signal.
- `src/main.tsx`: React Router and TanStack Query providers.

## Important invariants

Finding fingerprint is unique. Refresh token hashes are one-use and rotated. Finding exceptions cannot be approved by the requester. Closing a task requires evidence. Path score is capped at 100. Import batches retain per-row errors. Audit log routes expose reads only; no mutation endpoint is implemented.

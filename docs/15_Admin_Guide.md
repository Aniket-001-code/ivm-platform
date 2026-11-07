# Administrator Guide

## 1. Running the platform

| Option | Command | Notes |
|---|---|---|
| macOS / Linux dev | `./scripts/dev.sh` | Creates `.env` (random `SECRET_KEY`, SQLite), installs dependencies, migrates, starts API :8000 and web :5173 |
| Windows dev | see `README.md` | PowerShell steps with `.venv\Scripts\python.exe` |
| Docker Compose | `docker compose up --build` | PostgreSQL 15, API, nginx web on :8080; `--profile tls` adds HTTPS on :8443 (`infra/tls/generate-local-cert.ps1`) |
| Kubernetes | `deploy/k8s/README.md` | API replicas with HPA, one scheduler pod, TLS ingress, network policies |

The first API start applies migrations and seeds the synthetic dataset into an **empty** database. To reseed,
point `DATABASE_URL` at a new SQLite file (or drop the PostgreSQL volume with `docker compose down -v`).

## 2. Configuration (`backend/app/core/config.py`, `.env.example`)

| Setting | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Outside `development`/`test`, `SECRET_KEY` must be ≥ 32 chars and not the default or the API refuses to start |
| `SECRET_KEY` | placeholder | Signs JWTs and derives the key that encrypts MFA secrets |
| `DATABASE_URL` | PostgreSQL URL | `sqlite:///./file.sqlite` for development |
| `MFA_REQUIRED` | `false` | When `true`, admins, architects and vulnerability managers must have MFA enrolled to sign in |
| `LOGIN_RATE_LIMIT` / `AI_RATE_LIMIT` | 10 / 20 per minute | Per client IP; raise only for automated test runs |
| `INTEGRATION_WEBHOOK_SECRET` | unset | Enables the ticketing webhook (HMAC-SHA256 key) |
| `SCHEDULER_ENABLED` | `true` | Set `false` on web replicas when scaling out; run exactly one scheduler |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | unset / haiku | Optional Claude rephrasing of assistant answers (aggregates only) |

## 3. Users and access

Administration → Users and roles: add users (email, name, role, business unit, temporary password), change roles,
deactivate/reactivate, reset passwords (revokes sessions) and reset lost MFA authenticators. Administrators cannot
change or deactivate their own account or reset their own MFA. Roles and permissions: `06_API_Specification.md`.

**MFA rollout:** ask privileged users to enroll on *My account* (avatar, top right), confirm the MFA column shows
"on", then set `MFA_REQUIRED=true` and restart.

## 4. Risk model, SLAs and ownership

- **Scoring weights** (Administration → Risk model): eight maximum-point values that must total 100. *Preview impact*
  shows the new ranking without saving; *Save new version* versions the config and rescores every finding (audited).
- **SLA policy**: days per band and escalation thresholds (level 1 and level 2 days after the due date; level 3
  follows level 2). Changes are audited.
- **Ownership rules**: match business service, business unit (name or id), asset type, environment or regulatory tag;
  assign a user and/or group; lowest priority number wins; fallback is the asset owner, then the BU manager.
  Check the result on Reports → Ownership accuracy.

## 5. Scheduler

Runs the SLA check every 15 minutes and exception expiry hourly. *Run scheduler jobs now* (Administration) triggers
both immediately. With several API replicas, set `SCHEDULER_ENABLED=false` on them and run `deploy/k8s/scheduler.yaml`.

## 6. Integrations

Ticketing simulators: `jira-sim`, `servicenow-sim`. For an external system, set `INTEGRATION_WEBHOOK_SECRET` and have it
call `POST /api/v1/integrations/ticketing/webhook` with `{"ticket_key","status"}` and
`X-IVM-Signature: sha256=<HMAC hex of body>`. Statuses: open, in_progress, resolved, closed, cancelled.

## 7. Backup and restore

```bash
DATABASE_URL=sqlite:///./ivm_local_demo.sqlite backend/scripts/backup.sh backups/ivm.sqlite
DATABASE_URL=postgresql+psycopg://ivm:pw@host:5432/ivm backend/scripts/backup.sh   # pg_dump custom format
DATABASE_URL=... backend/scripts/restore.sh <file>    # stop the API first
```
Backups print a SHA-256 checksum. Schedule them (cron or a Kubernetes CronJob) and test restores regularly.

## 8. Audit and evidence

Audit trail → *Verify integrity* recomputes the hash chain (`GET /api/v1/audit/verify`). The database rejects
updates and deletes of audit rows. Regenerate quality and security evidence with `scripts/collect_evidence.sh
[--with-e2e]`; regenerate the data-model and API references with `.venv/bin/python scripts/generate_reference_docs.py`.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| "Rate limit exceeded" on login | Wait a minute or raise `LOGIN_RATE_LIMIT` for test runs |
| API refuses to start: `SECRET_KEY must be set…` | Set a strong key or `APP_ENV=development` locally |
| Port 8000/5173 in use | Stop the other process (`lsof -i :8000`) |
| No demo data | The database was not empty; use a new SQLite file |
| "MFA code required" | Enter the 6-digit code; an admin can reset a lost authenticator |
| Import rows failed | Imports → *view* failed rows; fix the cause (e.g. register the asset) and *Retry* |

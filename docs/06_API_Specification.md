# API Specification

FastAPI publishes the interactive schema at `/docs` and JSON schema at `/openapi.json`. All application routes are under `/api/v1`. Except `/health`, requests require `Authorization: Bearer <access_token>`. Uploads accept CSV or JSON up to 10 MB. Validation errors use `{ "error": { "code", "message", "details" } }`.

| Area | Routes |
|---|---|
| Health | `GET /health`, `GET /api/v1/metrics` |
| Authentication | `POST /api/v1/auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`, `POST /auth/mfa/setup`, `/auth/mfa/verify` |
| Users | `GET/POST /api/v1/users`, `PATCH /users/{id}` (admin) |
| Assets | `GET /assets`, `GET /assets/{id}`, `GET /assets/{id}/findings`, `/connections` |
| Findings | `GET /findings` with severity/band/status/asset/search filters, `GET /findings/{id}`, `PATCH /findings/{id}/status` |
| Imports | `POST /imports/{scanner|cspm|pentest|container|identity}`, `GET /imports`, `GET /imports/{id}`, `POST /imports/{id}/retry` |
| Risk/threat | `POST /risk/recalculate`, `/risk/what-if`, `GET /risk/findings/{id}/explain`, `/config/scoring`, `/threat-intel/{cve}` |
| Paths | `GET /attack-paths`, `/attack-paths/{id}`, `/attack-paths/graph`, `POST /attack-paths/recalculate` |
| Tasks | `GET /tasks`, `/tasks/my`, `/tasks/overdue`, `/tasks/{id}`, `PATCH /tasks/{id}`, `GET /escalations`, `POST /jobs/run` |
| Exceptions | `POST/GET /exceptions`, `GET /exceptions/{id}`, `/exceptions/expiring`, `/exceptions/export`, `POST /exceptions/{id}/approve|reject|revoke` |
| Analytics | `GET /dashboards/{executive|analyst|manager|auditor|heatmap|trend|mttr|sla-compliance}` |
| AI | `POST /ai/ask`, `/ai/explain/{finding_id}`, `/ai/executive-summary`, `GET /ai/recommendations` |
| Tickets | `POST /ticketing/{jira-sim|servicenow-sim}/issues`, `GET /ticketing/{system}/issues/{key}`, `POST /ticketing/{system}/issues/{key}/transition` |
| Audit | `GET /audit` |

The demo API uses JSON responses and Pydantic validation. Recalculate and mutation routes require elevated roles where applicable. Simulated ticket transitions update the linked task to pending verification when a ticket is resolved.

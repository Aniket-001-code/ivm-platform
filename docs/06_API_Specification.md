# API Specification

Generated from the live OpenAPI schema (104 operations) and the central permission map (`backend/app/core/rbac.py`) by `scripts/generate_reference_docs.py`. Interactive docs: `/docs`; machine-readable schema: `/openapi.json` (copy in `docs/evidence/openapi.json`).

## Conventions

- **Auth**: `POST /api/v1/auth/login` with `{email, password, totp_code?}` returns `access_token` (JWT, 15 min), `refresh_token` (7 days, rotated on every use) and the user with `permissions`. If MFA is enabled and no code is sent, the response is `401 {"error":{"message":"MFA code required"}}`. Send `Authorization: Bearer <access>`; refresh with `POST /api/v1/auth/refresh {refresh_token}`; `POST /api/v1/auth/logout` revokes the refresh token.
- **Authorization**: every authenticated route is checked twice — the central default-deny permission below, and row-level scope (`backend/app/core/scope.py`): out-of-scope records return `404`.
- **Errors**: `{"error": {"code", "message", "details"}}`. 401 unauthenticated, 403 permission, 404 not found/out of scope, 409 conflict (state transition, duplicate), 413 too large, 422 validation, 429 rate limited.
- **Paging**: list endpoints accept `limit`/`offset` (and `sort`/`order` where listed) and return the unpaged total in `X-Total-Count`. Every response carries `X-Request-ID`.
- **Exports**: `*/export` return CSV with formula-injection neutralisation; `reports/executive?format=html` and `exceptions/{id}/review-pack?format=html` return printable HTML.
- **Webhook**: `POST /api/v1/integrations/ticketing/webhook` with body `{ticket_key, status}` and header `X-IVM-Signature: sha256=<hex HMAC-SHA256 of the raw body using INTEGRATION_WEBHOOK_SECRET>`.
- **Rate limits**: login `LOGIN_RATE_LIMIT`/min (default 10), AI `AI_RATE_LIMIT`/min (default 20), per client IP.

## Permissions → roles

| Permission | Roles |
|---|---|
| `ai:executive_summary` | executive_ciso, platform_admin, security_architect |
| `ai:use` | platform_admin, security_analyst, security_architect, vulnerability_manager |
| `asset:manage` | platform_admin, vulnerability_manager |
| `asset:read` | business_unit_manager, it_asset_owner, platform_admin, security_analyst, security_architect, system_administrator, vulnerability_manager |
| `attack_path:read` | platform_admin, security_analyst, security_architect, vulnerability_manager |
| `audit:read` | auditor, platform_admin, security_analyst, security_architect |
| `authenticated` | auditor, business_unit_manager, executive_ciso, it_asset_owner, platform_admin, security_analyst, security_architect, system_administrator, vulnerability_manager |
| `config:manage` | platform_admin |
| `config:read` | platform_admin, security_analyst, vulnerability_manager |
| `exception:approve_all` | security_architect |
| `exception:approve_temporary` | security_architect, vulnerability_manager |
| `exception:read` | auditor, business_unit_manager, it_asset_owner, platform_admin, security_analyst, security_architect, vulnerability_manager |
| `exception:request` | it_asset_owner, platform_admin, security_analyst, security_architect, vulnerability_manager |
| `finding:read` | business_unit_manager, it_asset_owner, platform_admin, security_analyst, security_architect, vulnerability_manager |
| `finding:triage` | platform_admin, security_analyst, vulnerability_manager |
| `import:run` | platform_admin, security_analyst, vulnerability_manager |
| `notification:read` | business_unit_manager, platform_admin, vulnerability_manager |
| `report:read` | auditor, business_unit_manager, executive_ciso, it_asset_owner, platform_admin, security_analyst, security_architect, system_administrator, vulnerability_manager |
| `risk:manage` | platform_admin, security_architect, vulnerability_manager |
| `risk:read` | auditor, business_unit_manager, executive_ciso, it_asset_owner, platform_admin, security_analyst, security_architect, system_administrator, vulnerability_manager |
| `risk:what_if` | platform_admin, security_architect, vulnerability_manager |
| `scheduler:run` | platform_admin, vulnerability_manager |
| `task:assigned` | it_asset_owner, system_administrator |
| `task:manage` | platform_admin, vulnerability_manager |
| `task:read` | business_unit_manager, it_asset_owner, platform_admin, security_analyst, system_administrator, vulnerability_manager |
| `ticket:create` | it_asset_owner, platform_admin, security_analyst, system_administrator, vulnerability_manager |
| `user:manage` | platform_admin |
| `user:read` | platform_admin, security_analyst, vulnerability_manager |

## `ai`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/ai/ask` | `ai:use` |  | yes | Ai Ask |
| POST | `/api/v1/ai/executive-summary` | `ai:executive_summary` |  |  | Ai Executive Summary |
| POST | `/api/v1/ai/explain/{finding_id}` | `ai:use` | `finding_id` |  | Ai Explain |
| GET | `/api/v1/ai/recommendations` | `ai:use` |  |  | Ai Recommendations |

## `analytics`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/analytics/forecast` | `risk:read` | `weeks` |  | Risk trend projection and SLA breach forecast from historical data. |

## `assets`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/assets/bulk-import` | `asset:manage` |  | yes | Register many assets; invalid rows are reported, valid rows are created. |
| GET | `/api/v1/assets/export` | `asset:read` | `search`, `business_unit_id`, `environment`, `internet_exposed`, `crown_jewel`, `tier`, `sort`, `order` |  | Assets Export |
| GET | `/api/v1/assets/{asset_id}/connections` | `asset:read` | `asset_id` |  | Asset Connections |
| PUT | `/api/v1/assets/{asset_id}/criticality` | `asset:manage` | `asset_id` | yes | Kept for API compatibility; prefer PATCH /assets/{id}. |
| GET | `/api/v1/assets/{asset_id}/findings` | `asset:read` | `asset_id` |  | Asset Findings |
| PATCH | `/api/v1/assets/{asset_id}` | `asset:manage` | `asset_id` | yes | Update inventory, ownership or criticality context; risk-relevant edits rescore. |
| GET | `/api/v1/assets/{asset_id}` | `asset:read` | `asset_id` |  | Asset Detail |
| GET | `/api/v1/assets` | `asset:read` | `search`, `business_unit_id`, `environment`, `internet_exposed`, `crown_jewel`, `tier`, `sort`, `order`, `limit`, `offset` |  | List assets; the unpaged total is returned in the X-Total-Count header. |
| POST | `/api/v1/assets` | `asset:manage` |  | yes | Create Asset |

## `attack-paths`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/attack-paths/export` | `attack_path:read` | `format` |  | Export the scoped asset graph and modeled paths for a graph database (Neo4j) or GraphML tools. |
| GET | `/api/v1/attack-paths/graph` | `attack_path:read` | `asset_id` |  | Attack Graph |
| GET | `/api/v1/attack-paths/impact` | `attack_path:read` | `limit` |  | How path context changed finding scores, bands and ranking (SC-9). |
| POST | `/api/v1/attack-paths/recalculate` | `risk:manage` |  |  | Attack Paths Recalculate |
| GET | `/api/v1/attack-paths/{path_id}` | `attack_path:read` | `path_id` |  | Attack Path Detail |
| GET | `/api/v1/attack-paths` | `attack_path:read` |  |  | Attack Paths |

## `audit`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/audit/export` | `audit:read` | `action`, `entity_type`, `actor`, `since`, `until` |  | Audit Export |
| GET | `/api/v1/audit/facets` | `audit:read` |  |  | Distinct actions and entity types, used to populate the audit filter menus. |
| GET | `/api/v1/audit/verify` | `audit:read` |  |  | Recompute the audit hash chain and report whether any row was altered or removed. |
| GET | `/api/v1/audit` | `audit:read` | `action`, `entity_type`, `actor`, `since`, `until`, `limit`, `offset` |  | Filterable audit trail; the unpaged total is returned in X-Total-Count. |

## `auth`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/auth/login` | public |  | yes | Login |
| POST | `/api/v1/auth/logout` | `authenticated` |  |  | Logout |
| GET | `/api/v1/auth/me` | `authenticated` |  |  | Me |
| POST | `/api/v1/auth/mfa/disable` | `authenticated` |  | yes | Mfa Disable |
| POST | `/api/v1/auth/mfa/setup` | `authenticated` |  | yes | Start (or rotate) TOTP enrollment. Rotating an active factor needs a current code. |
| POST | `/api/v1/auth/mfa/verify` | `authenticated` |  | yes | Mfa Verify |
| POST | `/api/v1/auth/password` | `authenticated` |  | yes | Change Password |
| POST | `/api/v1/auth/refresh` | public |  | yes | Refresh |

## `business-services`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/business-services` | `authenticated` |  |  | Business Services |

## `business-units`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/business-units` | `authenticated` |  |  | Business Units |

## `config`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| DELETE | `/api/v1/config/ownership-rules/{rule_id}` | `config:manage` | `rule_id` |  | Delete Ownership Rule |
| GET | `/api/v1/config/ownership-rules` | `config:read` |  |  | Ownership Rules |
| POST | `/api/v1/config/ownership-rules` | `config:manage` |  | yes | Create Ownership Rule |
| GET | `/api/v1/config/scoring` | `config:read` |  |  | Scoring Config |
| PUT | `/api/v1/config/scoring` | `config:manage` |  | yes | Update Scoring |
| GET | `/api/v1/config/sla` | `config:read` |  |  | Sla Config |
| PUT | `/api/v1/config/sla` | `config:manage` |  | yes | Update Sla |

## `dashboards`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/dashboards/heatmap` | `risk:read` |  |  | Dashboard Heatmap |
| GET | `/api/v1/dashboards/mttr` | `risk:read` |  |  | Dashboard Mttr |
| GET | `/api/v1/dashboards/sla-compliance` | `risk:read` |  |  | Dashboard Sla Compliance |
| GET | `/api/v1/dashboards/trend` | `risk:read` |  |  | Dashboard Trend |
| GET | `/api/v1/dashboards/{view}` | `risk:read` | `view` |  | Dashboard |

## `escalations`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/escalations/{escalation_id}/acknowledge` | `authenticated` | `escalation_id` |  | Acknowledge Escalation |
| GET | `/api/v1/escalations` | `notification:read` |  |  | Escalations on tasks inside the caller's scope, newest first. |

## `exceptions`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/exceptions/expiring` | `exception:read` |  |  | Expiring Exceptions |
| GET | `/api/v1/exceptions/export` | `exception:read` |  |  | Exception Export |
| POST | `/api/v1/exceptions/{exception_id}/approve` | `exception:approve_temporary` | `exception_id` | yes | Approve Exception |
| POST | `/api/v1/exceptions/{exception_id}/reject` | `exception:approve_temporary` | `exception_id` | yes | Reject Exception |
| GET | `/api/v1/exceptions/{exception_id}/review-pack` | `exception:read` | `exception_id`, `format` |  | Evidence pack for approvers and auditors (JSON, or printable HTML). |
| POST | `/api/v1/exceptions/{exception_id}/revoke` | `exception:request` | `exception_id` | yes | Revoke Exception |
| GET | `/api/v1/exceptions/{exception_id}` | `exception:read` | `exception_id` |  | Exception Detail |
| GET | `/api/v1/exceptions` | `exception:read` |  |  | Exceptions |
| POST | `/api/v1/exceptions` | `exception:request` |  | yes | Request Exception |

## `findings`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/findings/export` | `finding:read` | `severity`, `band`, `status`, `asset_id`, `search`, `sort`, `order` |  | Findings Export |
| PATCH | `/api/v1/findings/{finding_id}/status` | `finding:triage` | `finding_id` | yes | Finding Status |
| GET | `/api/v1/findings/{finding_id}` | `finding:read` | `finding_id` |  | Finding Detail |
| GET | `/api/v1/findings` | `finding:read` | `severity`, `band`, `status`, `asset_id`, `search`, `sort`, `order`, `limit`, `offset` |  | List findings; the unpaged total is returned in the X-Total-Count header. |

## `health`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/health` | public |  |  | Api Health |
| GET | `/health` | public |  |  | Health |

## `imports`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/imports/{batch_id}/failed-rows` | `finding:read` | `batch_id` |  | Rows kept for recovery: the original payload plus the validation error. |
| POST | `/api/v1/imports/{batch_id}/retry` | `import:run` | `batch_id` |  | Reprocess the rows that failed in a batch (e.g. after registering a missing asset). |
| GET | `/api/v1/imports/{batch_id}` | `finding:read` | `batch_id` |  | Import Detail |
| POST | `/api/v1/imports/{source_type}` | `import:run` | `source_type` | yes | Import File |
| GET | `/api/v1/imports` | `finding:read` |  |  | Imports |

## `integrations`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/integrations/ticketing/webhook` | HMAC signature (no user session) |  |  | Inbound status updates from an external ticketing system (HMAC-signed). |

## `jobs`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/jobs/run` | `scheduler:run` |  |  | Run Jobs |

## `me`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/me/notifications` | `authenticated` |  |  | Personal inbox for every role: escalations, overdue/at-risk work, exception actions. |

## `metrics`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/metrics` | `report:read` |  |  | Metrics |

## `notifications`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/notifications` | `authenticated` |  |  | Escalations routed to the caller (kept for API compatibility; see /me/notifications). |

## `reports`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/reports/automation-impact` | `report:read` |  |  | Automation Impact |
| GET | `/api/v1/reports/executive` | `report:read` | `format` |  | Board-style summary (UC-12); ``format=html`` returns a printable report. |
| GET | `/api/v1/reports/ownership-accuracy` | `report:read` |  |  | Ownership Accuracy |
| GET | `/api/v1/reports/remediation-plan` | `report:read` | `limit` |  | Recommended remediation sequence by risk reduced per hour of effort. |
| GET | `/api/v1/reports/success-criteria` | `report:read` |  |  | Live, measured status of SPEC success criteria SC-1..SC-12. |

## `risk`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/risk/config` | `risk:read` |  |  | Risk Config |
| GET | `/api/v1/risk/findings/{finding_id}/explain` | `risk:read` | `finding_id` |  | Risk Explain |
| POST | `/api/v1/risk/recalculate` | `risk:manage` |  |  | Risk Recalculate |
| POST | `/api/v1/risk/what-if` | `risk:what_if` |  | yes | Risk What If |

## `tasks`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/tasks/breach-forecast` | `task:read` | `horizon_days` |  | Predicted SLA breaches for open work in scope (learned from closed-task history). |
| GET | `/api/v1/tasks/export` | `task:read` | `status`, `priority`, `overdue` |  | SLA / aging report as CSV for the caller's scope. |
| GET | `/api/v1/tasks/my` | `task:read` | `status`, `priority`, `overdue`, `limit`, `offset` |  | My Tasks |
| GET | `/api/v1/tasks/overdue` | `task:read` | `limit`, `offset` |  | Overdue Tasks |
| POST | `/api/v1/tasks/{task_id}/assign` | `task:assigned` | `task_id` | yes | Manual ownership override with a recorded reason (audited). |
| GET | `/api/v1/tasks/{task_id}` | `task:read` | `task_id` |  | Task Detail |
| PATCH | `/api/v1/tasks/{task_id}` | `task:assigned` | `task_id` | yes | Update Task |
| GET | `/api/v1/tasks` | `task:read` | `status`, `priority`, `overdue`, `limit`, `offset` |  | Tasks in the caller's scope, earliest SLA first; total in X-Total-Count. |

## `threat-intel`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/threat-intel/import/file` | `import:run` |  | yes | Import Threat Intel File |
| POST | `/api/v1/threat-intel/import` | `import:run` |  | yes | Apply a threat feed (JSON array) and immediately rescore affected findings. |
| GET | `/api/v1/threat-intel/{cve_id}` | `finding:read` | `cve_id` |  | Threat Intel |
| GET | `/api/v1/threat-intel` | `finding:read` | `kev_only` |  | Threat Intel Catalog |

## `ticketing`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| GET | `/api/v1/ticketing/issues` | `ticket:create` | `task_id` |  | List Tickets |
| PATCH | `/api/v1/ticketing/{system}/issues/{ticket_key}/transition` | `ticket:create` | `system`, `ticket_key` | yes | Transition Ticket |
| POST | `/api/v1/ticketing/{system}/issues/{ticket_key}/transition` | `ticket:create` | `system`, `ticket_key` | yes | Transition Ticket |
| GET | `/api/v1/ticketing/{system}/issues/{ticket_key}` | `ticket:create` | `system`, `ticket_key` |  | Get Ticket |
| POST | `/api/v1/ticketing/{system}/issues` | `ticket:create` | `system` | yes | Create Ticket |

## `users`

| Method | Path | Permission | Path/query params | Body | Description |
|---|---|---|---|---|---|
| POST | `/api/v1/users/{user_id}/reset-mfa` | `user:manage` | `user_id` |  | Clear a lost authenticator so the user can enroll again. |
| POST | `/api/v1/users/{user_id}/reset-password` | `user:manage` | `user_id` | yes | Administrator sets a temporary password; the user's sessions are revoked. |
| PATCH | `/api/v1/users/{user_id}` | `user:manage` | `user_id` | yes | Update User |
| GET | `/api/v1/users` | `user:read` |  |  | Users |
| POST | `/api/v1/users` | `user:manage` |  | yes | Create User |

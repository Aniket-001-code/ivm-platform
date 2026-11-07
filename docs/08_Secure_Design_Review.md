# Secure Design Review

Scope: the full platform as of 2026-11-07. Threats and abuse cases are in `07_Threat_Model.md`; the coding checklist
is `09_Secure_Coding_Checklist.md`. Status: **Implemented**, **Partial** (works, with a stated limit) or **Gap**.

## Design principles

| Principle | How it is applied | Status |
|---|---|---|
| Default deny / complete mediation | Every authenticated request maps to a permission in `core/rbac.py::permission_for_request` and is checked in `core/deps.py` before the handler runs; unmapped routes still require authentication | Implemented |
| Least privilege | 9 roles × 28 permissions; CISO and auditor are read-only; owners can update only their own tasks | Implemented |
| Row-level access | One rule set, `core/scope.py`, used by API, dashboards, reports and AI; out-of-scope records return 404 | Implemented (policy needs stakeholder sign-off) |
| Separation of duties | Requesters cannot approve their own exceptions; long-term exceptions need a security architect; admins cannot demote or deactivate themselves or reset their own MFA | Implemented |
| Defence in depth | Permissions + scope + validation + audit + DB triggers + network policies | Implemented |
| Fail secure | Unknown roles get no permissions and see no assets; invalid tokens → 401; weak `SECRET_KEY` refuses to start outside development | Implemented |
| Secure defaults | Synthetic data only, MFA available to all, CSP and security headers, rate limits on by default | Implemented |

## Control areas

| Area | Controls (code) | Status |
|---|---|---|
| Authentication | bcrypt; lockout after 5 failures for 15 min; constant-time unknown-email handling; login rate limit; TOTP MFA for any user who enables it, mandatory for privileged roles with `MFA_REQUIRED=true` (`routes/auth.py`) | Implemented |
| Session management | 15-min JWT access tokens; 7-day refresh tokens rotated on every use, stored hashed, revoked on logout/password change/deactivation; single-flight refresh in the browser (`frontend/src/api/client.ts`) | Partial — refresh token kept in `sessionStorage`; access token valid until expiry after logout |
| Access control | See principles above; tested role by endpoint (`tests/integration/test_role_matrix.py`) | Implemented |
| Input validation | Pydantic models (`extra="forbid"` on assets), enumerated statuses/roles/types, upload size 10 MB and type checks, CVSS/EPSS range checks, bounded AI question/history | Implemented |
| Output encoding | React escaping; HTML reports escape every value; CSV formula-injection neutralisation (`common._csv_cell`) | Implemented |
| Cryptography | MFA secrets encrypted with Fernet keyed from `SECRET_KEY`; SHA-256 audit chain; HMAC-SHA256 webhook signatures; TLS via nginx/ingress | Partial — DB-level encryption at rest relies on the platform (volume/managed DB encryption) |
| Logging & audit | JSON logs with request id; append-only, hash-chained `audit_logs` covering logins, imports, scoring/SLA/ownership/user changes, assignments, escalations, exceptions, tickets, AI queries, reports; `/audit/verify` | Partial — a DB superuser could drop triggers; ship to external WORM storage in production |
| Error handling | Uniform error envelope; unhandled exceptions return a generic 500 with request id, details only in server logs | Implemented |
| Configuration & secrets | All secrets from environment; `.env` git-ignored; gitleaks in CI; k8s secret template only | Implemented |
| API security | CORS allow-list; CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`; per-IP rate limits | Partial — rate limits are per process and per client IP |
| AI safety | Assistant answers from role-scoped queries; Claude (optional) receives only aggregates and a system prompt that treats input as a question | Implemented |
| Supply chain | Pinned dependencies, lockfile `npm ci`, pip-audit and npm audit in CI, non-root container, `.dockerignore` | Implemented |

## Security test evidence

| Evidence | Result |
|---|---|
| Role × endpoint matrix (9 roles × 24 endpoints) and unauthenticated checks | Pass (`test_every_role_gets_exactly_its_permissions`, `test_unauthenticated_requests_are_rejected`) |
| Scope isolation across findings, exceptions, exports, dashboards, AI | Pass (`test_business_unit_manager_sees_only_own_unit_everywhere`, `test_out_of_scope_findings_…`) |
| MFA enrollment, login step, rotation, all-role enforcement | Pass (`test_mfa_*`) |
| Audit tampering detection and append-only triggers | Pass (`test_audit_chain_detects_tampering_and_triggers_block_edits`) |
| Signed webhook (forged signature rejected) | Pass (`test_ticket_lifecycle_and_signed_webhook`) |
| CSV injection, lockout, user-role validation, weak secret refusal | Pass |
| bandit / pip-audit / npm audit | 0 issues / 0 known vulnerabilities / 0 vulnerabilities (`docs/evidence/`) |

## Recommendations before any production use (priority order)

1. Move the refresh token to a Secure, HttpOnly, SameSite cookie and add access-token revocation (token version).
2. Stream audit events to external immutable storage; restrict DB roles so the application user cannot alter triggers.
3. Use a shared rate-limit store (e.g. Redis) and trust `X-Forwarded-For` only from the ingress.
4. Agree the business-unit visibility policy with stakeholders; add SSO (OIDC) with MFA at the identity provider.
5. Enable encryption at rest on the database volume or managed service and rotate `SECRET_KEY` with key versioning.

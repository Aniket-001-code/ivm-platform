# Secure Coding Checklist

## Authentication and authorization

- [x] Hash passwords with bcrypt; do not log secrets.
- [x] Enforce password policy on administrative account creation.
- [x] Lock accounts after repeated failed authentication.
- [x] Use signed short-lived access tokens and rotate refresh tokens.
- [x] Encrypt TOTP secret at rest; MFA enforcement is configurable for privileged roles.
- [x] Protect business API routes with authenticated-user dependencies.
- [ ] Complete business-unit row-level scope before production.
- [x] Reject exception self-approval and disallow invalid state transitions.

## Data and input

- [x] Validate request body and path types with Pydantic/FastAPI.
- [x] Limit uploads to 10 MB; accept CSV/JSON extensions only.
- [x] Handle malformed rows as batch errors without exposing stack traces.
- [x] Use parameterized ORM queries; do not concatenate SQL input.
- [x] Render untrusted strings as React text, not HTML.
- [x] Preserve import provenance and finding fingerprints.
- [ ] Add production-grade MIME sniffing and antivirus scanning if user-uploaded files are exposed beyond the demo.

## Secrets, transport, and dependencies

- [x] Read credentials/API keys from environment; use dummy-only `.env.example` values.
- [x] Ignore local `.env` and generated self-signed key files.
- [x] Provide local TLS reverse-proxy profile and security headers.
- [x] Pin direct Python and frontend dependencies.
- [x] Add pip-audit, npm audit, Bandit, and gitleaks CI steps.
- [ ] Use managed secret storage, real TLS certificates, database encryption, and dependency update policy in production.

## Logs and AI

- [x] Include a request ID in API responses and structured logs.
- [x] Audit login, import, risk, task, exception, and AI actions.
- [x] Do not expose update/delete routes for audit rows.
- [x] Keep AI output labeled, rate-limited, role-aware, and offline-capable.
- [x] Avoid sending PII; this seeded environment contains only fictional records.

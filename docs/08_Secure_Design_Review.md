# Secure Design Review

## Review summary

The design uses a local service boundary and fictional fixtures. It does not scan targets. The backend owns authentication, validation, data writes, score calculation, and access decisions; the browser is not trusted for role checks. Uploaded records become raw finding rows and normalized records only after format and size validation.

## Controls reviewed

**Identity:** passwords are bcrypt hashes; repeated failed login attempts lock an account for 15 minutes; access JWTs expire after 15 minutes; refresh tokens rotate using stored hashes; optional MFA uses TOTP with encrypted secret storage. MFA enforcement can be enabled for administrators and approvers with `MFA_REQUIRED=true`.

**Authorization:** protected endpoints use the current-user dependency. Role-restricted operations cover user administration, exception review, risk recalculation, audit, and scheduled jobs. The task update route checks assignment or elevated role. Production deployment needs explicit business-unit scoping for all reads.

**Data protection:** secrets are environment-only; `.env` is ignored; `.env.example` includes demo placeholders. HTTPS is optional through the local self-signed reverse proxy. PostgreSQL volume encryption remains the host/operator responsibility.

**Application controls:** request payloads use Pydantic; SQL access uses SQLAlchemy; CSV/JSON uploads have an upper bound; API errors omit stack traces; security headers are set; CORS is restricted to local UI origins. Claude requests are optional and use aggregate synthetic context, bounded time, prompt-injection guidance, and fallback behavior.

## Findings and actions

| Priority | Observation | Action/status |
|---|---|---|
| High | Demo refresh token is returned in JSON | Move to Secure HttpOnly SameSite cookie before deployment; documented tradeoff |
| High | Default Compose credentials are convenient for local use | Override all secrets in any shared environment |
| Medium | User data scoping is not fully implemented | Define BU and manager scope; add negative tests before production |
| Medium | Audit table is application append-only, not database immutable | Use restricted DB roles and external immutable log storage in production |
| Medium | Scheduler is process-local | Run one scheduler instance or use an external durable scheduler for replicas |
| Low | Self-signed demo certificate is not trusted | Use managed certificate and TLS policy outside the local demo |

## Decision

Suitable as a synthetic academic capstone demo. Not approved as a production banking security platform without the listed deployment controls, independent security review, data-scoping work, and operational resilience design.

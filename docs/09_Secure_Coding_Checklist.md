# Secure Coding Checklist

`[x]` done and verified in code; `[~]` partial (see note); `[ ]` not done.

## Authentication and sessions
- [x] Passwords hashed with bcrypt; policy ≥ 12 chars, mixed case, digit, symbol (`routes/auth.py::password_problem`)
- [x] Account lockout and login rate limiting; unknown emails take the same time as known ones
- [x] TOTP MFA; rotation/disable need a current code; secrets encrypted at rest (`core/security.py`)
- [x] Refresh tokens rotated and stored hashed; revoked on logout, password change, deactivation
- [~] Refresh token held in `sessionStorage` (HttpOnly cookie recommended)

## Authorization
- [x] Central default-deny permission check for every authenticated route (`core/deps.py`)
- [x] Row-level scope from one module (`core/scope.py`); out-of-scope → 404
- [x] Segregation of duties on exceptions and self-administration
- [x] Role × endpoint regression tests

## Input and output
- [x] Pydantic validation; enumerations for statuses, roles, asset types, environments
- [x] Upload limits (10 MB, CSV/JSON only), per-row isolation, no code execution on import
- [x] SQL only through SQLAlchemy parameterised queries; no string-built SQL with user input
- [x] CSV formula-injection neutralisation; HTML reports escape values; React escapes UI output
- [x] XML generated (GraphML) but never parsed from user input

## Data protection and secrets
- [x] Synthetic data only; no personal or customer data
- [x] Secrets from environment; `.env` ignored; weak `SECRET_KEY` rejected outside development
- [x] Webhooks verified with HMAC-SHA256 and constant-time comparison
- [x] AI sends only aggregates to the optional external model

## Logging, audit and errors
- [x] Structured JSON logs with request ids; no secrets or tokens logged
- [x] Hash-chained, append-only audit trail with verification endpoint
- [x] Generic error responses; details only in server logs

## Dependencies and pipeline
- [x] Pinned versions; `npm ci` with lockfile
- [x] bandit 0 issues, pip-audit 0 known vulnerabilities, npm audit 0 (`docs/evidence/`)
- [x] CI gates: ruff, black, mypy, pytest + 70% coverage, Vitest, ESLint, build, Playwright, pip-audit, npm audit, gitleaks, docker build (`.github/workflows/ci.yml`)
- [x] Containers run as non-root; Kubernetes restricted pod security and default-deny network policies

## Review
- [x] Peer-review checklist in `CONTRIBUTING.md`; every new endpoint must state its permission and audit behaviour

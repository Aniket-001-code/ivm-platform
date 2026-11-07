# High-Level Design

## Components

The React client is organized around dashboards, registers, details, and workflow pages. Typed fetch wrappers attach the access token in memory and report API errors in the UI. FastAPI routers validate request payloads and resolve the user through a JWT dependency. Services implement normalization, risk scoring, attack-path analysis, scheduling, and AI fallback behavior. SQLAlchemy models define persistence. Alembic migrations create and evolve the database. The seed loader inserts business units, services, users, assets, connections, a local CVE catalog, imports, score history, and remediation tasks into an empty database.

## Data flow

Raw import rows are retained in `raw_findings`. Normalized findings point to an asset and optionally a catalog CVE. A fingerprint based on asset UUID and CVE (or title when no CVE exists) merges duplicates. `finding_sources` retains each source record. The risk engine combines CVSS, asset criticality, exposure, and threat-intelligence values. Attack-path recalculation discovers directed routes from exposed assets to crown jewels and adds a path signal. High/critical findings receive tasks. Scheduled jobs inspect tasks and approved exceptions.

## Availability and failure behavior

PostgreSQL health checks gate API startup. A migration failure prevents the backend command from reaching Uvicorn. The AI fallback catches provider errors and returns a rule-based answer. API exceptions are structured and request IDs are returned in headers. Scheduled jobs run within the backend process, so multiple backend replicas would require leader election or an external job service before scaling.

## Security design

Passwords are bcrypt-hashed. JWT access tokens last 15 minutes and refresh tokens are one-use rotated via a stored SHA-256 token hash. Role dependencies deny unauthorized access. MFA TOTP secrets are Fernet-encrypted using a key derived from `SECRET_KEY`. API calls log security-sensitive events. Browser access tokens remain in memory; the demo currently returns the refresh token in the login JSON response, a prototype tradeoff. Production should place refresh tokens only in Secure, HttpOnly, SameSite cookies and enforce HTTPS.

## Scale and performance

Indexes support common filters. Dashboard queries aggregate in SQL. The seed target is about 2,500 raw reports, 300 assets, and about 2,000 correlated findings. Current API response lists are capped to keep the demonstration responsive. The performance test plan measures the dashboard under this seeded volume; deployment hardware and caching should be tuned for real workloads.

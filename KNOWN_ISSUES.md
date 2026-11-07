# Remaining issues and verification gaps

- The requested domain-by-domain split of `backend/app/api/v1/router.py`, `backend/app/models/entities.py`, and `frontend/src/App.tsx` is not complete; these files remain monoliths.
- The frontend is not yet at full SPEC 9 depth. Dashboard APIs return role-specific payloads, but the UI still shares one dashboard layout. Table sorting/server pagination, API-backed asset/finding filters and CSVs, editable scoring/SLA/ownership forms, richer detail timelines, and some route guards remain incomplete.
- The offline AI still has a small intent set and does not return the required source table; optional Anthropic use is a bounded single-call summary, not tool-use mode. These endpoints were not fully validated for all role scopes.
- Backend has 42 tests and Playwright has five passing workflows. The 70% gate measures only `risk_engine.py` and `normalization.py` (100% for those modules), not whole-backend coverage. The requested broad role-by-endpoint negative matrix is not present.
- `docker compose config` and PostgreSQL/Compose startup could not run because Docker is not installed. Gitleaks is not installed in this environment. Bandit reports no issues (the disclosed synthetic password constant is explicitly marked), `pip-audit` reports no known vulnerable installed dependencies, and `npm audit` reports zero vulnerabilities.
- The existing database is not automatically reseeded when non-empty. README uses a fresh `ivm_spec_demo.sqlite` name for the expanded demo dataset; the old `ivm_demo.sqlite` is kept intact.
- SQLite local mode is verified. Production-grade business-unit policy, immutable external audit storage, and distributed scheduling remain beyond this prototype.

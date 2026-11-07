# Implementation assumptions

- Preserve the existing FastAPI/SQLAlchemy/React application and extend its established domain model instead of rebuilding it.
- Treat Section 8 routes as requiring both route presence and meaningful data-backed behavior; dynamic `{parameter}` paths are validated through OpenAPI plus representative calls.
- Keep SQLite as a local developer/test option and PostgreSQL 15 as the Compose target.
- Use the nine canonical roles from SPEC Section 7. Existing demo roles will be migrated in the seed map to these names; any old role aliases are accepted only at the authentication boundary during transition.
- Use SQLAlchemy ORM queries for analytics and preserve the current memory-only access token handling in the browser.
- Synthetic fixtures may be expanded deterministically; no real scanner, bank, or customer data is introduced.


- The verified final local run uses a separate SQLite file (`backend/ivm_spec_final.sqlite`) to preserve the pre-existing demo database. Its seed contains 3,532 open findings, 156 Critical, 434 High, 109 modeled attack paths, 26 weekly history points, six pending/four approved exceptions, and three escalations per level.
- Eight catalog rows receive deterministic synthetic KEV/weaponized threat metadata at seed time to make the demo score behavior visible; these are fictional fixture enrichments, not claims about the CVEs.

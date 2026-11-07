# Test Evidence Template

Copy one record per execution batch.

| Field | Value |
|---|---|
| Evidence ID | `EV-YYYYMMDD-NNN` |
| Build/commit | `<commit SHA>` |
| Environment | `<local / CI image / browser>` |
| Database | `PostgreSQL 15, seeded with generator seed 42` |
| Tester | `<name or team>` |
| Date/time UTC | `<timestamp>` |
| Scope and case IDs | `<TC IDs>` |
| Command/workflow | `<exact command>` |
| Expected outcome | `<expected>` |
| Actual outcome | `<actual>` |
| Result | `Pass / Fail / Blocked` |
| Report or screenshot path | `<synthetic-only artifact path>` |
| Defect references | `<DEF IDs or none>` |

Do not include a production credential, customer identifier, real host/IP, external scanner output, or an API key in evidence.

# Requirements Traceability Matrix

Use cases: UC-1 inventory; UC-2 import findings; UC-3 normalize/deduplicate; UC-4 enrich threat data; UC-5 score/explain risk; UC-6 inspect paths; UC-7 assign work; UC-8 update remediation; UC-9 escalate SLA; UC-10 request exception; UC-11 approve/reject exception; UC-12 review dashboards; UC-13 ask AI; UC-14 create simulated ticket.

| Use case | Modules / APIs | Screen | Verification |
|---|---|---|---|
| UC-1 Inventory assets | seed, `/assets`, `/assets/{id}` | Asset inventory/profile | TC-001–006 |
| UC-2 Import source records | ingestion, `/imports/{source}` | Data imports | TC-009–015 |
| UC-3 Normalize and deduplicate | normalization, `/findings` | Import summary/register | TC-016–022 |
| UC-4 Enrich threat data | catalog, `/threat-intel/{cve}` | Finding context | TC-026–027 |
| UC-5 Calculate explainable risk | risk engine, `/risk/*` | Finding detail/Admin | TC-023–030 |
| UC-6 Inspect attack route | attack_path, `/attack-paths*` | Attack paths | TC-031–033 |
| UC-7 Assign remediation | ownership/remediation, `/tasks` | Remediation | TC-034–035 |
| UC-8 Update remediation evidence | task update service, `PATCH /tasks/{id}` | Remediation | TC-036–038 |
| UC-9 Escalate SLA breach | scheduler, `/jobs/run`, `/escalations` | Admin/manager | TC-039–040 |
| UC-10 Request risk exception | exception API | Risk exceptions | TC-041, TC-045 |
| UC-11 Review exception | approve/reject/revoke APIs | Risk exceptions | TC-042–046 |
| UC-12 Review portfolio | dashboards API | Overview / auditor | TC-054–055 |
| UC-13 Ask risk assistant | AI intent/fallback, `/ai/ask` | AI assistant | TC-056–057 |
| UC-14 Create/transition ticket | ticket simulation APIs | Remediation | TC-058–059 |

| Criterion | Use case | Service/API | Screen | Test evidence |
|---|---|---|---|---|
| SC-1 all dataset assets | UC-1 | seed, `/assets` | Asset inventory/detail | TC-001–006 |
| SC-2 3+ source types | UC-2 | ingestion, `/imports/{source}` | Data imports | TC-009–012 |
| SC-3 automatic dedup | UC-3 | normalization, fingerprint | Import result / findings | TC-016–022 |
| SC-4 severity + business context | UC-5 | risk engine, `/risk/findings/{id}/explain` | Finding detail | TC-023–029 |
| SC-5 threat intel changes priority | UC-4/5 | vulnerability catalog, threat route | Finding detail | TC-026–027 |
| SC-6 owner accuracy >90% | UC-7 | seed owner assignment and asset fallback | Remediation | Evaluate generated ownership ground truth; see limitation |
| SC-7 detect/escalate SLA | UC-9 | APScheduler, `/jobs/run`, `/escalations` | Admin/manager dashboard | TC-035–040 |
| SC-8 exception E2E + audit | UC-10/11 | exception routes + audit | Risk exceptions, audit trail | TC-041–046 |
| SC-9 path changes priority | UC-6/5 | NetworkX, attack path recalculate | Attack paths/finding detail | TC-031–033 |
| SC-10 operational/executive dashboards | UC-12 | `/dashboards/{view}` | Overview, tasks, audit | TC-054 |
| SC-11 API + simulated ticketing | UC-14 | `/ticketing/{system}/issues` | Remediation workflow | TC-058–059 |
| SC-12 triage effort estimate | UC-12 | dashboard formula and six-minute assumption | Executive overview | TC-055 |

SC-6 is not certified by the current implementation: generated asset owners are assigned deterministically, but there is no separate holdout ground-truth evaluation/report yet. Treat the >90% target as unverified until that evaluation is added.


## Verification update (2026-11-03)

- `GET /api/v1/health`, analyst login, `/dashboards/analyst`, and `/attack-paths` were exercised against the final seeded SQLite run. It returned 3,532 open findings, 156 Critical, 434 High, 26 weekly history points, and 109 attack paths.
- Seed inspection confirmed six pending and four approved exceptions and three escalation records at each of levels 1, 2, and 3.
- `pytest` passes 42 tests. The CI-selected risk engine and normalization modules report 100% coverage. Frontend currently has one Vitest test.
- Detailed mapping and uncovered acceptance items are listed in `KNOWN_ISSUES.md`; this traceability document is not claiming every SPEC criterion is complete.

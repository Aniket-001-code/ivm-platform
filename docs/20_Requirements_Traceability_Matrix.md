# Requirements Traceability Matrix

Status: **Done** (implemented and verified), **Partial** (implemented with a stated limit), **Not verified** (built,
but the runtime was unavailable locally). Test names refer to `backend/tests`, `frontend/src/*.test.*` and
`e2e/workflows.spec.ts`; evidence files are in `docs/evidence/`.

## Use cases

| ID | Requirement | Implementation | Verification | Status |
|---|---|---|---|---|
| UC-1 | Asset registration | `POST/PATCH /assets`, bulk import, Assets page + editor | `test_asset_registration_validates_and_audits`, E2E "administrator registers an asset" | Done |
| UC-2 | Criticality assignment | Tier, crown jewel, customer-facing, sensitive data, regulatory tags, exposure, environment, BU/service, owner; rescoring on change | `test_criticality_change_rescores_findings_and_is_audited` | Done |
| UC-3 | Vulnerability import | Scanner, CSPM, pentest, container/K8s, identity, EASM, threat-intel feed | E2E import test; `test_seeded_smoke`; SC-2 | Done |
| UC-4 | Correlation | Fingerprint de-duplication, asset matching (host/FQDN/URL/IP), survivorship, reopen | `test_survivorship_…`, `test_closed_finding_is_reopened_…`; SC-3 | Done |
| UC-5 | Threat enrichment | Catalog EPSS/KEV/exploit/ransomware; feed import rescoring | `test_threat_feed_…`; SC-5 | Done |
| UC-6 | Risk scoring | 8-factor engine, bands, versioned weights, what-if, explanations | `test_risk_engine.py`; SC-4 | Done |
| UC-7 | Attack path analysis | networkx paths, path influence, impact report, graph export | `test_rescoring_preserves_attack_path_influence`, `test_attack_path_impact_…`; SC-9 | Done |
| UC-8 | Ownership assignment | Rules (BU/service/type/env/tag, user/group), fallbacks, audited, reassignment | `test_ownership_rules_…`, `test_reassignment_…`; SC-6 | Done |
| UC-9 | Remediation tracking | Status machine, evidence to close, finding sync, timeline, tickets | `test_closing_a_task_closes_its_finding`, E2E close task | Done |
| UC-10 | SLA monitoring | Policy-driven 3-level escalation, acknowledgement, inbox, breach forecast | `test_escalation_thresholds_follow_sla_policy`, `test_escalation_acknowledgement_…`; SC-7 | Done |
| UC-11 | Exception management | Temporary/long-term, SoD, revoke, expiry + warnings, review packs | E2E exception test, `test_exception_review_pack_…`; SC-8 | Done |
| UC-12 | Executive reporting | Role dashboards, heatmap, trend, MTTR, SLA, forecasts, board report HTML | `test_reports_endpoints_respond`, E2E executive tests | Done |
| UC-13 | AI recommendations | Remediation plan (effort-weighted), explanations, executive summary | `test_assistant_understands_entities_and_follow_ups` | Done |
| UC-14 | Natural language querying | Entity + intent NLQ, follow-ups, sources, optional Claude | Same + E2E assistant tests | Done (Claude path not verified: no key) |

## Business and technical objectives

| ID | Delivered by | Status |
|---|---|---|
| BO-1 visibility | Inventory, unified findings, dashboards | Done |
| BO-2 business/threat-aware prioritisation | Risk engine + threat intel + paths | Done |
| BO-3 remediation efficiency & ownership | Ownership routing, tasks, reassignment | Done |
| BO-4 SLA compliance | SLA policy, escalation, compliance KPI | Done |
| BO-5 executive reporting | Executive dashboard, board report, forecasts | Done |
| BO-6 less manual effort | De-duplication, auto-assignment, AI, automation-impact report (SC-12) | Done |
| BO-7 measurable indicators | SLA compliance, MTTR, overdue, BU trends, risk reduction | Done |
| TO-1..TO-10 | Map to UC-3; UC-1/2; UC-4; UC-6; UC-8/10; UC-11; API (104 ops); UC-12; UC-7; UC-13/14 | Done |

## Non-functional requirements

| Category | Evidence | Status |
|---|---|---|
| Performance (< 3 s) | `dashboard-latency.txt`; `load-benchmark.txt` p95 under 3 s at 25 concurrent users | Done |
| Scalability | Stateless API, paging, single-flight analytics cache, SQLite WAL / PostgreSQL pool, HPA manifests, separable scheduler; `load-benchmark.txt`: 600 requests from 25 concurrent users, 0 errors | Done |
| Availability & backup | `backup.sh`/`restore.sh` (SQLite, PostgreSQL), health probes | Done |
| Reliability | Failed rows kept and retryable; per-row savepoints | Done |
| Security | RBAC, scope, MFA, TLS, Fernet secrets, HttpOnly refresh cookie, secrets handling (`08`) | Done (production hardening items listed in `08`) |
| Privacy | Synthetic data only | Done |
| Maintainability | Modular services/routes/pages, config-driven scoring, 86% coverage | Done |
| Usability | Search, filters, sorting, paging, role views, notifications | Done |
| Auditability | Hash-chained append-only audit of imports, scoring, ownership, exceptions, approvals | Done |
| Explainability | Factor reasons, path base → final, AI sources | Done |
| Accessibility | Labels, keyboard focus, skip link, AA contrast, Escape-closable dialogs; axe-core WCAG 2 A/AA audit of 13 pages + login with 0 serious/critical violations (`e2e/accessibility.spec.ts`) | Done |

## Success criteria

| ID | Measured value (fresh seed) | Status |
|---|---|---|
| SC-1 | 300 of 300 dataset assets | Done |
| SC-2 | 5 import sources (+ EASM, threat intel) | Done |
| SC-3 | 714 duplicates merged (28.6%), 500 multi-source findings | Done |
| SC-4 | 2,588 of 3,454 open findings re-banded by context | Done |
| SC-5 | 444 findings would drop a band without threat signals | Done |
| SC-6 | 100% of 393 tasks match dataset owner (target 90%) | Done |
| SC-7 | All overdue tasks without an exception escalated | Done |
| SC-8 | All reviewed exceptions have audit evidence | Done |
| SC-9 | 300 findings raised a band; +9.67 average | Done |
| SC-10 | Four role dashboards + reports | Done |
| SC-11 | Jira/ServiceNow simulators + signed webhook | Done |
| SC-12 | ≈ 99 analyst hours saved (stated assumptions) | Done |

## Dashboard requirements (section 13)

Top risky assets ✔ · critical by business unit ✔ · internet-facing high-risk assets ✔ · overdue by owner and SLA
category ✔ · exceptions nearing expiry ✔ · attack paths to crown jewels ✔ · risk trend ✔ · risk reduction % ✔ · MTTR ✔
· executive heatmap by service ✔ — all in `frontend/src/pages/Dashboard.tsx` and the board report. **Done**

## Bonus items (section 17)

| Item | Implementation | Status |
|---|---|---|
| Predictive risk modelling | `services/forecasting.py` breach likelihood from closed-task history | Done |
| Advanced conversational assistant | Entities, follow-ups, sources | Done |
| Executive heatmaps & board summaries | Heatmap, `reports/executive?format=html` | Done |
| Cloud-native containers | Dockerfiles, Compose, `deploy/k8s` | Not verified (no Docker/cluster locally; CI builds images) |
| Simulated ServiceNow/JIRA | `routes/ticketing.py` + webhook | Done |
| Graph database for attack paths | Cypher/GraphML export for Neo4j (`/attack-paths/export`); in-process networkx | Partial (export, not a running graph DB) |
| Risk forecast from SLA breach likelihood | `/tasks/breach-forecast`, `/analytics/forecast` | Done |
| Remediation sequencing by effort and risk | `/reports/remediation-plan` | Done |
| Automated exception review packs | `/exceptions/{id}/review-pack` | Done |

## Mandatory practices (section 11) and deliverables (section 10)

| Item | Where | Status |
|---|---|---|
| Layered, modular, API-first | `backend/app/{api,services,models,core}`, OpenAPI | Done |
| Coding standards, static analysis | ruff, black, mypy, ESLint (evidence files) | Done |
| Source control, branching, PRs | Git history, `CONTRIBUTING.md`, `19_Project_Plan.md` | Done (PRs need a hosted remote) |
| Testing ≥ 70% + integration + E2E | 86%, 114 + 12 + 14 tests | Done |
| DevSecOps | bandit, pip-audit, npm audit, gitleaks, CI | Done (gitleaks CI-only) |
| Documentation | `docs/01`–`20`, diagrams | Done |
| Agile project management | `19_Project_Plan.md` | Done |
| Operational readiness | JSON logging, error envelope, audit, config, backup/restore | Done |
| Design deliverables | `01`–`06` | Done |
| Security deliverables | `07`–`09`, evidence scans, RBAC | Done |
| Testing deliverables | `10`–`13`, `docs/evidence/` | Done |
| Final report, user manual, admin guide | `16`, `14`, `15` | Done |
| Demonstration video | `docs/demo/ivm-demo.webm` | Done |
| Final presentation | `docs/presentation/IVM_Final_Presentation.pptx`, `18` | Done |

# Business Requirements Document (BRD)

Intelligent Vulnerability Management and Risk Prioritisation Platform (IVM)

| Item | Value |
|---|---|
| Document status | Capstone deliverable, aligned with the delivered code on 2026-11-07 |
| Data classification | Synthetic data only. No real bank, customer or employee data is used anywhere |
| Readiness | Academic prototype. It is not production-ready and has not been deployed to a live environment |
| Related documents | `02_Solution_Architecture.md`, `03_HLD.md`, `20_Requirements_Traceability_Matrix.md`, `docs/evidence/` |

## 1. Business problem

A bank's technology estate produces security findings from many tools: infrastructure scanners, cloud security posture management (CSPM), container and Kubernetes scanners, penetration tests, identity reviews and external attack-surface monitoring. Each tool uses its own field names, severity scale and asset identifiers. The result is:

- **Fragmented visibility.** No single view of which assets carry which findings, or who owns them.
- **Duplicate work.** The same weakness on the same host is reported by several tools and triaged several times.
- **Severity is not risk.** Scanner severity (CVSS) ignores whether the asset is internet-facing, holds sensitive or regulated data, is a crown-jewel system, sits on an attack route, or is affected by a vulnerability that is being actively exploited.
- **Ownership gaps.** Findings are not reliably routed to an accountable owner, so remediation stalls.
- **Weak SLA control.** Overdue work is not escalated consistently, and risk acceptances are granted informally, without expiry or audit evidence.
- **Slow reporting.** Executives and auditors receive manually compiled, point-in-time reports.

## 2. Vision

One business-aware platform that consolidates findings, prioritises them by true contextual risk, routes each one to an accountable owner, tracks remediation against SLAs, governs risk exceptions with segregation of duties, and gives every role (analyst to CISO and auditor) an explainable, evidence-backed view. Automation and an assistant that answers questions reduce manual triage, and every decision is auditable.

## 3. Business objectives (BO) and delivered capability

| ID | Objective | Delivered capability | Primary implementation |
|---|---|---|---|
| BO-1 | Centralised visibility of assets and vulnerabilities | Asset inventory with business context (300 synthetic assets) and a consolidated, filterable findings register with source provenance | `backend/app/api/v1/routes/assets.py`, `routes/findings.py`, `frontend/src/pages/Assets.tsx`, `Findings.tsx` |
| BO-2 | Business- and threat-aware prioritisation | Eight-factor contextual risk score (0-100) with per-factor points and reasons; threat-intelligence enrichment (EPSS, KEV, active exploitation, ransomware use, exploit maturity); attack-path influence | `backend/app/services/risk_engine.py`, `services/scoring.py`, `services/attack_path.py` |
| BO-3 | Remediation efficiency and clear ownership | Automatic task creation for high and critical findings, rule-based owner routing with group support and a fallback chain, audited assignment, task drawer with history and evidence | `services/remediation.py`, `services/ownership.py`, `routes/tasks.py`, `pages/Tasks.tsx` |
| BO-4 | SLA compliance | Policy-driven SLA due dates per risk band, scheduled three-level escalation, SLA-breach likelihood forecast | `services/sla.py`, `jobs/scheduler.py`, `services/forecasting.py` |
| BO-5 | Executive reporting and trends | Role dashboards (executive, analyst, manager, auditor), risk trend, heatmap by business service, MTTR, SLA compliance, risk reduction, downloadable executive report (JSON/HTML) | `services/analytics.py`, `services/reports.py`, `routes/dashboards.py`, `routes/reports.py` |
| BO-6 | Less manual triage through automation and AI | Duplicate correlation with survivorship, automatic ownership, automatic escalation, offline assistant with 15 intents and optional Claude rephrasing, automation-impact report | `services/ingestion.py`, `services/ai_assistant.py`, `reports.automation_impact` |
| BO-7 | Measurable indicators | Success-criteria scorecard SC-1 to SC-12 computed from live data; SLA compliance, MTTR, overdue risk and business-unit risk trends | `services/reports.py` (`success_criteria`), `GET /api/v1/reports/success-criteria` |

## 4. Technical objectives (TO) and delivered capability

| ID | Objective | Delivered capability | Primary implementation |
|---|---|---|---|
| TO-1 | Multi-source ingestion | Six source types: `scanner`, `cspm`, `pentest`, `container` (including Kubernetes misconfiguration), `identity`, `easm`; CSV and JSON up to 10 MB; separate threat-intelligence import | `services/ingestion.py` (`SOURCE_TYPES`), `routes/imports.py`, `routes/system.py` (`/threat-intel/import`) |
| TO-2 | Asset inventory with ownership metadata | Asset type, environment, business unit, business service, owner, criticality tier 1-5, crown jewel, customer-facing, sensitive data, regulatory tags, internet exposure; asset connections for the graph | `backend/app/models/inventory.py`, `routes/assets.py` |
| TO-3 | Normalise, correlate and de-duplicate | Common schema, severity aliasing, asset-key matching (hostname, FQDN, URL, IP), SHA-256 fingerprint of asset + CVE (or title), survivorship, re-detection reopens closed findings, raw rows retained | `services/normalization.py`, `services/ingestion.py` |
| TO-4 | Configurable risk engine | Eight factors with configurable maximum points (must total 100) and band thresholds; versioned `ScoringConfig`; every change audited and triggers a full rescore | `services/risk_engine.py`, `services/scoring.py`, `routes/config.py` |
| TO-5 | Ownership mapping, task assignment, SLA tracking | Ordered ownership rules (business unit, business service, asset type, environment, tag), groups, owner and business-unit-manager fallback; SLA policy per band | `services/ownership.py`, `services/remediation.py`, `services/sla.py` |
| TO-6 | Exception workflows | Temporary (up to 90 days) and long-term (up to 365 days) exceptions, approval rules by role, self-approval blocked, automatic expiry with 14- and 7-day warnings, revoke, review pack, CSV export | `routes/exceptions.py`, `services/exceptions.py` |
| TO-7 | Integration APIs | Versioned REST API (`/api/v1`, 104 operations, OpenAPI in `docs/evidence/openapi.json`); simulated Jira and ServiceNow; HMAC-SHA256 signed inbound webhook | `routes/*.py`, `routes/ticketing.py` |
| TO-8 | Dashboards for analysts, managers, auditors, executives | `GET /dashboards/{executive,analyst,manager,auditor}` plus heatmap, trend, MTTR, SLA compliance; navigation driven by permissions | `routes/dashboards.py`, `frontend/src/pages/Dashboard.tsx`, `frontend/src/access.ts` |
| TO-9 | Attack-path modelling | NetworkX directed graph from asset connections; simple paths (up to 5 hops, at most 3 kept per entry/target pair) from internet-exposed assets to crown-jewel or sensitive-data assets; base and final score shown per finding | `services/attack_path.py`, `routes/attack_paths.py`, `pages/AttackPaths.tsx` |
| TO-10 | AI / GenAI | Offline, data-scoped assistant: entity extraction, 15 intents, follow-up questions, source table per answer; explanations, recommendations, executive summary; optional Claude rephrasing from aggregate context | `services/ai_assistant.py`, `routes/ai.py`, `pages/Assistant.tsx` |

## 5. Stakeholders and actors

The platform implements all nine actors from the capstone specification as roles in `backend/app/core/rbac.py` (9 roles, 28 permissions, default deny). Row-level visibility is defined once in `backend/app/core/scope.py`.

| Actor | System role | Needs | Data visibility |
|---|---|---|---|
| Security Analyst | `security_analyst` | Import findings, triage, review risk explanations, request exceptions, raise tickets, use the assistant | Whole portfolio |
| Vulnerability Manager | `vulnerability_manager` | Manage tasks and assignment, run the SLA/expiry jobs, approve temporary exceptions, tune risk, view escalations | Whole portfolio |
| IT Asset Owner | `it_asset_owner` | See and update tasks assigned to them, request exceptions, raise tickets | Assets they own or in their business unit |
| System Administrator | `system_administrator` | Work on assigned remediation tasks and record evidence | Assets on tasks assigned to them |
| Security Architect | `security_architect` | Review attack paths, run what-if scoring, approve temporary and long-term exceptions | Assets they own or in their business unit |
| Business Unit Manager | `business_unit_manager` | Business-unit risk, overdue work and escalations | Their business unit |
| Executive / CISO | `executive_ciso` | Portfolio posture, trends, heatmap, success criteria, board report | Whole portfolio (read-only) |
| Platform Administrator | `platform_admin` | Users and roles, scoring, SLA and ownership configuration, asset administration | Whole portfolio; cannot approve exceptions |
| Auditor | `auditor` | Exception evidence, audit trail and its integrity check, reports | Whole portfolio (read-only) |

## 6. Scope

### 6.1 In scope (delivered)

| Area | Delivered |
|---|---|
| Asset management and criticality intelligence | Registration and reclassification of assets with customer-facing, crown-jewel, sensitive-data, regulatory, internet-exposure, environment and business-service attributes |
| Ingestion | Scanner, CSPM, pentest, container/Kubernetes, identity and EASM findings; threat-intelligence feed |
| Normalisation and correlation | Common schema, duplicate detection, asset linking, source consolidation (`finding_sources`), survivorship |
| Risk prioritisation | Eight-factor explainable score, configurable weights and thresholds, what-if analysis |
| Attack path graph | Entry-to-crown-jewel paths, path score, influence on finding scores, graph view, and export as Cypher (Neo4j) or GraphML |
| Remediation management | Ownership, tasks, status, SLA, escalation, ageing, ticket links, evidence on closure |
| Exception management | Risk acceptance (temporary and long-term), approval, expiry, revocation, audit evidence, review pack |
| Reporting | Executive and operational dashboards, trends, SLA compliance, MTTR, overdue, business-unit view, heatmap, executive report |
| AI assistant | Natural-language questions, recommendations, explanations, executive summary, remediation guidance |
| Integration | REST APIs with OpenAPI, simulated Jira and ServiceNow, signed webhook |
| Bonus items (specification section 17) | SLA-breach likelihood and risk-trend forecast (`services/forecasting.py`), remediation sequencing (`reports.remediation_plan`), exception review packs, executive heatmap and board report, container and Kubernetes manifests, follow-up-aware assistant |

### 6.2 Out of scope

- Real scanners or any active scanning. The generator and importer contact no network target.
- Patch deployment, endpoint management, production SOC or incident-response automation.
- Commercial integrations and live Jira/ServiceNow instances (only simulators are provided).
- Live bank systems, real or confidential data, production credentials.
- Running a graph database. Attack paths are computed in memory with NetworkX and stored as rows; the graph can be exported as Cypher or GraphML for an external graph database.

## 7. Business rules

### 7.1 Contextual risk score

`backend/app/services/risk_engine.py` computes eight factors. Each factor's raw points are scaled to its configured maximum, the total is clamped to 0-100, and each factor returns a plain-language reason.

| Factor | Default maximum | Rule (at default maximum) |
|---|---|---|
| CVSS technical severity | 25 | CVSS (0-10) / 10 x 25 |
| Asset criticality | 15 | Tier 1 = 15, 2 = 12, 3 = 8, 4 = 4, 5 = 2; +3 crown jewel, +2 customer-facing; capped at 15 |
| Internet exposure | 10 | 10 if the asset is internet-exposed, otherwise 0 |
| Exploitability | 10 | Higher of exploit maturity (none 0, PoC 4, functional 7, weaponised 10) and EPSS x 10 |
| Threat intelligence | 15 | KEV 8 + actively exploited 4 + ransomware use 3; capped at 15 |
| Data sensitivity | 10 | 10 if the asset holds sensitive data |
| Regulatory impact | 5 | 5 for PCI-DSS or SOX tags; 3 for any other regulatory tag |
| Attack-path influence | 10 | Path influence (0-1) x 10, where influence = strongest path score / 100 for any modelled path that contains the finding |

Risk bands (configurable): critical >= 80, high >= 60, medium >= 40, otherwise low. Administrators change maximum points through `PUT /api/v1/config/scoring`. The eight values must be non-negative and total 100. Each change creates a new `ScoringConfig` version, rescores every finding through `services/scoring.py` (`rescore_findings`), records score history and is audited.

### 7.2 SLA and escalation policy

Seeded in `backend/app/db/seed.py` and editable through `PUT /api/v1/config/sla` (audited).

| Band | SLA (days) | Level 1 (days overdue) | Level 2 (days overdue) | Level 3 (derived) |
|---|---|---|---|---|
| Critical | 7 | 0 | 7 | 14 |
| High | 15 | 0 | 7 | 14 |
| Medium | 30 | 15 | 30 | 45 |
| Low | 90 | 45 | 90 | 135 |

- Tasks are created automatically for open findings in the high or critical band. The due date is the creation date plus the band's SLA days.
- Level 3 = level 2 + max(7, level 2 - level 1) (`services/sla.py`).
- Recipients: level 1 goes to the owner's business-unit head or manager, level 2 to the asset's business-unit manager, level 3 to the Executive/CISO.
- A task covered by an approved, unexpired exception is not escalated. Each level is raised once per task and audited (`sla_escalated`).
- The scheduler runs the SLA check every 15 minutes and exception expiry every hour. A Vulnerability Manager or Platform Administrator can also run both jobs on demand (`POST /api/v1/jobs/run`).

### 7.3 Exception limits and segregation of duties

| Rule | Implementation |
|---|---|
| Temporary exception expiry must fall within 90 days; long-term within 365 days | `routes/exceptions.py` (`request_exception`), HTTP 422 otherwise |
| The requester can never review their own exception | HTTP 403 "Self-approval is forbidden" |
| Only Vulnerability Managers and Security Architects review exceptions | Role check in `review_exception` |
| Vulnerability Managers may approve temporary exceptions only; long-term exceptions require a Security Architect | Role check in `review_exception` |
| Only pending exceptions can be reviewed; only approved exceptions can be revoked | HTTP 409 otherwise |
| Platform Administrators hold no exception-approval permission | `ROLE_PERMISSIONS` in `core/rbac.py` |
| Approval sets the finding to `risk_accepted`; expiry or revocation reopens it and its task, with a fresh SLA due date on expiry | `services/exceptions.py` |
| Warnings are audited 14 and 7 days before expiry | `expire_exceptions` |
| Every request, decision, revocation and expiry is audited | `exception_*` audit actions |

### 7.4 Ownership routing

1. The first matching ownership rule by `priority_order`. Rules match on business unit or business service (by name or id), asset type, environment or regulatory tag, and assign a user, a group, or both.
2. Otherwise the asset's recorded owner.
3. Otherwise the active Business Unit Manager of the asset's unit.

Each assignment is audited (`ownership_assigned`) with the reason, for example `rule:environment=prod` or `asset_owner`.

### 7.5 Correlation and survivorship

When an imported row matches an existing finding (same asset and CVE, or same asset and title when there is no CVE): the highest severity and CVSS survive, the most specific description wins, a missing CVE link is filled in, sources are combined and `last_seen` is refreshed. A closed finding that is reported again is reopened together with its task. Rows that fail validation are kept as `RawFinding` records with an error message and can be retried.

## 8. Success criteria and measured results

Measured on a fresh seeded database (seed 42) on 2026-11-07. Source: `docs/evidence/success-criteria.json`, produced by `GET /api/v1/reports/success-criteria`. All twelve criteria pass.

| ID | Criterion | Measured value |
|---|---|---|
| SC-1 | All dataset assets managed | 300 of 300 assets |
| SC-2 | At least three simulated sources ingested | 5 sources seeded (scanner, CSPM, pentest, container, identity); EASM also supported |
| SC-3 | Duplicates identified and correlated | 714 duplicate rows merged (28.6%); 500 findings corroborated by more than one source |
| SC-4 | Scoring uses business context | 2,588 of 3,454 open findings have a band different from scanner severity |
| SC-5 | Threat intelligence changes priority | 901 findings carry threat points; 444 would drop a band without KEV or exploitation signals |
| SC-6 | Ownership accuracy above 90% | 100% of 393 tasks match the dataset owner (`owner_email` ground truth); routing engine 100% |
| SC-7 | SLA breaches identified and escalated | All overdue tasks without an approved exception are escalated |
| SC-8 | Exception workflow end to end with audit evidence | All reviewed or expired exceptions have audit records |
| SC-9 | Attack paths change priority | 555 findings on modelled paths; 300 raised a band; +9.67 points on average |
| SC-10 | Operational and executive dashboards | Four role dashboards plus heatmap, trend, MTTR, SLA, forecast and executive report |
| SC-11 | Ticketing integration APIs | Jira and ServiceNow simulators and an HMAC-signed webhook |
| SC-12 | Measurable reduction in manual effort | About 99 analyst hours saved under the stated assumptions (section 9) |

Other measured indicators (demo seed): MTTR about 4.4 days for critical and 8.5 days for high findings; SLA compliance about 96%; risk reduction about 6.6% over six months.

Non-functional acceptance measures:

| Requirement | Target | Measured |
|---|---|---|
| Dashboard response | < 3 s | Mean 0.500 s, p95 0.514 s over 10 samples (`docs/evidence/dashboard-latency.txt`) |
| Unit test coverage | >= 70% | 85% whole-backend coverage, 114 pytest tests; 12 Vitest tests |
| End-to-end workflows | Key journeys automated | 14 Playwright workflows pass (`e2e/workflows.spec.ts`) |
| Dependency and static security scans | No known issues | bandit 0 issues, pip-audit and npm audit 0 known vulnerabilities |

## 9. Assumptions

- All data is synthetic and generated by `backend/scripts/generate_synthetic_data.py` with fixed seed 42. Regenerated files are content-identical.
- The synthetic demo accounts share the password `DemoPass!234`. It is for the demo only and must never be reused.
- SC-12 effort savings use these assumptions (`services/reports.py`): 6 minutes per duplicate row, 4 minutes per manual assignment, 10 minutes per escalation chase, 240 minutes per manually compiled report, 5 minutes per manual data lookup.
- The offline assistant is the default. Claude is used only when `ANTHROPIC_API_KEY` is set, and receives only the question and the aggregate synthetic context.
- The business-unit scoping policy in `core/scope.py` is a proposed policy that needs stakeholder sign-off.
- The latency figure was measured on a developer machine with the seeded volume. It is an acceptance check, not a guarantee for other hardware.

## 10. Constraints

- Docker was not installed on the development machine. The PostgreSQL and container runtime paths are verified only by CI jobs (docker build, compose config). Local development and tests use SQLite.
- The Kubernetes manifests in `deploy/k8s` have been parsed as YAML but never applied to a cluster.
- The optional Claude path has not been exercised because no API key was available. Gitleaks runs only in CI.
- Known security limits that are accepted for the prototype: rate limits are held per process and keyed on client IP; an access token stays valid for up to 15 minutes after logout; a database superuser could still drop the audit-immutability triggers.
- Capstone timebox: a single team, with the delivery practices described in `CONTRIBUTING.md` and the test documents.

# Final Report — Intelligent Vulnerability Management & Risk Prioritization Platform

## Abstract

Large organisations receive vulnerability and exposure findings from many tools, with heavy duplication, little
business context and unclear ownership. This project delivers a working platform that consolidates findings from six
simulated sources, prioritises them with an explainable eight-factor risk model that includes threat intelligence and
attack-path context, routes each fix to an accountable owner with an SLA, governs risk acceptance, and gives each of
nine roles its own view, from analyst to CISO. On the deterministic synthetic dataset every one of the twelve success
criteria is met and measured from live data. The codebase has 140 automated tests (86% backend coverage), zero known
vulnerable dependencies and a dashboard p95 latency of 0.51 seconds.

## 1. Problem and business alignment

Banks operate thousands of applications, cloud resources, containers and identities. Scanners, cloud posture tools,
penetration tests, external attack-surface monitoring and identity reviews each report issues in their own format.
In the supplied dataset 2,500 raw rows produce 714 duplicates (28.6%), and severity alone misplaces most findings:
2,588 of 3,454 open findings belong in a different risk band once business and threat context are applied.
The platform addresses the business objectives BO-1 to BO-7: enterprise visibility, business- and threat-aware
prioritisation, accountable remediation, SLA compliance, executive reporting, reduced manual effort and measurable
risk-reduction indicators (`01_BRD.md`).

## 2. Requirements

The scope follows the capstone use-case document: fourteen use cases (asset registration through natural-language
querying), nine actors, the suggested risk formula, eleven non-functional categories and twelve success criteria.
Every item is traced to code and evidence in `20_Requirements_Traceability_Matrix.md`. Out of scope, as required:
real scanners, patching, live bank systems and real data.

## 3. Architecture and design

The system is layered and API-first (`02_Solution_Architecture.md`, `03_HLD.md`). A React and TypeScript single-page
application talks to a FastAPI service exposing 104 REST operations documented by OpenAPI (`06_API_Specification.md`).
Business logic lives in focused services: ingestion, normalisation, scoring, attack paths, ownership, SLA, exceptions,
analytics, forecasting, reporting, AI and audit. SQLAlchemy models sit on PostgreSQL 15 in containers and on SQLite in
development, with Alembic migrations (`05_Data_Model.md`). Two architecture decisions shaped the quality of the result:

- **One scoring path.** Every score — at import, after a weights change, an asset edit or a threat-feed update — is
  produced by `services/scoring.py`, which always applies full threat intelligence and the current attack-path
  influence. An earlier design rescored without path context and silently erased it (DEF-019).
- **One visibility rule set.** `core/scope.py` decides which assets a user may see. API routes, dashboards, reports
  and the AI assistant all use it, so a user never sees different numbers on different screens (DEF-002).

Deployment options are a one-command developer script, Docker Compose with an optional TLS proxy, and Kubernetes
reference manifests with autoscaled API replicas, a single scheduler pod, TLS ingress and default-deny network
policies.

## 4. Implementation highlights

**Ingestion and correlation.** Six parsers (scanner CSV, CSPM, pentest, container/Kubernetes, identity CSV and EASM
JSON) normalise rows into a common schema and match them to assets by hostname, FQDN, URL or IP. A fingerprint of
asset and CVE (or title) identifies duplicates. Survivorship keeps the highest severity and CVSS, the most specific
description and the CVE link, unions sources, and reopens findings that reappear after closure. Each row is processed
in its own savepoint; rows that fail validation are kept with their error and can be retried once the cause is fixed,
satisfying the "no record loss" reliability requirement.

**Risk engine.** The score is the sum of eight factors with configurable maximum points (CVSS 25, asset criticality
15, threat intelligence 15, internet exposure 10, exploitability 10, data sensitivity 10, attack-path influence 10,
regulatory impact 5). Bands are critical ≥ 80, high ≥ 60 and medium ≥ 40. Each factor records its points and a reason,
which the finding page shows. Weights are versioned, and a what-if preview re-ranks findings before a change is saved.
Threat intelligence is decisive: removing KEV and exploitation signals would lower the band of 444 findings.

**Attack paths.** A directed graph of asset connections is searched for simple paths of up to five hops from
internet-exposed assets to crown-jewel or sensitive-data targets. Path risk feeds back into each finding on the route.
On the dataset 555 findings sit on modelled paths, 300 move up a band and scores rise by 9.67 points on average. The
graph can be exported as Cypher for Neo4j or as GraphML.

**Remediation workflow.** Critical and high findings create tasks with SLA dates from the configured policy. Ownership
rules match business unit or service (by name or id), asset type, environment or regulatory tag and can assign a user
and a group; otherwise the asset owner, then the business-unit manager, is assigned. Every assignment is audited.
Ownership accuracy against the dataset's recorded owners is 100% (target 90%). Tasks follow a state machine; closing
requires evidence and closes the finding. Overdue work escalates in three levels with thresholds from the SLA policy;
recipients acknowledge from a notification inbox. Tickets can be raised in simulated Jira or ServiceNow, and an
HMAC-signed webhook lets external systems update them.

**Exceptions.** Temporary (up to 90 days) and long-term (up to 365 days) risk acceptance with justification and
compensating controls. Requesters can never approve their own requests, and long-term exceptions require a security
architect. Warnings are raised at 14 and 7 days, expiry reopens the finding and its SLA, and a one-click review pack
gives approvers and auditors the full evidence with a checklist.

**Analytics, forecasting and reporting.** Four role dashboards cover every section-13 requirement: top risky assets,
critical findings by business unit, internet-facing high-risk assets, overdue work by owner and SLA category,
exceptions nearing expiry, paths to crown jewels, risk trend, risk reduction, MTTR and a heatmap by business service.
A transparent model learns typical time-to-close per band and each owner's on-time rate from closed tasks to predict
SLA breaches, and a least-squares fit projects the risk trend four weeks ahead. A remediation plan groups findings into
campaigns and orders them by risk removed per hour of effort (the first five campaigns remove 44–48% of open
high/critical risk, depending on data state). A printable board report summarises it all.

**AI assistant.** Questions are parsed for CVE ids, business units, asset names and risk bands, mapped to one of
fifteen intents (priorities, SLA status, MTTR and compliance, trend, remediation plan, CVE lookup, ownership, exceptions,
attack paths, threat exposure, business-unit breakdown and others) and answered from role-scoped queries. Follow-ups
such as "what about Retail Banking?" reuse earlier context. Each answer lists its source tables and row counts and is
logged. If an Anthropic API key is configured, Claude may rephrase the answer from the same aggregates only.

## 5. Security engineering

Security is designed in (`07_Threat_Model.md`, `08_Secure_Design_Review.md`, `09_Secure_Coding_Checklist.md`):
central default-deny authorisation across 9 roles and 28 permissions; row-level scope; bcrypt with lockout and rate
limiting; rotating refresh tokens; TOTP MFA for any user who enables it and mandatory for privileged roles when
configured, with secrets encrypted at rest; strict validation; CSV formula-injection protection; signed webhooks; CSP
and security headers; secrets only from the environment, with weak keys refused outside development; non-root
containers. The audit trail is hash-chained with SHA-256, protected by database triggers that reject updates and
deletes, and verifiable from the UI. Static analysis (bandit) reports no issues, and pip-audit and npm audit report no
known vulnerabilities.

## 6. Testing and quality

The strategy is in `10_Test_Plan.md` and the catalogue in `11_Test_Cases.md`. Results (`12_Test_Evidence.md`):
114 backend tests (unit, integration, role-by-endpoint matrix, seeded smoke) with 86% line coverage against a 70% gate;
12 frontend tests; 14 Playwright end-to-end workflows covering every role; ruff, black, mypy and ESLint clean; dashboard
p95 latency of 0.51 seconds against a 3-second target. Thirty-four defects were found and closed during hardening
(`13_Defect_Summary.md`), fifteen of them high severity, including scope leaks through AI endpoints, an incomplete MFA
flow, lost attack-path context on re-scoring, IP-address mis-matching and import rows being discarded.

## 6a. Performance, scalability and accessibility

**Performance.** A single dashboard request computes its aggregates in about half a second on a cold cache. The
non-functional target is under three seconds, so the single-user case had ample headroom. Concurrency was a different
story. The first load test (25 concurrent users, 600 mixed requests) exposed two real problems:

1. SQLite's default journal mode let readers block writers, so concurrent sign-ins and audit writes failed with
   "database is locked".
2. Every dashboard request recomputed the six-month trend from about 93,000 score-history rows. Concurrent requests
   competed for the Python interpreter, and some waited more than two minutes.

The fixes were proportionate:

- SQLite runs in write-ahead-log mode with a busy timeout, and PostgreSQL uses a sized connection pool.
- Dashboard aggregates are cached per user scope for 30 seconds with single-flight semantics: one request computes,
  and concurrent requests for the same scope wait for that result instead of repeating the work.
- Because every state change in the platform is audited, the audit writer is the single place that invalidates the
  cache. Dashboards therefore never show a change later than the action that caused it.

After the fixes the same test completes with zero errors, about 65 requests per second and a p95 latency of
1.5 seconds on one process (`docs/evidence/load-benchmark.txt`). The Kubernetes manifests scale this horizontally:
the API is stateless, and scheduling runs in a dedicated single pod.

**Accessibility.** The NFR asks for "basic accessibility considerations for UI contrast, labels, and keyboard
navigation". Rather than assert this, the end-to-end suite runs the axe-core engine against the login page and all
thirteen application pages for WCAG 2 A and AA rules. The first run found hundreds of contrast failures. The root
cause was a stylesheet ordering bug that silently discarded the earlier contrast fixes, plus a heatmap that placed
white text on light colours. After the fixes the audit reports no serious or critical violations, and it now runs
on every CI build. Every form control is labelled, dialogs close with Escape, a skip link leads to the main content,
and keyboard focus is always visible.

**Session security.** The refresh token moved from browser storage to an HttpOnly, SameSite=Strict cookie scoped
to the authentication endpoints. The test written for that change exposed a subtle replay weakness: two tokens issued
in the same second were byte-identical, so a rotated-out token could be reused. Every token now carries a unique
identifier, which closes it.

## 6b. Completion verification

`scripts/verify_completion.py` turns the capstone specification into 98 mechanically checked items: use cases,
in-scope capabilities, dashboard requirements, non-functional requirements, success criteria, engineering practices,
deliverables and bonus opportunities. It checks the repository, the OpenAPI contract, the tests and the evidence
files. It writes `21_Completion_Checklist.md` and fails if any item is not met. At submission all 98 items pass.

## 7. Results against the success criteria

| ID | Result |
|---|---|
| SC-1 | 300 of 300 assets tracked |
| SC-2 | Five import sources, plus EASM and threat intelligence |
| SC-3 | 714 duplicate rows merged; 500 findings corroborated by more than one tool |
| SC-4 | 2,588 open findings re-banded by business and threat context |
| SC-5 | 444 findings depend on threat signals for their band |
| SC-6 | 100% ownership accuracy (target > 90%) |
| SC-7 | Every overdue task without an approved exception escalated |
| SC-8 | Exception workflow end to end with audit records for every decision |
| SC-9 | 300 findings raised a band by attack-path context |
| SC-10 | Executive, analyst, manager and auditor dashboards plus reports |
| SC-11 | Jira/ServiceNow simulators and a signed webhook |
| SC-12 | About 99 analyst hours saved under stated, conservative assumptions |

These figures are computed by `services/reports.py` and shown live on the Reports page, so assessors can check them.

## 8. Evaluation against the rubric

- **Problem understanding:** grounded in measured duplication and mis-prioritisation in the dataset.
- **Architecture:** layered, modular, API-first, with single sources of truth for scoring and scope, and three
  deployment options.
- **Implementation:** all fourteen use cases are working end to end in the UI and the API.
- **Risk engine:** all eight factors, explainable, configurable, with a what-if preview and measured impact.
- **Attack paths:** graph model with measurable influence on priority, plus graph-database export.
- **UX:** role-specific dashboards, server-side search, filtering, sorting and paging, notifications and accessibility
  basics.
- **Security:** layered controls, a tamper-evident audit trail, role-matrix tests and clean scans.
- **Testing:** 140 automated tests at three levels, reproducible evidence and a defect log.
- **Documentation:** the full deliverable set, with reference documents generated from code.
- **AI and innovation:** a grounded conversational assistant, predictive breach model, remediation sequencing and
  review packs.
- **Demonstration:** a scripted demo and a recorded video.

## 9. Limitations and future work

- Access tokens stay valid for up to 15 minutes after logout; token versioning would make revocation immediate.
- Audit immutability is enforced in the database. Production needs external write-once storage and restricted database roles.
- Rate limits are kept per process. A shared store is needed once there are several replicas.
- Docker, PostgreSQL and Kubernetes were not run locally (no Docker on the development machine); CI builds the images.
- The business-unit visibility policy needs stakeholder approval.
- Future work: SSO with MFA at the identity provider; learning factor weights from remediation outcomes; real
  connectors behind the same ingestion interface; load testing at enterprise scale.

## 10. Conclusion

The platform turns noisy, duplicated findings into a short, explainable, owned and governed list of actions. Every
requirement in the capstone specification is implemented or explicitly qualified. The claims in this report can be
reproduced from the repository with one script (`scripts/collect_evidence.sh`).

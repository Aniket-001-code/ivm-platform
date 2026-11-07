# Business Requirements Document

## Business problem

Banking technology teams receive vulnerability and configuration findings from separate tools. Tool-specific names, duplicates, technical severity, ownership gaps, and disconnected SLA workflows make it difficult to decide which issue presents the greatest business risk. This demo models a central work queue using fictional data only.

## Objectives

- **BO-1:** Maintain a business-aware inventory of technology assets.
- **BO-2:** Normalize and correlate findings from multiple simulated sources.
- **BO-3:** Explain risk priority using technical, threat, exposure, and business factors.
- **BO-4:** Make attack routes to crown-jewel assets visible.
- **BO-5:** Route remediation actions to owners and track due dates and escalation.
- **BO-6:** Govern risk acceptance with independent review and audit evidence.
- **BO-7:** Provide role-appropriate dashboards and plain-English explanations.

## Stakeholders

Security analysts operate imports and triage; remediation owners update work; managers monitor SLA and escalations; approvers and security architects review exceptions; auditors inspect evidence; executives review portfolio posture; platform administrators maintain accounts and configuration.

## Scope and boundaries

Included: synthetic assets, CVE catalog metadata, simulated scanner/CSPM/pentest/container/identity exports, normalization, deduplication, threat enrichment, risk scoring, NetworkX attack paths, task/SLA/exception workflows, dashboards, REST APIs, simulated ticket records, audit history, offline AI answers, and documentation.

Excluded: real scanning, real bank/customer data, production credentials, patch deployment, endpoint/SOC functions, and live Jira/ServiceNow connections. No network target is contacted by the generator or importer.

## Assumptions

The demo uses one local PostgreSQL database and fixed seed 42. Password `DemoPass!234` is intentionally shared by synthetic accounts and must never be reused. Triage-effort savings assume six minutes per raw record that does not remain a distinct prioritized action. The offline AI assistant is the default; an optional API key enables Claude on aggregate synthetic context only.

## Functional requirements

| ID | Requirement | Success measure |
|---|---|---|
| BR-01 | Register assets with business unit/service, environment, owner and impact flags | Seed contains 300 assets |
| BR-02 | Import at least three distinct source formats | Five accepted simulated source types |
| BR-03 | Preserve source traceability while correlating duplicates | Batch reports new, duplicate and failed counts |
| BR-04 | Enrich CVEs from a local threat-intelligence feed | EPSS/KEV/exploitation values are visible |
| BR-05 | Calculate configurable, explainable contextual risk | Each score has factor points and reason text |
| BR-06 | Model routes from exposed assets to crown jewels | Graph and stored path records are available |
| BR-07 | Create owned remediation tasks with SLA due dates | High/critical tasks are assigned and tracked |
| BR-08 | Escalate overdue work on a schedule or manual trigger | Escalation records identify level and reason |
| BR-09 | Enforce independent risk-exception review | Requester cannot approve own request |
| BR-10 | Keep append-oriented audit records | Sensitive workflow operations emit audit events |
| BR-11 | Present operational, manager, auditor and executive data | Role-specific views and APIs are provided |
| BR-12 | Answer questions without requiring an LLM key | Rule-based fallback uses database aggregates |
| BR-13 | Expose ticketing simulation and REST APIs | Local ticket IDs link back to tasks |
| BR-14 | Run as a local Compose application | `docker compose up --build` starts DB/API/UI |

## Nonfunctional requirements

Use input validation, parameterized ORM access, role checks, structured logs, TLS option, content-security headers, responsive accessible pages, pinned direct dependencies, and repeatable synthetic generation. Dashboard performance is measured locally; the three-second goal is an acceptance target rather than a benchmark guarantee on arbitrary hardware.

# Project Plan (Agile)

Delivery model: Scrum-style, six two-week sprints (12 weeks) plus two weeks of hardening, documentation and rehearsal.
Ceremonies: sprint planning, 15-minute daily stand-up, sprint review with a demo checkpoint, retrospective.
Backlog tool: GitHub issues/projects; each story references its use case (UC) and acceptance criteria.

## Definition of Done

Code reviewed through a pull request; unit/integration tests added and green in CI; coverage gate (70%) holds;
ruff/black/mypy/ESLint clean; bandit, pip-audit and npm audit clean; new endpoints declare permission, scope and audit
behaviour; documentation and RTM updated; demo-able on the seeded dataset.

## Sprints

| Sprint | Goal | Key stories (acceptance criteria abridged) | Demo checkpoint |
|---|---|---|---|
| 1 (wk 1–2) | Foundations | Repo, CI, data model, auth + RBAC skeleton, synthetic data generator (seed 42) | Login per role; CI green |
| 2 (wk 3–4) | Assets & ingestion | UC-1/2 asset register and criticality; UC-3 five source parsers; UC-4 fingerprint de-duplication | Import scanner file, see duplicates merged |
| 3 (wk 5–6) | Risk engine | UC-5 threat enrichment; UC-6 eight-factor score with reasons; configurable weights; what-if | Explain a finding's score factor by factor |
| 4 (wk 7–8) | Workflow | UC-8 ownership rules; UC-9 task states with evidence; UC-10 SLA + escalation; UC-11 exceptions with SoD | Close a task with evidence; approve an exception as a second user |
| 5 (wk 9–10) | Attack paths & dashboards | UC-7 graph paths and influence; UC-12 role dashboards, heatmap, MTTR, trend | Show a path raising a finding's band |
| 6 (wk 11–12) | AI & integration | UC-13/14 assistant; ticketing simulators; exports; E2E suite | Ask questions; raise a Jira ticket |
| Hardening (wk 13–14) | Assurance | Security review, defect fixing, evidence, documentation, presentation, demo video | Full rehearsal against the rubric |

## Branching and reviews

`main` (releasable) ← `develop` (integration) ← `feature/*`, `fix/*`, `docs/*`. Conventional Commits. Every change
reaches `develop` through a pull request with the checklist in `CONTRIBUTING.md` and at least one reviewer; releases
are merged to `main` and tagged.

## Risk log

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope creep across 14 use cases | High | High | MoSCoW per sprint; bonus items only after SC-1..12 met |
| Security defects in access control | Medium | High | Central default-deny, single scope module, role × endpoint tests |
| Unrealistic data hides bugs | Medium | Medium | Deterministic generator with deliberate duplicates and malformed rows |
| Environment differences (SQLite vs PostgreSQL) | Medium | Medium | Datetime normalisation; PostgreSQL in Compose and CI |
| Demo fragility | Medium | High | Seeded data, E2E suite, recorded demo video |

## Hardening retrospective (2026-11-06 / 2026-11-07)

Two hardening passes split the monolithic API and UI into domain modules, unified scoping and scoring, completed the
remaining SPEC items (asset editing, survivorship, recovery, EASM, MFA flow, audit chain, forecasting, remediation
sequencing, review packs, success-criteria scorecard, board report, Kubernetes manifests) and closed 34 defects
(`13_Defect_Summary.md`). What worked: measuring success criteria from live data; one module per cross-cutting rule.
What to improve: run PostgreSQL locally from day one; add E2E tests alongside each feature rather than at the end.

# Final Report Outline

## Cover and approval

Project title, course/capstone identifiers, contributors, supervisor, institution, and submission date.

## Executive summary

State the operational triage problem, the synthetic prototype delivered, the measured workflow, and limitations. Include the core result: multiple noisy exports are consolidated into prioritized actions with explainable business context.

## Chapters

1. **Introduction:** banking technology context, problem statement, objectives BO-1 to BO-7, scope, assumptions, and success criteria.
2. **Background and related work:** vulnerability lifecycle, CVSS/EPSS/KEV concepts, attack graph use, remediation SLAs, and responsible use of synthetic security data.
3. **Requirements:** stakeholders, use cases UC-1 to UC-14, BRD IDs, functional/nonfunctional/security constraints, and RTM.
4. **Architecture and design:** component/deployment/sequence diagrams, trust boundaries, API and data model, and technology rationale.
5. **Implementation:** ingestion adapters, dedup logic, risk formula, graph feedback, ownership, tasks, exceptions, dashboards, AI fallback, and simulated ticketing.
6. **Security and privacy:** STRIDE, OWASP mapping, authentication, RBAC, audit, upload controls, AI boundaries, residual risks.
7. **Testing and evaluation:** unit/integration/E2E cases, coverage, dashboard latency, owner accuracy methodology, import totals, dedup precision, and defect summary.
8. **Results:** success criteria SC-1 to SC-12, screenshots/evidence, manual effort assumption, and demo narrative.
9. **Limitations and future work:** production data scoping, trusted TLS, refresh-cookie migration, immutable logs, distributed scheduler, validation, and bonus ideas.
10. **Conclusion:** objectives met, operational benefit, and safe deployment conditions.

## Appendices

API schema, test evidence, test cases, defect records, demo users, setup commands, scoring configuration, sample synthetic imports, and glossary. Include no real vulnerability scan output or secrets.

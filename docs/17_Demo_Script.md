# Demonstration Script (≈ 12 minutes)

Prerequisite: `LOGIN_RATE_LIMIT=100 ./scripts/dev.sh`, browser at http://127.0.0.1:5173. All passwords `DemoPass!234`.
A captioned recording of this flow is `docs/demo/ivm-demo.webm` (regenerate with `node e2e/demo/record-demo.mjs`).

| Time | Account | Steps | Talking points (rubric) |
|---|---|---|---|
| 0:00 | — | Title slide | Problem: volume, duplicates, no context, unclear ownership (business alignment) |
| 1:00 | user11 (CISO) | Overview: KPIs, trend, BU risk, internet-facing assets, crown-jewel paths, heatmap | Role-specific executive view; section-13 dashboard items |
| 2:30 | user11 | Reports & insights: success-criteria table, remediation plan, forecast; download Executive report | SC-1..12 measured live; recommendation engine; board summary |
| 4:00 | user2 (analyst) | Findings → filter Critical → open top finding | Eight explainable factors, threat intel, attack-path base → final |
| 5:00 | user2 | Attack paths: pick a route | Exposure chains raise priority (SC-9) |
| 5:45 | user2 | AI assistant: "Critical findings in Treasury", "what about Retail Banking?", "What should we fix first?" | NLQ, follow-ups, sources, audit |
| 7:00 | user2 | Data imports → EASM → run; view failed rows | Correlation (13 merged), survivorship, recoverable failures |
| 8:00 | user1 (admin) | Asset inventory → register asset → edit: crown jewel + internet exposed → save; retry EASM failed rows | UC-1/2, rescoring, reliability |
| 9:00 | user4 (manager) | Remediation → open task drawer: owner reason, breach risk, timeline → Create Jira ticket | UC-8/9/10, SC-11 |
| 10:00 | user4 / user2 | Exceptions: user2 requests, user4 approves; download review pack | Segregation of duties, evidence (UC-11) |
| 11:00 | user5 (auditor) | Audit trail → filter → Verify integrity | Tamper-evident audit, auditability NFR |
| 11:30 | — | Quality slide: 113/12/13 tests, 85% coverage, 0 vulnerabilities, p95 0.51 s | Testing and secure engineering evidence |

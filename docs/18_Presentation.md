# Final Presentation

The deck is `docs/presentation/IVM_Final_Presentation.pptx` (16 slides, 16:9, speaker notes on every slide).

| # | Slide | Message |
|---|---|---|
| 1 | Title | Platform in one sentence; synthetic data only |
| 2 | Problem | 2,500 raw rows, 28.6% duplicates, 3,454 open findings, unclear ownership |
| 3 | Capabilities | Eight capability tiles mapped to UC-1..UC-14 |
| 4 | Architecture | Layered, API-first; one scoring path; dev / Compose / Kubernetes |
| 5 | Risk engine | Native chart of the eight factor weights; bands; what-if; SC-4/SC-5 numbers |
| 6 | Explainability | Finding detail: factors, threat intel, path context, source records |
| 7 | Attack paths | 555 findings on paths, 300 raised a band, +9.7 points |
| 8 | Ingestion | Pipeline; 714 duplicates merged; failed rows kept and retryable |
| 9 | Remediation | 100% ownership accuracy, MTTR 4.4/8.5 days, ≈96% SLA, breach prediction |
| 10 | Governance | Request → approve → expire → evidence pack |
| 11 | Dashboards | Executive view and section-13 coverage |
| 12 | AI assistant | Example questions, sources, scoping |
| 13 | Security | Access control, identity, audit chain, input/output safety, secrets, DevSecOps |
| 14 | Quality | Test chart, 86% coverage, 0.51 s p95, 0 vulnerabilities |
| 15 | Success criteria | 12/12 met with values |
| 16 | Close | Honest limits and next steps; questions |

The generator script is reproducible (pptxgenjs); figures match `docs/evidence/`.

# Demo Script — “From 2,500 Noisy Findings to 12 Prioritized Actions”

The seeded fixture set is approximately 2,500 raw source rows. The dashboard and import totals calculate the deduplicated counts from the generated records; the phrase “12 prioritized actions” is the presentation target for the walkthrough, not a fixed database total.

## Ten-minute run

**0:00–1:00 — Set the scene.** Sign in as `user2@demo.bank`. Explain that all data is synthetic and no scanner or bank connection exists. Point out the posture KPIs and effort-saved estimate.

**1:00–2:30 — Show noisy sources.** Open Data Imports. Identify scanner CSV, CSPM JSON, pentest JSON, and container/Kubernetes JSON. Select scanner export and import it. Explain new, duplicate, and malformed-row counts; each original row remains traceable.

**2:30–4:00 — Explain the priority.** Open Findings and select a top high/critical finding. Walk through severity, business criticality, internet exposure, threat intelligence, and attack-path points. Compare with an internal lower-tier asset.

**4:00–5:30 — Show attack paths.** Open Attack Paths, recalculate, and point out an internet entry, intermediate assets, and crown-jewel targets. Explain how a modeled route raises finding priority.

**5:30–6:45 — Assign and remediate.** Sign in as `user8@demo.bank`, open Remediation, set a task in progress, then close one with synthetic evidence. Optionally create a simulated JIRA ticket.

**6:45–8:00 — SLA escalation.** Sign in as manager `user4@demo.bank`, open Administration, run scheduler jobs, and inspect escalation levels and reason for the seeded overdue example.

**8:00–9:15 — Govern exception.** As analyst request a time-bound exception with controls. Sign in separately as `user6@demo.bank` (security architect), approve, then inspect accepted status and audit log. Demonstrate self-approval is blocked if time permits.

**9:15–10:00 — Ask the assistant.** Ask “Which findings should we prioritize first?” Show the rule-based answer and disclaimer. End at the executive dashboard and cite the six-minute triage-time assumption.

## Reset and backup

For a clean demo, run `docker compose down -v` and `docker compose up --build`. For evidence, record the commit, command, and synthetic-only screenshot paths in the evidence template.

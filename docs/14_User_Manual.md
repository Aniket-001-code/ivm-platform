# User Manual

## Sign-in

Open `http://localhost:8080` and use a documented demo user. All demo users share `DemoPass!234`. The token is held in browser memory, so reloading signs out. This is a local synthetic environment.

## Analyst

1. Open **Data imports**, choose Host scanner, Cloud posture, Pentest, Container/Kubernetes, or Identity.
2. Choose a CSV or JSON export and select **Run import**.
3. Review new, duplicate, and failed counts. Open the import batch for individual row errors.
4. Open **Findings** and search or filter by risk. Select a row to view score factors, source list, linked asset, and history.
5. Use **Attack paths** to inspect routes to crown jewels. Recalculate after changing graph data.
6. Ask the **AI assistant** a natural-language question. Answers are labeled AI-generated and can be rule-based when no provider key is set.

## Remediation owner

1. Open **Remediation** to see tasks assigned to your account.
2. Move a task to In progress while work is underway.
3. Add a comment/evidence through the task form; closing a task requires evidence.
4. Use the simulated ticket connector when available to generate a local ticket reference. A resolved ticket moves the task to verification.

## Manager

Review overdue tasks and the manager dashboard. In **Administration**, run the scheduler manually to create escalation records for overdue tasks and expire approved exceptions. Inspect the escalation reason and level.

## Approver / security architect

Open **Risk exceptions** and examine the request justification, compensating controls, and expiry. Approve or reject with a comment. The requester cannot approve their own exception. Approved exceptions mark the linked finding risk accepted; revoke or expiry reopens the finding.

## Auditor

Use **Audit trail** to inspect login, import, exception, risk, task, and AI events. The demo exposes a read-only audit route. Protect any exported evidence as synthetic operational data.

## Executive

The overview shows open finding count, critical risk, SLA compliance, estimated manual triage effort saved, six-month risk trend, risk distribution, and top-priority findings. The effort estimate assumes six minutes per finding record eliminated from manual triage.

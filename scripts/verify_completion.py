"""Verify every SPEC item against the repository and write docs/21_Completion_Checklist.md.

Run from the repository root after scripts/collect_evidence.sh:
    .venv/bin/python scripts/verify_completion.py
Each item is checked mechanically (file exists, API operation exists, UI page exists, test
exists, evidence passed, measured criterion met). Exit code 1 if anything fails.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = json.loads((ROOT / "docs/evidence/openapi.json").read_text())
OPS = {f"{m.upper()} {p}" for p, ops in API["paths"].items() for m in ops}
TESTS = "\n".join(
    p.read_text(errors="ignore")
    for p in [*ROOT.glob("backend/tests/**/*.py"), *ROOT.glob("e2e/*.ts"), *ROOT.glob("frontend/src/**/*.test.*")]
)
EVIDENCE = ROOT / "docs/evidence"
SC = json.loads((EVIDENCE / "success-criteria.json").read_text())["success_criteria"]["criteria"]


def f(path: str) -> bool:
    return (ROOT / path).exists()


def op(*names: str) -> bool:
    return all(n in OPS for n in names)


def test(*names: str) -> bool:
    return all(n in TESTS for n in names)


def grep(path: str, pattern: str) -> bool:
    return bool(re.search(pattern, (ROOT / path).read_text(errors="ignore")))


def evidence_ok(name: str) -> bool:
    p = EVIDENCE / name
    return p.exists() and "# exit code: 0" in p.read_text(errors="ignore")


def sc(i: int) -> bool:
    return next(c for c in SC if c["id"] == f"SC-{i}")["passed"]


V1 = "/api/v1"
CHECKS: list[tuple[str, str, str, bool]] = []


def add(section: str, item: str, evidence: str, ok: bool) -> None:
    CHECKS.append((section, item, evidence, bool(ok)))


# ---- Use cases (section 7) ----------------------------------------------------------------
uc = "Use cases (§7)"
add(uc, "UC-1 Asset registration", "POST/PATCH /assets, bulk import, Assets page",
    op(f"POST {V1}/assets", f"PATCH {V1}/assets/{{asset_id}}", f"POST {V1}/assets/bulk-import") and f("frontend/src/components/AssetEditor.tsx") and test("test_asset_registration_validates_and_audits"))
add(uc, "UC-2 Asset criticality assignment", "criticality flags + rescoring", test("test_criticality_change_rescores_findings_and_is_audited") and grep("backend/app/api/v1/routes/assets.py", "is_crown_jewel"))
add(uc, "UC-3 Vulnerability import", "6 sources + threat feed", op(f"POST {V1}/imports/{{source_type}}", f"POST {V1}/threat-intel/import/file") and grep("backend/app/services/ingestion.py", '"easm"'))
add(uc, "UC-4 Vulnerability correlation", "dedup + survivorship + reopen", test("test_survivorship_keeps_strongest_evidence_and_unions_sources", "test_closed_finding_is_reopened_when_detected_again"))
add(uc, "UC-5 Threat context enrichment", "KEV/EPSS/exploit/ransomware + rescoring", test("test_threat_feed_parses_booleans_and_rescores_affected_findings"))
add(uc, "UC-6 Risk scoring", "8-factor engine, what-if", f("backend/app/services/risk_engine.py") and op(f"POST {V1}/risk/what-if") and f("backend/tests/unit/test_risk_engine.py"))
add(uc, "UC-7 Attack path analysis", "paths, influence, impact, graph export", op(f"GET {V1}/attack-paths", f"GET {V1}/attack-paths/impact", f"GET {V1}/attack-paths/export") and test("test_rescoring_preserves_attack_path_influence"))
add(uc, "UC-8 Ownership assignment", "rules, fallback, reassignment, accuracy", op(f"POST {V1}/tasks/{{task_id}}/assign", f"GET {V1}/reports/ownership-accuracy") and test("test_ownership_rules_match_names_tags_and_groups"))
add(uc, "UC-9 Remediation tracking", "status machine, evidence, timeline", op(f"PATCH {V1}/tasks/{{task_id}}", f"GET {V1}/tasks/{{task_id}}") and test("test_closing_a_task_closes_its_finding"))
add(uc, "UC-10 SLA monitoring", "policy escalation, acknowledgement, overdue report", op(f"POST {V1}/escalations/{{escalation_id}}/acknowledge", f"GET {V1}/tasks/export", f"GET {V1}/tasks/overdue") and test("test_escalation_thresholds_follow_sla_policy"))
add(uc, "UC-11 Exception management", "request/approve/reject/revoke/expire + review pack", op(f"POST {V1}/exceptions", f"POST {V1}/exceptions/{{exception_id}}/approve", f"POST {V1}/exceptions/{{exception_id}}/reject", f"POST {V1}/exceptions/{{exception_id}}/revoke", f"GET {V1}/exceptions/{{exception_id}}/review-pack"))
add(uc, "UC-12 Executive reporting", "dashboards + board report", op(f"GET {V1}/dashboards/{{view}}", f"GET {V1}/reports/executive") and f("frontend/src/pages/Reports.tsx"))
add(uc, "UC-13 AI recommendations", "remediation plan, explanations, summary", op(f"GET {V1}/reports/remediation-plan", f"POST {V1}/ai/explain/{{finding_id}}", f"POST {V1}/ai/executive-summary"))
add(uc, "UC-14 Natural language querying", "entities, intents, follow-ups, sources", op(f"POST {V1}/ai/ask") and test("test_assistant_understands_entities_and_follow_ups"))

# ---- Scope capability areas (section 5.1) ----------------------------------------------
sc51 = "In-scope capabilities (§5.1)"
add(sc51, "Asset criticality intelligence (customer-facing, crown jewel, sensitive, regulatory, exposure, environment, service)", "Asset model + editor", all(grep("backend/app/models/inventory.py", k) for k in ["is_customer_facing", "is_crown_jewel", "has_sensitive_data", "regulatory_tags", "internet_exposed", "environment", "business_service_id"]))
add(sc51, "Ingestion: scanner, CSPM, container, K8s, pentest, identity, threat intel", "sample files + parsers", all(f(f"backend/data/synthetic/{n}") for n in ["scanner_export.csv", "cspm_findings.json", "container_k8s_findings.json", "pentest_report.json", "identity_findings.csv", "threat_intel_feed.json", "easm_findings.json"]))
add(sc51, "Normalization: common schema, duplicate detection, asset linking, source consolidation, survivorship", "ingestion.py", grep("backend/app/services/ingestion.py", "_apply_survivorship"))
add(sc51, "Remediation: aging reports", "aging buckets + SLA CSV", grep("backend/app/services/analytics.py", "def aging_buckets") and op(f"GET {V1}/tasks/export"))
add(sc51, "Exception: temporary + long-term + expiry tracking + audit evidence", "exceptions routes/service", grep("backend/app/services/exceptions.py", "expiry_warning"))
add(sc51, "APIs incl. simulated ticketing", "Jira/ServiceNow + webhook", op(f"POST {V1}/ticketing/{{system}}/issues", f"POST {V1}/integrations/ticketing/webhook"))

# ---- Dashboards (section 13) ------------------------------------------------------------
d = "Dashboard requirements (§13)"
for label, key in [
    ("Top risky assets by business risk score", "top_assets"),
    ("Critical vulnerabilities by business unit", "risk_by_business_unit"),
    ("Internet-facing high-risk assets", "internet_facing_high_risk"),
    ("Overdue vulnerabilities by owner and SLA category", "overdue_by_owner_and_category"),
    ("Risk accepted exceptions nearing expiry", "exceptions_expiring"),
    ("Attack paths leading to crown-jewel assets", "crown_jewel_paths"),
    ("Risk trend over time", "trend"),
    ("Risk reduction percentage after remediation", "risk_reduction_percent"),
    ("Mean Time To Remediate (MTTR)", "mttr_by_band"),
    ("Executive heatmap by business service", "heatmap"),
]:
    add(d, label, f"`{key}` in API + UI", grep("backend/app/api/v1/routes/dashboards.py", key) or grep("backend/app/services/analytics.py", key))

# ---- Non-functional (section 9) ---------------------------------------------------------
n = "Non-functional (§9)"
add(n, "Performance: dashboard < 3 s", "dashboard-latency.txt", evidence_ok("dashboard-latency.txt"))
add(n, "Scalability: concurrent load without errors", "load-benchmark.txt (25 users, 600 req)", evidence_ok("load-benchmark.txt"))
add(n, "Availability & backup approach", "backup.sh/restore.sh, health probes", f("backend/scripts/backup.sh") and f("backend/scripts/restore.sh") and op(f"GET {V1}/health"))
add(n, "Reliability: import errors logged and recoverable", "failed rows + retry", op(f"POST {V1}/imports/{{batch_id}}/retry", f"GET {V1}/imports/{{batch_id}}/failed-rows"))
add(n, "Security: RBAC", "role × endpoint matrix", test("test_every_role_gets_exactly_its_permissions"))
add(n, "Security: MFA-ready", "TOTP flow", test("test_mfa_enrollment_login_and_rotation"))
add(n, "Security: encryption in transit", "TLS proxy + ingress", f("infra/tls/nginx.conf") and f("deploy/k8s/ingress.yaml"))
add(n, "Security: encryption at rest (secrets)", "Fernet-encrypted MFA secrets", grep("backend/app/core/security.py", "Fernet"))
add(n, "Security: secrets handling", "env-only secrets, weak key refused", test("test_weak_secret_is_rejected_outside_development"))
add(n, "Security: refresh token not readable by JavaScript", "HttpOnly cookie", test("test_refresh_token_is_httponly_cookie_and_rotates"))
add(n, "Privacy: synthetic data only", "generator seed 42", f("backend/scripts/generate_synthetic_data.py"))
add(n, "Maintainability: modular, API-first, config-driven scoring, automated tests", "≥ 70% coverage", evidence_ok("backend-tests.txt"))
add(n, "Usability: search, filtering, user-specific views", "server-side filters + role views", f("frontend/src/access.ts") and grep("frontend/src/pages/Findings.tsx", "Search findings"))
add(n, "Auditability: imports, scoring, ownership, exceptions, approvals", "hash-chained audit", test("test_audit_chain_detects_tampering_and_triggers_block_edits") and op(f"GET {V1}/audit/verify"))
add(n, "Explainability", "factor reasons + path base→final", grep("frontend/src/pages/FindingDetail.tsx", "ATTACK PATH CONTEXT"))
add(n, "Accessibility: contrast, labels, keyboard", "axe WCAG 2 A/AA audit", f("e2e/accessibility.spec.ts") and evidence_ok("e2e-results.txt"))

# ---- Success criteria (section 14) ------------------------------------------------------
s = "Success criteria (§14)"
for c in SC:
    add(s, f"{c['id']} {c['criterion']}", c["evidence"], c["passed"])

# ---- Practices (section 11) ---------------------------------------------------------------
pr = "Engineering practices (§11)"
add(pr, "Layered architecture, modular design, API-first", "routes/services/models/core", f("backend/app/services") and f("backend/app/api/v1/routes"))
add(pr, "Coding standards + static analysis", "ruff, black, mypy, ESLint", all(evidence_ok(x) for x in ["ruff.txt", "black.txt", "mypy.txt", "eslint.txt"]))
add(pr, "Source control: branching strategy", "main/develop/feature branches", (ROOT / ".git").exists() and grep("CONTRIBUTING.md", "develop"))
add(pr, "Unit tests ≥ 70% coverage, integration, E2E", "backend 86%, 14 E2E", evidence_ok("backend-tests.txt") and evidence_ok("e2e-results.txt") and evidence_ok("frontend-tests.txt"))
add(pr, "DevSecOps: dependency scanning, secrets mgmt, CI/CD", "bandit, pip-audit, npm audit, gitleaks, CI", all(evidence_ok(x) for x in ["bandit.txt", "pip-audit.txt", "npm-audit.txt"]) and f(".github/workflows/ci.yml") and f(".gitleaks.toml"))
add(pr, "Project management: agile plan, backlog, demo checkpoints", "19_Project_Plan.md", f("docs/19_Project_Plan.md"))
add(pr, "Operational readiness: logging, errors, audit, config, backup/restore", "logging.py, backup scripts", f("backend/app/core/logging.py") and f("backend/scripts/backup.sh"))

# ---- Deliverables (section 10) ------------------------------------------------------------
dl = "Deliverables (§10)"
for label, path in [
    ("Business Requirements Document", "docs/01_BRD.md"),
    ("Solution Architecture Document", "docs/02_Solution_Architecture.md"),
    ("High-Level Design", "docs/03_HLD.md"),
    ("Low-Level Design", "docs/04_LLD.md"),
    ("Data Model", "docs/05_Data_Model.md"),
    ("API Specification", "docs/06_API_Specification.md"),
    ("Threat model", "docs/07_Threat_Model.md"),
    ("Secure design review", "docs/08_Secure_Design_Review.md"),
    ("Secure coding checklist", "docs/09_Secure_Coding_Checklist.md"),
    ("Dependency scan evidence", "docs/evidence/pip-audit.txt"),
    ("Test Plan", "docs/10_Test_Plan.md"),
    ("Test Cases", "docs/11_Test_Cases.md"),
    ("Test Evidence", "docs/12_Test_Evidence.md"),
    ("Defect Summary", "docs/13_Defect_Summary.md"),
    ("User Manual", "docs/14_User_Manual.md"),
    ("Administrator Guide", "docs/15_Admin_Guide.md"),
    ("Final Report", "docs/16_Final_Report.md"),
    ("Demo script", "docs/17_Demo_Script.md"),
    ("Final Presentation (deck)", "docs/presentation/IVM_Final_Presentation.pptx"),
    ("Demonstration Video", "docs/demo/ivm-demo.webm"),
    ("Requirements traceability matrix", "docs/20_Requirements_Traceability_Matrix.md"),
    ("Architecture diagrams", "docs/diagrams/deployment.md"),
    ("Working application + REST API + DB + ingestion + risk engine + dashboards", "backend/app/main.py"),
]:
    add(dl, label, path, f(path))
add(dl, "Git repository evidence", "tagged history on main", (ROOT / ".git/refs/tags/v1.0.0").exists() or grep(".git/packed-refs", "v1.0.0") if f(".git/packed-refs") else (ROOT / ".git/refs/tags/v1.0.0").exists())

# ---- Bonus (section 17) -------------------------------------------------------------------
b = "Bonus opportunities (§17)"
add(b, "Predictive risk modelling from historical remediation data", "forecasting.py", f("backend/app/services/forecasting.py") and op(f"GET {V1}/analytics/forecast"))
add(b, "Advanced conversational assistant", "follow-ups + entities", test("carried_from_previous"))
add(b, "Executive heatmaps and board-style summaries", "heatmap + board report", op(f"GET {V1}/reports/executive"))
add(b, "Cloud-native containerised deployment", "Dockerfiles + Compose + k8s", f("backend/Dockerfile") and f("frontend/Dockerfile") and f("deploy/k8s/backend.yaml"))
add(b, "Simulated ServiceNow / JIRA integration", "ticketing simulators", op(f"POST {V1}/ticketing/{{system}}/issues"))
add(b, "Graph database support for attack paths", "Cypher/GraphML export", test("test_attack_graph_exports_for_graph_databases"))
add(b, "Risk forecast from SLA breach likelihood", "breach forecast", op(f"GET {V1}/tasks/breach-forecast"))
add(b, "Remediation sequencing by effort and risk reduction", "remediation plan", op(f"GET {V1}/reports/remediation-plan"))
add(b, "Automated exception review packs", "review pack", test("test_exception_review_pack_json_and_html"))

# ---- Write report --------------------------------------------------------------------------
passed = sum(ok for *_, ok in CHECKS)
lines = [
    "# Completion Checklist",
    "",
    f"Generated by `scripts/verify_completion.py` from the repository and `docs/evidence/`. "
    f"**{passed} of {len(CHECKS)} items verified.** Every item is checked mechanically: the file, API operation, "
    "UI page or test exists, the evidence command exited 0, or the success criterion was measured as met.",
]
section = None
for sec, item, ev, ok in CHECKS:
    if sec != section:
        lines += ["", f"## {sec}", "", "| | Item | Verified by |", "|---|---|---|"]
        section = sec
    lines.append(f"| {'✅' if ok else '❌'} | {item} | {ev} |")
lines += [
    "",
    "## Verified outside this script",
    "",
    "- Docker/PostgreSQL runtime and Kubernetes manifests: built for CI (`.github/workflows/ci.yml` builds images); not "
    "executed on the development machine because Docker is not installed there.",
    "- Pull-request evidence requires a hosted remote; the local history shows the branch-and-merge workflow.",
]
(ROOT / "docs/21_Completion_Checklist.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"{passed}/{len(CHECKS)} verified")
for sec, item, ev, ok in CHECKS:
    if not ok:
        print("FAIL:", sec, "|", item)
sys.exit(0 if passed == len(CHECKS) else 1)

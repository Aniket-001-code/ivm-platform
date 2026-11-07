# Defect Summary

Defects found during the two hardening passes (2026-11-06 and 2026-11-07). All are **Closed**, each verified by an
automated test or by evidence in `docs/evidence/`.

| ID | Defect | Severity | Area | Root cause → fix | Verification |
|---|---|---|---|---|---|
| DEF-001 | AI assistant stuck on "Thinking…" | High | Frontend | Mutation observer lost under StrictMode remount → local request state | E2E "finding detail sends its context to the assistant" |
| DEF-002 | Three inconsistent data-scope rule sets | High | Security | Duplicated logic → single `core/scope.py` | `test_auditor_dashboard_and_exception_page_agree` |
| DEF-003 | `/ai/explain`, `/ai/recommendations` unscoped (data leak) | High | Security | Missing scope check → scoped queries | `test_out_of_scope_findings_are_hidden_from_ai_and_exception_requests` |
| DEF-004 | Exception request/review/revoke/export ignored scope | High | Security | Missing checks → `_check_asset_scope` / scope condition | `test_business_unit_manager_sees_only_own_unit_everywhere` |
| DEF-005 | `/tasks/overdue` crashed | High | Backend | Naive vs aware datetimes in Python → SQL comparison | `test_overdue_tasks_filter_in_sql` |
| DEF-006 | Locked-out account crashed login | High | Security | Same datetime issue → `as_utc` | `test_locked_account_is_refused_not_crashed` |
| DEF-007 | CSV formula injection in exports | Medium | Security | Raw cell values → prefix neutralisation | `test_csv_exports_neutralise_formula_injection` |
| DEF-008 | Unknown roles / self-demotion allowed | Medium | Security | No validation → role check, self-protection | `test_user_updates_validate_roles_and_protect_self` |
| DEF-009 | Finding status accepted any text | Medium | Backend | No validation → allowed set | `test_finding_status_is_validated` |
| DEF-010 | SLA and ownership changes not audited | Medium | Auditability | Missing audit calls → added | `test_config_changes_are_audited` |
| DEF-011 | Swagger `/docs` blocked by CSP | Low | Ops | Global CSP → docs-specific policy | Manual check `/docs` |
| DEF-012 | Users logged out after 15 minutes | High | Frontend | No token refresh → single-flight refresh | `client.test.ts` |
| DEF-013 | Scoring weights shown as "2500%" | Medium | Frontend | Points shown as fractions → points editor | Admin page review |
| DEF-014 | Task filter text saved as update comment | Medium | Frontend | Shared state → separate fields | E2E "finding work can be closed with evidence" |
| DEF-015 | Owners matched a non-existent role | Medium | Frontend | Legacy alias → `usesOwnTaskQueue` | `access.test.ts` |
| DEF-016 | Hard-coded date; factor bars scaled wrongly | Low | Frontend | Static text / wrong denominator → computed | Visual review |
| DEF-017 | Menu showed pages that returned 403 | Medium | Frontend | Role lists vs permissions → permission-driven nav | `App.test.tsx`, E2E CISO test |
| DEF-018 | Flaky E2E reading stale table | Low | Test | Race on navigation → wait for heading | 13/14 E2E stable |
| DEF-019 | Re-score erased attack-path influence | High | Risk engine | No path context in rescore → `services/scoring.py` | `test_rescoring_preserves_attack_path_influence` |
| DEF-020 | Imported findings missed exploit maturity | High | Risk engine | Partial intel dict → shared `intel_for` | `test_threat_feed_parses_booleans_and_rescores_affected_findings` |
| DEF-021 | All IP addresses matched the same asset | High | Ingestion | `asset_key` truncated at first dot → IP/URL aware | `test_asset_keys_keep_ip_addresses_and_parse_urls` |
| DEF-022 | No survivorship; closed findings never reopened | Medium | Ingestion | Duplicates only appended source → survivorship + reopen | `test_survivorship_…`, `test_closed_finding_is_reopened_…` |
| DEF-023 | Failed rows lost; retry re-ran good rows | High | Reliability | Errors only logged → failed rows stored and retried | `test_failed_rows_are_kept_and_recoverable_…` |
| DEF-024 | Threat feed read "false" as true; no rescoring | High | Threat intel | `bool("false")` → explicit parsing + rescore | `test_threat_feed_parses_booleans_…` |
| DEF-025 | Escalation days hard-coded | Medium | Workflow | Ignored SLA policy → policy thresholds | `test_escalation_thresholds_follow_sla_policy` |
| DEF-026 | MFA gaps (role-limited, resettable, timing leak, no UI step) | High | Security | Incomplete flow → full MFA flow | `test_mfa_enrollment_login_and_rotation`, `test_mfa_applies_to_every_role_…` |
| DEF-027 | Ownership rules ignored groups/tags and names | Medium | Workflow | Raw UUID compare → name/tag/group matching | `test_ownership_rules_match_names_tags_and_groups` |
| DEF-028 | Ticketing unscoped, unaudited, duplicate tickets | Medium | Integration | Rewrite with scope, audit, uniqueness | `test_ticket_lifecycle_and_signed_webhook` |
| DEF-029 | Late-closed tasks counted SLA-compliant | Medium | Analytics | Formula → on-time check | SLA KPI in `success-criteria.json` |
| DEF-030 | Seeded approvals audited without entity id | Low | Data | Missing id → linked records | SC-8 measured met |
| DEF-031 | "0h effort saved"; trend dip from mixed cohorts | Medium | Analytics | Formula/cohort → duplicates-based KPI, latest score per finding | Dashboard review, forecast R² 0.91 |
| DEF-032 | Backup passed SQLAlchemy URL to `pg_dump`; no SQLite | Medium | Ops | URL scheme → normalised; SQLite `.backup` | Manual backup run |
| DEF-033 | Root container, lockfile ignored, no `.dockerignore` | Medium | Supply chain | Dockerfiles hardened | CI docker build |
| DEF-034 | Dataset reproducibility unverified; no EASM sample | Low | Data | Verified content-identical; EASM file added | 13 EASM rows correlate with scanner findings |

## Statistics

| Severity | Count |
|---|---|
| High | 15 |
| Medium | 16 |
| Low | 3 |

By area: security 9, backend/ingestion/risk engine 10, frontend 8, workflow/integration/analytics 6, ops/test 4
(some defects span areas).

## Lessons learned

1. Duplicated rules drift: one module for scope and one entry point for scoring removed whole classes of bugs.
2. Datetimes must be normalised at the database boundary (SQLite returns naive values).
3. Measuring success criteria from live data (the SC scorecard) found a defect the tests had missed (DEF-030).
4. Security features need end-to-end flows (MFA UI step, token refresh), not just endpoints.

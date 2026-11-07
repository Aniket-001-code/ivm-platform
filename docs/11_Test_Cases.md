# Test Cases

This catalogue lists every automated test in the repository: one row per test function. A parametrised function gets one row, and the number of generated cases is shown in brackets. Status comes from the 2026-11-07 evidence run (`docs/evidence/backend-junit.xml`, `frontend-tests.txt`, `e2e-results.txt`).

| Suite | Files | Functions (rows) | Executed cases | Result |
|---|---|---|---|---|
| Backend unit | `backend/tests/unit/*.py` (4) | 14 | 31 | 31 passed |
| Backend integration | `backend/tests/integration/*.py` (5) | 60 | 82 | 82 passed |
| Frontend (Vitest) | `frontend/src/**/*.test.ts(x)` (3) | 12 | 12 | 12 passed |
| End-to-end (Playwright) | `e2e/workflows.spec.ts` (1) | 13 | 13 | 13 passed |
| **Total** | 13 | **99** | **138** | **138 passed** |

Requirement IDs follow `20_Requirements_Traceability_Matrix.md`. Use cases: UC-1 asset registration, UC-2 criticality assignment, UC-3 vulnerability import, UC-4 correlation, UC-5 threat enrichment, UC-6 risk scoring, UC-7 attack path analysis, UC-8 ownership assignment, UC-9 remediation tracking, UC-10 SLA monitoring, UC-11 exception management, UC-12 executive reporting, UC-13 AI recommendations, UC-14 natural-language querying. NFR tags: NFR-PERF, NFR-REL (reliability), NFR-SEC, NFR-MAINT, NFR-USE (usability), NFR-AUD (auditability), NFR-EXPL (explainability), NFR-A11Y (accessibility).

Type codes: **U** unit, **I** integration (service level with a database), **A** API integration (HTTP through `TestClient`), **S** security-focused, **F** frontend component, **E** end-to-end.

Shared fixtures live in `backend/tests/conftest.py`: `db_session` (isolated in-memory SQLite) and `world` (two business units, one user per role scoped to unit A, an asset and finding in each unit, an overdue task on unit A, and an approved exception per finding containing CSV-injection payloads).

## 1. Risk engine and normalization (unit)

File: `backend/tests/unit/test_risk_engine.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-U-01 | `test_risk_score_is_bounded_and_has_spec_factors` [15] | UC-6, SC-4 | U | Score 15 combinations of CVSS 0–10, tier 1–5 and exposure, with EPSS 0.8 and KEV. The score is between 0 and 100, the band is one of the four, the breakdown factors equal `DEFAULT_MAX_POINTS` in order, and each factor's points are between 0 and its max. | Pass |
| TC-U-02 | `test_attack_path_signal_increases_score` | UC-7, SC-9 | U | The same finding is scored with and without `on_attack_path=True`. The on-path score is higher, and the last factor's reason mentions "modeled route". | Pass |
| TC-U-03 | `test_severity_aliases` [6] | UC-4 | U | `Critical`, `crit`, `Severe`, `Moderate`, `Informational` and `None` normalise to critical/critical/high/medium/low/medium. | Pass |
| TC-U-04 | `test_asset_aliases_correlate_fqdns_and_hostnames` | UC-4 | U | `asset_key("web01.bank.local") == asset_key("web01")`. | Pass |
| TC-U-05 | `test_fingerprint_is_stable_and_asset_scoped` | UC-4, SC-3 | U | The fingerprint ignores CVE case and title, and differs between assets. | Pass |
| TC-U-06 | `test_seeded_owner_mapping_matches_generator_ground_truth` | UC-8, SC-6 | U | Reads `backend/data/synthetic/assets.json`. At least 90% of `owner_email` values follow the generator's deterministic owner rule (the test skips if the data has not been generated; it ran in the evidence run). | Pass |

## 2. Forecasting (unit)

File: `backend/tests/unit/test_forecasting.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-U-07 | `test_linear_forecast_recovers_slope_and_projects` | Bonus: predictive risk / forecast, BO-5 | U | Series 10,12,14,16 gives slope 2.0, projection [18, 20] and R² 1.0. | Pass |
| TC-U-08 | `test_linear_forecast_handles_short_series` | Bonus: forecast | U | A single point gives slope 0.0 (no crash). | Pass |
| TC-U-09 | `test_breach_likelihood_is_explainable_and_ordered` | UC-10, bonus: SLA-breach forecast, NFR-EXPL | U | A task due in 2 days scores higher than one due in 30 days and higher than one in `pending_verification`. All values are strictly between 0 and 1. The factors include "owner on-time rate". | Pass |
| TC-U-10 | `test_breached_and_closed_tasks` | UC-10 | U | An overdue task returns `(1.0, "breached")` and a closed task returns `(0.0, "none")`. | Pass |

## 3. AI assistant and upload parsing (unit)

Files: `backend/tests/unit/test_ai_assistant.py`, `backend/tests/unit/test_upload_parser.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-U-11 | `test_finding_context_returns_selected_finding_and_risk_drivers` | UC-13, NFR-EXPL | U | `answer_question(..., finding_id=...)` returns intent `explain_finding`. The answer quotes the title, "94.5/100" and the stored factor reason, and the data row names the asset. | Pass |
| TC-U-12 | `test_csv_parser_keeps_header_fields` | UC-3 | U | A scanner CSV parses to a list of dicts keyed by the header. | Pass |
| TC-U-13 | `test_json_parser_accepts_wrapped_items` | UC-3 | U | `{"items": [...]}` JSON is unwrapped. | Pass |
| TC-U-14 | `test_upload_rejects_unsupported_or_empty_files` [2] | UC-3, NFR-SEC, NFR-REL | U, S | A `.exe` file and an empty `.csv` both raise `ValueError`. | Pass |

## 4. Authentication and default-deny (API)

File: `backend/tests/integration/test_api_auth.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-01 | `test_login_protected_inventory_and_default_deny` | NFR-SEC, UC-1 | A, S | Anonymous `GET /assets` returns 401. Login with a bcrypt password returns 200 with an access token. The assets list contains only the scoped asset, `GET /users` returns 200 for the analyst alias, and the secret key is set. | Pass |

## 5. Ingestion and correlation workflows (service integration)

File: `backend/tests/integration/test_workflows.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-02 | `test_import_normalize_score_and_create_task` | UC-3, UC-4, UC-6, UC-8, SC-2 | I | A scanner row for `web01.bank.local` (CVSS 9.8) against a tier-1, exposed, crown-jewel, PCI asset. Batch success 1 / failed 0, a finding with risk > 0, and a task assigned to the asset owner. | Pass |
| TC-I-03 | `test_each_source_normalizes_to_a_finding` [4] | UC-3, SC-2 | I | One record each for CSPM, pentest, container and identity, using source-specific field names. Each gives success 1 and a stored finding. | Pass |
| TC-I-04 | `test_same_asset_cve_deduplicates_and_keeps_both_sources` | UC-4, SC-3 | I | Scanner then container rows for the same asset and CVE. The second batch has `duplicate_count == 1`, one finding exists, and its sources are {scanner, container}. | Pass |
| TC-I-05 | `test_asset_owner_fallback_and_ordered_ownership_rule` | UC-8, SC-6 | I | Without rules the asset owner is chosen; after a priority-1 `asset_type=server` rule, the rule's user is chosen. | Pass |
| TC-I-06 | `test_attack_path_connects_entry_to_crown_jewel_and_feedback` | UC-7, SC-9 | I | Assets entry → middle → crown linked by connections. `recalculate_paths` stores 1 path with the expected asset IDs. On the middle finding, the `attack_path_influence` factor has final score = risk score > base score. | Pass |
| TC-I-07 | `test_sla_escalation_levels_are_idempotent` | UC-10, SC-7 | I | A task 15 days overdue under a policy with level-1 = 1 day and level-2 = 2 days. The first run creates 3 escalations; the second creates 0. | Pass |
| TC-I-08 | `test_exception_self_approval_blocked_and_approved_finding_accepted` | UC-11, SC-8, NFR-SEC | I, S | The requester approving their own exception gets 403. A separate approver approves, and the finding becomes `risk_accepted`. | Pass |
| TC-I-09 | `test_exception_expiry_reopens_finding` | UC-11, SC-8 | I | An approved exception past its expiry: `expire_exceptions` returns 1 and the finding returns to `open`. | Pass |
| TC-I-10 | `test_role_guard_denies_unauthorized_user` | NFR-SEC | U, S | `has_permission(auditor, AUDIT_READ)` is true; `security_analyst` lacks `EXCEPTION_APPROVE_ALL`. | Pass |

## 6. RBAC matrix, data scope and API hardening

File: `backend/tests/integration/test_role_matrix.py`

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-11 | `test_every_role_gets_exactly_its_permissions` [9] | NFR-SEC, actors (9 roles) | A, S | For each role, 24 guarded endpoints return 200 if `ROLE_PERMISSIONS` grants the permission and 403 if not. | Pass |
| TC-I-12 | `test_unauthenticated_requests_are_rejected` | NFR-SEC | A, S | All 24 endpoints return 401 without a bearer token. | Pass |
| TC-I-13 | `test_read_only_roles_cannot_change_anything` | NFR-SEC | A, S | For auditor and CISO, finding status PATCH, risk recalculation and scoring PUT all return 403. | Pass |
| TC-I-14 | `test_login_payload_carries_permissions` | NFR-SEC, NFR-USE | A | The auditor login payload includes `audit:read` and not `finding:read`; `/auth/me` returns the same list. | Pass |
| TC-I-15 | `test_business_unit_manager_sees_only_own_unit_everywhere` | NFR-SEC, BO-1 | A, S | The BU manager sees only the unit-A finding. Unit-B finding detail returns 404. The exceptions list, CSV export (header + 1 row) and manager dashboard KPI agree. | Pass |
| TC-I-16 | `test_out_of_scope_findings_are_hidden_from_ai_and_exception_requests` | NFR-SEC, UC-13, UC-11 | A, S | The architect (scoped to unit A) gets 404 from `/ai/explain/{f_b}` and from an exception request on `f_b`. | Pass |
| TC-I-17 | `test_system_administrator_sees_only_assets_with_assigned_tasks` | NFR-SEC, actor: System Administrator | A, S | The asset list for the system administrator is `["asset-a"]` only. | Pass |
| TC-I-18 | `test_auditor_dashboard_and_exception_page_agree` | NFR-SEC, NFR-AUD, SC-10 | A | Exceptions page count = auditor dashboard exception count = 2. | Pass |
| TC-I-19 | `test_ai_answers_name_their_sources_and_respect_scope` | UC-13, UC-14, NFR-EXPL, NFR-SEC | A | The analyst gets intent `prioritize_findings` with a sources table (`findings`, 2 rows). The architect sees only the unit-A finding. "Anything overdue on SLA?" gives intent `sla_status` with 1 row. | Pass |
| TC-I-20 | `test_finding_list_paging_sorting_and_total_header` | NFR-USE, NFR-PERF | A | `limit/offset/sort/order` paging, `X-Total-Count = 2`, `sort=password` returns 422, and the `crown_jewel=true` filter returns a total of 1. | Pass |
| TC-I-21 | `test_csv_exports_neutralise_formula_injection` | NFR-SEC | A, S | The findings export prefixes `=HYPERLINK(...)` with `'`; every exception justification starts with `'+`. | Pass |
| TC-I-22 | `test_config_changes_are_audited` | NFR-AUD, NFR-MAINT | A | An SLA PUT, ownership-rule create and delete write `sla_policy_changed`, `ownership_rule_created` and `ownership_rule_deleted`. The audit facets list the action, and the action filter returns 1 row with the actor's email. | Pass |
| TC-I-23 | `test_locked_account_is_refused_not_crashed` | NFR-SEC, NFR-REL | A, S | An account with `locked_until` in the future, reloaded as a naive SQLite timestamp, gets 401 (not 500). | Pass |
| TC-I-24 | `test_overdue_tasks_filter_in_sql` | UC-10 | A | `/tasks/overdue` returns 200 with `X-Total-Count = 1`. | Pass |
| TC-I-25 | `test_user_updates_validate_roles_and_protect_self` | NFR-SEC | A, S | Role `superuser` returns 422. The `analyst` alias maps to `security_analyst`. An admin deactivating themselves gets 409. | Pass |
| TC-I-26 | `test_finding_status_is_validated` | UC-9, NFR-REL | A | Status `pwned` returns 422; `in_remediation` returns 200. | Pass |

## 7. Seeded demo smoke tests

File: `backend/tests/integration/test_seeded_smoke.py` (full `seed_demo` once per module)

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-27 | `test_seed_matches_documented_dataset` | SC-1, NFR-PRIV (synthetic data) | I | 300 assets, more than 1,500 open findings, at least 1 attack path. A second `seed_demo` call is idempotent (still 300). | Pass |
| TC-I-28 | `test_read_endpoints_respond_on_seeded_data` [5] | SC-10, section 13 dashboards, UC-12 | A | Admin (23 read endpoints including dashboards, heatmap, trend, MTTR, SLA compliance, metrics, recommendations), analyst dashboard, manager dashboard + escalations, auditor dashboard and owner `tasks/my` all return 200. | Pass |
| TC-I-29 | `test_detail_endpoints_and_what_if_on_seeded_data` | UC-6, UC-7, UC-13, NFR-EXPL | A | Finding detail, risk explain, asset detail/findings/connections, attack-path detail, `/ai/explain` and `/ai/executive-summary` (non-empty) all return 200. | Pass |
| TC-I-30 | `test_assistant_intents_on_seeded_data` [5] | UC-14 | A | Questions map to `asset_inventory`, `exception_status`, `attack_paths`, `threat_exposure` and `portfolio_summary`, each with sources and a non-empty answer. | Pass |

## 8. Specification features (pass 2)

File: `backend/tests/integration/test_spec_features.py`

### 8.1 Ingestion, correlation, recovery

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-31 | `test_asset_keys_keep_ip_addresses_and_parse_urls` | UC-4 | U | `10.0.0.2` stays whole and differs from `10.0.0.3`; URL `https://host004.bank.local:8443/login` gives `host004`. | Pass |
| TC-I-32 | `test_survivorship_keeps_strongest_evidence_and_unions_sources` | UC-4, SC-3 | I | A medium/5.0 scanner row followed by a critical/9.1 EASM row for the same CVE. Duplicate count 1; the surviving finding has severity critical, CVSS 9.1, sources [scanner, easm] and the longer EASM description. | Pass |
| TC-I-33 | `test_failed_rows_are_kept_and_recoverable_after_asset_registration` | UC-3, UC-1, NFR-REL | A | An EASM row for an unknown FQDN gives failed 1; the raw row keeps "Asset not found". `GET /imports/{id}/failed-rows` returns the payload. After registering the asset, retry gives success 1 / failed 0; a second retry returns 409. | Pass |
| TC-I-34 | `test_closed_finding_is_reopened_when_detected_again` | UC-4, UC-9, NFR-AUD | I | A closed finding detected again is `open` with `reopened_count == 1`, and a `finding_reopened` audit row exists. | Pass |

### 8.2 Threat intelligence, scoring, attack paths

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-35 | `test_threat_feed_parses_booleans_and_rescores_affected_findings` | UC-5, UC-6, SC-5 | A | `POST /threat-intel/import` with string booleans (`"true"`, `"yes"`, `"false"`), EPSS 0.9 and `weaponized`, plus one invalid CVE. Updated 1, rescored 1, skipped 1; `ransomware_used` is stored as False; the finding's risk score increases. | Pass |
| TC-I-36 | `test_rescoring_preserves_attack_path_influence` | UC-6, UC-7, SC-9 | I | With a stored path containing `f_a`, `rescore_findings` keeps `attack_path_influence` points > 0 and final > base. | Pass |
| TC-I-37 | `test_attack_path_impact_reports_rank_and_band_changes` | UC-7, SC-9 | A | `GET /attack-paths/impact` shows `findings_on_paths == 1` and final > base. | Pass |
| TC-I-38 | `test_attack_graph_exports_for_graph_databases` | UC-7, bonus: graph DB | A | `/attack-paths/export?format=cypher` contains `MERGE (:Asset {id: "`; `format=graphml` contains `<graphml` and the asset name. | Pass |

### 8.3 Assets and criticality

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-39 | `test_asset_registration_validates_and_audits` | UC-1, NFR-SEC, NFR-AUD | A, S | Bad `asset_type` returns 422; an unknown field returns 422 (`extra=forbid`). A valid asset returns 201 with regulatory tags deduplicated to `["PCI-DSS"]`; a case-insensitive duplicate name returns 409; `asset_registered` is audited. | Pass |
| TC-I-40 | `test_criticality_change_rescores_findings_and_is_audited` | UC-2, UC-6, NFR-AUD | A | The vulnerability manager PATCHes crown jewel, exposure and tier 1. `findings_rescored == 1` and the score rises; `asset_updated` records old and new values; the analyst gets 403. | Pass |
| TC-I-41 | `test_bulk_asset_import_reports_row_errors` | UC-1, NFR-REL | A | Three rows (valid, duplicate, bad environment) give created 1 and 2 errors. | Pass |
| TC-I-42 | `test_asset_rows_unaffected` | Test isolation | I | Sanity check that `asset-a` still exists, i.e. helper tests do not leak state. | Pass |

### 8.4 Ownership, remediation, SLA

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-43 | `test_ownership_rules_match_names_tags_and_groups` | UC-8, SC-6 | I | The `tag=pci-dss` rule assigns group `payments-sre`, reason `rule:tag=pci-dss`, and keeps the asset owner as the user. Without the tag, the `business_unit=Unit A` rule (matched by name) assigns the system administrator. | Pass |
| TC-I-44 | `test_unowned_asset_falls_back_to_business_unit_manager` | UC-8 | I | With no owner, `decide_owner` returns the BU manager. | Pass |
| TC-I-45 | `test_reassignment_requires_task_manage_and_is_audited` | UC-8, NFR-SEC, NFR-AUD | A | The owner gets 403 on `/tasks/{id}/assign`. The vulnerability manager gets 200 with `assigned_by_rule == manual_override`, and `ownership_reassigned` is audited. | Pass |
| TC-I-46 | `test_closing_a_task_closes_its_finding` | UC-9 | A | Statuses in_progress → pending_verification move the finding to `in_remediation`. Closing with evidence closes the finding and sets `closed_at`; the task history lists all three transitions. | Pass |
| TC-I-47 | `test_escalation_thresholds_follow_sla_policy` | UC-10, SC-7 | I | Policy level-1 = 1 day, level-2 = 30 days, task 2 days overdue: exactly one level-1 escalation, and `sla_escalated` is audited. | Pass |
| TC-I-48 | `test_escalation_acknowledgement_and_personal_inbox` | UC-10, NFR-USE | A | The BU manager's inbox has an `escalation` item and the system administrator's has `overdue_task`. The auditor acknowledging gets 403; the manager gets 200 and the escalation records who acknowledged it. | Pass |
| TC-I-49 | `test_sla_report_and_breach_forecast` | UC-10, BO-4, bonus: SLA-breach forecast | A | The `/tasks/export` CSV header starts `task_id, finding_id, asset_id` and has 1 data row; `/tasks/breach-forecast` shows `already_breached == 1`. | Pass |

### 8.5 Ticketing, exceptions

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-50 | `test_ticket_lifecycle_and_signed_webhook` | SC-11, TO-7, bonus: ServiceNow/Jira | A, S | Create Jira-sim ticket returns 201; a duplicate for the same task returns 409; looking it up under ServiceNow-sim returns 404. A webhook with a bad signature returns 401; a valid HMAC-SHA256 webhook returns 200, moves the task to `pending_verification`, and sets the ticket to `resolved`. | Pass |
| TC-I-51 | `test_exception_review_pack_json_and_html` | UC-11, SC-8, bonus: review packs | A, S | The auditor gets the JSON pack with the exception ID and the "Compensating controls documented" check; the HTML variant is `text/html` and contains no `<script`. | Pass |

### 8.6 Security: MFA, passwords, audit chain, secrets

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-52 | `test_mfa_enrollment_login_and_rotation` | NFR-SEC (MFA) | A, S | Setup → verify with a wrong code returns 400, with the current TOTP returns 200. Login without a code: 401 "MFA code required"; wrong code: 401; correct code: 200 and `mfa_enabled`. Re-setup without a code returns 403. | Pass |
| TC-I-53 | `test_mfa_applies_to_every_role_that_enables_it` | NFR-SEC (MFA) | A, S | An auditor who enrolled MFA cannot log in without a code (401). | Pass |
| TC-I-54 | `test_password_change_enforces_policy_and_revokes_sessions` | NFR-SEC | A, S | Wrong current password returns 403; a weak new password returns 422; a valid change returns 200 and `refresh_token_hash` is cleared. | Pass |
| TC-I-55 | `test_audit_chain_detects_tampering_and_triggers_block_edits` | NFR-AUD, NFR-SEC | I, S | Three records verify as valid (checked 3). A direct SQL UPDATE makes verification fail at sequence 2. After installing the `SQLITE_TRIGGERS` from migration 0002, a DELETE raises "append-only". | Pass |
| TC-I-56 | `test_audit_verify_endpoint` | NFR-AUD | A | The auditor's `GET /audit/verify` returns 200 with `valid: true`. | Pass |
| TC-I-57 | `test_weak_secret_is_rejected_outside_development` | NFR-SEC (secrets) | U, S | `Settings(app_env="production", secret_key="short")` raises; a 40-character key is accepted. | Pass |

### 8.7 Reporting, AI, measured criteria

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-I-58 | `test_reports_endpoints_respond` | UC-12, SC-1..SC-12, BO-5, BO-7, bonus: remediation sequencing, forecast | A | Success criteria, automation impact, ownership accuracy, remediation plan, forecast and executive report all return 200. The criteria IDs are exactly SC-1..SC-12; the HTML report has its title; `executive_report_generated` is audited. | Pass |
| TC-I-59 | `test_assistant_understands_entities_and_follow_ups` | UC-13, UC-14, bonus: conversational assistant | A | Entities `business_unit=Unit B` and `band=high` are extracted. The follow-up "what about Unit A?" carries context forward. "who owns asset-a" gives `owner_lookup` with the owner's name; "what should we fix first?" gives `remediation_plan`; the query is logged in `AiQueryLog`. | Pass |
| TC-I-60 | `test_ownership_accuracy_uses_dataset_ground_truth` | SC-6 | A | The report target is 90 and the ground truth is `owner_email` from the dataset. | Pass |

## 9. Frontend (Vitest)

| ID | File / test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-F-01 | `App.test.tsx` › shows the seeded local demo sign-in without requesting data | NFR-USE, NFR-A11Y | F | The "Sign in to IVM" heading is present, and the email and password fields are found by label and prefilled with demo values. | Pass |
| TC-F-02 | `App.test.tsx` › asks sessions saved without permissions to sign in again | NFR-SEC | F | A stored user without `permissions` is sent back to the login screen. | Pass |
| TC-F-03 | `App.test.tsx` › builds navigation from permissions and redirects guarded routes | NFR-SEC, NFR-USE | F | The auditor's nav shows "Audit trail" and hides "Data imports" and "Findings". Visiting `/imports` shows an alert and not the import page. | Pass |
| TC-F-04 | `access.test.ts` › hides finding and path pages from the CISO | NFR-SEC, SC-10 | F | The CISO's nav is exactly Overview and Reports & insights. | Pass |
| TC-F-05 | `access.test.ts` › shows the audit trail to auditors but not remediation or imports | NFR-SEC | F | The auditor's nav is Overview, Risk exceptions, Reports & insights and Audit trail. | Pass |
| TC-F-06 | `access.test.ts` › does not offer the audit trail to vulnerability managers without audit:read | NFR-SEC | F | The manager's nav includes Administration and excludes Audit trail. | Pass |
| TC-F-07 | `access.test.ts` › maps each role to its dashboard view | SC-10 | F | CISO/admin → executive, analyst → analyst, BU manager → manager, auditor → auditor. | Pass |
| TC-F-08 | `access.test.ts` › sends owners and system administrators to their own task queue | UC-9, NFR-USE | F | `usesOwnTaskQueue` is true for owner and system administrator, false for the manager. | Pass |
| TC-F-09 | `api/client.test.ts` › refreshes once and retries when the access token has expired | NFR-SEC, NFR-USE | F | Two concurrent 401 responses trigger exactly one `/auth/refresh`. Both calls retry and succeed, and the rotated refresh token is stored. | Pass |
| TC-F-10 | `api/client.test.ts` › reports session loss when the refresh token is rejected | NFR-SEC | F | A rejected refresh calls `expired` once and rejects with the server message. | Pass |
| TC-F-11 | `api/client.test.ts` › reads the unpaged total from X-Total-Count | NFR-USE | F | `apiPage` returns `{rows, total: 42}`. | Pass |
| TC-F-12 | `api/client.test.ts` › builds query strings without empty values | NFR-USE | F | Empty and undefined values are dropped; `false` and numbers are kept. | Pass |

## 10. End-to-end (Playwright, Chromium)

File: `e2e/workflows.spec.ts`. Demo users: `user1` platform admin, `user2` security analyst, `user4` vulnerability manager, `user5` auditor, `user8` IT asset owner, `user11` executive/CISO (from `backend/app/db/seed.py`). Durations are from `e2e-results.txt`.

| ID | Test | Requirements | Type | Steps / assertion summary | Status |
|---|---|---|---|---|---|
| TC-E-01 | analyst imports a scanner file and sees a batch result | UC-3, UC-4, SC-2, SC-3 | E | The analyst uploads `backend/data/synthetic/scanner_export.csv` → "Import finished" and a duplicates figure are shown. (1.4 s) | Pass |
| TC-E-02 | finding work can be closed with evidence | UC-9 | E | The owner enters remediation evidence, then moves an open task through in_progress → pending_verification → closed; each status pill updates. (841 ms) | Pass |
| TC-E-03 | manager runs the SLA job and reviews escalation records | UC-10, SC-7 | E | The manager clicks Administration → Run scheduler → "escalations created" and "Recent escalations" appear. (663 ms) | Pass |
| TC-E-04 | exception request is approved by a separate approver and appears in the audit trail | UC-11, SC-8 | E | The manager picks a finding; the analyst requests an exception (expiry, justification) and it shows pending; the manager approves it and it shows approved. (2.3 s) | Pass |
| TC-E-05 | analyst views attack paths and asks the offline assistant | UC-7, UC-14, UC-13 | E | The Attack paths page shows "modeled paths". On the assistant page, the prompt is sent, the input clears, the user message is shown, and "AI-generated demo guidance" appears. (1.4 s) | Pass |
| TC-E-06 | navigation shortcuts and a page refresh keep the signed-in session | NFR-USE, NFR-SEC | E | Findings → "Import findings" shortcut → reload: the page and nav remain and the login screen is not shown. (564 ms) | Pass |
| TC-E-07 | finding detail sends its context to the assistant and chat follows new messages | UC-13, NFR-EXPL, NFR-USE | E | "Explain with AI" on a finding → the chat shows the title in the question and the answer; 4 more messages give 5 exchanges, and the history is scrolled to the bottom. (2.4 s) | Pass |
| TC-E-08 | executive gets a portfolio dashboard and only the pages their role allows | SC-10, UC-12, NFR-SEC | E | The CISO sees Overview but no Findings link, "Executive risk overview" and "Risk by business unit". "Generate briefing" shows an AI demo summary. Direct `/findings` does not render the page. (1.3 s) | Pass |
| TC-E-09 | analyst filters, sorts and pages through findings on the server | NFR-USE, NFR-PERF | E | Next page shows "51–100 of"; the critical band filter sets the URL and "1–50 of"; sorting by risk score ascending gives the first ≤ the second. (1.3 s) | Pass |
| TC-E-10 | administrator registers an asset and reclassifies its criticality | UC-1, UC-2 | E | The admin registers an asset via the form, then edits it to crown jewel and internet exposed → "Saved", and "Crown jewel: Yes" is shown. (1.5 s) | Pass |
| TC-E-11 | manager opens a task, raises a Jira ticket and sees it on the task | SC-11, UC-9, UC-10, NFR-A11Y | E | The task drawer (dialog "Task details") shows "SLA breach risk"; "Create Jira ticket" shows `JIRA_SIM` and `IVM-XXXXXXXX · open`; Escape closes the drawer. (1.0 s) | Pass |
| TC-E-12 | executive reviews measured success criteria and downloads the board report | UC-12, SC-1..SC-12, BO-5, bonus: board summaries, remediation sequencing | E | Reports & insights shows a "Success criteria" table with 12 rows and the "First five campaigns remove" plan text; downloading the executive report gives `ivm-executive-report.html`. (2.9 s) | Pass |
| TC-E-13 | auditor verifies the tamper-evident audit chain | NFR-AUD, actor: Auditor | E | Audit trail → "Verify integrity" → "Hash chain intact". (707 ms) | Pass |

## 11. Non-functional checks (not test functions)

| ID | Check | Requirements | Evidence | Result |
|---|---|---|---|---|
| TC-N-01 | Executive dashboard API latency, 10 samples | NFR-PERF | `dashboard-latency.txt` | mean 0.500 s, p95 0.514 s (target < 3 s) — Pass |
| TC-N-02 | Whole-backend coverage gate ≥ 70% | Section 11 practices | `backend-tests.txt` | 85% (85.33%) — Pass |
| TC-N-03 | ruff, black, mypy | NFR-MAINT | `ruff.txt`, `black.txt`, `mypy.txt` | Clean — Pass |
| TC-N-04 | bandit SAST | NFR-SEC | `bandit.txt` | No issues identified — Pass |
| TC-N-05 | pip-audit / npm audit | NFR-SEC, dependency-scan deliverable | `pip-audit.txt`, `npm-audit.txt` | No known vulnerabilities / 0 vulnerabilities — Pass |
| TC-N-06 | ESLint + production build | NFR-MAINT | `eslint.txt`, `frontend-build.txt` | Clean; built in 866 ms — Pass |
| TC-N-07 | Success criteria on a fresh seed | SC-1..SC-12 | `success-criteria.json` | 12/12 `passed: true` — Pass |
| TC-N-08 | gitleaks secrets scan | NFR-SEC | CI job `secrets` only | Not run locally — Not verified |
| TC-N-09 | Docker compose build / PostgreSQL runtime | NFR availability, bonus: containers | CI job `docker` only | Not run locally — Not verified |

## 12. Known coverage gaps in the catalogue

- No automated test checks the scope of `/ai/recommendations`, exception review/revoke, ticket creation for an out-of-scope task, or ticket audit rows. These fixes (DEF-003, DEF-004, DEF-028) were checked by code review and manual re-test only.
- No automated test checks SLA-compliance arithmetic for late-closed tasks (DEF-029), the scoring-weight display (DEF-013), the task-comment fix (DEF-014) or the login timing equalisation (part of DEF-026).
- Dashboard section-13 widgets are only checked for an HTTP 200 response (TC-I-28) and partial rendering (TC-E-08); their computed values are not asserted.
- There is no automated accessibility scan (contrast, focus order).

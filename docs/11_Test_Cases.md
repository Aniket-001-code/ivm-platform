# Test Cases

The cases below map to `BR-xx` requirements. The regression subset should run for every pull request; role and workflow cases are repeated in the Playwright environment.

| ID | Objective | Steps | Expected result | Requirement |
|---|---|---|---|---|
| TC-001 | Generate stable assets | Run generator twice with seed 42 | Asset JSON is repeatable | BR-01 |
| TC-002 | Generate all business units | Inspect unit output | Five named units exist | BR-01 |
| TC-003 | Generate business services | Inspect service output | Twelve services exist | BR-01 |
| TC-004 | Generate asset target count | Count assets by ID | Exactly 300 assets | BR-01 |
| TC-005 | Validate exposure proportion | Count internet flags | Approximately one fifth exposed | BR-01 |
| TC-006 | Validate crown-jewel proportion | Count crown flags | Approximately eight percent | BR-01 |
| TC-007 | Generate catalog | Count catalog rows | 120 CVE rows | BR-04 |
| TC-008 | Keep malformed fixture rows | Inspect scanner CSV | Invalid rows remain for error path | BR-02 |
| TC-009 | Parse scanner CSV | Parse fixture | Host/CVE/severity fields retained | BR-02 |
| TC-010 | Parse CSPM JSON | Parse fixture | Array of resource findings returned | BR-02 |
| TC-011 | Parse pentest JSON | Parse fixture | Risk rating and target retained | BR-02 |
| TC-012 | Parse container JSON | Parse fixture | Image and CVE fields retained | BR-02 |
| TC-013 | Reject unsupported extension | Upload executable extension | 400 validation error | BR-02 |
| TC-014 | Reject empty upload | Upload empty bytes | Batch is not created | BR-02 |
| TC-015 | Enforce 10 MB limit | Upload over limit | Request rejected | BR-02 |
| TC-016 | Normalize critical alias | Normalize `crit` | `critical` returned | BR-03 |
| TC-017 | Normalize severity default | Normalize missing severity | `medium` returned | BR-03 |
| TC-018 | Correlate FQDN alias | Resolve `web01.bank.local` | Same asset as `web01` | BR-03 |
| TC-019 | Correlate scanner CVE | Import known target/CVE | One normalized finding | BR-03 |
| TC-020 | Merge cross-tool duplicate | Import same asset/CVE twice | Duplicate count increments | BR-03 |
| TC-021 | Retain traceability | Inspect merged sources | Both raw rows remain linked | BR-03 |
| TC-022 | Report unknown asset | Import unmapped host | Row error captured | BR-02 |
| TC-023 | Score CVSS | Score a high CVSS finding | Severity factor points increase | BR-05 |
| TC-024 | Score criticality | Compare tier 1 and tier 5 assets | Tier 1 receives higher score | BR-05 |
| TC-025 | Score exposure | Compare exposed and internal assets | Exposed asset score increases | BR-05 |
| TC-026 | Score KEV signal | Add KEV metadata | Threat factor increases | BR-04 |
| TC-027 | Score EPSS signal | Raise EPSS | Threat points rise monotonically | BR-04 |
| TC-028 | Bound score | Use maximum all factors | Score remains at or below 100 | BR-05 |
| TC-029 | Explain score | Fetch explain endpoint | Points and reason strings exist | BR-05 |
| TC-030 | Recalculate history | Run risk recalculation | History record is inserted | BR-05 |
| TC-031 | Build attack graph | Recalculate routes | Exposed-to-crown-jewel paths stored | BR-06 |
| TC-032 | Add path feedback | Score a path finding | Path signal raises score | BR-06 |
| TC-033 | Reject missing route | Use disconnected target | No path row emitted | BR-06 |
| TC-034 | Owner fallback | Create high finding on owned asset | Task inherits asset owner | BR-07 |
| TC-035 | Create SLA due date | Seed critical task | Due date uses critical policy | BR-07 |
| TC-036 | Close task without evidence | PATCH status closed | 422 response | BR-07 |
| TC-037 | Close task with evidence | Add evidence and close | Status closes and update is stored | BR-07 |
| TC-038 | Reject another owner's change | Update assigned task as peer | 403 response | BR-07 |
| TC-039 | Escalate overdue task | Run SLA job twice | First run creates levels; second is idempotent | BR-07 |
| TC-040 | Detect overdue task | Query overdue endpoint | Open past-due task is returned | BR-07 |
| TC-041 | Create exception | Submit reason, controls, expiry | Pending row and audit event exist | BR-09 |
| TC-042 | Block self-approval | Request then approve as requester | 403 response; still pending | BR-09 |
| TC-043 | Approve exception | Approver decides | Status approved and finding accepted | BR-09 |
| TC-044 | Reject exception | Approver rejects | Status rejected; finding remains open | BR-09 |
| TC-045 | Enforce expiry horizon | Request more than 365 days | 422 response | BR-09 |
| TC-046 | Expire approved exception | Run expiry job after expiry | Expired status and reopened finding | BR-09 |
| TC-047 | Authenticate correct password | Login seeded analyst | Access and refresh tokens returned | BR-10 |
| TC-048 | Reject bad password | Login with bad password | 401; failure audit created | BR-10 |
| TC-049 | Lock account | Submit five failures | Further login rejected during lock | BR-10 |
| TC-050 | Reject missing bearer | Call protected route anonymously | 401 structured error | BR-10 |
| TC-051 | Enforce role restriction | Analyst reads audit API | 403 response | BR-10 |
| TC-052 | Rotate refresh token | Refresh twice with same token | Second use rejected | BR-10 |
| TC-053 | Verify TOTP | Setup and submit current code | MFA enabled | BR-10 |
| TC-054 | Verify dashboard aggregation | Fetch executive dashboard | KPI values and risk bands returned | BR-11 |
| TC-055 | Verify triage effort formula | Compare raw and action counts | Six-minute assumption is exposed | BR-11 |
| TC-056 | Ask offline assistant | Ask for priorities with no key | Rule-based answer returned | BR-12 |
| TC-057 | Log AI query | Ask a question | Audit record stores intent, not secrets | BR-12 |
| TC-058 | Create simulated ticket | Create from task | Ticket key links back to task | BR-13 |
| TC-059 | Transition ticket | Resolve simulated ticket | Task becomes pending verification | BR-13 |
| TC-060 | Health database check | GET `/health` | `status=ok` and DB check succeeds | BR-14 |

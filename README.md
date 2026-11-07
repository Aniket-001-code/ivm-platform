# Intelligent Vulnerability Management & Risk Prioritization Platform

A local academic capstone demo that turns noisy, fictional vulnerability exports into explainable business risk, attack paths, and owned remediation actions. The project does not scan networks, connect to a bank, deploy patches, or contain customer data.

## Five-minute quick start

Requirements: Docker Desktop with Compose v2.

```powershell
Copy-Item .env.example .env
# Set SECRET_KEY in .env to a local random value.
docker compose up --build
```

Open [http://localhost:8080](http://localhost:8080) for the application and [http://localhost:8000/docs](http://localhost:8000/docs) for Swagger. The first backend startup applies Alembic migrations and loads the seeded synthetic dataset. Allow a minute for the initial seed.

Stop with Ctrl+C. Remove local records with `docker compose down -v`; this deletes the named database volume.

### Open it without Docker on macOS or Linux

Requirements: Node.js 20+ and either [uv](https://docs.astral.sh/uv/) or Python 3.11–3.13.

```bash
./scripts/dev.sh
```

The script creates `.env` (random `SECRET_KEY`, local SQLite file), installs backend and frontend dependencies on first run, applies migrations, and starts the API on port 8000 and the web app on [http://127.0.0.1:5173](http://127.0.0.1:5173). Stop both with Ctrl+C.

### Open it without Docker (Windows development mode)

Do not double-click `frontend/index.html`; it is a Vite entry file and will appear blank when opened as a `file://` URL. Start the API and Vite development server instead. Use Python 3.11–3.13 and Node.js 20 or newer.

In PowerShell window 1, from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e "backend[dev]"
$env:DATABASE_URL = "sqlite:///./ivm_spec_demo.sqlite"
$env:SECRET_KEY = "local-demo-only-secret-change-before-deployment"
Push-Location backend
..\.venv\Scripts\alembic.exe upgrade head
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In PowerShell window 2, from the repository root:

```powershell
Push-Location frontend
npm ci
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173), sign in as `user2@demo.bank` with `DemoPass!234`, and explore the seeded demo. The API seeds the SQLite database on its first start. This local mode uses SQLite for development; use Docker Compose when you need to validate the PostgreSQL setup.

## Demo accounts

All accounts use the synthetic-only password `DemoPass!234`.

| Account | Role | Typical use |
|---|---|---|
| `user1@demo.bank` | Platform admin | Users, scoring, scheduler, settings |
| `user2@demo.bank` | Analyst | Imports, finding triage, risk scoring |
| `user3@demo.bank` | Analyst | Analyst workflow alternate |
| `user4@demo.bank` | Vulnerability manager | Remediation, SLA, temporary exception approval |
| `user5@demo.bank` | Auditor | Read-only audit and exception review |
| `user6@demo.bank` | Security architect | Risk and exception governance |
| `user7@demo.bank` | System administrator | Assigned system tasks |
| `user8@demo.bank`–`user10@demo.bank` | IT asset owners | Assigned tasks, evidence, closure |
| `user11@demo.bank` | Executive CISO | Portfolio risk overview |
| `user12@demo.bank` | Business unit manager | BU-scoped work and escalations |

The default login form is prefilled with `user2@demo.bank`. Change the address to switch roles. Each role sees only the menu entries and data its permissions allow, and gets its own dashboard (executive, analyst, manager, or auditor view). For local demo access, MFA enforcement is off by default; privileged accounts can enroll TOTP through the API. Set `MFA_REQUIRED=true` only after privileged users are enrolled.

## Synthetic dataset

`backend/scripts/generate_synthetic_data.py` uses seed 42 and writes 300 fictional assets, five business units, 12 services, 120 CVE metadata rows, asset connections, threat feed, and about 2,500 source rows. The scanner CSV, CSPM JSON, pentest JSON, container JSON, and identity CSV intentionally use different field names and formats. Approximately 20% of rows are deliberate duplicates, with malformed scanner rows included for error handling. CVE identifiers are public identifiers; descriptive records are synthetic and include no exploit code.

Run it locally with `python backend/scripts/generate_synthetic_data.py`. It may be run repeatedly to reproduce the same records. The seed also adds a deterministic catalog-to-asset matrix plus curated synthetic threat signals so risk bands, exceptions, escalation levels, and six months of history are populated. It creates more than 1,500 open findings. Start with a new SQLite filename such as `ivm_spec_demo.sqlite` to load the expanded seed; existing non-empty SQLite files are preserved and are not reseeded.

## Core workflows

1. Import a sample file from `backend/data/synthetic/` using the Imports page.
2. Review new, duplicate, and failed counts, then inspect a finding's factor-by-factor risk score.
3. Recalculate attack paths to see entry routes toward crown-jewel assets.
4. Sign in as a remediation owner to update an assigned task; closure requires evidence.
5. Sign in as a manager and run scheduler jobs to demonstrate overdue escalation.
6. Request an exception as one user and approve/reject as a different approver.
7. Ask the offline-first AI assistant to prioritize findings, summarize overdue work, list exploited findings, expiring exceptions or attack paths. Every answer lists the source tables and row counts it used.
8. As an administrator, edit scoring weights (with an impact preview), SLA targets, ownership rules, and user roles; every change is written to the audit trail.

The executive effort estimate assumes six minutes of manual triage per raw record that does not remain a distinct action. This is an explicit demo assumption, not a measured production savings claim.

## Configuration and security

Copy `.env.example` and set a unique local `SECRET_KEY`. PostgreSQL credentials and all API keys come from environment configuration. An empty `ANTHROPIC_API_KEY` uses the rule-based assistant. Setting it enables the optional Anthropic SDK; the prompt sends only a bounded question and aggregate synthetic context. Never use production or personal data in this demo.

The default app uses HTTP on localhost. For local TLS testing, install OpenSSL and run `./infra/tls/generate-local-cert.ps1`, then start `docker compose --profile tls up --build` and visit `https://localhost:8443`. The self-signed certificate is not suitable for deployment. See [secure design review](docs/08_Secure_Design_Review.md) for prototype limits, including browser token handling, business-unit row-level scoping, process-local scheduling, and database audit immutability.

## Test and quality commands

macOS/Linux (after `./scripts/dev.sh` has created `.venv`):

```bash
cd backend
../.venv/bin/ruff check app tests && ../.venv/bin/black --check app tests && ../.venv/bin/mypy app
../.venv/bin/python -m pytest --cov=app --cov-fail-under=70     # 113 tests, ~85% whole-backend coverage
cd ../frontend
npm test && npm run lint && npm run build                        # 12 unit tests
```

Browser tests (13 workflows) run against a running stack. Raise the login rate limit for the API process during the run, because the suite signs in more than ten times a minute:

```bash
LOGIN_RATE_LIMIT=100 ./scripts/dev.sh          # in one terminal
npm ci && npx playwright install chromium      # once, from the repository root
PLAYWRIGHT_BASE_URL=http://127.0.0.1:5173 npx playwright test
```

Windows PowerShell equivalents use `.\.venv\Scripts\python.exe` in place of `../.venv/bin/python`. Without `PLAYWRIGHT_BASE_URL`, Playwright targets the Docker Compose app on port 8080.

Security scans: `bandit -r backend/app`, `pip-audit --skip-editable`, `npm audit --audit-level=high`, and `gitleaks detect`. `.github/workflows/ci.yml` runs all of the above plus a Docker build.

## Repository map

- `backend/app/api/v1/routes/`: one FastAPI router per domain (auth, findings, assets, exceptions, …); `common.py` holds shared helpers.
- `backend/app/models/`: ORM entities grouped by domain; `entities.py` re-exports them.
- `backend/app/core/scope.py`: the single rule set for which assets each role can see (used by the API, dashboards, and AI).
- `backend/app/services`: risk engine, ingestion, attack paths, SLA, exceptions, analytics, AI assistant.
- `backend/scripts`: deterministic fixture generation and PostgreSQL backup/restore scripts.
- `frontend/src/pages/`: one file per screen; `access.ts` maps permissions to navigation and route guards; `api/client.ts` handles token refresh, paging, and CSV downloads.
- `scripts/dev.sh`: one-command local start for macOS/Linux.
- `e2e`: 13 browser-level workflow scenarios; `e2e/demo/record-demo.mjs` records the demo video.
- `deploy/k8s`: Kubernetes reference manifests; `scripts/collect_evidence.sh` regenerates `docs/evidence/`.
- `docs`: business, architecture, model, API, security, test, user/admin, demo, and traceability deliverables.
- `.github/workflows/ci.yml`: lint, tests, dependency/security scans, frontend build, Docker build.

## Deliverables

| Deliverable | Location |
|---|---|
| BRD, architecture, HLD, LLD, data model, API spec | `docs/01`–`06` (05/06 generated from code: `scripts/generate_reference_docs.py`) |
| Threat model, secure design review, secure coding checklist | `docs/07`–`09` |
| Test plan, test cases, test evidence, defect summary | `docs/10`–`13`, raw evidence in `docs/evidence/` |
| User manual, admin guide, final report, demo script | `docs/14`–`17` |
| Presentation | `docs/presentation/IVM_Final_Presentation.pptx` (outline `docs/18_Presentation.md`) |
| Project plan, traceability matrix | `docs/19_Project_Plan.md`, `docs/20_Requirements_Traceability_Matrix.md` |
| Demonstration video | `docs/demo/ivm-demo.webm` |

All twelve success criteria are measured live on **Reports & insights** (`GET /api/v1/reports/success-criteria`).

## Known limitations

This is an educational prototype. It is not certified for production banking use. Business-unit row scoping needs a stakeholder-approved policy; refresh tokens are kept in browser session storage and should move to Secure HttpOnly cookies; audit rows need database/external immutability controls; a multi-replica deployment needs a distributed scheduler; and security findings from dependency scans require review and updates. Dashboard latency depends on machine capacity and has a measurement script rather than a guarantee.

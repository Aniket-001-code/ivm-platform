"""Regenerate docs/05_Data_Model.md and docs/06_API_Specification.md from the code.

Run from the repository root: .venv/bin/python scripts/generate_reference_docs.py
"""
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app import models  # noqa: E402,F401
from app.core.rbac import ROLE_PERMISSIONS, permission_for_request  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.main import app  # noqa: E402

# ---------------- Data model ----------------
lines = [
    "# Data Model",
    "",
    "Generated from the SQLAlchemy models (`backend/app/models/*.py`) by "
    "`scripts/generate_reference_docs.py`. Every table also has `id` (UUID primary key), "
    "`created_at` and `updated_at` from `TimestampMixin`.",
    "",
    "## Migrations",
    "",
    "| Revision | Purpose |",
    "|---|---|",
    "| `0001_foundation` | Creates every table from the current metadata. |",
    "| `0002_audit_chain_and_workflow` | Adds (only when missing) `audit_logs.sequence/prev_hash/row_hash` "
    "with a unique index, `raw_findings.error_message`, `findings.closed_at/reopened_count`, "
    "`remediation_tasks.assigned_group`, `escalations.acknowledged_at/acknowledged_by`; installs "
    "triggers that reject `UPDATE` and `DELETE` on `audit_logs` (SQLite and PostgreSQL). |",
    "",
    "## Entity relationships",
    "",
    "```mermaid",
    "erDiagram",
]
tables = sorted(Base.metadata.tables.values(), key=lambda t: t.name)
for table in tables:
    for fk in table.foreign_keys:
        lines.append(f"    {fk.column.table.name} ||--o{{ {table.name} : \"{fk.parent.name}\"")
lines.append("```")
lines.append("")
lines.append("## Tables")
for table in tables:
    lines += ["", f"### `{table.name}`", "", "| Column | Type | Null | Key / index |", "|---|---|---|---|"]
    for col in table.columns:
        if col.name in {"id", "created_at", "updated_at"}:
            continue
        keys = []
        if col.foreign_keys:
            keys.append("FK → " + ", ".join(f"`{fk.target_fullname}`" for fk in col.foreign_keys))
        if col.unique:
            keys.append("unique")
        if col.index:
            keys.append("indexed")
        lines.append(f"| `{col.name}` | {col.type} | {'yes' if col.nullable else 'no'} | {', '.join(keys)} |")
lines += [
    "",
    "## Synthetic dataset → tables",
    "",
    "| File (`backend/data/synthetic/`) | Loaded into |",
    "|---|---|",
    "| `business_units.json`, `business_services.json` | `business_units`, `business_services` |",
    "| `assets.json` (300 assets; `owner_email` is the SC-6 ownership ground truth) | `assets` |",
    "| `asset_connections.json` | `asset_connections` (attack-path graph edges) |",
    "| `vulnerability_catalog.json`, `threat_intel_feed.json` (120 CVEs) | `vulnerability_catalog` |",
    "| `scanner_export.csv`, `cspm_findings.json`, `pentest_report.json`, `container_k8s_findings.json`, "
    "`identity_findings.csv`, `easm_findings.json` | `import_batches`, `raw_findings`, `finding_sources`, `findings` |",
    "",
    "Retention: raw rows (including failed rows) are kept for traceability and retry; audit rows are append-only; "
    "score history is kept per recalculation and drives trend analytics.",
]
(ROOT / "docs/05_Data_Model.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

# ---------------- API specification ----------------
schema = app.openapi()
roles_for = {}
for perm in {p for perms in ROLE_PERMISSIONS.values() for p in perms}:
    roles_for[perm] = sorted(r for r, perms in ROLE_PERMISSIONS.items() if perm in perms)
groups: dict[str, list[str]] = {}
for path, ops in schema["paths"].items():
    for method, op in ops.items():
        api_path = path.removeprefix("/api/v1")
        if path.startswith("/api/v1/integrations"):
            perm = "HMAC signature (no user session)"
        elif not path.startswith("/api/v1") or path in {"/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/refresh"}:
            perm = "public"
        else:
            request = SimpleNamespace(method=method.upper(), url=SimpleNamespace(path=path))
            perm = f"`{permission_for_request(request).value}`"
        params = ", ".join(
            f"`{p['name']}`" for p in op.get("parameters", []) if p.get("in") in {"query", "path"}
        )
        body = "yes" if "requestBody" in op else ""
        summary = (op.get("description") or op.get("summary") or "").strip().split("\n")[0]
        area = api_path.strip("/").split("/")[0] or "root"
        groups.setdefault(area, []).append(
            f"| {method.upper()} | `{path}` | {perm} | {params} | {body} | {summary} |"
        )
out = [
    "# API Specification",
    "",
    f"Generated from the live OpenAPI schema ({sum(len(v) for v in groups.values())} operations) and the central "
    "permission map (`backend/app/core/rbac.py`) by `scripts/generate_reference_docs.py`. Interactive docs: `/docs`; "
    "machine-readable schema: `/openapi.json` (copy in `docs/evidence/openapi.json`).",
    "",
    "## Conventions",
    "",
    "- **Auth**: `POST /api/v1/auth/login` with `{email, password, totp_code?}` returns `access_token` (JWT, 15 min), "
    "`refresh_token` (7 days, rotated on every use) and the user with `permissions`. If MFA is enabled and no code is "
    "sent, the response is `401 {\"error\":{\"message\":\"MFA code required\"}}`. Send `Authorization: Bearer <access>`; "
    "refresh with `POST /api/v1/auth/refresh {refresh_token}`; `POST /api/v1/auth/logout` revokes the refresh token.",
    "- **Authorization**: every authenticated route is checked twice — the central default-deny permission below, and "
    "row-level scope (`backend/app/core/scope.py`): out-of-scope records return `404`.",
    "- **Errors**: `{\"error\": {\"code\", \"message\", \"details\"}}`. 401 unauthenticated, 403 permission, 404 not found/"
    "out of scope, 409 conflict (state transition, duplicate), 413 too large, 422 validation, 429 rate limited.",
    "- **Paging**: list endpoints accept `limit`/`offset` (and `sort`/`order` where listed) and return the unpaged total "
    "in `X-Total-Count`. Every response carries `X-Request-ID`.",
    "- **Exports**: `*/export` return CSV with formula-injection neutralisation; `reports/executive?format=html` and "
    "`exceptions/{id}/review-pack?format=html` return printable HTML.",
    "- **Webhook**: `POST /api/v1/integrations/ticketing/webhook` with body `{ticket_key, status}` and header "
    "`X-IVM-Signature: sha256=<hex HMAC-SHA256 of the raw body using INTEGRATION_WEBHOOK_SECRET>`.",
    "- **Rate limits**: login `LOGIN_RATE_LIMIT`/min (default 10), AI `AI_RATE_LIMIT`/min (default 20), per client IP.",
    "",
    "## Permissions → roles",
    "",
    "| Permission | Roles |",
    "|---|---|",
]
for perm in sorted(roles_for, key=lambda p: p.value):
    out.append(f"| `{perm.value}` | {', '.join(roles_for[perm])} |")
for area in sorted(groups):
    out += ["", f"## `{area}`", "", "| Method | Path | Permission | Path/query params | Body | Description |",
            "|---|---|---|---|---|---|", *sorted(groups[area], key=lambda r: r.split("|")[2])]
(ROOT / "docs/06_API_Specification.md").write_text("\n".join(out) + "\n", encoding="utf-8")
print("written")

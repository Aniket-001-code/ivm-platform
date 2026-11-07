"""Role-by-endpoint access matrix and data-scope tests.

Each of the nine canonical roles is checked against every guarded area of the API, both
for "allowed vs forbidden" and for "only sees data inside its scope".
"""

import csv
import io
from datetime import datetime, timedelta, timezone

import pytest

from app.core.rbac import ROLE_PERMISSIONS, Permission
from app.models.entities import (
    AuditLog,
)

ROLES = sorted(ROLE_PERMISSIONS)

# (method, path, body, permission the route must require)
ENDPOINTS = [
    ("GET", "/api/v1/users", None, Permission.USER_READ),
    ("GET", "/api/v1/assets", None, Permission.ASSET_READ),
    ("GET", "/api/v1/assets/export", None, Permission.ASSET_READ),
    ("GET", "/api/v1/findings", None, Permission.FINDING_READ),
    ("GET", "/api/v1/findings/export", None, Permission.FINDING_READ),
    ("GET", "/api/v1/imports", None, Permission.FINDING_READ),
    ("GET", "/api/v1/attack-paths", None, Permission.ATTACK_PATH_READ),
    ("GET", "/api/v1/tasks", None, Permission.TASK_READ),
    ("GET", "/api/v1/exceptions", None, Permission.EXCEPTION_READ),
    ("GET", "/api/v1/exceptions/export", None, Permission.EXCEPTION_READ),
    ("GET", "/api/v1/audit", None, Permission.AUDIT_READ),
    ("GET", "/api/v1/audit/export", None, Permission.AUDIT_READ),
    ("GET", "/api/v1/audit/facets", None, Permission.AUDIT_READ),
    ("GET", "/api/v1/config/scoring", None, Permission.CONFIG_READ),
    ("GET", "/api/v1/config/sla", None, Permission.CONFIG_READ),
    ("GET", "/api/v1/config/ownership-rules", None, Permission.CONFIG_READ),
    ("PUT", "/api/v1/config/sla", [], Permission.CONFIG_MANAGE),
    ("GET", "/api/v1/escalations", None, Permission.NOTIFICATION_READ),
    ("GET", "/api/v1/dashboards/executive", None, Permission.RISK_READ),
    ("GET", "/api/v1/dashboards/trend", None, Permission.RISK_READ),
    ("GET", "/api/v1/metrics", None, Permission.REPORT_READ),
    ("POST", "/api/v1/ai/ask", {"question": "What is overdue?"}, Permission.AI_USE),
    ("POST", "/api/v1/ai/executive-summary", None, Permission.AI_EXECUTIVE),
    ("POST", "/api/v1/jobs/run", None, Permission.SCHEDULER_RUN),
]


@pytest.mark.parametrize("role", ROLES)
def test_every_role_gets_exactly_its_permissions(world, role):
    client, headers = world["client"], world["headers"](role)
    granted = ROLE_PERMISSIONS[role]
    for method, path, body, permission in ENDPOINTS:
        response = client.request(method, path, headers=headers, json=body)
        if permission in granted:
            assert response.status_code == 200, (role, method, path, response.text)
        else:
            assert response.status_code == 403, (
                role,
                method,
                path,
                response.status_code,
            )


def test_unauthenticated_requests_are_rejected(world):
    for method, path, body, _ in ENDPOINTS:
        assert world["client"].request(method, path, json=body).status_code == 401, path


def test_read_only_roles_cannot_change_anything(world):
    client = world["client"]
    for role in ("auditor", "executive_ciso"):
        h = world["headers"](role)
        assert (
            client.patch(
                f"/api/v1/findings/{world['f_a'].id}/status",
                headers=h,
                json={"status": "closed"},
            ).status_code
            == 403
        )
        assert client.post("/api/v1/risk/recalculate", headers=h).status_code == 403
        assert (
            client.put("/api/v1/config/scoring", headers=h, json={}).status_code == 403
        )


def test_login_payload_carries_permissions(world, db_session):
    import bcrypt

    user = world["users"]["auditor"]
    user.hashed_password = bcrypt.hashpw(b"StrongDemo!123", bcrypt.gensalt()).decode()
    db_session.commit()
    login = world["client"].post(
        "/api/v1/auth/login", json={"email": user.email, "password": "StrongDemo!123"}
    )
    assert login.status_code == 200
    perms = login.json()["user"]["permissions"]
    assert "audit:read" in perms and "finding:read" not in perms
    me = world["client"].get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.json()["permissions"] == perms


def test_business_unit_manager_sees_only_own_unit_everywhere(world):
    client, h = world["client"], world["headers"]("business_unit_manager")
    titles = [row["title"] for row in client.get("/api/v1/findings", headers=h).json()]
    assert titles == [world["f_a"].title]
    assert (
        client.get(f"/api/v1/findings/{world['f_b'].id}", headers=h).status_code == 404
    )
    exceptions = client.get("/api/v1/exceptions", headers=h).json()
    assert {row["finding_id"] for row in exceptions} == {str(world["f_a"].id)}
    exported = list(
        csv.reader(io.StringIO(client.get("/api/v1/exceptions/export", headers=h).text))
    )
    assert len(exported) == 2  # header + unit A exception only
    dashboard = client.get("/api/v1/dashboards/manager", headers=h).json()
    assert dashboard["kpis"]["open_findings"] == len(titles)


def test_out_of_scope_findings_are_hidden_from_ai_and_exception_requests(world):
    client, h = world["client"], world["headers"]("security_architect")
    f_b = world["f_b"]
    assert client.post(f"/api/v1/ai/explain/{f_b.id}", headers=h).status_code == 404
    request = client.post(
        "/api/v1/exceptions",
        headers=h,
        json={
            "finding_id": str(f_b.id),
            "justification": "Out of scope request attempt",
            "compensating_controls": "No compensating controls",
            "exception_type": "temporary",
            "requested_expiry_date": (
                datetime.now(timezone.utc) + timedelta(days=10)
            ).isoformat(),
        },
    )
    assert request.status_code == 404


def test_system_administrator_sees_only_assets_with_assigned_tasks(world):
    names = [
        row["name"]
        for row in world["client"]
        .get("/api/v1/assets", headers=world["headers"]("system_administrator"))
        .json()
    ]
    assert names == ["asset-a"]


def test_auditor_dashboard_and_exception_page_agree(world):
    client, h = world["client"], world["headers"]("auditor")
    page = client.get("/api/v1/exceptions", headers=h).json()
    dashboard = client.get("/api/v1/dashboards/auditor", headers=h).json()
    assert len(page) == len(dashboard["exceptions"]) == 2


def test_ai_answers_name_their_sources_and_respect_scope(world):
    client = world["client"]
    analyst = client.post(
        "/api/v1/ai/ask",
        headers=world["headers"]("security_analyst"),
        json={"question": "What are the top priorities?"},
    ).json()
    assert analyst["intent"] == "prioritize_findings"
    assert analyst["sources"][0]["table"] == "findings"
    assert analyst["sources"][0]["rows"] == 2
    architect = client.post(
        "/api/v1/ai/ask",
        headers=world["headers"]("security_architect"),
        json={"question": "What are the top priorities?"},
    ).json()
    assert [row["title"] for row in architect["data"]] == [world["f_a"].title]
    overdue = client.post(
        "/api/v1/ai/ask",
        headers=world["headers"]("security_analyst"),
        json={"question": "Anything overdue on SLA?"},
    ).json()
    assert overdue["intent"] == "sla_status" and len(overdue["data"]) == 1


def test_finding_list_paging_sorting_and_total_header(world):
    client, h = world["client"], world["headers"]("security_analyst")
    first = client.get("/api/v1/findings?limit=1&sort=risk_score&order=asc", headers=h)
    assert first.headers["X-Total-Count"] == "2"
    assert [r["title"] for r in first.json()] == ["Unit B only finding"]
    second = client.get(
        "/api/v1/findings?limit=1&offset=1&sort=risk_score&order=asc", headers=h
    )
    assert [r["id"] for r in second.json()] == [str(world["f_a"].id)]
    assert client.get("/api/v1/findings?sort=password", headers=h).status_code == 422
    assets = client.get("/api/v1/assets?crown_jewel=true", headers=h)
    assert assets.headers["X-Total-Count"] == "1"


def test_csv_exports_neutralise_formula_injection(world):
    client, h = world["client"], world["headers"]("security_analyst")
    rows = list(
        csv.reader(io.StringIO(client.get("/api/v1/findings/export", headers=h).text))
    )
    titles = [row[1] for row in rows[1:]]
    assert '\'=HYPERLINK("http://evil")' in titles
    exceptions = list(
        csv.reader(io.StringIO(client.get("/api/v1/exceptions/export", headers=h).text))
    )
    assert all(row[4].startswith("'+") for row in exceptions[1:])


def test_config_changes_are_audited(world, db_session):
    client, h = world["client"], world["headers"]("platform_admin")
    sla = client.put(
        "/api/v1/config/sla", headers=h, json=[{"risk_band": "critical", "sla_days": 5}]
    )
    assert sla.status_code == 200
    rule = client.post(
        "/api/v1/config/ownership-rules",
        headers=h,
        json={
            "match_field": "environment",
            "match_value": "prod",
            "assign_to_group": "ops",
        },
    ).json()
    assert client.delete(
        f"/api/v1/config/ownership-rules/{rule['id']}", headers=h
    ).json() == {"deleted": rule["id"]}
    actions = set(
        db_session.scalars(
            AuditLog.__table__.select().with_only_columns(AuditLog.action)
        )
    )
    assert {
        "sla_policy_changed",
        "ownership_rule_created",
        "ownership_rule_deleted",
    } <= actions
    facets = client.get("/api/v1/audit/facets", headers=h).json()
    assert "sla_policy_changed" in facets["actions"]
    filtered = client.get("/api/v1/audit?action=ownership_rule_deleted", headers=h)
    assert filtered.headers["X-Total-Count"] == "1"
    assert filtered.json()[0]["actor_email"] == "platform_admin@test.local"


def test_locked_account_is_refused_not_crashed(world, db_session):
    import bcrypt

    user = world["users"]["security_analyst"]
    user.hashed_password = bcrypt.hashpw(b"StrongDemo!123", bcrypt.gensalt()).decode()
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    db_session.commit()
    db_session.expire_all()  # reload as SQLite returns it: a naive timestamp
    response = world["client"].post(
        "/api/v1/auth/login", json={"email": user.email, "password": "StrongDemo!123"}
    )
    assert response.status_code == 401


def test_overdue_tasks_filter_in_sql(world):
    response = world["client"].get(
        "/api/v1/tasks/overdue", headers=world["headers"]("vulnerability_manager")
    )
    assert response.status_code == 200
    assert response.headers["X-Total-Count"] == "1"


def test_user_updates_validate_roles_and_protect_self(world):
    client, h = world["client"], world["headers"]("platform_admin")
    target = world["users"]["auditor"]
    bad = client.patch(
        f"/api/v1/users/{target.id}", headers=h, json={"role": "superuser"}
    )
    assert bad.status_code == 422
    ok = client.patch(f"/api/v1/users/{target.id}", headers=h, json={"role": "analyst"})
    assert ok.json()["role"] == "security_analyst"
    me = world["users"]["platform_admin"]
    assert (
        client.patch(
            f"/api/v1/users/{me.id}", headers=h, json={"is_active": False}
        ).status_code
        == 409
    )


def test_finding_status_is_validated(world):
    client, h = world["client"], world["headers"]("security_analyst")
    url = f"/api/v1/findings/{world['f_a'].id}/status"
    assert client.patch(url, headers=h, json={"status": "pwned"}).status_code == 422
    assert (
        client.patch(url, headers=h, json={"status": "in_remediation"}).status_code
        == 200
    )

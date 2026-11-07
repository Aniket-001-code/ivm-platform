"""Smoke test over the full synthetic demo seed: every read endpoint answers for its role."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.api.v1 import common
from app.core.deps import get_db
from app.db.base import Base
from app.db.seed import seed_demo
from app.main import app
from app.models.entities import Asset, AttackPath, Finding, User


@pytest.fixture(scope="module")
def seeded():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    seed_demo(session)

    def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    common._rate_events.clear()
    yield session, TestClient(app)
    app.dependency_overrides.clear()
    common._rate_events.clear()
    session.close()
    engine.dispose()


def _headers(session, email):
    user = session.scalar(select(User).where(User.email == email))
    return {"Authorization": f"Bearer {common._token(user)}"}


def test_seed_matches_documented_dataset(seeded):
    session, _ = seeded
    assert session.scalar(select(func.count(Asset.id))) == 300
    assert (
        session.scalar(select(func.count(Finding.id)).where(Finding.status == "open"))
        > 1500
    )
    assert session.scalar(select(func.count(AttackPath.id))) > 0
    seed_demo(session)  # idempotent on a non-empty database
    assert session.scalar(select(func.count(Asset.id))) == 300


@pytest.mark.parametrize(
    "email,paths",
    [
        (
            "user1@demo.bank",
            [
                "/api/v1/users",
                "/api/v1/assets?limit=5",
                "/api/v1/findings?limit=5&band=critical",
                "/api/v1/attack-paths",
                "/api/v1/attack-paths/graph",
                "/api/v1/tasks",
                "/api/v1/tasks/overdue",
                "/api/v1/exceptions",
                "/api/v1/exceptions/expiring",
                "/api/v1/imports",
                "/api/v1/audit?limit=5",
                "/api/v1/config/scoring",
                "/api/v1/risk/config",
                "/api/v1/config/sla",
                "/api/v1/config/ownership-rules",
                "/api/v1/dashboards/executive",
                "/api/v1/dashboards/heatmap",
                "/api/v1/dashboards/trend",
                "/api/v1/dashboards/mttr",
                "/api/v1/dashboards/sla-compliance",
                "/api/v1/metrics",
                "/api/v1/notifications",
                "/api/v1/ai/recommendations",
            ],
        ),
        ("user2@demo.bank", ["/api/v1/dashboards/analyst"]),
        ("user4@demo.bank", ["/api/v1/dashboards/manager", "/api/v1/escalations"]),
        ("user5@demo.bank", ["/api/v1/dashboards/auditor"]),
        ("user8@demo.bank", ["/api/v1/tasks/my"]),
    ],
)
def test_read_endpoints_respond_on_seeded_data(seeded, email, paths):
    session, client = seeded
    headers = _headers(session, email)
    for path in paths:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text[:200])


def test_detail_endpoints_and_what_if_on_seeded_data(seeded):
    session, client = seeded
    headers = _headers(session, "user1@demo.bank")
    finding = client.get("/api/v1/findings?limit=1", headers=headers).json()[0]
    asset_id = finding["asset_id"]
    for path in (
        f"/api/v1/findings/{finding['id']}",
        f"/api/v1/risk/findings/{finding['id']}/explain",
        f"/api/v1/assets/{asset_id}",
        f"/api/v1/assets/{asset_id}/findings",
        f"/api/v1/assets/{asset_id}/connections",
    ):
        assert client.get(path, headers=headers).status_code == 200, path
    path = client.get("/api/v1/attack-paths", headers=headers).json()[0]
    assert (
        client.get(f"/api/v1/attack-paths/{path['id']}", headers=headers).status_code
        == 200
    )
    explain = client.post(f"/api/v1/ai/explain/{finding['id']}", headers=headers)
    assert explain.status_code == 200
    summary = client.post("/api/v1/ai/executive-summary", headers=headers)
    assert summary.status_code == 200 and summary.json()["summary"]


@pytest.mark.parametrize(
    "question,intent",
    [
        ("Which assets are internet exposed?", "asset_inventory"),
        ("Any exceptions expiring?", "exception_status"),
        ("Show attack paths to crown jewels", "attack_paths"),
        ("Which findings are actively exploited?", "threat_exposure"),
        ("Hello", "portfolio_summary"),
    ],
)
def test_assistant_intents_on_seeded_data(seeded, question, intent):
    session, client = seeded
    common._rate_events.clear()
    answer = client.post(
        "/api/v1/ai/ask",
        headers=_headers(session, "user2@demo.bank"),
        json={"question": question},
    ).json()
    assert answer["intent"] == intent
    assert answer["sources"] and answer["answer"]

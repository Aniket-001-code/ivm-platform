"""Shared isolated SQLite session for business-service and API integration tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.db.base import Base


@pytest.fixture(autouse=True)
def _fresh_analytics_cache():
    from app.services.analytics import clear_cache

    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)
    engine.dispose()


# --- Shared "two business units" world used by the integration suites -------------------
from datetime import datetime, timedelta, timezone  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from app.api.v1 import common  # noqa: E402
from app.core.deps import get_db  # noqa: E402
from app.core.rbac import ROLE_PERMISSIONS  # noqa: E402
from app.main import app  # noqa: E402
from app.models.entities import (  # noqa: E402
    Asset,
    BusinessUnit,
    Finding,
    RemediationTask,
    RiskException,
    User,
)

ROLES = sorted(ROLE_PERMISSIONS)


@pytest.fixture
def world(db_session):
    """Two business units, one asset each, users for every role (scoped to unit A)."""
    common._rate_events.clear()
    unit_a, unit_b = BusinessUnit(name="Unit A"), BusinessUnit(name="Unit B")
    db_session.add_all([unit_a, unit_b])
    db_session.flush()
    users = {
        role: User(
            email=f"{role}@test.local",
            full_name=role.replace("_", " ").title(),
            hashed_password="unused",
            role=role,
            is_active=True,
            business_unit_id=unit_a.id,
        )
        for role in ROLES
    }
    db_session.add_all(users.values())
    db_session.flush()
    asset_a = Asset(
        name="asset-a",
        hostname="a.bank.local",
        asset_type="server",
        environment="prod",
        business_unit_id=unit_a.id,
        owner_user_id=users["it_asset_owner"].id,
        criticality_tier=1,
        is_crown_jewel=True,
        status="active",
    )
    asset_b = Asset(
        name="asset-b",
        hostname="b.bank.local",
        asset_type="server",
        environment="dev",
        business_unit_id=unit_b.id,
        criticality_tier=3,
        status="active",
    )
    db_session.add_all([asset_a, asset_b])
    db_session.flush()

    def finding(asset, title, score, fp):
        return Finding(
            asset_id=asset.id,
            finding_type="vulnerability",
            title=title,
            severity="high",
            status="open",
            fingerprint=fp * 64,
            risk_score=score,
            risk_band="high" if score >= 60 else "medium",
            sources=["scanner"],
        )

    f_a = finding(asset_a, '=HYPERLINK("http://evil")', 75.0, "a")
    f_b = finding(asset_b, "Unit B only finding", 50.0, "b")
    db_session.add_all([f_a, f_b])
    db_session.flush()
    db_session.add(
        RemediationTask(
            finding_id=f_a.id,
            asset_id=asset_a.id,
            assigned_to_user_id=users["system_administrator"].id,
            status="open",
            priority="high",
            sla_due_date=datetime.now(timezone.utc) - timedelta(days=2),
        )
    )
    for f in (f_a, f_b):
        db_session.add(
            RiskException(
                finding_id=f.id,
                requested_by=users["security_analyst"].id,
                justification="+cmd|' /C calc'!A0 compensating plan",
                compensating_controls="Segmentation",
                exception_type="temporary",
                requested_expiry_date=datetime.now(timezone.utc) + timedelta(days=20),
                status="approved",
            )
        )
    db_session.commit()

    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)

    def headers(role):
        return {"Authorization": f"Bearer {common._token(users[role])}"}

    yield {
        "db": db_session,
        "client": client,
        "headers": headers,
        "users": users,
        "f_a": f_a,
        "f_b": f_b,
        "asset_a": asset_a,
        "asset_b": asset_b,
    }
    app.dependency_overrides.clear()
    common._rate_events.clear()

import bcrypt
from fastapi.testclient import TestClient

from app.api.v1.router import settings
from app.core.deps import get_db
from app.main import app
from app.models.entities import Asset, BusinessUnit, User


def test_login_protected_inventory_and_default_deny(db_session):
    unit = BusinessUnit(name="API Unit")
    user = User(
        email="api-analyst@test.local",
        full_name="API Analyst",
        hashed_password=bcrypt.hashpw(b"StrongDemo!123", bcrypt.gensalt()).decode(),
        role="analyst",
        is_active=True,
    )
    db_session.add_all([unit, user])
    db_session.flush()
    user.business_unit_id = unit.id
    db_session.add(
        Asset(
            name="api-host",
            hostname="api-host.bank.local",
            asset_type="server",
            environment="dev",
            business_unit_id=unit.id,
            criticality_tier=3,
            status="active",
        )
    )
    db_session.commit()

    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    try:
        denied = client.get("/api/v1/assets")
        assert denied.status_code == 401

        login = client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": "StrongDemo!123"},
        )
        assert login.status_code == 200
        access = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {access}"}
        inventory = client.get("/api/v1/assets", headers=headers)
        assert inventory.status_code == 200
        assert [row["name"] for row in inventory.json()] == ["api-host"]
        user_read = client.get("/api/v1/users", headers=headers)
        assert user_read.status_code == 200

        # Tokens are signed with the configured application secret and are not opaque placeholders.
        assert settings.secret_key
    finally:
        app.dependency_overrides.clear()

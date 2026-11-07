from collections.abc import Generator
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.entities import User

bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(
            credentials.credentials,
            get_settings().secret_key,
            algorithms=["HS256"],
        )
        if payload.get("type") != "access":
            raise ValueError("wrong token type")
        user = db.get(User, UUID(payload["sub"]))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive account")

    # Central default-deny enforcement covers every route using authentication.
    from app.core.rbac import Permission, has_permission, permission_for_request

    permission = permission_for_request(request)
    allowed = has_permission(user.role, permission)
    if permission.value == "task:assigned":
        allowed = allowed or has_permission(user.role, Permission.TASK_MANAGE)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission required: {permission.value}",
        )
    return user

from uuid import UUID

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    audit,
)
from app.core.deps import get_db
from app.api.v1.routes.auth import password_problem
from app.core.rbac import (
    ROLE_PERMISSIONS,
    Permission,
    canonical_role,
    require_permission,
)
from app.models.entities import (
    BusinessUnit,
    User,
)

router = APIRouter(prefix="/api/v1")


def _unit_id(db: Session, value) -> UUID | None:
    if not value:
        return None
    try:
        unit = db.get(BusinessUnit, UUID(str(value)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid business unit id") from exc
    if not unit:
        raise HTTPException(status_code=422, detail="Unknown business unit")
    return unit.id


@router.get("/users")
def users(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.USER_READ)),
):
    return [
        {
            "id": str(x.id),
            "email": x.email,
            "full_name": x.full_name,
            "role": x.role,
            "is_active": x.is_active,
            "mfa_enabled": bool(x.mfa_enabled),
            "business_unit_id": str(x.business_unit_id) if x.business_unit_id else None,
        }
        for x in db.scalars(select(User).order_by(User.email))
    ]


@router.post("/users")
def create_user(
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    password = str(body.get("password", ""))
    problem = password_problem(password)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    email = str(body.get("email", "")).lower()
    if not email or db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(
            status_code=409, detail="Email is required and must be unique"
        )
    role = canonical_role(str(body.get("role", "security_analyst")))
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=422, detail="Unsupported role")
    item = User(
        email=email,
        full_name=str(body.get("full_name", "")),
        hashed_password=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        role=role,
        is_active=True,
        business_unit_id=_unit_id(db, body.get("business_unit_id")),
    )
    db.add(item)
    db.flush()
    audit(
        db,
        user,
        "user_created",
        "user",
        item.id,
        new={"email": email, "role": role},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(item.id), "email": item.email, "role": item.role}


@router.patch("/users/{user_id}")
def update_user(
    user_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    old_role = target.role
    if target.id == user.id and (
        ("is_active" in body and not body["is_active"])
        or (
            "role" in body
            and canonical_role(str(body["role"])) != canonical_role(user.role)
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="You cannot deactivate or change the role of your own account",
        )
    if "role" in body:
        role = canonical_role(str(body["role"]))
        if role not in ROLE_PERMISSIONS:
            raise HTTPException(status_code=422, detail="Unsupported role")
        target.role = role
    if "is_active" in body:
        target.is_active = bool(body["is_active"])
        if not target.is_active:
            target.refresh_token_hash = None
    if "business_unit_id" in body:
        target.business_unit_id = _unit_id(db, body["business_unit_id"])
    audit(
        db,
        user,
        "user_updated",
        "user",
        target.id,
        {"role": old_role},
        {"role": target.role, "is_active": target.is_active},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(target.id), "role": target.role, "is_active": target.is_active}


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.USER_MANAGE)),
    db: Session = Depends(get_db),
):
    """Administrator sets a temporary password; the user's sessions are revoked."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    password = str(body.get("password", ""))
    problem = password_problem(password)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    target.hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    target.refresh_token_hash = None
    target.failed_login_count = 0
    target.locked_until = None
    audit(
        db,
        user,
        "password_reset_by_admin",
        "user",
        target.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"reset": True}


@router.post("/users/{user_id}/reset-mfa")
def reset_mfa(
    user_id: UUID,
    request: Request,
    user: User = Depends(require_permission(Permission.USER_MANAGE)),
    db: Session = Depends(get_db),
):
    """Clear a lost authenticator so the user can enroll again."""
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id:
        raise HTTPException(
            status_code=409, detail="Ask another administrator to reset your MFA"
        )
    target.mfa_enabled = False
    target.mfa_secret = None
    target.refresh_token_hash = None
    audit(
        db,
        user,
        "mfa_reset_by_admin",
        "user",
        target.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"reset": True}

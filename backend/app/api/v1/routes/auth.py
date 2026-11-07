import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
import jwt
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    ALGORITHM,
    LoginInput,
    _limit,
    _refresh_token,
    _token,
    audit,
    settings,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import permissions_for
from app.core.rbac import (
    canonical_role,
)
from app.core.timeutil import as_utc
from app.core.security import decrypt_secret, encrypt_secret
from app.models.entities import (
    User,
)

router = APIRouter(prefix="/api/v1")


PRIVILEGED_ROLES = {"platform_admin", "security_architect", "vulnerability_manager"}
# Compared against when the email is unknown so response time does not reveal accounts.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt()).decode()
MFA_REQUIRED_DETAIL = "MFA code required"


def _fail_login(
    db: Session, user: User | None, request: Request, now: datetime, reason: str
):
    if user:
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= 5:
            user.locked_until = now + timedelta(minutes=15)
    audit(
        db,
        user,
        "login_failed",
        "user",
        user.id if user else None,
        new={"reason": reason},
        ip=request.client.host if request.client else None,
    )
    db.commit()


@router.post("/auth/login")
def login(body: LoginInput, request: Request, db: Session = Depends(get_db)):
    _limit(request, "login", settings.login_rate_limit)
    user = db.scalar(select(User).where(func.lower(User.email) == body.email.lower()))
    now = datetime.now(timezone.utc)
    password_ok = bcrypt.checkpw(
        body.password.encode()[:72],
        (user.hashed_password if user else _DUMMY_HASH).encode(),
    )
    if user is None:
        _fail_login(db, None, request, now, "unknown_email")
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    locked = user.locked_until is not None and as_utc(user.locked_until) > now
    if not (password_ok and user.is_active and not locked):
        _fail_login(db, user, request, now, "locked" if locked else "bad_credentials")
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    role = canonical_role(user.role)
    if settings.mfa_required and role in PRIVILEGED_ROLES and not user.mfa_enabled:
        _fail_login(db, user, request, now, "mfa_enrollment_required")
        raise HTTPException(
            status_code=403,
            detail="MFA enrollment is required for this role; ask an administrator",
        )
    if user.mfa_enabled:
        if not body.totp_code:
            # Password was correct; ask for the second factor without counting a failure.
            raise HTTPException(status_code=401, detail=MFA_REQUIRED_DETAIL)
        secret = decrypt_secret(user.mfa_secret) if user.mfa_secret else None
        if not (secret and pyotp.TOTP(secret).verify(body.totp_code, valid_window=1)):
            _fail_login(db, user, request, now, "bad_mfa_code")
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    user.failed_login_count = 0
    user.locked_until = None
    user.role = role
    audit(
        db,
        user,
        "login_succeeded",
        "user",
        user.id,
        new={"mfa": bool(user.mfa_enabled)},
        ip=request.client.host if request.client else None,
    )
    refresh_token = _refresh_token(user)
    db.commit()
    return {
        "access_token": _token(user),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": _user_payload(user),
    }


def _user_payload(user: User) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "permissions": permissions_for(user.role),
        "mfa_enabled": bool(user.mfa_enabled),
        "business_unit_id": (
            str(user.business_unit_id) if user.business_unit_id else None
        ),
    }


@router.post("/auth/refresh")
def refresh(body: dict, db: Session = Depends(get_db)):
    try:
        data = jwt.decode(
            body["refresh_token"], settings.secret_key, algorithms=[ALGORITHM]
        )
        if data.get("type") != "refresh":
            raise ValueError("invalid refresh")
        user = db.get(User, UUID(data["sub"]))
        supplied_hash = hashlib.sha256(body["refresh_token"].encode()).hexdigest()
        if (
            not user
            or not user.refresh_token_hash
            or not hmac.compare_digest(user.refresh_token_hash, supplied_hash)
        ):
            raise ValueError("refresh token already used or revoked")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive account")
    next_refresh = _refresh_token(user)
    db.commit()
    return {
        "access_token": _token(user),
        "refresh_token": next_refresh,
        "token_type": "bearer",
    }


@router.post("/auth/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.refresh_token_hash = None
    db.commit()
    return {"logged_out": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return _user_payload(user)


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaSetupInput(BaseModel):
    current_code: str | None = Field(default=None, max_length=8)


def _verify_code(user: User, code: str | None) -> bool:
    if not user.mfa_secret or not code:
        return False
    return pyotp.TOTP(decrypt_secret(user.mfa_secret)).verify(code, valid_window=1)


@router.post("/auth/mfa/setup")
def mfa_setup(
    request: Request,
    body: MfaSetupInput | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Start (or rotate) TOTP enrollment. Rotating an active factor needs a current code."""
    if user.mfa_enabled and not _verify_code(user, body.current_code if body else None):
        raise HTTPException(
            status_code=403,
            detail="Enter a current MFA code to replace your authenticator",
        )
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt_secret(secret)
    user.mfa_enabled = False  # active only after the new code is verified
    audit(
        db,
        user,
        "mfa_enrollment_started",
        "user",
        user.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {
        "secret": secret,
        "provisioning_uri": pyotp.TOTP(secret).provisioning_uri(
            user.email, issuer_name="IVM Demo"
        ),
    }


@router.post("/auth/mfa/verify")
def mfa_verify(
    body: MfaCode,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not _verify_code(user, body.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    user.mfa_enabled = True
    audit(
        db,
        user,
        "mfa_enabled",
        "user",
        user.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"mfa_enabled": True}


class MfaDisableInput(BaseModel):
    code: str = Field(min_length=6, max_length=8)
    password: str = Field(min_length=1, max_length=200)


@router.post("/auth/mfa/disable")
def mfa_disable(
    body: MfaDisableInput,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not bcrypt.checkpw(body.password.encode()[:72], user.hashed_password.encode()):
        raise HTTPException(status_code=403, detail="Password is incorrect")
    if not _verify_code(user, body.code):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    if settings.mfa_required and canonical_role(user.role) in PRIVILEGED_ROLES:
        raise HTTPException(status_code=409, detail="MFA is mandatory for your role")
    user.mfa_enabled = False
    user.mfa_secret = None
    audit(
        db,
        user,
        "mfa_disabled",
        "user",
        user.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"mfa_enabled": False}


def password_problem(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be at least 12 characters"
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        return "Password must mix upper- and lower-case letters"
    if not any(c.isdigit() for c in password) or not any(
        not c.isalnum() for c in password
    ):
        return "Password must include a number and a symbol"
    return None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=12, max_length=200)


@router.post("/auth/password")
def change_password(
    body: PasswordChange,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not bcrypt.checkpw(
        body.current_password.encode()[:72], user.hashed_password.encode()
    ):
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    problem = password_problem(body.new_password)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    if body.new_password == body.current_password:
        raise HTTPException(status_code=422, detail="Choose a different password")
    user.hashed_password = bcrypt.hashpw(
        body.new_password.encode(), bcrypt.gensalt()
    ).decode()
    user.refresh_token_hash = None  # sign out other sessions
    audit(
        db,
        user,
        "password_changed",
        "user",
        user.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"changed": True}

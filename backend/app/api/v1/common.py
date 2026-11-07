"""Shared API helpers, request schemas and scope checks."""

import hashlib
import csv
import io
from fastapi.responses import Response
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.services.audit import record_audit
from app.services.scoring import rescore_findings
from app.core import scope
from app.core.config import get_settings
from app.models.entities import (
    Asset,
    ScoringConfig,
    User,
)

settings = get_settings()
ALGORITHM = "HS256"
_rate_events: dict[str, list[datetime]] = {}


def _limit(request: Request, route: str, count: int, seconds: int = 60) -> None:
    now = datetime.now(timezone.utc)
    key = f"{request.client.host if request.client else 'unknown'}:{route}"
    recent = [
        stamp
        for stamp in _rate_events.get(key, [])
        if (now - stamp).total_seconds() < seconds
    ]
    if len(recent) >= count:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rate_events[key] = [*recent, now]


class LoginInput(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


class TaskPatch(BaseModel):
    status: str | None = None
    comment: str | None = None
    evidence_notes: str | None = None


class ExceptionInput(BaseModel):
    finding_id: UUID
    justification: str = Field(min_length=10, max_length=2000)
    compensating_controls: str = Field(min_length=5, max_length=2000)
    exception_type: str = "temporary"
    requested_expiry_date: datetime


class QuestionInput(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    finding_id: UUID | None = None
    # Earlier questions in this conversation, newest last (used for follow-ups).
    history: list[str] = Field(default_factory=list, max_length=10)


def _token(user: User, kind: str = "access") -> str:
    lifetime = timedelta(minutes=15) if kind == "access" else timedelta(days=7)
    return jwt.encode(
        {
            "sub": str(user.id),
            "role": user.role,
            "type": kind,
            "exp": datetime.now(timezone.utc) + lifetime,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )


def _refresh_token(user: User) -> str:
    token = _token(user, "refresh")
    user.refresh_token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token


def audit(
    db: Session,
    actor: User | None,
    action: str,
    entity: str,
    entity_id: UUID | None = None,
    old=None,
    new=None,
    ip=None,
):
    record_audit(
        db, actor.id if actor else None, action, entity, entity_id, old, new, ip
    )


def _active_scoring_config(db: Session) -> ScoringConfig | None:
    return db.scalar(select(ScoringConfig).where(ScoringConfig.is_active.is_(True)))


def _rescore_findings(db: Session, findings, config: ScoringConfig | None = None):
    """Rescore with full threat and attack-path context (see app/services/scoring.py)."""
    return rescore_findings(db, findings, config)


def _global_scope(user: User) -> bool:
    return scope.is_global(user)


def _asset_scope(query, user: User):
    condition = scope.asset_condition(user)
    return query if condition is None else query.where(condition)


def _check_asset_scope(asset: Asset | None, user: User, db: Session) -> Asset:
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    condition = scope.asset_condition(user)
    if condition is not None and not db.scalar(
        select(Asset.id).where(Asset.id == asset.id, condition)
    ):
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value) -> str:
    """Stringify a CSV cell and neutralise spreadsheet formula injection."""
    if value is None:
        return ""
    text = value.isoformat() if hasattr(value, "isoformat") else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _csv_response(filename: str, header: list[str], rows) -> Response:
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(header)
    for row in rows:
        writer.writerow([_csv_cell(value) for value in row])
    return Response(
        stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


def _page(db: Session, response: Response, query, order_by, limit: int, offset: int):
    """Apply ordering and paging; report the unpaged total in X-Total-Count."""
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    response.headers["X-Total-Count"] = str(total or 0)
    return db.scalars(query.order_by(*order_by).offset(offset).limit(limit)).all()

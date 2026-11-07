from datetime import datetime

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.common import _csv_response
from app.core.deps import get_db
from app.services.audit import verify_chain
from app.core.rbac import (
    Permission,
    require_permission,
)
from app.models.entities import (
    AuditLog,
    User,
)

router = APIRouter(prefix="/api/v1")


def _filtered_audit(action, entity_type, actor, since, until):
    query = select(AuditLog, User.email).outerjoin(
        User, AuditLog.actor_user_id == User.id
    )
    if action:
        query = query.where(AuditLog.action == action)
    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
    if actor:
        query = query.where(User.email.ilike(f"%{actor}%"))
    if since:
        query = query.where(AuditLog.created_at >= since)
    if until:
        query = query.where(AuditLog.created_at <= until)
    return query


@router.get("/audit")
def audit_records(
    response: Response,
    action: str | None = None,
    entity_type: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Filterable audit trail; the unpaged total is returned in X-Total-Count."""
    query = _filtered_audit(action, entity_type, actor, since, until)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    response.headers["X-Total-Count"] = str(total or 0)
    rows = db.execute(
        query.order_by(AuditLog.created_at.desc(), AuditLog.id)
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        {
            "id": str(x.id),
            "actor_user_id": str(x.actor_user_id) if x.actor_user_id else None,
            "actor_email": email,
            "action": x.action,
            "entity_type": x.entity_type,
            "entity_id": str(x.entity_id) if x.entity_id else None,
            "new_value": x.new_value,
            "timestamp": x.created_at,
        }
        for x, email in rows
    ]


@router.get("/audit/facets")
def audit_facets(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Distinct actions and entity types, used to populate the audit filter menus."""
    return {
        "actions": sorted(db.scalars(select(AuditLog.action).distinct())),
        "entity_types": sorted(db.scalars(select(AuditLog.entity_type).distinct())),
    }


@router.get("/audit/verify")
def audit_verify(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Recompute the audit hash chain and report whether any row was altered or removed."""
    return verify_chain(db)


@router.get("/audit/export")
def audit_export(
    action: str | None = None,
    entity_type: str | None = None,
    actor: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    query = _filtered_audit(action, entity_type, actor, since, until)
    rows = db.execute(query.order_by(AuditLog.created_at.desc()).limit(10000)).all()
    return _csv_response(
        "ivm-audit.csv",
        ["timestamp", "actor", "action", "entity_type", "entity_id", "ip_address"],
        (
            [
                x.created_at,
                email or "system",
                x.action,
                x.entity_type,
                x.entity_id,
                x.ip_address,
            ]
            for x, email in rows
        ),
    )

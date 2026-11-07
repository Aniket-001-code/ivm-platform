"""Remediation tasks (UC-8/9/10): queues, detail timeline, status workflow, reassignment."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    TaskPatch,
    _check_asset_scope,
    _csv_response,
    _page,
    audit,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import Permission, canonical_role, require_permission
from app.core.timeutil import as_utc
from app.models.entities import (
    Asset,
    Escalation,
    Finding,
    RemediationTask,
    TaskUpdate,
    TicketRecord,
    User,
)
from app.services import analytics
from app.services.forecasting import breach_forecast, breach_likelihood, learn_history

router = APIRouter(prefix="/api/v1")

TASK_STATUSES = {"open", "in_progress", "pending_verification", "closed", "blocked"}
ALLOWED_TRANSITIONS = {
    "open": {"in_progress", "blocked"},
    "in_progress": {"pending_verification", "blocked"},
    "pending_verification": {"closed", "in_progress"},
    "blocked": {"open", "in_progress"},
    "closed": set(),
}


def _task_dict(t: RemediationTask, history=None) -> dict:
    row = {
        "id": str(t.id),
        "finding_id": str(t.finding_id),
        "asset_id": str(t.asset_id),
        "assigned_to_user_id": (
            str(t.assigned_to_user_id) if t.assigned_to_user_id else None
        ),
        "assigned_group": t.assigned_group,
        "assigned_by_rule": t.assigned_by_rule,
        "status": t.status,
        "priority": t.priority,
        "sla_due_date": t.sla_due_date,
        "sla_category": t.sla_category,
        "evidence_notes": t.evidence_notes,
        "ticket_ref": t.ticket_ref,
        "created_at": t.created_at,
        "closed_at": t.closed_at,
    }
    if history is not None:
        probability, level, _ = breach_likelihood(t, history)
        row["breach_probability"] = probability
        row["breach_level"] = level
    return row


def _filtered(query, status_filter, priority, overdue):
    if status_filter:
        query = query.where(RemediationTask.status == status_filter)
    if priority:
        query = query.where(RemediationTask.priority == priority)
    if overdue:
        # Compare in SQL so naive (SQLite) and aware (PostgreSQL) timestamps both work.
        query = query.where(
            RemediationTask.status != "closed",
            RemediationTask.sla_due_date.is_not(None),
            RemediationTask.sla_due_date < datetime.now(timezone.utc),
        )
    return query


# Open work first (earliest SLA first), closed history last.
_ORDER = [
    RemediationTask.status == "closed",
    RemediationTask.sla_due_date.is_(None),
    RemediationTask.sla_due_date,
    RemediationTask.id,
]


def _task_list(db, response, query, status_filter, priority, overdue, limit, offset):
    history = learn_history(db)
    rows = _page(
        db,
        response,
        _filtered(query, status_filter, priority, overdue),
        _ORDER,
        limit,
        offset,
    )
    return [_task_dict(t, history) for t in rows]


@router.get("/tasks")
def list_tasks(
    response: Response,
    status_filter: str | None = Query(default=None, alias="status"),
    priority: str | None = None,
    overdue: bool = False,
    limit: int = Query(default=2000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Tasks in the caller's scope, earliest SLA first; total in X-Total-Count."""
    return _task_list(
        db,
        response,
        analytics.task_query(user),
        status_filter,
        priority,
        overdue,
        limit,
        offset,
    )


@router.get("/tasks/my")
def my_tasks(
    response: Response,
    status_filter: str | None = Query(default=None, alias="status"),
    priority: str | None = None,
    overdue: bool = False,
    limit: int = Query(default=2000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(RemediationTask).where(
        RemediationTask.assigned_to_user_id == user.id
    )
    return _task_list(
        db, response, query, status_filter, priority, overdue, limit, offset
    )


@router.get("/tasks/overdue")
def overdue_tasks(
    response: Response,
    limit: int = Query(default=2000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    return _task_list(
        db, response, analytics.task_query(user), None, None, True, limit, offset
    )


@router.get("/tasks/export")
def tasks_export(
    status_filter: str | None = Query(default=None, alias="status"),
    priority: str | None = None,
    overdue: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """SLA / aging report as CSV for the caller's scope."""
    query = _filtered(analytics.task_query(user), status_filter, priority, overdue)
    history = learn_history(db)
    now = datetime.now(timezone.utc)
    owners = {u.id: u.email for u in db.scalars(select(User))}
    rows = []
    for t in db.scalars(query.order_by(*_ORDER).limit(10000)):
        due = as_utc(t.sla_due_date) if t.sla_due_date else None
        created = as_utc(t.created_at) if t.created_at else None
        probability, level, _ = breach_likelihood(t, history, now)
        rows.append(
            [
                t.id,
                t.finding_id,
                t.asset_id,
                owners.get(t.assigned_to_user_id, ""),
                t.assigned_group,
                t.priority,
                t.sla_category,
                t.status,
                t.sla_due_date,
                (now - created).days if created else "",
                (now - due).days if due and t.status != "closed" and due < now else 0,
                probability,
                t.ticket_ref,
            ]
        )
    return _csv_response(
        "ivm-sla-report.csv",
        [
            "task_id",
            "finding_id",
            "asset_id",
            "owner",
            "group",
            "priority",
            "sla_category",
            "status",
            "sla_due_date",
            "age_days",
            "days_overdue",
            "breach_probability",
            "ticket",
        ],
        rows,
    )


@router.get("/tasks/breach-forecast")
def tasks_breach_forecast(
    horizon_days: int = Query(default=14, ge=1, le=90),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Predicted SLA breaches for open work in scope (learned from closed-task history)."""
    tasks = db.scalars(
        analytics.task_query(user).where(RemediationTask.status != "closed")
    ).all()
    return breach_forecast(db, tasks, horizon_days)


@router.get("/tasks/{task_id}")
def task_detail(
    task_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    asset = _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    finding = db.get(Finding, task.finding_id)
    owner = db.get(User, task.assigned_to_user_id) if task.assigned_to_user_id else None
    users: dict = {u.id: u.email for u in db.scalars(select(User))}
    history = learn_history(db)
    probability, level, factors = breach_likelihood(task, history)
    return {
        **_task_dict(task),
        "owner_email": owner.email if owner else None,
        "finding": (
            {
                "id": str(finding.id),
                "title": finding.title,
                "risk_score": finding.risk_score,
                "risk_band": finding.risk_band,
                "status": finding.status,
            }
            if finding
            else None
        ),
        "asset": {"id": str(asset.id), "name": asset.name},
        "breach": {"probability": probability, "level": level, "factors": factors},
        "updates": [
            {
                "old_status": x.old_status,
                "new_status": x.new_status,
                "comment": x.comment,
                "user": users.get(x.user_id),
                "created_at": x.created_at,
            }
            for x in db.scalars(
                select(TaskUpdate)
                .where(TaskUpdate.task_id == task.id)
                .order_by(TaskUpdate.created_at)
            )
        ],
        "escalations": [
            {
                "id": str(e.id),
                "level": e.level,
                "reason": e.reason,
                "escalated_to": users.get(e.escalated_to_user_id),
                "acknowledged": e.acknowledged,
                "created_at": e.created_at,
            }
            for e in db.scalars(
                select(Escalation)
                .where(Escalation.task_id == task.id)
                .order_by(Escalation.level)
            )
        ],
        "tickets": [
            {"system": t.system, "ticket_key": t.ticket_key, "status": t.status}
            for t in db.scalars(
                select(TicketRecord).where(TicketRecord.task_id == task.id)
            )
        ],
    }


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: UUID,
    body: TaskPatch,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    role = canonical_role(user.role)
    if task.assigned_to_user_id != user.id and role not in {
        "platform_admin",
        "vulnerability_manager",
    }:
        raise HTTPException(status_code=403, detail="Task is assigned to another owner")
    old = task.status
    if body.status:
        if body.status not in TASK_STATUSES:
            raise HTTPException(status_code=422, detail="Unsupported task status")
        if body.status != old and body.status not in ALLOWED_TRANSITIONS.get(
            old, set()
        ):
            raise HTTPException(
                status_code=409,
                detail=f"Invalid task transition: {old} -> {body.status}",
            )
        if body.status == "closed" and not (body.evidence_notes or task.evidence_notes):
            raise HTTPException(
                status_code=422, detail="Evidence is required to close a task"
            )
        task.status = body.status
        task.closed_at = datetime.now(timezone.utc) if body.status == "closed" else None
    if body.evidence_notes:
        task.evidence_notes = body.evidence_notes[:4000]
    finding = db.get(Finding, task.finding_id)
    if finding and task.status != old:
        # Keep the finding lifecycle in step with its remediation task.
        if task.status == "closed":
            finding.status = "closed"
            finding.closed_at = task.closed_at
        elif finding.status == "open" and task.status in {
            "in_progress",
            "pending_verification",
        }:
            finding.status = "in_remediation"
    db.add(
        TaskUpdate(
            task_id=task.id,
            user_id=user.id,
            old_status=old,
            new_status=task.status,
            comment=(body.comment or None) and body.comment[:2000],
        )
    )
    audit(
        db,
        user,
        "task_updated",
        "remediation_task",
        task.id,
        {"status": old},
        {"status": task.status, "evidence": bool(task.evidence_notes)},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(task.id), "status": task.status}


class AssignInput(BaseModel):
    user_id: UUID | None = None
    group: str | None = Field(default=None, max_length=120)
    reason: str = Field(min_length=3, max_length=500)


@router.post("/tasks/{task_id}/assign")
def reassign_task(
    task_id: UUID,
    body: AssignInput,
    request: Request,
    user: User = Depends(require_permission(Permission.TASK_MANAGE)),
    db: Session = Depends(get_db),
):
    """Manual ownership override with a recorded reason (audited)."""
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    if body.user_id is None and not body.group:
        raise HTTPException(status_code=422, detail="Choose an owner or a group")
    if body.user_id is not None:
        target = db.get(User, body.user_id)
        if not target or not target.is_active:
            raise HTTPException(status_code=422, detail="Owner must be an active user")
    old = {
        "assigned_to_user_id": (
            str(task.assigned_to_user_id) if task.assigned_to_user_id else None
        ),
        "group": task.assigned_group,
    }
    task.assigned_to_user_id = body.user_id or task.assigned_to_user_id
    task.assigned_group = body.group if body.group is not None else task.assigned_group
    task.assigned_by_rule = "manual_override"
    db.add(
        TaskUpdate(
            task_id=task.id,
            user_id=user.id,
            old_status=task.status,
            new_status=task.status,
            comment=f"Reassigned: {body.reason}",
        )
    )
    audit(
        db,
        user,
        "ownership_reassigned",
        "remediation_task",
        task.id,
        old,
        {
            "assigned_to_user_id": (
                str(task.assigned_to_user_id) if task.assigned_to_user_id else None
            ),
            "group": task.assigned_group,
            "reason": body.reason,
        },
        request.client.host if request.client else None,
    )
    db.commit()
    return _task_dict(task)

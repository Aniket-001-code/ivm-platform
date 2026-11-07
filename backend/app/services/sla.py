"""SLA checks and three-stage escalation routing."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    BusinessUnit,
    Escalation,
    RemediationTask,
    RiskException,
    User,
)


def _recipient(db: Session, task: RemediationTask, level: int) -> User | None:
    owner = db.get(User, task.assigned_to_user_id) if task.assigned_to_user_id else None
    asset = db.get(Asset, task.asset_id)
    if level == 1 and owner and owner.business_unit_id:
        unit = db.get(BusinessUnit, owner.business_unit_id)
        if unit and unit.head_user_id:
            head = db.get(User, unit.head_user_id)
            if head:
                return head
        manager = db.scalar(
            select(User).where(
                User.business_unit_id == owner.business_unit_id,
                User.role == "business_unit_manager",
            )
        )
        if manager:
            return manager
        if asset and asset.business_unit_id:
            return db.scalar(
                select(User).where(
                    User.business_unit_id == asset.business_unit_id,
                    User.role == "business_unit_manager",
                )
            )
    if level == 2 and asset and asset.business_unit_id:
        manager = db.scalar(
            select(User).where(
                User.business_unit_id == asset.business_unit_id,
                User.role == "business_unit_manager",
            )
        )
        if manager:
            return manager
    return db.scalar(select(User).where(User.role == "executive_ciso"))


def check_overdue_tasks(db: Session) -> int:
    now = datetime.now(timezone.utc)
    tasks = db.scalars(
        select(RemediationTask).where(
            RemediationTask.status.notin_(["closed", "fixed"]),
            RemediationTask.sla_due_date.is_not(None),
            RemediationTask.sla_due_date < now,
        )
    ).all()
    escalated = 0
    for task in tasks:
        exception = db.scalar(
            select(RiskException.id).where(
                RiskException.finding_id == task.finding_id,
                RiskException.status == "approved",
                RiskException.requested_expiry_date >= now,
            )
        )
        if exception:
            continue
        due = task.sla_due_date
        if due and due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        overdue_days = max(0, (now - due).days) if due else 0
        existing = {
            row.level
            for row in db.scalars(
                select(Escalation).where(Escalation.task_id == task.id)
            )
        }
        thresholds = ((1, 0), (2, 7), (3, 14))
        for level, threshold in thresholds:
            if overdue_days < threshold or level in existing:
                continue
            recipient = _recipient(db, task, level)
            db.add(
                Escalation(
                    task_id=task.id,
                    level=level,
                    escalated_to_user_id=recipient.id if recipient else None,
                    reason=f"Task is {overdue_days} days overdue; escalation level {level}.",
                )
            )
            escalated += 1
    db.commit()
    return escalated

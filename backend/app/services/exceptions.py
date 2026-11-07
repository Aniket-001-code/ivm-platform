"""Exception expiry, SLA pause, and warning lifecycle."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    AuditLog,
    Finding,
    RemediationTask,
    RiskException,
    SlaPolicy,
)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def expire_exceptions(db: Session) -> int:
    now = datetime.now(timezone.utc)
    active = db.scalars(
        select(RiskException).where(RiskException.status == "approved")
    ).all()
    changed = 0
    for item in active:
        expiry = _aware(item.requested_expiry_date)
        finding = db.get(Finding, item.finding_id)
        if expiry <= now:
            item.status = "expired"
            if finding and finding.status == "risk_accepted":
                finding.status = "open"
            if finding:
                policy = db.scalar(
                    select(SlaPolicy).where(SlaPolicy.risk_band == finding.risk_band)
                )
                days = (
                    policy.sla_days
                    if policy
                    else {"critical": 7, "high": 15, "medium": 30, "low": 90}.get(
                        finding.risk_band, 30
                    )
                )
                task = db.scalar(
                    select(RemediationTask).where(
                        RemediationTask.finding_id == finding.id
                    )
                )
                if task and task.status != "closed":
                    task.status = "open"
                    task.closed_at = None
                    task.sla_due_date = now + timedelta(days=days)
            db.add(
                AuditLog(
                    actor_user_id=None,
                    action="exception_expired",
                    entity_type="risk_exception",
                    entity_id=item.id,
                    new_value={"status": "expired", "finding_reopened": bool(finding)},
                )
            )
            changed += 1
            continue
        days_left = (expiry - now).total_seconds() / 86400
        for warning_days in (14, 7):
            action = f"exception_expiry_warning_{warning_days}d"
            if days_left <= warning_days and not db.scalar(
                select(AuditLog.id)
                .where(AuditLog.entity_id == item.id, AuditLog.action == action)
                .limit(1)
            ):
                db.add(
                    AuditLog(
                        actor_user_id=None,
                        action=action,
                        entity_type="risk_exception",
                        entity_id=item.id,
                        new_value={
                            "days_until_expiry": max(0, round(days_left, 1)),
                            "finding_id": str(item.finding_id),
                        },
                    )
                )
                changed += 1
    db.commit()
    return changed


def approved_exception_for_finding(
    db: Session, finding_id, as_of: datetime | None = None
):
    now = as_of or datetime.now(timezone.utc)
    return db.scalar(
        select(RiskException).where(
            RiskException.finding_id == finding_id,
            RiskException.status == "approved",
            RiskException.requested_expiry_date > now,
        )
    )

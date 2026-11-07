"""Remediation task creation with SLA due dates and audited ownership assignment."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, Finding, RemediationTask, SlaPolicy
from app.services.audit import record_audit
from app.services.ownership import decide_owner

DEFAULT_SLA_DAYS = {"critical": 7, "high": 15, "medium": 30, "low": 90}


def sla_days(db: Session, band: str) -> int:
    policy = db.scalar(select(SlaPolicy).where(SlaPolicy.risk_band == band))
    return policy.sla_days if policy else DEFAULT_SLA_DAYS.get(band, 30)


def create_task_for_finding(
    db: Session, finding: Finding, asset: Asset
) -> RemediationTask | None:
    """Create (or return) the remediation task for a critical/high finding."""
    if finding.risk_band not in {"critical", "high"}:
        return None
    existing = db.scalar(
        select(RemediationTask).where(RemediationTask.finding_id == finding.id)
    )
    if existing is None:
        existing = next(
            (
                obj
                for obj in db.new
                if isinstance(obj, RemediationTask) and obj.finding_id == finding.id
            ),
            None,
        )
    if existing:
        return existing
    decision = decide_owner(db, asset)
    task = RemediationTask(
        id=uuid4(),
        finding_id=finding.id,
        asset_id=asset.id,
        assigned_to_user_id=decision.user_id,
        assigned_by_rule=decision.reason,
        assigned_group=decision.group,
        status="open",
        priority=finding.risk_band,
        sla_category=finding.risk_band,
        sla_due_date=datetime.now(timezone.utc)
        + timedelta(days=sla_days(db, finding.risk_band)),
    )
    db.add(task)
    record_audit(
        db,
        None,
        "ownership_assigned",
        "remediation_task",
        task.id,
        new={
            "finding_id": str(finding.id),
            "assigned_to_user_id": str(decision.user_id) if decision.user_id else None,
            "group": decision.group,
            "reason": decision.reason,
        },
    )
    return task


def reopen_task(db: Session, finding: Finding) -> RemediationTask | None:
    """Reopen a closed task when its finding is detected again (regression)."""
    task = db.scalar(
        select(RemediationTask).where(RemediationTask.finding_id == finding.id)
    )
    if task and task.status == "closed":
        task.status = "open"
        task.closed_at = None
        task.sla_due_date = datetime.now(timezone.utc) + timedelta(
            days=sla_days(db, finding.risk_band)
        )
        record_audit(
            db,
            None,
            "task_reopened",
            "remediation_task",
            task.id,
            new={"reason": "finding detected again after closure"},
        )
    return task

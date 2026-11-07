from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, Finding, RemediationTask, SlaPolicy
from app.services.ownership import choose_owner


def create_task_for_finding(
    db: Session, finding: Finding, asset: Asset
) -> RemediationTask | None:
    if finding.risk_band not in {"critical", "high"}:
        return None
    existing = db.scalar(
        select(RemediationTask).where(RemediationTask.finding_id == finding.id)
    )
    if existing:
        return existing
    policy = db.scalar(
        select(SlaPolicy).where(SlaPolicy.risk_band == finding.risk_band)
    )
    days = (
        policy.sla_days
        if policy
        else {"critical": 7, "high": 15, "medium": 30, "low": 90}[finding.risk_band]
    )
    owner_id, rule = choose_owner(db, asset)
    task = RemediationTask(
        finding_id=finding.id,
        asset_id=asset.id,
        assigned_to_user_id=owner_id,
        assigned_by_rule=rule,
        status="open",
        priority=finding.risk_band,
        sla_category=finding.risk_band,
        sla_due_date=datetime.now(timezone.utc) + timedelta(days=days),
    )
    db.add(task)
    return task

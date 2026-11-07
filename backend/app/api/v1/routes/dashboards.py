from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _global_scope,
)
from app.api.v1.routes.findings import _finding_rows
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import (
    Asset,
    AuditLog,
    BusinessUnit,
    Escalation,
    Finding,
    ImportBatch,
    RemediationTask,
    RiskException,
    User,
)
from app.services import analytics

router = APIRouter(prefix="/api/v1")


@router.get("/dashboards/heatmap")
def dashboard_heatmap(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    return {"items": analytics.heatmap(db, user)}


@router.get("/dashboards/trend")
def dashboard_trend(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return {"weeks": analytics.trend(db, user)}


@router.get("/dashboards/mttr")
def dashboard_mttr(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return {"by_band": analytics.mttr_by_band(db, user)}


@router.get("/dashboards/sla-compliance")
def dashboard_sla_compliance(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    data = analytics.summary(db, user)
    return {
        "compliance_percent": data["sla_compliance_percent"],
        "overdue_count": data["overdue_count"],
        "overdue_by_owner": data["overdue_by_owner"],
        "aging_buckets": data["aging_buckets"],
    }


@router.get("/dashboards/{view}")
def dashboard(
    view: str, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    if view not in {"executive", "analyst", "manager", "auditor"}:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return _dashboard_payload(db, user, view)


@analytics.cached
def _dashboard_payload(db: Session, user: User, view: str):
    if view not in {"executive", "analyst", "manager", "auditor"}:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    data = analytics.summary(db, user)
    base_findings = analytics.finding_query(user).where(Finding.status == "open")
    top_findings = _finding_rows(
        db, base_findings.order_by(Finding.risk_score.desc()).limit(10)
    )
    if view == "executive":
        return {
            "view": view,
            "kpis": data,
            "risk_bands": data["risk_bands"],
            "top_findings": top_findings,
            "top_assets": data["top_assets"],
            "trend": data["trend"],
            "heatmap": data["heatmap"],
            "exceptions_expiring": data["exceptions_expiring"],
            "risk_by_business_unit": _risk_by_business_unit(db, user),
            "internet_facing_high_risk": data["internet_facing_high_risk"],
            "crown_jewel_paths": data["crown_jewel_paths"],
            "overdue_by_owner_and_category": data["overdue_by_owner_and_category"],
            "risk_reduction_percent": data["risk_reduction_percent"],
            "assumption": "Effort saved assumes 6 minutes of manual triage per raw finding not represented by a distinct open action.",
        }
    if view == "analyst":
        batches = db.scalars(
            select(ImportBatch).order_by(ImportBatch.created_at.desc()).limit(10)
        ).all()
        return {
            "view": view,
            "kpis": data,
            "risk_bands": data["risk_bands"],
            "top_findings": top_findings,
            "top_assets": data["top_assets"],
            "trend": data["trend"],
            "heatmap": data["heatmap"],
            "findings_by_source": data["findings_by_source"],
            "internet_facing_high_risk": data["internet_facing_high_risk"],
            "crown_jewel_paths": data["crown_jewel_paths"],
            "recent_imports": [
                {
                    "id": str(b.id),
                    "source": b.source_name,
                    "file": b.file_name,
                    "total": b.total_records,
                    "failed": b.failed_count,
                    "duplicates": b.duplicate_count,
                }
                for b in batches
            ],
        }
    if view == "manager":
        return {
            "view": view,
            "kpis": data,
            "risk_bands": data["risk_bands"],
            "top_findings": top_findings,
            "trend": data["trend"],
            "assumption": "Effort saved assumes six minutes per raw record that does not remain a distinct action.",
            "overdue_by_owner": data["overdue_by_owner"],
            "overdue_by_owner_and_category": data["overdue_by_owner_and_category"],
            "aging_buckets": data["aging_buckets"],
            "escalations": _scoped_escalations(db, user),
            "tasks_by_status": _tasks_by_status(db, user),
        }
    return {
        "view": view,
        "kpis": data,
        "risk_bands": data["risk_bands"],
        "top_findings": top_findings,
        "trend": data["trend"],
        "assumption": "Aggregated audit view; finding detail is read-only.",
        "recent_audit": _scoped_audit_summary(db),
        "exceptions": _scoped_exceptions(db, user),
        "exceptions_expiring": data["exceptions_expiring"],
    }


def _risk_by_business_unit(db: Session, user: User):
    query = (
        select(BusinessUnit.name, Finding.risk_band, func.count(Finding.id))
        .join(Asset, Asset.business_unit_id == BusinessUnit.id)
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
        .group_by(BusinessUnit.name, Finding.risk_band)
    )
    scope = analytics.asset_scope(user)
    if scope is not None:
        query = query.where(scope)
    return [
        {"business_unit": bu, "risk_band": band, "count": count}
        for bu, band, count in db.execute(query)
    ]


def _scoped_escalations(db: Session, user: User):
    query = select(Escalation).join(
        RemediationTask, Escalation.task_id == RemediationTask.id
    )
    if not _global_scope(user):
        query = query.join(Asset, RemediationTask.asset_id == Asset.id)
        scope = analytics.asset_scope(user)
        if scope is not None:
            query = query.where(scope)
    return [
        {
            "id": str(x.id),
            "task_id": str(x.task_id),
            "level": x.level,
            "reason": x.reason,
            "acknowledged": x.acknowledged,
        }
        for x in db.scalars(query.order_by(Escalation.created_at.desc()).limit(100))
    ]


def _tasks_by_status(db: Session, user: User):
    query = (
        analytics.task_query(user)
        .with_only_columns(RemediationTask.status, func.count(RemediationTask.id))
        .group_by(RemediationTask.status)
    )
    return {status: count for status, count in db.execute(query)}


def _scoped_audit_summary(db: Session):
    rows = db.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(20)
    ).all()
    return [
        {
            "id": str(x.id),
            "action": x.action,
            "entity_type": x.entity_type,
            "timestamp": x.created_at.isoformat() if x.created_at else None,
        }
        for x in rows
    ]


def _scoped_exceptions(db: Session, user: User):
    query = select(RiskException)
    if not _global_scope(user):
        query = query.join(Finding, RiskException.finding_id == Finding.id).join(
            Asset, Finding.asset_id == Asset.id
        )
        scope = analytics.asset_scope(user)
        if scope is not None:
            query = query.where(scope)
    return [
        {
            "id": str(x.id),
            "finding_id": str(x.finding_id),
            "status": x.status,
            "expiry": x.requested_expiry_date.isoformat(),
        }
        for x in db.scalars(query.order_by(RiskException.created_at.desc()).limit(100))
    ]

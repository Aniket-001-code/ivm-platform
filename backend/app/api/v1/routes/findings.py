from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _csv_response,
    _page,
    _check_asset_scope,
    audit,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import (
    Asset,
    AttackPath,
    Finding,
    FindingSource,
    RawFinding,
    RemediationTask,
    VulnerabilityCatalog,
    RiskScoreHistory,
    User,
)
from app.services import analytics

router = APIRouter(prefix="/api/v1")


def _finding_dict(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "asset_id": str(f.asset_id),
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "risk_band": f.risk_band,
        "status": f.status,
        "sources": f.sources or [],
        "fingerprint": f.fingerprint,
    }


def _finding_rows(db: Session, query):
    return [
        _finding_dict(f)
        for f in db.scalars(query.order_by(Finding.risk_score.desc()).limit(2000))
    ]


FINDING_STATUSES = {"open", "in_remediation", "risk_accepted", "closed"}

FINDING_SORT = {
    "risk_score": Finding.risk_score,
    "title": Finding.title,
    "severity": Finding.severity,
    "status": Finding.status,
    "cvss_score": Finding.cvss_score,
    "created_at": Finding.created_at,
}


def _filtered_findings(user, severity, band, status_filter, asset_id, search):
    query = analytics.finding_query(user)
    if severity:
        query = query.where(Finding.severity == severity.lower())
    if band:
        query = query.where(Finding.risk_band == band.lower())
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if search:
        query = query.where(Finding.title.ilike(f"%{search}%"))
    return query


def _finding_order(sort: str, order: str):
    column = FINDING_SORT.get(sort)
    if column is None:
        raise HTTPException(status_code=422, detail=f"Unsupported sort field: {sort}")
    return [column.asc() if order == "asc" else column.desc(), Finding.id]


@router.get("/findings")
def findings(
    response: Response,
    severity: str | None = None,
    band: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    asset_id: UUID | None = None,
    search: str | None = None,
    sort: str = "risk_score",
    order: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=2000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List findings; the unpaged total is returned in the X-Total-Count header."""
    query = _filtered_findings(user, severity, band, status_filter, asset_id, search)
    rows = _page(db, response, query, _finding_order(sort, order), limit, offset)
    return [_finding_dict(f) for f in rows]


@router.get("/findings/export")
def findings_export(
    severity: str | None = None,
    band: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    asset_id: UUID | None = None,
    search: str | None = None,
    sort: str = "risk_score",
    order: Literal["asc", "desc"] = "desc",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = _filtered_findings(user, severity, band, status_filter, asset_id, search)
    rows = db.scalars(query.order_by(*_finding_order(sort, order)).limit(10000))
    return _csv_response(
        "ivm-findings.csv",
        [
            "id",
            "title",
            "severity",
            "cvss_score",
            "risk_score",
            "risk_band",
            "status",
            "asset_id",
            "sources",
        ],
        (
            [
                f.id,
                f.title,
                f.severity,
                f.cvss_score,
                f.risk_score,
                f.risk_band,
                f.status,
                f.asset_id,
                ";".join(f.sources or []),
            ]
            for f in rows
        ),
    )


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    asset = db.get(Asset, f.asset_id)
    _check_asset_scope(asset, user, db)
    catalog = (
        db.get(VulnerabilityCatalog, f.vulnerability_id) if f.vulnerability_id else None
    )
    task = db.scalar(select(RemediationTask).where(RemediationTask.finding_id == f.id))
    history = db.scalars(
        select(RiskScoreHistory)
        .where(RiskScoreHistory.finding_id == f.id)
        .order_by(RiskScoreHistory.calculated_at)
    ).all()
    return {
        "id": str(f.id),
        "asset": {"id": str(asset.id), "name": asset.name} if asset else None,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "sources": f.sources,
        "status": f.status,
        "risk_score": f.risk_score,
        "risk_band": f.risk_band,
        "risk_breakdown": f.risk_breakdown,
        "history": [
            {"score": h.score, "band": h.band, "calculated_at": h.calculated_at}
            for h in history
        ],
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "closed_at": f.closed_at,
        "reopened_count": f.reopened_count or 0,
        "finding_type": f.finding_type,
        "threat_intel": (
            {
                "cve_id": catalog.cve_id,
                "epss_score": catalog.epss_score,
                "in_kev_list": catalog.in_kev_list,
                "actively_exploited": catalog.actively_exploited,
                "ransomware_used": catalog.ransomware_used,
                "exploit_maturity": catalog.exploit_maturity,
                "cvss_base_score": catalog.cvss_base_score,
            }
            if catalog
            else None
        ),
        "source_records": [
            {
                "source": src.source_name,
                "seen_at": src.created_at,
                "raw": raw.raw_payload if raw else None,
            }
            for src, raw in db.execute(
                select(FindingSource, RawFinding)
                .join(
                    RawFinding,
                    FindingSource.raw_finding_id == RawFinding.id,
                    isouter=True,
                )
                .where(FindingSource.finding_id == f.id)
                .order_by(FindingSource.created_at)
                .limit(25)
            )
        ],
        "task": (
            {
                "id": str(task.id),
                "status": task.status,
                "priority": task.priority,
                "sla_due_date": task.sla_due_date,
                "assigned_group": task.assigned_group,
                "ticket_ref": task.ticket_ref,
            }
            if task
            else None
        ),
        "attack_paths": [
            {"id": str(p.id), "name": p.name, "path_risk_score": p.path_risk_score}
            for p in db.scalars(
                select(AttackPath).order_by(AttackPath.path_risk_score.desc())
            )
            if str(f.id) in (p.path_finding_ids or [])
        ][:10],
    }


@router.patch("/findings/{finding_id}/status")
def finding_status(
    finding_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    old = finding.status
    new_status = str(body.get("status", "open"))
    if new_status not in FINDING_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported finding status")
    finding.status = new_status
    audit(
        db,
        user,
        "finding_status_changed",
        "finding",
        finding.id,
        {"status": old},
        {"status": finding.status},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(finding.id), "status": finding.status}

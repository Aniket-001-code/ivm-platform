"""Executive reporting, success-criteria evidence, forecasting and recommendations."""

from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.v1.common import audit
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import User
from app.services import reports

router = APIRouter(prefix="/api/v1")


@router.get("/reports/success-criteria")
def success_criteria(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Live, measured status of SPEC success criteria SC-1..SC-12."""
    return reports.success_criteria(db, user)


@router.get("/reports/executive")
def executive_report(
    request: Request,
    format: Literal["json", "html"] = "json",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Board-style summary (UC-12); ``format=html`` returns a printable report."""
    report = reports.executive_report(db, user)
    audit(
        db,
        user,
        "executive_report_generated",
        "report",
        new={"format": format},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    if format == "html":
        return HTMLResponse(
            reports.executive_report_html(report),
            headers={
                "Content-Disposition": "attachment; filename=ivm-executive-report.html"
            },
        )
    return report


@router.get("/reports/automation-impact")
def automation_impact(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return reports.automation_impact(db)


@router.get("/reports/ownership-accuracy")
def ownership_accuracy(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    return reports.ownership_accuracy(db, user)


@router.get("/reports/remediation-plan")
def remediation_plan(
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Recommended remediation sequence by risk reduced per hour of effort."""
    return reports.remediation_plan(db, user, limit)


@router.get("/analytics/forecast")
def forecast(
    weeks: int = Query(default=4, ge=1, le=12),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Risk trend projection and SLA breach forecast from historical data."""
    return reports.risk_forecast(db, user, weeks)

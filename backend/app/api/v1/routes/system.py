from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _check_asset_scope,
    audit,
)
from app.core import scope
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import (
    Permission,
    canonical_role,
    has_permission,
    require_permission,
)
from app.db.session import engine
from app.models.entities import (
    Asset,
    Escalation,
    Finding,
    RemediationTask,
    RiskException,
    User,
    VulnerabilityCatalog,
)
from app.services.exceptions import expire_exceptions
from app.services.ingestion import MAX_UPLOAD_BYTES, parse_upload
from app.services.scoring import rescore_findings
from app.services.sla import check_overdue_tasks

router = APIRouter(prefix="/api/v1")


@router.get("/metrics")
def metrics(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return {
        "assets": db.scalar(select(func.count()).select_from(Asset)) or 0,
        "findings": db.scalar(select(func.count()).select_from(Finding)) or 0,
        "tasks": db.scalar(select(func.count()).select_from(RemediationTask)) or 0,
    }


@router.get("/health")
def api_health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok", "database": "ok"}


def _catalog_dict(item: VulnerabilityCatalog) -> dict:
    return {
        "cve_id": item.cve_id,
        "title": item.title,
        "cvss_base_score": item.cvss_base_score,
        "epss_score": item.epss_score,
        "in_kev_list": item.in_kev_list,
        "ransomware_used": item.ransomware_used,
        "actively_exploited": item.actively_exploited,
        "exploit_maturity": item.exploit_maturity,
    }


@router.get("/threat-intel")
def threat_intel_catalog(
    kev_only: bool = False,
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
):
    query = select(VulnerabilityCatalog).order_by(
        VulnerabilityCatalog.epss_score.desc()
    )
    if kev_only:
        query = query.where(VulnerabilityCatalog.in_kev_list.is_(True))
    return [_catalog_dict(item) for item in db.scalars(query.limit(1000))]


@router.get("/threat-intel/{cve_id}")
def threat_intel(
    cve_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    item = db.scalar(
        select(VulnerabilityCatalog).where(
            VulnerabilityCatalog.cve_id == cve_id.upper()
        )
    )
    if not item:
        raise HTTPException(
            status_code=404, detail="Threat intelligence record not found"
        )
    return _catalog_dict(item)


_TRUE = {"true", "1", "yes", "y"}
_MATURITY = {"none", "poc", "functional", "weaponized"}


def _as_bool(value, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _TRUE


def _apply_threat_feed(db: Session, rows: list, user: User, ip: str | None) -> dict:
    if len(rows) > 5000:
        raise HTTPException(status_code=413, detail="Threat feed is too large")
    changed, skipped, touched = 0, [], []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            skipped.append({"row": index, "error": "row is not an object"})
            continue
        cve = str(row.get("cve_id") or row.get("cve") or "").strip().upper()
        if not cve.startswith("CVE-"):
            skipped.append({"row": index, "error": "missing or invalid cve_id"})
            continue
        try:
            raw_epss, raw_cvss = row.get("epss_score"), row.get("cvss_base_score")
            epss = None if raw_epss in (None, "") else float(str(raw_epss))
            cvss = None if raw_cvss in (None, "") else float(str(raw_cvss))
        except (TypeError, ValueError):
            skipped.append(
                {"row": index, "error": "epss_score/cvss_base_score must be numbers"}
            )
            continue
        maturity = str(row.get("exploit_maturity") or "").strip().lower() or None
        if maturity and maturity not in _MATURITY:
            skipped.append(
                {"row": index, "error": f"unknown exploit_maturity '{maturity}'"}
            )
            continue
        item = db.scalar(
            select(VulnerabilityCatalog).where(VulnerabilityCatalog.cve_id == cve)
        )
        if not item:
            item = VulnerabilityCatalog(
                cve_id=cve,
                title=str(row.get("title") or cve)[:300],
                description=str(row.get("description") or ""),
                cvss_base_score=cvss or 0.0,
                epss_score=0,
                exploit_maturity="none",
                in_kev_list=False,
                ransomware_used=False,
                actively_exploited=False,
            )
            db.add(item)
        if epss is not None:
            item.epss_score = max(0.0, min(1.0, epss))
        if cvss is not None:
            item.cvss_base_score = max(0.0, min(10.0, cvss))
        item.in_kev_list = _as_bool(row.get("in_kev_list"), item.in_kev_list)
        item.ransomware_used = _as_bool(
            row.get("ransomware_used"), item.ransomware_used
        )
        item.actively_exploited = _as_bool(
            row.get("actively_exploited"), item.actively_exploited
        )
        if maturity:
            item.exploit_maturity = maturity
        touched.append(item)
        changed += 1
    db.flush()
    affected = db.scalars(
        select(Finding).where(
            Finding.vulnerability_id.in_([i.id for i in touched]),
            Finding.status != "closed",
        )
    ).all()
    before = {f.id: f.risk_band for f in affected}
    rescore_findings(db, affected)
    band_changes = sum(1 for f in affected if before[f.id] != f.risk_band)
    audit(
        db,
        user,
        "threat_intel_imported",
        "vulnerability_catalog",
        new={
            "records": changed,
            "skipped": len(skipped),
            "findings_rescored": len(affected),
            "band_changes": band_changes,
        },
        ip=ip,
    )
    db.commit()
    return {
        "updated": changed,
        "skipped": skipped[:100],
        "findings_rescored": len(affected),
        "band_changes": band_changes,
    }


@router.post("/threat-intel/import")
def import_threat_intel(
    body: Annotated[list[Any], Body()],
    request: Request,
    user: User = Depends(require_permission(Permission.IMPORT)),
    db: Session = Depends(get_db),
):
    """Apply a threat feed (JSON array) and immediately rescore affected findings."""
    return _apply_threat_feed(
        db, body, user, request.client.host if request.client else None
    )


@router.post("/threat-intel/import/file")
async def import_threat_intel_file(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_permission(Permission.IMPORT)),
    db: Session = Depends(get_db),
):
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        rows = parse_upload("threat_intel", file.filename or "feed.json", content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _apply_threat_feed(
        db, rows, user, request.client.host if request.client else None
    )


def _escalation_dict(row: Escalation, emails: dict) -> dict:
    return {
        "id": str(row.id),
        "task_id": str(row.task_id),
        "level": row.level,
        "reason": row.reason,
        "escalated_to": emails.get(row.escalated_to_user_id),
        "acknowledged": row.acknowledged,
        "acknowledged_at": row.acknowledged_at,
        "created_at": row.created_at,
    }


@router.get("/escalations")
def escalations(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Escalations on tasks inside the caller's scope, newest first."""
    query = select(Escalation).join(
        RemediationTask, Escalation.task_id == RemediationTask.id
    )
    condition = scope.asset_condition(user)
    if condition is not None:
        query = query.join(Asset, RemediationTask.asset_id == Asset.id).where(condition)
    emails = {u.id: u.email for u in db.scalars(select(User))}
    return [
        _escalation_dict(x, emails)
        for x in db.scalars(query.order_by(Escalation.created_at.desc()).limit(500))
    ]


@router.post("/escalations/{escalation_id}/acknowledge")
def acknowledge_escalation(
    escalation_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    row = db.get(Escalation, escalation_id)
    if not row:
        raise HTTPException(status_code=404, detail="Escalation not found")
    task = db.get(RemediationTask, row.task_id)
    if task:
        _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    if row.escalated_to_user_id not in {user.id, None} and canonical_role(
        user.role
    ) not in {
        "platform_admin",
        "vulnerability_manager",
    }:
        raise HTTPException(
            status_code=403, detail="Only the recipient can acknowledge this"
        )
    if not row.acknowledged:
        row.acknowledged = True
        row.acknowledged_at = datetime.now(timezone.utc)
        row.acknowledged_by = user.id
        audit(
            db,
            user,
            "escalation_acknowledged",
            "escalation",
            row.id,
            new={"task_id": str(row.task_id), "level": row.level},
            ip=request.client.host if request.client else None,
        )
        db.commit()
    return {"id": str(row.id), "acknowledged": True}


@router.get("/notifications")
def notifications(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    """Escalations routed to the caller (kept for API compatibility; see /me/notifications)."""
    emails = {u.id: u.email for u in db.scalars(select(User))}
    rows = db.scalars(
        select(Escalation)
        .where(Escalation.escalated_to_user_id == user.id)
        .order_by(Escalation.created_at.desc())
        .limit(100)
    ).all()
    return [_escalation_dict(row, emails) for row in rows]


def _day(value) -> str:
    return value.date().isoformat() if value else "unknown"


@router.get("/me/notifications")
def my_notifications(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Personal inbox for every role: escalations, overdue/at-risk work, exception actions."""
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=14)
    items: list[dict] = []
    for e in db.scalars(
        select(Escalation)
        .where(
            Escalation.escalated_to_user_id == user.id,
            Escalation.acknowledged.is_(False),
        )
        .order_by(Escalation.created_at.desc())
        .limit(50)
    ):
        items.append(
            {
                "id": f"escalation:{e.id}",
                "kind": "escalation",
                "severity": "high" if e.level >= 2 else "medium",
                "title": f"Level {e.level} escalation",
                "detail": e.reason,
                "link": "/tasks",
                "escalation_id": str(e.id),
                "created_at": e.created_at,
            }
        )
    mine = select(RemediationTask).where(
        RemediationTask.assigned_to_user_id == user.id,
        RemediationTask.status != "closed",
        RemediationTask.sla_due_date.is_not(None),
    )
    for t in db.scalars(mine.where(RemediationTask.sla_due_date < now).limit(50)):
        items.append(
            {
                "id": f"overdue:{t.id}",
                "kind": "overdue_task",
                "severity": "high",
                "title": f"Overdue {t.priority} task",
                "detail": f"Task {str(t.id)[:8]} was due {_day(t.sla_due_date)}",
                "link": "/tasks?overdue=true",
                "created_at": t.sla_due_date,
            }
        )
    for t in db.scalars(
        mine.where(
            RemediationTask.sla_due_date >= now, RemediationTask.sla_due_date <= soon
        )
        .order_by(RemediationTask.sla_due_date)
        .limit(20)
    ):
        items.append(
            {
                "id": f"due:{t.id}",
                "kind": "due_soon",
                "severity": "medium",
                "title": f"{t.priority.title()} task due soon",
                "detail": f"Task {str(t.id)[:8]} is due {_day(t.sla_due_date)}",
                "link": "/tasks",
                "created_at": t.sla_due_date,
            }
        )
    if has_permission(user.role, Permission.EXCEPTION_APPROVE_TEMP):
        pending = db.scalars(
            select(RiskException)
            .where(
                RiskException.status == "pending", RiskException.requested_by != user.id
            )
            .limit(50)
        ).all()
        if pending:
            items.append(
                {
                    "id": "exceptions:pending",
                    "kind": "approval_needed",
                    "severity": "medium",
                    "title": f"{len(pending)} exception request(s) awaiting review",
                    "detail": "Review risk acceptance requests from other users.",
                    "link": "/exceptions",
                    "created_at": max(p.created_at for p in pending),
                }
            )
    for x in db.scalars(
        select(RiskException).where(
            RiskException.requested_by == user.id,
            RiskException.status == "approved",
            RiskException.requested_expiry_date <= soon,
        )
    ):
        items.append(
            {
                "id": f"expiring:{x.id}",
                "kind": "exception_expiring",
                "severity": "medium",
                "title": "Your risk exception expires soon",
                "detail": f"Expires {_day(x.requested_expiry_date)}",
                "link": "/exceptions",
                "created_at": x.requested_expiry_date,
            }
        )
    return {"count": len(items), "items": items}


@router.post("/jobs/run")
def run_jobs(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.SCHEDULER_RUN)),
):
    return {
        "escalations_created": check_overdue_tasks(db),
        "exceptions_expired": expire_exceptions(db),
    }

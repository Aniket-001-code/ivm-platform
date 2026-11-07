import html
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from app.core import scope
from app.core.timeutil import as_utc
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _csv_response,
    ExceptionInput,
    _check_asset_scope,
    _global_scope,
    audit,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import (
    Permission,
    canonical_role,
    require_permission,
)
from app.models.entities import (
    Asset,
    AttackPath,
    AuditLog,
    Finding,
    RemediationTask,
    RiskException,
    User,
    VulnerabilityCatalog,
)

router = APIRouter(prefix="/api/v1")


@router.get("/exceptions")
def exceptions(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(RiskException).join(Finding, RiskException.finding_id == Finding.id)
    if not _global_scope(user):
        query = query.join(Asset, Finding.asset_id == Asset.id).where(
            scope.asset_condition(user)
        )
    return [
        {
            "id": str(x.id),
            "finding_id": str(x.finding_id),
            "requested_by": str(x.requested_by),
            "justification": x.justification,
            "compensating_controls": x.compensating_controls,
            "exception_type": x.exception_type,
            "requested_expiry_date": x.requested_expiry_date,
            "status": x.status,
            "review_comment": x.review_comment,
        }
        for x in db.scalars(query.order_by(RiskException.created_at.desc()))
    ]


@router.post("/exceptions")
def request_exception(
    body: ExceptionInput,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, body.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    maximum = 90 if body.exception_type == "temporary" else 365
    expiry = as_utc(body.requested_expiry_date)
    if (
        body.exception_type not in {"temporary", "long_term"}
        or expiry <= datetime.now(timezone.utc)
        or expiry > datetime.now(timezone.utc) + timedelta(days=maximum)
    ):
        raise HTTPException(
            status_code=422,
            detail=f"{body.exception_type} exception expiry must be within {maximum} days",
        )
    item = RiskException(
        finding_id=finding.id,
        requested_by=user.id,
        justification=body.justification,
        compensating_controls=body.compensating_controls,
        exception_type=body.exception_type,
        requested_expiry_date=body.requested_expiry_date,
        status="pending",
    )
    db.add(item)
    db.flush()
    audit(db, user, "exception_requested", "risk_exception", item.id)
    db.commit()
    return {"id": str(item.id), "status": item.status}


@router.get("/exceptions/expiring")
def expiring_exceptions(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    cutoff = datetime.now(timezone.utc) + timedelta(days=30)
    query = select(RiskException).where(
        RiskException.status == "approved",
        RiskException.requested_expiry_date <= cutoff,
    )
    if not _global_scope(user):
        query = (
            query.join(Finding, RiskException.finding_id == Finding.id)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(scope.asset_condition(user))
        )
    return [
        {
            "id": str(x.id),
            "finding_id": str(x.finding_id),
            "expiry": x.requested_expiry_date,
            "status": x.status,
        }
        for x in db.scalars(query)
    ]


@router.get("/exceptions/export")
def exception_export(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EXCEPTION_READ)),
):
    query = select(RiskException).join(Finding, RiskException.finding_id == Finding.id)
    condition = scope.asset_condition(user)
    if condition is not None:
        query = query.join(Asset, Finding.asset_id == Asset.id).where(condition)
    items = db.scalars(query.order_by(RiskException.created_at.desc()))
    return _csv_response(
        "ivm-exceptions.csv",
        [
            "id",
            "finding_id",
            "status",
            "exception_type",
            "justification",
            "compensating_controls",
            "expiry",
            "review_comment",
        ],
        (
            [
                x.id,
                x.finding_id,
                x.status,
                x.exception_type,
                x.justification,
                x.compensating_controls,
                x.requested_expiry_date,
                x.review_comment,
            ]
            for x in items
        ),
    )


@router.get("/exceptions/{exception_id}")
def exception_detail(
    exception_id: UUID,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    item = db.get(RiskException, exception_id)
    if not item:
        raise HTTPException(status_code=404, detail="Exception not found")
    finding = db.get(Finding, item.finding_id)
    if finding:
        _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    return {
        "id": str(item.id),
        "finding_id": str(item.finding_id),
        "requested_by": str(item.requested_by),
        "justification": item.justification,
        "compensating_controls": item.compensating_controls,
        "status": item.status,
        "reviewed_by": str(item.reviewed_by) if item.reviewed_by else None,
        "review_comment": item.review_comment,
        "requested_expiry_date": item.requested_expiry_date,
    }


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(
    exception_id: UUID,
    body: dict,
    user: User = Depends(require_permission(Permission.EXCEPTION_APPROVE_TEMP)),
    db: Session = Depends(get_db),
):
    item = db.get(RiskException, exception_id)
    if not item:
        raise HTTPException(status_code=404, detail="Exception not found")
    if item.status != "approved":
        raise HTTPException(
            status_code=409, detail="Only approved exceptions can be revoked"
        )
    finding = db.get(Finding, item.finding_id)
    if finding:
        _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    item.status = "revoked"
    if finding and finding.status == "risk_accepted":
        finding.status = "open"
    audit(
        db,
        user,
        "exception_revoked",
        "risk_exception",
        item.id,
        new={"comment": body.get("comment", "")},
    )
    db.commit()
    return {"id": str(item.id), "status": item.status}


def review_exception(
    exception_id: UUID, action: str, comment: str, user: User, db: Session
):
    item = db.get(RiskException, exception_id)
    if not item:
        raise HTTPException(status_code=404, detail="Exception not found")
    if item.requested_by == user.id:
        raise HTTPException(status_code=403, detail="Self-approval is forbidden")
    target = db.get(Finding, item.finding_id)
    if target:
        _check_asset_scope(db.get(Asset, target.asset_id), user, db)
    role = canonical_role(user.role)
    if role not in {"security_architect", "vulnerability_manager"}:
        raise HTTPException(
            status_code=403, detail="Role cannot review risk exceptions"
        )
    if item.exception_type == "long_term" and role != "security_architect":
        raise HTTPException(
            status_code=403,
            detail="Long-term exceptions require Security Architect approval",
        )
    if item.exception_type != "temporary" and role == "vulnerability_manager":
        raise HTTPException(
            status_code=403,
            detail="Vulnerability Manager may approve temporary exceptions only",
        )
    if item.status != "pending":
        raise HTTPException(
            status_code=409, detail="Only pending exceptions may be reviewed"
        )
    item.status = action
    item.reviewed_by = user.id
    item.review_comment = comment
    if action == "approved":
        item.approved_at = datetime.now(timezone.utc)
        finding = db.get(Finding, item.finding_id)
        if finding:
            finding.status = "risk_accepted"
    audit(
        db,
        user,
        f"exception_{action}",
        "risk_exception",
        item.id,
        new={"status": action, "comment": comment},
    )
    db.commit()
    return {"id": str(item.id), "status": item.status}


@router.post("/exceptions/{exception_id}/approve")
def approve_exception(
    exception_id: UUID,
    body: dict,
    user: User = Depends(require_permission(Permission.EXCEPTION_APPROVE_TEMP)),
    db: Session = Depends(get_db),
):
    return review_exception(
        exception_id, "approved", str(body.get("comment", "Approved")), user, db
    )


@router.post("/exceptions/{exception_id}/reject")
def reject_exception(
    exception_id: UUID,
    body: dict,
    user: User = Depends(require_permission(Permission.EXCEPTION_APPROVE_TEMP)),
    db: Session = Depends(get_db),
):
    return review_exception(
        exception_id, "rejected", str(body.get("comment", "Rejected")), user, db
    )


def _review_pack(db: Session, item: RiskException) -> dict:
    finding = db.get(Finding, item.finding_id)
    asset = db.get(Asset, finding.asset_id) if finding else None
    catalog = (
        db.get(VulnerabilityCatalog, finding.vulnerability_id)
        if finding and finding.vulnerability_id
        else None
    )
    task = (
        db.scalar(
            select(RemediationTask).where(RemediationTask.finding_id == finding.id)
        )
        if finding
        else None
    )
    users: dict = {u.id: u.email for u in db.scalars(select(User))}
    entity_ids = [
        i
        for i in (item.id, finding.id if finding else None, task.id if task else None)
        if i
    ]
    events = db.scalars(
        select(AuditLog)
        .where(AuditLog.entity_id.in_(entity_ids))
        .order_by(AuditLog.created_at)
    ).all()
    paths = [
        {"name": p.name, "path_risk_score": p.path_risk_score}
        for p in db.scalars(select(AttackPath))
        if finding and str(finding.id) in (p.path_finding_ids or [])
    ][:10]
    expiry = as_utc(item.requested_expiry_date)
    created = as_utc(item.created_at) if item.created_at else None
    duration_days = (expiry - created).days if created else None
    checks = [
        {
            "check": "Requester is not the approver (segregation of duties)",
            "passed": item.reviewed_by is None or item.reviewed_by != item.requested_by,
        },
        {
            "check": "Duration within policy (temporary ≤ 90 days, long-term ≤ 365 days)",
            "passed": duration_days is not None
            and duration_days <= (90 if item.exception_type == "temporary" else 365),
        },
        {
            "check": "Compensating controls documented",
            "passed": len((item.compensating_controls or "").strip()) >= 10,
        },
        {
            "check": "Business justification documented",
            "passed": len((item.justification or "").strip()) >= 10,
        },
        {
            "check": "Not on a modeled attack path to a crown jewel",
            "passed": not paths,
        },
        {
            "check": "No known exploitation (KEV / active exploitation)",
            "passed": not (
                catalog and (catalog.in_kev_list or catalog.actively_exploited)
            ),
        },
    ]
    return {
        "generated_at": datetime.now(timezone.utc),
        "exception": {
            "id": str(item.id),
            "status": item.status,
            "type": item.exception_type,
            "justification": item.justification,
            "compensating_controls": item.compensating_controls,
            "requested_by": users.get(item.requested_by),
            "reviewed_by": users.get(item.reviewed_by),
            "review_comment": item.review_comment,
            "requested_at": item.created_at,
            "approved_at": item.approved_at,
            "expires": item.requested_expiry_date,
            "duration_days": duration_days,
        },
        "finding": (
            {
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "cvss": finding.cvss_score,
                "risk_score": finding.risk_score,
                "risk_band": finding.risk_band,
                "status": finding.status,
                "risk_breakdown": finding.risk_breakdown,
            }
            if finding
            else None
        ),
        "threat_intel": (
            {
                "cve_id": catalog.cve_id,
                "epss_score": catalog.epss_score,
                "in_kev_list": catalog.in_kev_list,
                "actively_exploited": catalog.actively_exploited,
                "ransomware_used": catalog.ransomware_used,
                "exploit_maturity": catalog.exploit_maturity,
            }
            if catalog
            else None
        ),
        "asset": (
            {
                "name": asset.name,
                "environment": asset.environment,
                "criticality_tier": asset.criticality_tier,
                "internet_exposed": asset.internet_exposed,
                "is_crown_jewel": asset.is_crown_jewel,
                "has_sensitive_data": asset.has_sensitive_data,
                "regulatory_tags": asset.regulatory_tags or [],
            }
            if asset
            else None
        ),
        "remediation_task": (
            {
                "id": str(task.id),
                "status": task.status,
                "owner": users.get(task.assigned_to_user_id),
                "sla_due_date": task.sla_due_date,
            }
            if task
            else None
        ),
        "attack_paths": paths,
        "review_checks": checks,
        "checks_passed": sum(c["passed"] for c in checks),
        "audit_trail": [
            {
                "at": e.created_at,
                "actor": users.get(e.actor_user_id, "system"),
                "action": e.action,
                "details": e.new_value,
                "row_hash": e.row_hash,
            }
            for e in events
        ],
    }


def _pack_html(pack: dict) -> str:
    def esc(value) -> str:
        return html.escape("—" if value is None else str(value))

    ex, finding, asset = pack["exception"], pack["finding"] or {}, pack["asset"] or {}
    checks = "".join(
        f"<tr><td>{'✔' if c['passed'] else '✘'}</td><td>{esc(c['check'])}</td></tr>"
        for c in pack["review_checks"]
    )
    factors = "".join(
        f"<tr><td>{esc(f.get('factor'))}</td><td>{esc(f.get('points'))} / {esc(f.get('max_points'))}</td>"
        f"<td>{esc(f.get('reason'))}</td></tr>"
        for f in (finding.get("risk_breakdown") or [])
        if isinstance(f, dict)
    )
    trail = "".join(
        f"<tr><td>{esc(e['at'])}</td><td>{esc(e['actor'])}</td><td>{esc(e['action'])}</td>"
        f"<td><code>{esc((e['row_hash'] or '')[:12])}</code></td></tr>"
        for e in pack["audit_trail"]
    )
    ti = pack["threat_intel"] or {}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Exception review pack {esc(ex['id'][:8])}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:32px;color:#17273e}}h1{{font-size:22px}}
h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #dde3ea;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #e3e8ed;padding:6px 8px;text-align:left;vertical-align:top}}
.meta td:first-child{{width:220px;color:#5b6b7e}}.note{{color:#5b6b7e;font-size:12px}}</style></head><body>
<h1>Risk exception review pack</h1>
<p class="note">Generated {esc(pack['generated_at'])} · synthetic academic data · checks passed {pack['checks_passed']}/{len(pack['review_checks'])}</p>
<h2>Exception</h2><table class="meta">
<tr><td>Status / type</td><td>{esc(ex['status'])} · {esc(ex['type'])}</td></tr>
<tr><td>Requested by</td><td>{esc(ex['requested_by'])} on {esc(ex['requested_at'])}</td></tr>
<tr><td>Reviewed by</td><td>{esc(ex['reviewed_by'])} — {esc(ex['review_comment'])}</td></tr>
<tr><td>Expires</td><td>{esc(ex['expires'])} ({esc(ex['duration_days'])} days)</td></tr>
<tr><td>Business justification</td><td>{esc(ex['justification'])}</td></tr>
<tr><td>Compensating controls</td><td>{esc(ex['compensating_controls'])}</td></tr></table>
<h2>Review checklist</h2><table>{checks}</table>
<h2>Finding and risk explanation</h2><table class="meta">
<tr><td>Finding</td><td>{esc(finding.get('title'))}</td></tr>
<tr><td>Risk</td><td>{esc(finding.get('risk_score'))} ({esc(finding.get('risk_band'))}) · CVSS {esc(finding.get('cvss'))}</td></tr>
<tr><td>Threat intelligence</td><td>{esc(ti.get('cve_id'))} · EPSS {esc(ti.get('epss_score'))} · KEV {esc(ti.get('in_kev_list'))} · exploit {esc(ti.get('exploit_maturity'))}</td></tr>
<tr><td>Asset</td><td>{esc(asset.get('name'))} · {esc(asset.get('environment'))} · tier {esc(asset.get('criticality_tier'))} · crown jewel {esc(asset.get('is_crown_jewel'))} · internet {esc(asset.get('internet_exposed'))}</td></tr></table>
<table><tr><th>Factor</th><th>Points</th><th>Reason</th></tr>{factors}</table>
<h2>Audit trail (hash-chained)</h2><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Row hash</th></tr>{trail}</table>
</body></html>"""


@router.get("/exceptions/{exception_id}/review-pack")
def exception_review_pack(
    exception_id: UUID,
    format: Literal["json", "html"] = "json",
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.EXCEPTION_READ)),
):
    """Evidence pack for approvers and auditors (JSON, or printable HTML)."""
    item = db.get(RiskException, exception_id)
    if not item:
        raise HTTPException(status_code=404, detail="Exception not found")
    finding = db.get(Finding, item.finding_id)
    if finding:
        _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    pack = _review_pack(db, item)
    if format == "html":
        return HTMLResponse(
            _pack_html(pack),
            headers={
                "Content-Disposition": f"attachment; filename=exception-review-{str(item.id)[:8]}.html"
            },
        )
    return pack

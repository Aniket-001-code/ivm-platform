from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _active_scoring_config,
    _check_asset_scope,
    _rescore_findings,
    audit,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import (
    Permission,
    require_permission,
)
from app.models.entities import (
    Asset,
    Finding,
    User,
    VulnerabilityCatalog,
)
from app.services import analytics
from app.services.risk_engine import (
    DEFAULT_MAX_POINTS,
    DEFAULT_THRESHOLDS,
    score_finding,
)

router = APIRouter(prefix="/api/v1")


@router.post("/risk/recalculate")
def risk_recalculate(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.RISK_MANAGE)),
):
    findings_to_score = db.scalars(select(Finding)).all()
    _rescore_findings(db, findings_to_score)
    db.commit()
    audit(
        db, user, "risk_recalculated", "finding", new={"count": len(findings_to_score)}
    )
    db.commit()
    return {"rescored": len(findings_to_score)}


@router.get("/risk/findings/{finding_id}/explain")
def risk_explain(
    finding_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    _check_asset_scope(db.get(Asset, f.asset_id), user, db)
    return {
        "finding_id": str(f.id),
        "score": f.risk_score,
        "band": f.risk_band,
        "breakdown": f.risk_breakdown,
    }


@router.post("/risk/what-if")
def risk_what_if(
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.RISK_WHAT_IF)),
):
    config = _active_scoring_config(db)
    weights = body.get("weights", config.weights if config else DEFAULT_MAX_POINTS)
    if (
        set(weights) != set(DEFAULT_MAX_POINTS)
        or any(float(v) < 0 for v in weights.values())
        or abs(sum(float(v) for v in weights.values()) - 100) > 0.001
    ):
        raise HTTPException(
            status_code=422,
            detail="What-if weights must include all eight factors and sum to 100",
        )
    query = analytics.finding_query(user).where(Finding.status == "open")
    scored = []
    requested_id = body.get("finding_id")
    for finding in db.scalars(query):
        asset = db.get(Asset, finding.asset_id)
        if asset is None:
            continue
        original_tier = asset.criticality_tier
        if requested_id and str(finding.id) == str(requested_id):
            asset.criticality_tier = max(
                1, min(5, int(body.get("asset_criticality_tier", original_tier)))
            )
        catalog = (
            db.get(VulnerabilityCatalog, finding.vulnerability_id)
            if finding.vulnerability_id
            else None
        )
        intel = (
            {
                "epss_score": catalog.epss_score,
                "exploit_maturity": catalog.exploit_maturity,
                "in_kev_list": catalog.in_kev_list,
                "ransomware_used": catalog.ransomware_used,
                "actively_exploited": catalog.actively_exploited,
            }
            if catalog
            else {}
        )
        result = score_finding(
            finding,
            asset,
            intel,
            weights=weights,
            band_thresholds=config.band_thresholds if config else DEFAULT_THRESHOLDS,
        )
        asset.criticality_tier = original_tier
        scored.append(
            {
                "finding_id": str(finding.id),
                "title": finding.title,
                "base_score": finding.risk_score,
                "what_if_score": result.score,
                "risk_band": result.band,
                "breakdown": result.breakdown,
            }
        )
    ranked = sorted(scored, key=lambda row: row["what_if_score"], reverse=True)[:20]
    return {"count": len(ranked), "top_findings": ranked}

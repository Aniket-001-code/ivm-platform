from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _active_scoring_config,
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
    Finding,
    OwnershipRule,
    ScoringConfig,
    SlaPolicy,
    User,
)
from app.services.risk_engine import (
    DEFAULT_MAX_POINTS,
    DEFAULT_THRESHOLDS,
)

router = APIRouter(prefix="/api/v1")


@router.get("/config/scoring")
def scoring_config(db: Session = Depends(get_db), _: User = Depends(current_user)):
    config = _active_scoring_config(db)
    return (
        {
            "version": config.version,
            "weights": config.weights,
            "band_thresholds": config.band_thresholds,
        }
        if config
        else {
            "version": 1,
            "weights": DEFAULT_MAX_POINTS,
            "band_thresholds": DEFAULT_THRESHOLDS,
        }
    )


@router.get("/risk/config")
def risk_config(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return scoring_config(db, user)


@router.put("/config/scoring")
def update_scoring(
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    weights = body.get("weights", {})
    required = set(DEFAULT_MAX_POINTS)
    if (
        set(weights) != required
        or any(float(value) < 0 for value in weights.values())
        or abs(sum(float(value) for value in weights.values()) - 100) > 0.001
    ):
        raise HTTPException(
            status_code=422,
            detail="Provide the eight nonnegative factor max points that sum to 100",
        )
    thresholds = body.get("band_thresholds", DEFAULT_THRESHOLDS)
    db.query(ScoringConfig).update({ScoringConfig.is_active: False})
    latest = db.scalar(select(func.max(ScoringConfig.version))) or 0
    config = ScoringConfig(
        version=latest + 1,
        weights=weights,
        band_thresholds=thresholds,
        is_active=True,
        created_by=user.id,
    )
    db.add(config)
    db.flush()
    _rescore_findings(db, db.scalars(select(Finding)).all(), config)
    audit(
        db,
        user,
        "scoring_config_changed",
        "scoring_config",
        config.id,
        new={"version": config.version, "weights": weights},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {
        "version": config.version,
        "weights": config.weights,
        "band_thresholds": config.band_thresholds,
    }


@router.get("/config/sla")
def sla_config(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {
            "risk_band": p.risk_band,
            "sla_days": p.sla_days,
            "escalation_level_1_days": p.escalation_level_1_days,
            "escalation_level_2_days": p.escalation_level_2_days,
        }
        for p in db.scalars(select(SlaPolicy))
    ]


@router.put("/config/sla")
def update_sla(
    body: list[dict],
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    before = sla_config(db, user)
    for row in body:
        if row.get("risk_band") not in {"critical", "high", "medium", "low"}:
            raise HTTPException(status_code=422, detail="Unknown risk band")
        policy = db.scalar(
            select(SlaPolicy).where(SlaPolicy.risk_band == row["risk_band"])
        )
        if not policy:
            defaults = {"critical": 7, "high": 15, "medium": 30, "low": 90}
            policy = SlaPolicy(
                risk_band=row["risk_band"],
                sla_days=defaults[row["risk_band"]],
                escalation_level_1_days=0,
                escalation_level_2_days=7,
            )
            db.add(policy)
        policy.sla_days = max(1, min(365, int(row.get("sla_days", policy.sla_days))))
        policy.escalation_level_1_days = max(
            0, int(row.get("escalation_level_1_days", policy.escalation_level_1_days))
        )
        policy.escalation_level_2_days = max(
            policy.escalation_level_1_days,
            int(row.get("escalation_level_2_days", policy.escalation_level_2_days)),
        )
    db.flush()
    after = sla_config(db, user)
    audit(
        db,
        user,
        "sla_policy_changed",
        "sla_policy",
        old={"policies": before},
        new={"policies": after},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return after


@router.get("/config/ownership-rules")
def ownership_rules(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.CONFIG_READ)),
):
    return [
        {
            "id": str(x.id),
            "priority_order": x.priority_order,
            "match_field": x.match_field,
            "match_value": x.match_value,
            "assign_to_user_id": (
                str(x.assign_to_user_id) if x.assign_to_user_id else None
            ),
            "assign_to_group": x.assign_to_group,
        }
        for x in db.scalars(
            select(OwnershipRule).order_by(OwnershipRule.priority_order)
        )
    ]


@router.post("/config/ownership-rules")
def create_ownership_rule(
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    if not str(body.get("match_value", "")).strip():
        raise HTTPException(status_code=422, detail="match_value is required")
    if body.get("match_field") not in {
        "business_service",
        "business_unit",
        "asset_type",
        "environment",
        "tag",
    }:
        raise HTTPException(status_code=422, detail="Unsupported ownership match field")
    rule = OwnershipRule(
        priority_order=int(body.get("priority_order", 100)),
        match_field=body["match_field"],
        match_value=str(body["match_value"]),
        assign_to_user_id=(
            UUID(body["assign_to_user_id"]) if body.get("assign_to_user_id") else None
        ),
        assign_to_group=body.get("assign_to_group"),
    )
    db.add(rule)
    db.flush()
    audit(
        db,
        user,
        "ownership_rule_created",
        "ownership_rule",
        rule.id,
        new={
            k: body.get(k)
            for k in ("match_field", "match_value", "priority_order", "assign_to_group")
        },
        ip=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(rule)
    return {"id": str(rule.id), "priority_order": rule.priority_order}


@router.delete("/config/ownership-rules/{rule_id}")
def delete_ownership_rule(
    rule_id: UUID,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    rule = db.get(OwnershipRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Ownership rule not found")
    snapshot = {"match_field": rule.match_field, "match_value": rule.match_value}
    db.delete(rule)
    audit(
        db,
        user,
        "ownership_rule_deleted",
        "ownership_rule",
        rule_id,
        old=snapshot,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"deleted": str(rule_id)}

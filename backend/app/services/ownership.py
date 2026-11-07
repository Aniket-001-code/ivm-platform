"""Remediation ownership routing (UC-8).

Order of precedence:
1. The first ownership rule (lowest ``priority_order``) whose match field equals the asset's
   value. Business unit and business service rules match by name or id; ``tag`` matches any
   regulatory tag. A rule assigns a named user, a group, or both.
2. The asset's recorded owner.
3. The business-unit manager for the asset's unit (so work is never unowned).
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    BusinessService,
    BusinessUnit,
    OwnershipRule,
    User,
)

MATCH_FIELDS = {"business_service", "business_unit", "asset_type", "environment", "tag"}


@dataclass(frozen=True)
class OwnerDecision:
    user_id: UUID | None
    group: str | None
    reason: str


def _asset_values(db: Session, asset: Asset) -> dict[str, set[str]]:
    unit = (
        db.get(BusinessUnit, asset.business_unit_id) if asset.business_unit_id else None
    )
    service = (
        db.get(BusinessService, asset.business_service_id)
        if asset.business_service_id
        else None
    )
    values = {
        "asset_type": {asset.asset_type},
        "environment": {asset.environment},
        "business_unit": {str(asset.business_unit_id)}
        | ({unit.name} if unit else set()),
        "business_service": {str(asset.business_service_id)}
        | ({service.name} if service else set()),
        "tag": set(asset.regulatory_tags or []),
    }
    return {
        key: {v.lower() for v in vals if v and v != "None"}
        for key, vals in values.items()
    }


def decide_owner(db: Session, asset: Asset, rules=None) -> OwnerDecision:
    rules = (
        rules
        if rules is not None
        else db.scalars(
            select(OwnershipRule).order_by(OwnershipRule.priority_order)
        ).all()
    )
    values = _asset_values(db, asset)
    for rule in rules:
        if rule.match_value.lower() in values.get(rule.match_field, set()):
            if rule.assign_to_user_id or rule.assign_to_group:
                return OwnerDecision(
                    rule.assign_to_user_id or asset.owner_user_id,
                    rule.assign_to_group,
                    f"rule:{rule.match_field}={rule.match_value}",
                )
    if asset.owner_user_id:
        return OwnerDecision(asset.owner_user_id, None, "asset_owner")
    if asset.business_unit_id:
        manager = db.scalar(
            select(User.id).where(
                User.business_unit_id == asset.business_unit_id,
                User.role == "business_unit_manager",
                User.is_active.is_(True),
            )
        )
        if manager:
            return OwnerDecision(manager, None, "business_unit_manager_fallback")
    return OwnerDecision(None, None, "unassigned")


def choose_owner(db: Session, asset: Asset):
    """Backward-compatible wrapper returning (user_id, reason)."""
    decision = decide_owner(db, asset)
    return decision.user_id, decision.reason

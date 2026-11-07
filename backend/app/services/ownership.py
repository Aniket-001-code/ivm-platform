from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, OwnershipRule


def choose_owner(db: Session, asset: Asset):
    rules = db.scalars(
        select(OwnershipRule).order_by(OwnershipRule.priority_order)
    ).all()
    fields = {"asset_type": asset.asset_type, "environment": asset.environment}
    for rule in rules:
        candidate = fields.get(rule.match_field)
        if rule.match_field == "business_unit":
            candidate = str(asset.business_unit_id)
        if rule.match_field == "business_service":
            candidate = str(asset.business_service_id)
        if (
            candidate
            and candidate.lower() == rule.match_value.lower()
            and rule.assign_to_user_id
        ):
            return rule.assign_to_user_id, f"ownership rule {rule.id}"
    return asset.owner_user_id, "asset owner fallback"

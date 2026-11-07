import ipaddress
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _csv_response,
    _page,
    _asset_scope,
    _check_asset_scope,
    audit,
)
from app.api.v1.routes.findings import _finding_rows
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import (
    Permission,
    require_permission,
)
from app.models.entities import (
    Asset,
    AssetConnection,
    BusinessService,
    BusinessUnit,
    Finding,
    User,
)
from app.services.scoring import rescore_findings

router = APIRouter(prefix="/api/v1")


ASSET_SORT = {
    "name": Asset.name,
    "criticality_tier": Asset.criticality_tier,
    "environment": Asset.environment,
    "asset_type": Asset.asset_type,
    "created_at": Asset.created_at,
}


def _asset_dict(a: Asset) -> dict:
    return {
        "id": str(a.id),
        "name": a.name,
        "hostname": a.hostname,
        "asset_type": a.asset_type,
        "environment": a.environment,
        "business_unit_id": str(a.business_unit_id) if a.business_unit_id else None,
        "criticality_tier": a.criticality_tier,
        "internet_exposed": a.internet_exposed,
        "is_crown_jewel": a.is_crown_jewel,
        "is_customer_facing": a.is_customer_facing,
        "has_sensitive_data": a.has_sensitive_data,
        "status": a.status,
    }


def _filtered_assets(
    user, search, business_unit_id, environment, internet_exposed, crown_jewel, tier
):
    query = _asset_scope(select(Asset), user)
    if search:
        query = query.where(
            or_(Asset.name.ilike(f"%{search}%"), Asset.hostname.ilike(f"%{search}%"))
        )
    if business_unit_id:
        query = query.where(Asset.business_unit_id == business_unit_id)
    if environment:
        query = query.where(Asset.environment == environment)
    if internet_exposed is not None:
        query = query.where(Asset.internet_exposed.is_(internet_exposed))
    if crown_jewel is not None:
        query = query.where(Asset.is_crown_jewel.is_(crown_jewel))
    if tier is not None:
        query = query.where(Asset.criticality_tier == tier)
    return query


def _asset_order(sort: str, order: str):
    column = ASSET_SORT.get(sort)
    if column is None:
        raise HTTPException(status_code=422, detail=f"Unsupported sort field: {sort}")
    return [column.asc() if order == "asc" else column.desc(), Asset.id]


@router.get("/assets")
def assets(
    response: Response,
    search: str | None = None,
    business_unit_id: UUID | None = None,
    environment: str | None = None,
    internet_exposed: bool | None = None,
    crown_jewel: bool | None = None,
    tier: int | None = Query(default=None, ge=1, le=5),
    sort: str = "name",
    order: Literal["asc", "desc"] = "asc",
    limit: int = Query(default=1000, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List assets; the unpaged total is returned in the X-Total-Count header."""
    query = _filtered_assets(
        user, search, business_unit_id, environment, internet_exposed, crown_jewel, tier
    )
    rows = _page(db, response, query, _asset_order(sort, order), limit, offset)
    return [_asset_dict(a) for a in rows]


@router.get("/assets/export")
def assets_export(
    search: str | None = None,
    business_unit_id: UUID | None = None,
    environment: str | None = None,
    internet_exposed: bool | None = None,
    crown_jewel: bool | None = None,
    tier: int | None = Query(default=None, ge=1, le=5),
    sort: str = "name",
    order: Literal["asc", "desc"] = "asc",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = _filtered_assets(
        user, search, business_unit_id, environment, internet_exposed, crown_jewel, tier
    )
    columns = [
        "id",
        "name",
        "hostname",
        "asset_type",
        "environment",
        "criticality_tier",
        "internet_exposed",
        "is_crown_jewel",
        "has_sensitive_data",
        "status",
    ]
    rows = db.scalars(query.order_by(*_asset_order(sort, order)).limit(10000))
    return _csv_response(
        "ivm-assets.csv", columns, ([getattr(a, c) for c in columns] for a in rows)
    )


ASSET_TYPES = {
    "server",
    "application",
    "database",
    "container",
    "cloud_resource",
    "network_device",
    "endpoint",
    "saas",
    "identity",
}
ENVIRONMENTS = {"prod", "uat", "dev", "test", "dr"}
ASSET_STATUSES = {"active", "maintenance", "retired"}
RISK_FIELDS = {
    "criticality_tier",
    "internet_exposed",
    "is_customer_facing",
    "is_crown_jewel",
    "has_sensitive_data",
    "regulatory_tags",
}


class AssetInput(BaseModel):
    """Validated asset registration / criticality payload (UC-1, UC-2)."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=45)
    asset_type: str | None = None
    environment: str | None = None
    business_unit_id: UUID | None = None
    business_service_id: UUID | None = None
    owner_user_id: UUID | None = None
    criticality_tier: int | None = Field(default=None, ge=1, le=5)
    internet_exposed: bool | None = None
    is_customer_facing: bool | None = None
    is_crown_jewel: bool | None = None
    has_sensitive_data: bool | None = None
    regulatory_tags: list[str] | None = Field(default=None, max_length=20)
    os_or_platform: str | None = Field(default=None, max_length=120)
    status: str | None = None

    @field_validator("asset_type")
    @classmethod
    def _type(cls, v):
        if v is not None and v not in ASSET_TYPES:
            raise ValueError(f"asset_type must be one of {sorted(ASSET_TYPES)}")
        return v

    @field_validator("environment")
    @classmethod
    def _env(cls, v):
        if v is not None and v not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(ENVIRONMENTS)}")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v):
        if v is not None and v not in ASSET_STATUSES:
            raise ValueError(f"status must be one of {sorted(ASSET_STATUSES)}")
        return v

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v):
        if v:
            ipaddress.ip_address(v)
        return v or None

    @field_validator("regulatory_tags")
    @classmethod
    def _tags(cls, v):
        if v is None:
            return v
        return sorted({t.strip().upper()[:40] for t in v if t and t.strip()})


def _validate_links(db: Session, data: dict) -> None:
    if data.get("business_unit_id") and not db.get(
        BusinessUnit, data["business_unit_id"]
    ):
        raise HTTPException(status_code=422, detail="Unknown business unit")
    if data.get("business_service_id"):
        service = db.get(BusinessService, data["business_service_id"])
        if not service:
            raise HTTPException(status_code=422, detail="Unknown business service")
        if (
            data.get("business_unit_id")
            and service.business_unit_id != data["business_unit_id"]
        ):
            raise HTTPException(
                status_code=422,
                detail="Business service belongs to a different business unit",
            )
    if data.get("owner_user_id"):
        owner = db.get(User, data["owner_user_id"])
        if not owner or not owner.is_active:
            raise HTTPException(status_code=422, detail="Owner must be an active user")


def _snapshot(asset: Asset) -> dict:
    snapshot = {}
    for field in AssetInput.model_fields:
        value = getattr(asset, field, None)
        snapshot[field] = str(value) if isinstance(value, UUID) else value
    return snapshot


def _rescore_asset(db: Session, asset: Asset) -> int:
    findings = db.scalars(
        select(Finding).where(Finding.asset_id == asset.id, Finding.status != "closed")
    ).all()
    rescore_findings(db, findings)
    return len(findings)


@router.post("/assets", status_code=201)
def create_asset(
    body: AssetInput,
    request: Request,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    data = body.model_dump(exclude_none=True)
    if not data.get("name"):
        raise HTTPException(status_code=422, detail="Asset name is required")
    if db.scalar(
        select(Asset.id).where(func.lower(Asset.name) == data["name"].lower())
    ):
        raise HTTPException(
            status_code=409, detail="An asset with this name already exists"
        )
    _validate_links(db, data)
    asset = Asset(
        **{
            "asset_type": "server",
            "environment": "dev",
            "criticality_tier": 3,
            "regulatory_tags": [],
            "status": "active",
            **data,
        }
    )
    db.add(asset)
    db.flush()
    audit(
        db,
        user,
        "asset_registered",
        "asset",
        asset.id,
        new=_snapshot(asset),
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return _asset_dict(asset)


@router.post("/assets/bulk-import")
def bulk_assets(
    body: list[dict],
    request: Request,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    """Register many assets; invalid rows are reported, valid rows are created."""
    if len(body) > 1000:
        raise HTTPException(
            status_code=413, detail="At most 1000 assets may be imported at once"
        )
    created, errors = 0, []
    existing = {name.lower() for name in db.scalars(select(Asset.name))}
    for index, row in enumerate(body, 1):
        try:
            data = AssetInput.model_validate(row).model_dump(exclude_none=True)
            if not data.get("name"):
                raise ValueError("name is required")
            if data["name"].lower() in existing:
                raise ValueError("an asset with this name already exists")
            _validate_links(db, data)
        except (ValueError, HTTPException) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            errors.append({"row": index, "error": str(detail)[:300]})
            continue
        db.add(
            Asset(
                **{
                    "asset_type": "server",
                    "environment": "dev",
                    "criticality_tier": 3,
                    "regulatory_tags": [],
                    "status": "active",
                    **data,
                }
            )
        )
        existing.add(data["name"].lower())
        created += 1
    audit(
        db,
        user,
        "assets_bulk_registered",
        "asset",
        new={"created": created, "rejected": len(errors)},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"created": created, "errors": errors}


@router.patch("/assets/{asset_id}")
def update_asset(
    asset_id: UUID,
    body: AssetInput,
    request: Request,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    """Update inventory, ownership or criticality context; risk-relevant edits rescore."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    data = body.model_dump(exclude_unset=True)
    if "name" in data and not data["name"]:
        raise HTTPException(status_code=422, detail="Asset name cannot be empty")
    merged = {
        "business_unit_id": data.get("business_unit_id", asset.business_unit_id),
        "business_service_id": data.get(
            "business_service_id", asset.business_service_id
        ),
        "owner_user_id": data.get("owner_user_id"),
    }
    _validate_links(db, merged)
    before = _snapshot(asset)
    for field, value in data.items():
        setattr(asset, field, value)
    after = _snapshot(asset)
    changes = {k: after[k] for k in after if after[k] != before[k]}
    if not changes:
        return _asset_dict(asset)
    rescored = _rescore_asset(db, asset) if RISK_FIELDS & set(changes) else 0
    audit(
        db,
        user,
        "asset_updated",
        "asset",
        asset.id,
        {k: before[k] for k in changes},
        {**changes, "findings_rescored": rescored},
        request.client.host if request.client else None,
    )
    db.commit()
    return {**_asset_dict(asset), "findings_rescored": rescored}


@router.put("/assets/{asset_id}/criticality")
def update_criticality(
    asset_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    """Kept for API compatibility; prefer PATCH /assets/{id}."""
    tier = body.get("criticality_tier")
    return update_asset(
        asset_id,
        AssetInput(criticality_tier=int(tier) if tier is not None else None),
        request,
        user,
        db,
    )


@router.get("/business-units")
def business_units(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {"id": str(u.id), "name": u.name}
        for u in db.scalars(select(BusinessUnit).order_by(BusinessUnit.name))
    ]


@router.get("/business-services")
def business_services(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "business_unit_id": str(s.business_unit_id),
        }
        for s in db.scalars(select(BusinessService).order_by(BusinessService.name))
    ]


@router.get("/assets/{asset_id}")
def asset_detail(
    asset_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    asset = _check_asset_scope(db.get(Asset, asset_id), user, db)
    unit = (
        db.get(BusinessUnit, asset.business_unit_id) if asset.business_unit_id else None
    )
    service = (
        db.get(BusinessService, asset.business_service_id)
        if asset.business_service_id
        else None
    )
    owner = db.get(User, asset.owner_user_id) if asset.owner_user_id else None
    open_findings = db.scalars(
        select(Finding).where(Finding.asset_id == asset.id, Finding.status != "closed")
    ).all()
    return {
        **_asset_dict(asset),
        "ip_address": asset.ip_address,
        "os_or_platform": asset.os_or_platform,
        "regulatory_tags": asset.regulatory_tags or [],
        "business_unit": unit.name if unit else None,
        "business_service_id": (
            str(asset.business_service_id) if asset.business_service_id else None
        ),
        "business_service": service.name if service else None,
        "owner_user_id": str(asset.owner_user_id) if asset.owner_user_id else None,
        "owner_email": owner.email if owner else None,
        "open_findings": len(open_findings),
        "max_risk": max((f.risk_score for f in open_findings), default=0),
        "connections": [
            str(x.target_asset_id)
            for x in db.scalars(
                select(AssetConnection).where(
                    AssetConnection.source_asset_id == asset_id
                )
            )
        ],
    }


@router.get("/assets/{asset_id}/findings")
def asset_findings(
    asset_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    _check_asset_scope(db.get(Asset, asset_id), user, db)
    return _finding_rows(db, select(Finding).where(Finding.asset_id == asset_id))


@router.get("/assets/{asset_id}/connections")
def asset_connections(
    asset_id: UUID, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    _check_asset_scope(db.get(Asset, asset_id), _, db)
    edges = db.scalars(
        select(AssetConnection).where(
            or_(
                AssetConnection.source_asset_id == asset_id,
                AssetConnection.target_asset_id == asset_id,
            )
        )
    ).all()
    peer_ids = {x.source_asset_id for x in edges} | {x.target_asset_id for x in edges}
    # Names are only revealed for peers the caller is allowed to see.
    visible = {
        a.id: a.name
        for a in db.scalars(
            _asset_scope(select(Asset).where(Asset.id.in_(peer_ids)), _)
        )
    }
    return [
        {
            "source_asset_id": str(x.source_asset_id),
            "target_asset_id": str(x.target_asset_id),
            "source_name": visible.get(x.source_asset_id),
            "target_name": visible.get(x.target_asset_id),
            "direction": "outbound" if x.source_asset_id == asset_id else "inbound",
            "connection_type": x.connection_type,
            "port_or_protocol": x.port_or_protocol,
        }
        for x in edges
    ]

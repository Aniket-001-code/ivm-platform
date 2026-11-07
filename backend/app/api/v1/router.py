from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
import jwt
import pyotp
import csv
import io
import hashlib
import hmac
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import false, func, or_, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import get_current_user as current_user, get_db
from app.core.rbac import (
    Permission,
    ROLE_PERMISSIONS,
    canonical_role,
    require_permission,
)
from app.models.entities import (
    Asset,
    AssetConnection,
    AuditLog,
    AttackPath,
    BusinessUnit,
    Escalation,
    Finding,
    ImportBatch,
    OwnershipRule,
    RawFinding,
    RemediationTask,
    RiskException,
    RiskScoreHistory,
    ScoringConfig,
    SlaPolicy,
    TaskUpdate,
    TicketRecord,
    User,
    VulnerabilityCatalog,
)
from app.services.ai_assistant import answer_question
from app.services import analytics
from app.services.attack_path import recalculate_paths
from app.services.ingestion import ingest_records, parse_upload
from app.services.risk_engine import (
    DEFAULT_MAX_POINTS,
    DEFAULT_THRESHOLDS,
    score_finding,
)
from app.core.security import decrypt_secret, encrypt_secret
from app.db.session import engine
from app.services.exceptions import expire_exceptions
from app.services.remediation import create_task_for_finding
from app.services.sla import check_overdue_tasks

router = APIRouter(prefix="/api/v1")
settings = get_settings()
ALGORITHM = "HS256"
_rate_events: dict[str, list[datetime]] = {}


def _limit(request: Request, route: str, count: int, seconds: int = 60) -> None:
    now = datetime.now(timezone.utc)
    key = f"{request.client.host if request.client else 'unknown'}:{route}"
    recent = [
        stamp
        for stamp in _rate_events.get(key, [])
        if (now - stamp).total_seconds() < seconds
    ]
    if len(recent) >= count:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    _rate_events[key] = [*recent, now]


class LoginInput(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


class TaskPatch(BaseModel):
    status: str | None = None
    comment: str | None = None
    evidence_notes: str | None = None


class ExceptionInput(BaseModel):
    finding_id: UUID
    justification: str = Field(min_length=10, max_length=2000)
    compensating_controls: str = Field(min_length=5, max_length=2000)
    exception_type: str = "temporary"
    requested_expiry_date: datetime


class QuestionInput(BaseModel):
    question: str = Field(min_length=3, max_length=2000)
    finding_id: UUID | None = None


def _token(user: User, kind: str = "access") -> str:
    lifetime = timedelta(minutes=15) if kind == "access" else timedelta(days=7)
    return jwt.encode(
        {
            "sub": str(user.id),
            "role": user.role,
            "type": kind,
            "exp": datetime.now(timezone.utc) + lifetime,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )


def _refresh_token(user: User) -> str:
    token = _token(user, "refresh")
    user.refresh_token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token


def audit(
    db: Session,
    actor: User | None,
    action: str,
    entity: str,
    entity_id: UUID | None = None,
    old=None,
    new=None,
    ip=None,
):
    db.add(
        AuditLog(
            actor_user_id=actor.id if actor else None,
            action=action,
            entity_type=entity,
            entity_id=entity_id,
            old_value=old,
            new_value=new,
            ip_address=ip,
        )
    )


def _active_scoring_config(db: Session) -> ScoringConfig | None:
    return db.scalar(select(ScoringConfig).where(ScoringConfig.is_active.is_(True)))


def _rescore_findings(db: Session, findings, config: ScoringConfig | None = None):
    config = config or _active_scoring_config(db)
    version = config.version if config else 1
    weights = config.weights if config else DEFAULT_MAX_POINTS
    thresholds = config.band_thresholds if config else DEFAULT_THRESHOLDS
    for finding in findings:
        asset = db.get(Asset, finding.asset_id)
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
        if asset is None:
            continue
        result = score_finding(
            finding, asset, intel, weights=weights, band_thresholds=thresholds
        )
        finding.risk_score, finding.risk_band, finding.risk_breakdown = (
            result.score,
            result.band,
            result.breakdown,
        )
        db.add(
            RiskScoreHistory(
                finding_id=finding.id,
                score=result.score,
                band=result.band,
                config_version=version,
            )
        )
        if finding.status == "open" and result.band in {"critical", "high"}:
            create_task_for_finding(db, finding, asset)


def _global_scope(user: User) -> bool:
    return canonical_role(user.role) in {
        "platform_admin",
        "security_analyst",
        "vulnerability_manager",
    }


def _asset_scope(query, user: User):
    if _global_scope(user):
        return query
    role = canonical_role(user.role)
    if role == "business_unit_manager":
        return query.where(Asset.business_unit_id == user.business_unit_id)
    if role in {"it_asset_owner", "security_architect"}:
        return query.where(
            or_(
                Asset.owner_user_id == user.id,
                Asset.business_unit_id == user.business_unit_id,
            )
        )
    if role == "system_administrator":
        assigned_asset_ids = select(RemediationTask.asset_id).where(
            RemediationTask.assigned_to_user_id == user.id
        )
        return query.where(Asset.id.in_(assigned_asset_ids))
    return query.where(False)


def _check_asset_scope(asset: Asset | None, user: User, db: Session) -> Asset:
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    role = canonical_role(user.role)
    visible = _global_scope(user)
    if role == "business_unit_manager":
        visible = asset.business_unit_id == user.business_unit_id
    elif role in {"it_asset_owner", "security_architect"}:
        visible = (
            asset.owner_user_id == user.id
            or asset.business_unit_id == user.business_unit_id
        )
    elif role == "system_administrator":
        visible = bool(
            db.scalar(
                select(RemediationTask.id).where(
                    RemediationTask.asset_id == asset.id,
                    RemediationTask.assigned_to_user_id == user.id,
                )
            )
        )
    if not visible:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.post("/auth/login")
def login(body: LoginInput, request: Request, db: Session = Depends(get_db)):
    _limit(request, "login", 10)
    user = db.scalar(select(User).where(func.lower(User.email) == body.email.lower()))
    now = datetime.now(timezone.utc)
    if user is None:
        audit(
            db,
            None,
            "login_failed",
            "user",
            ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    locked = user.locked_until is not None and user.locked_until > now
    ok = (
        user.is_active
        and not locked
        and bcrypt.checkpw(body.password.encode(), user.hashed_password.encode())
    )
    if (
        ok
        and settings.mfa_required
        and canonical_role(user.role) in {"platform_admin", "security_architect"}
        and not user.mfa_enabled
    ):
        ok = False
    if (
        ok
        and user.mfa_enabled
        and canonical_role(user.role) in {"platform_admin", "security_architect"}
    ):
        secret = decrypt_secret(user.mfa_secret) if user.mfa_secret else None
        ok = bool(
            secret
            and body.totp_code
            and pyotp.TOTP(secret).verify(body.totp_code, valid_window=1)
        )
    if not ok:
        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= 5:
                user.locked_until = now + timedelta(minutes=15)
        audit(
            db,
            user,
            "login_failed",
            "user",
            user.id if user else None,
            ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    user.failed_login_count = 0
    user.locked_until = None
    user.role = canonical_role(user.role)
    audit(
        db,
        user,
        "login_succeeded",
        "user",
        user.id,
        ip=request.client.host if request.client else None,
    )
    db.commit()
    refresh_token = _refresh_token(user)
    db.commit()
    return {
        "access_token": _token(user),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
        },
    }


@router.post("/auth/refresh")
def refresh(body: dict, db: Session = Depends(get_db)):
    try:
        data = jwt.decode(
            body["refresh_token"], settings.secret_key, algorithms=[ALGORITHM]
        )
        if data.get("type") != "refresh":
            raise ValueError("invalid refresh")
        user = db.get(User, UUID(data["sub"]))
        supplied_hash = hashlib.sha256(body["refresh_token"].encode()).hexdigest()
        if (
            not user
            or not user.refresh_token_hash
            or not hmac.compare_digest(user.refresh_token_hash, supplied_hash)
        ):
            raise ValueError("refresh token already used or revoked")
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive account")
    next_refresh = _refresh_token(user)
    db.commit()
    return {
        "access_token": _token(user),
        "refresh_token": next_refresh,
        "token_type": "bearer",
    }


@router.post("/auth/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.refresh_token_hash = None
    db.commit()
    return {"logged_out": True}


@router.get("/auth/me")
def me(user: User = Depends(current_user)):
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "business_unit_id": (
            str(user.business_unit_id) if user.business_unit_id else None
        ),
    }


@router.post("/auth/mfa/setup")
def mfa_setup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt_secret(secret)
    db.commit()
    return {
        "secret": secret,
        "provisioning_uri": pyotp.TOTP(secret).provisioning_uri(
            user.email, issuer_name="IVM Demo"
        ),
    }


@router.post("/auth/mfa/verify")
def mfa_verify(
    body: dict, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    if not user.mfa_secret or not pyotp.TOTP(decrypt_secret(user.mfa_secret)).verify(
        str(body.get("code", "")), valid_window=1
    ):
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    return {"mfa_enabled": True}


@router.get("/users")
def users(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.USER_READ)),
):
    return [
        {
            "id": str(x.id),
            "email": x.email,
            "full_name": x.full_name,
            "role": x.role,
            "is_active": x.is_active,
        }
        for x in db.scalars(select(User).order_by(User.email))
    ]


@router.post("/users")
def create_user(
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    password = str(body.get("password", ""))
    if (
        len(password) < 12
        or not any(c.isupper() for c in password)
        or not any(c.isdigit() for c in password)
        or not any(not c.isalnum() for c in password)
    ):
        raise HTTPException(
            status_code=422,
            detail="Password must be 12+ characters and include uppercase, number, and symbol",
        )
    email = str(body.get("email", "")).lower()
    if not email or db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(
            status_code=409, detail="Email is required and must be unique"
        )
    role = canonical_role(str(body.get("role", "security_analyst")))
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=422, detail="Unsupported role")
    item = User(
        email=email,
        full_name=str(body.get("full_name", "")),
        hashed_password=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        role=role,
        is_active=True,
    )
    db.add(item)
    db.flush()
    audit(
        db,
        user,
        "user_created",
        "user",
        item.id,
        new={"email": email, "role": role},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(item.id), "email": item.email, "role": item.role}


@router.patch("/users/{user_id}")
def update_user(
    user_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    old_role = target.role
    if "role" in body:
        target.role = str(body["role"])
    if "is_active" in body:
        target.is_active = bool(body["is_active"])
    audit(
        db,
        user,
        "user_updated",
        "user",
        target.id,
        {"role": old_role},
        {"role": target.role, "is_active": target.is_active},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(target.id), "role": target.role, "is_active": target.is_active}


@router.get("/assets")
def assets(
    search: str | None = None,
    business_unit_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = _asset_scope(select(Asset), user)
    if search:
        query = query.where(
            or_(Asset.name.ilike(f"%{search}%"), Asset.hostname.ilike(f"%{search}%"))
        )
    if business_unit_id:
        query = query.where(Asset.business_unit_id == business_unit_id)
    return [
        {
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
        for a in db.scalars(query.limit(1000))
    ]


@router.post("/assets")
def create_asset(
    body: dict,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(status_code=422, detail="Asset name is required")
    asset = Asset(
        name=name,
        hostname=body.get("hostname"),
        ip_address=body.get("ip_address"),
        asset_type=str(body.get("asset_type", "server")),
        environment=str(body.get("environment", "dev")),
        criticality_tier=max(1, min(5, int(body.get("criticality_tier", 3)))),
        internet_exposed=bool(body.get("internet_exposed", False)),
        is_customer_facing=bool(body.get("is_customer_facing", False)),
        is_crown_jewel=bool(body.get("is_crown_jewel", False)),
        has_sensitive_data=bool(body.get("has_sensitive_data", False)),
        regulatory_tags=body.get("regulatory_tags", []),
        status="active",
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": str(asset.id), "name": asset.name}


@router.post("/assets/bulk-import")
def bulk_assets(
    body: list[dict],
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    if len(body) > 1000:
        raise HTTPException(
            status_code=413, detail="At most 1000 assets may be imported at once"
        )
    created = 0
    for row in body:
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        db.add(
            Asset(
                name=name,
                asset_type=str(row.get("asset_type", "server")),
                environment=str(row.get("environment", "dev")),
                criticality_tier=max(1, min(5, int(row.get("criticality_tier", 3)))),
                internet_exposed=bool(row.get("internet_exposed", False)),
                status="active",
            )
        )
        created += 1
    db.commit()
    return {"created": created}


@router.put("/assets/{asset_id}/criticality")
def update_criticality(
    asset_id: UUID,
    body: dict,
    request: Request,
    user: User = Depends(require_permission(Permission.ASSET_MANAGE)),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    old = asset.criticality_tier
    asset.criticality_tier = max(1, min(5, int(body.get("criticality_tier", old))))
    audit(
        db,
        user,
        "asset_criticality_changed",
        "asset",
        asset.id,
        {"criticality_tier": old},
        {"criticality_tier": asset.criticality_tier},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(asset.id), "criticality_tier": asset.criticality_tier}


@router.get("/assets/{asset_id}")
def asset_detail(
    asset_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    asset = _check_asset_scope(db.get(Asset, asset_id), user, db)
    return {
        "id": str(asset.id),
        "name": asset.name,
        "hostname": asset.hostname,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "criticality_tier": asset.criticality_tier,
        "business_unit_id": (
            str(asset.business_unit_id) if asset.business_unit_id else None
        ),
        "owner_user_id": str(asset.owner_user_id) if asset.owner_user_id else None,
        "internet_exposed": asset.internet_exposed,
        "is_crown_jewel": asset.is_crown_jewel,
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
    return [
        {
            "source_asset_id": str(x.source_asset_id),
            "target_asset_id": str(x.target_asset_id),
            "connection_type": x.connection_type,
            "port_or_protocol": x.port_or_protocol,
        }
        for x in edges
    ]


def _finding_rows(db: Session, query):
    return [
        {
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
        for f in db.scalars(query.order_by(Finding.risk_score.desc()).limit(2000))
    ]


@router.get("/findings")
def findings(
    severity: str | None = None,
    band: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    asset_id: UUID | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
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
    return _finding_rows(db, query)


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    asset = db.get(Asset, f.asset_id)
    _check_asset_scope(asset, user, db)
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
    finding.status = str(body.get("status", "open"))
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


@router.post("/imports/{source_type}")
async def import_file(
    source_type: str,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    allowed = {"scanner", "cspm", "pentest", "container", "identity"}
    if source_type not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported source type")
    content = await file.read(10 * 1024 * 1024 + 1)
    try:
        records = parse_upload(source_type, file.filename or "upload", content)
        batch = ingest_records(db, source_type, file.filename or "upload", records)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        db,
        user,
        "import_completed",
        "import_batch",
        batch.id,
        new={
            "total": batch.total_records,
            "failed": batch.failed_count,
            "duplicates": batch.duplicate_count,
        },
    )
    db.commit()
    return {
        "id": str(batch.id),
        "source_name": batch.source_name,
        "status": batch.status,
        "total_records": batch.total_records,
        "success_count": batch.success_count,
        "failed_count": batch.failed_count,
        "duplicate_count": batch.duplicate_count,
        "errors": batch.errors,
    }


@router.get("/imports")
def imports(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {
            "id": str(x.id),
            "source_name": x.source_name,
            "file_name": x.file_name,
            "status": x.status,
            "total_records": x.total_records,
            "success_count": x.success_count,
            "failed_count": x.failed_count,
            "duplicate_count": x.duplicate_count,
        }
        for x in db.scalars(
            select(ImportBatch).order_by(ImportBatch.created_at.desc()).limit(100)
        )
    ]


@router.get("/imports/{batch_id}")
def import_detail(
    batch_id: UUID, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    batch = db.get(ImportBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Import batch not found")
    return {
        "id": str(batch.id),
        "source_name": batch.source_name,
        "status": batch.status,
        "total_records": batch.total_records,
        "success_count": batch.success_count,
        "failed_count": batch.failed_count,
        "duplicate_count": batch.duplicate_count,
        "errors": batch.errors,
    }


@router.post("/imports/{batch_id}/retry")
def retry_import(
    batch_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    batch = db.get(ImportBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Import batch not found")
    rows = db.scalars(
        select(RawFinding).where(RawFinding.import_batch_id == batch.id)
    ).all()
    if not rows:
        raise HTTPException(
            status_code=409,
            detail="No successfully parsed rows are available to retry; upload the file again",
        )
    result = ingest_records(
        db, batch.source_name, batch.file_name, [row.raw_payload for row in rows]
    )
    audit(
        db,
        user,
        "import_retried",
        "import_batch",
        result.id,
        new={"source_batch_id": str(batch.id)},
    )
    db.commit()
    return {
        "id": str(result.id),
        "status": result.status,
        "total_records": result.total_records,
        "success_count": result.success_count,
        "failed_count": result.failed_count,
        "duplicate_count": result.duplicate_count,
    }


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


@router.get("/attack-paths")
def attack_paths(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(AttackPath)
    if not _global_scope(user):
        scope = analytics.asset_scope(user)
        query = (
            query.join(Asset, AttackPath.entry_asset_id == Asset.id).where(scope)
            if scope is not None
            else query.where(false())
        )
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "entry_asset_id": str(p.entry_asset_id),
            "target_asset_id": str(p.target_asset_id),
            "path_asset_ids": p.path_asset_ids,
            "path_finding_ids": p.path_finding_ids,
            "path_risk_score": p.path_risk_score,
            **_path_score_values(db, p),
        }
        for p in db.scalars(
            query.order_by(AttackPath.path_risk_score.desc()).limit(200)
        )
    ]


def _path_score_values(db: Session, path: AttackPath):
    scores = []
    influences = []
    for raw_id in path.path_finding_ids or []:
        finding = db.get(Finding, UUID(raw_id))
        if not finding:
            continue
        factor = next(
            (
                x
                for x in finding.risk_breakdown or []
                if isinstance(x, dict) and x.get("factor") == "attack_path_influence"
            ),
            {},
        )
        scores.append(
            (
                float(factor.get("base_score", finding.risk_score)),
                float(factor.get("final_score", finding.risk_score)),
            )
        )
        influences.append(float(factor.get("path_influence", 0)))
    base = (
        round(sum(x for x, _ in scores) / len(scores), 1)
        if scores
        else path.path_risk_score
    )
    final = (
        round(sum(y for _, y in scores) / len(scores), 1)
        if scores
        else path.path_risk_score
    )
    return {
        "base_score": base,
        "final_score": final,
        "path_influence": round(max(influences, default=0), 2),
    }


@router.get("/attack-paths/graph")
def attack_graph(
    asset_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    assets = db.scalars(_asset_scope(select(Asset), user)).all()
    allowed_ids = {a.id for a in assets}
    edges = (
        db.scalars(
            select(AssetConnection).where(
                AssetConnection.source_asset_id.in_(allowed_ids),
                AssetConnection.target_asset_id.in_(allowed_ids),
            )
        ).all()
        if allowed_ids
        else []
    )
    selected = next(
        (
            p
            for p in db.scalars(select(AttackPath))
            if asset_id and asset_id in [UUID(x) for x in p.path_asset_ids]
        ),
        None,
    )
    path_nodes = set(selected.path_asset_ids) if selected else set()
    nodes = []
    for asset in assets:
        open_findings = db.scalars(
            select(Finding).where(
                Finding.asset_id == asset.id, Finding.status == "open"
            )
        ).all()
        top = max(open_findings, key=lambda row: row.risk_score, default=None)
        base_scores = []
        influences = []
        for finding in open_findings:
            factor = next(
                (
                    x
                    for x in finding.risk_breakdown or []
                    if isinstance(x, dict)
                    and x.get("factor") == "attack_path_influence"
                ),
                {},
            )
            base_scores.append(float(factor.get("base_score", finding.risk_score)))
            influences.append(float(factor.get("path_influence", 0)))
        nodes.append(
            {
                "id": str(asset.id),
                "name": asset.name,
                "risk_band": (
                    top.risk_band
                    if top
                    else (
                        "critical"
                        if asset.is_crown_jewel
                        else "high" if asset.internet_exposed else "low"
                    )
                ),
                "base_score": round(
                    max(base_scores, default=top.risk_score if top else 0), 1
                ),
                "final_score": round(
                    max([x.risk_score for x in open_findings], default=0), 1
                ),
                "path_influence": round(max(influences, default=0), 2),
                "is_crown_jewel": asset.is_crown_jewel,
                "selected": str(asset.id) in path_nodes,
                "findings": [
                    {
                        "id": str(x.id),
                        "title": x.title,
                        "risk_score": x.risk_score,
                        "risk_band": x.risk_band,
                    }
                    for x in sorted(
                        open_findings, key=lambda x: x.risk_score, reverse=True
                    )[:10]
                ],
            }
        )
    return {
        "nodes": nodes,
        "links": [
            {
                "source": str(e.source_asset_id),
                "target": str(e.target_asset_id),
                "type": e.connection_type,
            }
            for e in edges
        ],
    }


@router.get("/attack-paths/{path_id}")
def attack_path_detail(
    path_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    path = db.get(AttackPath, path_id)
    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")
    _check_asset_scope(db.get(Asset, path.entry_asset_id), user, db)
    return {
        "id": str(path.id),
        "name": path.name,
        "entry_asset_id": str(path.entry_asset_id),
        "target_asset_id": str(path.target_asset_id),
        "path_asset_ids": path.path_asset_ids,
        "path_finding_ids": path.path_finding_ids,
        "path_risk_score": path.path_risk_score,
        **_path_score_values(db, path),
    }


@router.post("/attack-paths/recalculate")
def attack_paths_recalculate(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.RISK_MANAGE)),
):
    paths = recalculate_paths(db)
    return {"calculated": len(paths)}


def tasks(db: Session, user: User):
    query = select(RemediationTask)
    role = canonical_role(user.role)
    if role in {"it_asset_owner", "system_administrator"}:
        query = query.where(RemediationTask.assigned_to_user_id == user.id)
    elif role not in {"platform_admin", "security_analyst", "vulnerability_manager"}:
        scope = analytics.asset_scope(user)
        query = (
            query.join(Asset, RemediationTask.asset_id == Asset.id).where(scope)
            if scope is not None
            else query.where(false())
        )
    return [
        {
            "id": str(t.id),
            "finding_id": str(t.finding_id),
            "asset_id": str(t.asset_id),
            "assigned_to_user_id": (
                str(t.assigned_to_user_id) if t.assigned_to_user_id else None
            ),
            "status": t.status,
            "priority": t.priority,
            "sla_due_date": t.sla_due_date,
            "sla_category": t.sla_category,
            "evidence_notes": t.evidence_notes,
            "ticket_ref": t.ticket_ref,
        }
        for t in db.scalars(
            query.order_by(
                RemediationTask.priority, RemediationTask.created_at.desc()
            ).limit(2000)
        )
    ]


@router.get("/tasks")
def list_tasks(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return tasks(db, user)


@router.get("/tasks/my")
def my_tasks(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [t for t in tasks(db, user) if t["assigned_to_user_id"] == str(user.id)]


@router.get("/tasks/overdue")
def overdue_tasks(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return [
        item
        for item in tasks(db, user)
        if item["sla_due_date"]
        and item["sla_due_date"] < datetime.now(timezone.utc)
        and item["status"] != "closed"
    ]


@router.get("/tasks/{task_id}")
def task_detail(
    task_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    return {
        "id": str(task.id),
        "finding_id": str(task.finding_id),
        "asset_id": str(task.asset_id),
        "assigned_to_user_id": (
            str(task.assigned_to_user_id) if task.assigned_to_user_id else None
        ),
        "status": task.status,
        "priority": task.priority,
        "sla_due_date": task.sla_due_date,
        "evidence_notes": task.evidence_notes,
        "updates": [
            {
                "old_status": x.old_status,
                "new_status": x.new_status,
                "comment": x.comment,
                "created_at": x.created_at,
            }
            for x in db.scalars(
                select(TaskUpdate)
                .where(TaskUpdate.task_id == task.id)
                .order_by(TaskUpdate.created_at)
            )
        ],
    }


@router.patch("/tasks/{task_id}")
def update_task(
    task_id: UUID,
    body: TaskPatch,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    role = canonical_role(user.role)
    if task.assigned_to_user_id != user.id and role not in {
        "platform_admin",
        "vulnerability_manager",
        "security_analyst",
    }:
        raise HTTPException(status_code=403, detail="Task is assigned to another owner")
    old = task.status
    if body.status:
        allowed_transitions = {
            "open": {"in_progress", "blocked"},
            "in_progress": {"pending_verification", "blocked"},
            "pending_verification": {"closed", "in_progress"},
            "blocked": {"open", "in_progress"},
            "closed": set(),
        }
        if body.status not in {
            "open",
            "in_progress",
            "pending_verification",
            "closed",
            "blocked",
        }:
            raise HTTPException(status_code=422, detail="Unsupported task status")
        if body.status != old and body.status not in allowed_transitions.get(
            old, set()
        ):
            raise HTTPException(
                status_code=409,
                detail=f"Invalid task transition: {old} -> {body.status}",
            )
        if body.status == "closed" and not (body.evidence_notes or task.evidence_notes):
            raise HTTPException(
                status_code=422, detail="Evidence is required to close a task"
            )
        task.status = body.status
        task.closed_at = datetime.now(timezone.utc) if body.status == "closed" else None
    if body.evidence_notes:
        task.evidence_notes = body.evidence_notes[:4000]
    db.add(
        TaskUpdate(
            task_id=task.id,
            user_id=user.id,
            old_status=old,
            new_status=task.status,
            comment=body.comment,
        )
    )
    audit(
        db,
        user,
        "task_updated",
        "remediation_task",
        task.id,
        {"status": old},
        {"status": task.status, "evidence": bool(task.evidence_notes)},
        request.client.host if request.client else None,
    )
    db.commit()
    return {"id": str(task.id), "status": task.status}


@router.get("/exceptions")
def exceptions(db: Session = Depends(get_db), user: User = Depends(current_user)):
    query = select(RiskException).join(Finding, RiskException.finding_id == Finding.id)
    if not _global_scope(user):
        query = query.join(Asset, Finding.asset_id == Asset.id).where(
            or_(
                Asset.business_unit_id == user.business_unit_id,
                Asset.owner_user_id == user.id,
            )
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
    maximum = 90 if body.exception_type == "temporary" else 365
    if (
        body.exception_type not in {"temporary", "long_term"}
        or body.requested_expiry_date <= datetime.now(timezone.utc)
        or body.requested_expiry_date
        > datetime.now(timezone.utc) + timedelta(days=maximum)
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
            .where(
                or_(
                    Asset.business_unit_id == user.business_unit_id,
                    Asset.owner_user_id == user.id,
                )
            )
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
    _: User = Depends(require_permission(Permission.EXCEPTION_READ)),
):
    items = db.scalars(
        select(RiskException).order_by(RiskException.created_at.desc())
    ).all()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["id", "finding_id", "status", "justification", "expiry"])
    for item in items:
        writer.writerow(
            [
                str(item.id),
                str(item.finding_id),
                item.status,
                item.justification,
                item.requested_expiry_date.isoformat(),
            ]
        )
    return Response(
        stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ivm-exceptions.csv"},
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
    item.status = "revoked"
    finding = db.get(Finding, item.finding_id)
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


@router.post("/ai/ask")
def ai_ask(
    body: QuestionInput,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _limit(request, "ai", 20)
    if body.finding_id:
        finding = db.get(Finding, body.finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    result = answer_question(
        db,
        body.question,
        user.role,
        user.business_unit_id,
        user.id,
        finding_id=body.finding_id,
    )
    audit(
        db,
        user,
        "ai_query",
        "ai_query",
        new={"intent": result["intent"], "used_llm": False},
    )
    db.commit()
    return result


@router.post("/ticketing/{system}/issues")
def create_ticket(
    system: str,
    body: dict,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    task = db.get(RemediationTask, UUID(body["task_id"]))
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if system not in {"jira-sim", "servicenow-sim"}:
        raise HTTPException(status_code=400, detail="Unsupported simulation")
    count = db.scalar(select(func.count()).select_from(TicketRecord)) or 0
    key = f"{'IVM' if system == 'jira-sim' else 'INC'}-{count + 1:05d}"
    ticket = TicketRecord(
        task_id=task.id,
        system=system.upper().replace("-", "_"),
        ticket_key=key,
        status="open",
        payload={"summary": body.get("summary", "Remediate " + str(task.finding_id))},
    )
    task.ticket_ref = key
    db.add(ticket)
    db.commit()
    return {"ticket_key": key, "status": "open", "task_id": str(task.id)}


@router.get("/audit")
def audit_records(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    return [
        {
            "id": str(x.id),
            "actor_user_id": str(x.actor_user_id) if x.actor_user_id else None,
            "action": x.action,
            "entity_type": x.entity_type,
            "entity_id": str(x.entity_id) if x.entity_id else None,
            "new_value": x.new_value,
            "timestamp": x.created_at,
        }
        for x in db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(1000)
        )
    ]


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
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
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
    db.commit()
    return sla_config(db, user)


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
    user: User = Depends(require_permission(Permission.CONFIG_MANAGE)),
    db: Session = Depends(get_db),
):
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
    db.commit()
    db.refresh(rule)
    return {"id": str(rule.id), "priority_order": rule.priority_order}


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
    return {
        "cve_id": item.cve_id,
        "epss_score": item.epss_score,
        "in_kev_list": item.in_kev_list,
        "ransomware_used": item.ransomware_used,
        "actively_exploited": item.actively_exploited,
        "exploit_maturity": item.exploit_maturity,
    }


@router.post("/threat-intel/import")
def import_threat_intel(
    body: list[dict],
    user: User = Depends(require_permission(Permission.IMPORT)),
    db: Session = Depends(get_db),
):
    if len(body) > 5000:
        raise HTTPException(status_code=413, detail="Threat feed is too large")
    changed = 0
    for row in body:
        cve = str(row.get("cve_id", "")).upper()
        if not cve.startswith("CVE-"):
            continue
        item = db.scalar(
            select(VulnerabilityCatalog).where(VulnerabilityCatalog.cve_id == cve)
        )
        if not item:
            item = VulnerabilityCatalog(
                cve_id=cve,
                title=str(row.get("title", cve)),
                description=str(row.get("description", "")),
                cvss_base_score=float(row.get("cvss_base_score", 0)),
                epss_score=0,
            )
            db.add(item)
        item.epss_score = max(0, min(1, float(row.get("epss_score", item.epss_score))))
        item.in_kev_list = bool(row.get("in_kev_list", item.in_kev_list))
        item.ransomware_used = bool(row.get("ransomware_used", item.ransomware_used))
        item.actively_exploited = bool(
            row.get("actively_exploited", item.actively_exploited)
        )
        item.exploit_maturity = str(row.get("exploit_maturity", item.exploit_maturity))
        changed += 1
    audit(
        db,
        user,
        "threat_intel_imported",
        "vulnerability_catalog",
        new={"records": changed},
    )
    db.commit()
    return {"updated": changed}


@router.get("/audit/export")
def audit_export(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    rows = db.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5000)
    ).all()
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["timestamp", "actor", "action", "entity_type", "entity_id"])
    for row in rows:
        writer.writerow(
            [
                row.created_at.isoformat() if row.created_at else "",
                row.actor_user_id or "",
                row.action,
                row.entity_type,
                row.entity_id or "",
            ]
        )
    return Response(
        stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ivm-audit.csv"},
    )


@router.get("/ai/recommendations")
def ai_recommendations(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return _finding_rows(
        db,
        select(Finding)
        .where(Finding.status == "open")
        .order_by(Finding.risk_score.desc())
        .limit(10),
    )


@router.post("/ai/explain/{finding_id}")
def ai_explain(
    finding_id: UUID, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    factors = f.risk_breakdown or []
    parts = [factor.get("reason", "") for factor in factors if isinstance(factor, dict)]
    return {
        "answer": f"This finding has a {f.risk_band} contextual risk score of {f.risk_score:.1f}. "
        + " ".join(parts),
        "used_llm": False,
        "disclaimer": "AI-generated demo explanation; verify with evidence.",
    }


@router.post("/ai/executive-summary")
def ai_executive_summary(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    result = answer_question(
        db, "Summarize highest priorities", user.role, user.business_unit_id, user.id
    )
    return {
        "summary": result["answer"],
        "used_llm": result["used_llm"],
        "label": "AI-generated demo summary",
    }


@router.get("/escalations")
def escalations(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {
            "id": str(x.id),
            "task_id": str(x.task_id),
            "level": x.level,
            "reason": x.reason,
            "acknowledged": x.acknowledged,
        }
        for x in db.scalars(select(Escalation).order_by(Escalation.created_at.desc()))
    ]


@router.get("/notifications")
def notifications(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.NOTIFICATION_READ)),
):
    rows = db.scalars(
        select(Escalation)
        .where(Escalation.escalated_to_user_id == user.id)
        .order_by(Escalation.created_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "id": str(row.id),
            "task_id": str(row.task_id),
            "level": row.level,
            "reason": row.reason,
            "acknowledged": row.acknowledged,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/jobs/run")
def run_jobs(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.SCHEDULER_RUN)),
):
    return {
        "escalations_created": check_overdue_tasks(db),
        "exceptions_expired": expire_exceptions(db),
    }


@router.post("/ticketing/{system}/issues/{ticket_key}/transition")
@router.patch("/ticketing/{system}/issues/{ticket_key}/transition")
def transition_ticket(
    system: str,
    ticket_key: str,
    body: dict,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    ticket = db.scalar(
        select(TicketRecord).where(TicketRecord.ticket_key == ticket_key)
    )
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    ticket.status = str(body.get("status", "in_progress"))
    task = db.get(RemediationTask, ticket.task_id)
    if task and ticket.status.lower() in {"resolved", "closed"}:
        task.status = "pending_verification"
    audit(
        db,
        user,
        "ticket_transition",
        "ticket_record",
        ticket.id,
        new={"status": ticket.status},
    )
    db.commit()
    return {
        "ticket_key": ticket.ticket_key,
        "status": ticket.status,
        "task_status": task.status if task else None,
    }


@router.get("/ticketing/{system}/issues/{ticket_key}")
def get_ticket(
    system: str,
    ticket_key: str,
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
):
    ticket = db.scalar(
        select(TicketRecord).where(TicketRecord.ticket_key == ticket_key)
    )
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return {
        "ticket_key": ticket.ticket_key,
        "system": ticket.system,
        "status": ticket.status,
        "payload": ticket.payload,
    }

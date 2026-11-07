"""SQL-backed dashboard analytics with portable SQLite/PostgreSQL aggregation."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.rbac import canonical_role
from app.models.entities import (
    Asset,
    BusinessService,
    BusinessUnit,
    Finding,
    ImportBatch,
    RemediationTask,
    RiskException,
    RiskScoreHistory,
    User,
)

MINUTES_PER_RAW_RECORD = 6
GLOBAL_ROLES = {
    "platform_admin",
    "security_analyst",
    "vulnerability_manager",
    "executive_ciso",
    "auditor",
}


def asset_scope(user: User):
    role = canonical_role(user.role)
    if role in GLOBAL_ROLES:
        return None
    if role == "business_unit_manager":
        return Asset.business_unit_id == user.business_unit_id
    if role == "system_administrator":
        return Asset.id.in_(
            select(RemediationTask.asset_id).where(
                RemediationTask.assigned_to_user_id == user.id
            )
        )
    if role in {"it_asset_owner", "security_architect"}:
        return Asset.owner_user_id == user.id
    return Asset.business_unit_id == user.business_unit_id


def finding_query(user: User):
    query = select(Finding)
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, Finding.asset_id == Asset.id).where(scope)
    return query


def task_query(user: User):
    query = select(RemediationTask)
    role = canonical_role(user.role)
    if role in GLOBAL_ROLES:
        return query
    if role in {"it_asset_owner", "system_administrator"}:
        return query.where(RemediationTask.assigned_to_user_id == user.id)
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, RemediationTask.asset_id == Asset.id).where(scope)
    return query


def _rows(db: Session, query, limit=100):
    return db.execute(query.limit(limit)).all()


def risk_bands(db: Session, user: User) -> dict[str, int]:
    base = (
        finding_query(user)
        .with_only_columns(Finding.risk_band, func.count(Finding.id))
        .where(Finding.status == "open")
        .group_by(Finding.risk_band)
    )
    return {band: count for band, count in db.execute(base)}


def trend(db: Session, user: User, weeks: int = 26) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(weeks=weeks)
    query = (
        select(RiskScoreHistory.calculated_at, RiskScoreHistory.score)
        .join(Finding, RiskScoreHistory.finding_id == Finding.id)
        .where(RiskScoreHistory.calculated_at >= cutoff)
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, Finding.asset_id == Asset.id).where(scope)
    groups: dict[tuple[int, int], list[float]] = defaultdict(list)
    labels = {}
    for timestamp, score in db.execute(query):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        year, week, _ = timestamp.isocalendar()
        groups[(year, week)].append(float(score))
        labels[(year, week)] = timestamp.date().isoformat()
    ordered = sorted(groups)[-weeks:]
    return [
        {
            "week": labels[key],
            "average_score": round(sum(groups[key]) / len(groups[key]), 1),
            "sample_count": len(groups[key]),
        }
        for key in ordered
    ]


def heatmap(db: Session, user: User) -> list[dict]:
    query = (
        select(
            BusinessService.name,
            BusinessUnit.name,
            Finding.risk_band,
            func.count(Finding.id),
        )
        .join(Asset, Asset.business_service_id == BusinessService.id)
        .join(BusinessUnit, BusinessUnit.id == BusinessService.business_unit_id)
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
        .group_by(BusinessService.name, BusinessUnit.name, Finding.risk_band)
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.where(scope)
    matrix: dict[tuple[str, str], dict[str, int]] = {}
    for service, unit, band, count in db.execute(query):
        row = matrix.setdefault(
            (service, unit), {name: 0 for name in ("critical", "high", "medium", "low")}
        )
        row[str(band).lower()] = int(count)
    return [
        {"business_service": service, "business_unit": unit, "risk_bands": bands}
        for (service, unit), bands in sorted(matrix.items())
    ]


def mttr_by_band(db: Session, user: User) -> list[dict]:
    query = (
        select(Finding.risk_band, RemediationTask.created_at, RemediationTask.closed_at)
        .join(RemediationTask, RemediationTask.finding_id == Finding.id)
        .where(
            RemediationTask.status == "closed", RemediationTask.closed_at.is_not(None)
        )
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, Finding.asset_id == Asset.id).where(scope)
    totals: dict[str, list[float]] = defaultdict(list)
    for band, created, closed in db.execute(query):
        if created and closed:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if closed.tzinfo is None:
                closed = closed.replace(tzinfo=timezone.utc)
            totals[band].append(max(0.0, (closed - created).total_seconds() / 86400))
    return [
        {
            "risk_band": band,
            "mttr_days": round(sum(values) / len(values), 2),
            "closed_tasks": len(values),
        }
        for band, values in sorted(totals.items())
    ]


def overdue_by_owner(db: Session, user: User) -> list[dict]:
    now = datetime.now(timezone.utc)
    query = (
        select(User.id, User.full_name, func.count(RemediationTask.id))
        .join(RemediationTask, RemediationTask.assigned_to_user_id == User.id)
        .where(RemediationTask.status != "closed", RemediationTask.sla_due_date < now)
        .group_by(User.id, User.full_name)
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, RemediationTask.asset_id == Asset.id).where(scope)
    return [
        {"owner_id": str(uid), "owner": name, "overdue_tasks": count}
        for uid, name, count in db.execute(query)
    ]


def aging_buckets(db: Session, user: User) -> dict[str, int]:
    now = datetime.now(timezone.utc)
    tasks = db.scalars(task_query(user).where(RemediationTask.status != "closed")).all()
    buckets = {"0-7": 0, "8-15": 0, "16-30": 0, "30+": 0}
    for task in tasks:
        created = task.created_at or now
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = max(0, (now - created).days)
        bucket = (
            "0-7"
            if age <= 7
            else "8-15" if age <= 15 else "16-30" if age <= 30 else "30+"
        )
        buckets[bucket] += 1
    return buckets


def top_assets(db: Session, user: User, limit: int = 10) -> list[dict]:
    query = (
        select(
            Asset.id,
            Asset.name,
            func.count(Finding.id),
            func.avg(Finding.risk_score),
            func.max(Finding.risk_score),
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
        .group_by(Asset.id, Asset.name)
        .order_by(func.sum(Finding.risk_score).desc())
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.where(scope)
    return [
        {
            "asset_id": str(i),
            "asset": n,
            "open_findings": c,
            "average_risk": round(float(a or 0), 1),
            "max_risk": float(m or 0),
        }
        for i, n, c, a, m in db.execute(query.limit(limit))
    ]


def findings_by_source(db: Session, user: User) -> list[dict]:
    counts: dict[str, int] = defaultdict(int)
    for (sources,) in db.execute(
        finding_query(user)
        .with_only_columns(Finding.sources)
        .where(Finding.status == "open")
    ):
        for source in set(sources or []):
            counts[source] += 1
    return [
        {"source": source, "findings": count}
        for source, count in sorted(counts.items())
    ]


def exceptions_expiring(db: Session, user: User, days: int = 30) -> list[dict]:
    query = select(RiskException).where(
        RiskException.status == "approved",
        RiskException.requested_expiry_date
        <= datetime.now(timezone.utc) + timedelta(days=days),
    )
    scope = asset_scope(user)
    if scope is not None:
        query = (
            query.join(Finding, RiskException.finding_id == Finding.id)
            .join(Asset, Finding.asset_id == Asset.id)
            .where(scope)
        )
    return [
        {
            "id": str(x.id),
            "finding_id": str(x.finding_id),
            "expiry": x.requested_expiry_date.isoformat(),
            "status": x.status,
        }
        for x in db.scalars(
            query.order_by(RiskException.requested_expiry_date).limit(100)
        )
    ]


def summary(db: Session, user: User, baseline_days: int = 180) -> dict:
    findings = finding_query(user)
    task_base = task_query(user)
    open_count = (
        db.scalar(
            findings.with_only_columns(func.count(Finding.id)).where(
                Finding.status == "open"
            )
        )
        or 0
    )
    bands = risk_bands(db, user)
    total_tasks = (
        db.scalar(task_base.with_only_columns(func.count(RemediationTask.id))) or 0
    )
    now = datetime.now(timezone.utc)
    overdue = (
        db.scalar(
            task_base.with_only_columns(func.count(RemediationTask.id)).where(
                RemediationTask.status != "closed", RemediationTask.sla_due_date < now
            )
        )
        or 0
    )
    compliant = max(0, total_tasks - overdue)
    raw_count = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.total_records), 0))) or 0
    )
    distinct_actions = open_count
    mttr = mttr_by_band(db, user)
    history_query = select(RiskScoreHistory.calculated_at, RiskScoreHistory.score).join(
        Finding, RiskScoreHistory.finding_id == Finding.id
    )
    scope = asset_scope(user)
    if scope is not None:
        history_query = history_query.join(Asset, Finding.asset_id == Asset.id).where(
            scope
        )
    histories = db.execute(history_query).all()
    baseline = now - timedelta(days=baseline_days)
    normalized_history = [
        (t.replace(tzinfo=timezone.utc) if t and t.tzinfo is None else t, float(s))
        for t, s in histories
        if t
    ]
    before = [s for t, s in normalized_history if t <= baseline]
    after = [s for t, s in normalized_history if t >= baseline]
    risk_reduction = (
        round((1 - sum(after) / len(after) / (sum(before) / len(before))) * 100, 1)
        if before and after and sum(before)
        else 0.0
    )
    return {
        "open_findings": int(open_count),
        "critical_count": int(bands.get("critical", 0)),
        "high_count": int(bands.get("high", 0)),
        "risk_bands": {
            band: int(bands.get(band, 0))
            for band in ("critical", "high", "medium", "low")
        },
        "overdue_count": int(overdue),
        "sla_compliance_percent": round(100 * compliant / max(total_tasks, 1), 1),
        "task_count": int(total_tasks),
        "assets": int(
            db.scalar(
                select(func.count(Asset.id)).where(scope)
                if scope is not None
                else select(func.count(Asset.id))
            )
            or 0
        ),
        "raw_records": int(raw_count),
        "prioritized_actions": int(distinct_actions),
        "effort_saved_minutes": max(0, int(raw_count) - int(distinct_actions))
        * MINUTES_PER_RAW_RECORD,
        "effort_saved_assumption_minutes_per_raw_record": MINUTES_PER_RAW_RECORD,
        "mttr_by_band": mttr,
        "risk_reduction_percent": risk_reduction,
        "trend": trend(db, user),
        "heatmap": heatmap(db, user),
        "top_assets": top_assets(db, user),
        "overdue_by_owner": overdue_by_owner(db, user),
        "aging_buckets": aging_buckets(db, user),
        "findings_by_source": findings_by_source(db, user),
        "exceptions_expiring": exceptions_expiring(db, user),
    }

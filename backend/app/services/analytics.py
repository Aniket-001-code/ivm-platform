"""SQL-backed dashboard analytics with portable SQLite/PostgreSQL aggregation."""

import functools
import threading
import time

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import scope
from app.core.rbac import canonical_role
from app.core.timeutil import as_utc
from app.models.entities import (
    Asset,
    AttackPath,
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
GLOBAL_ROLES = scope.GLOBAL_ROLES


# --- Short-lived result cache -------------------------------------------------------------
# Dashboard aggregates scan the whole score history; they change slowly, so concurrent
# dashboard requests share a result for a few seconds instead of recomputing it each time.
_CACHE: dict[tuple, tuple[float, object]] = {}
_CACHE_LOCK = threading.Lock()
CACHE_SECONDS = 30.0


def _scope_key(user: User) -> tuple:
    role = canonical_role(user.role)
    if role in GLOBAL_ROLES:
        return (role,)
    return (role, str(user.business_unit_id), str(user.id))


_KEY_LOCKS: dict[tuple, threading.Lock] = {}


def cached(fn):
    """Cache per user scope for CACHE_SECONDS with single-flight: one thread computes a missing
    value while concurrent callers for the same key wait for it (no thundering herd)."""

    @functools.wraps(fn)
    def wrapper(db: Session, user: User, *args, **kwargs):
        key = (fn.__name__, _scope_key(user), args, tuple(sorted(kwargs.items())))
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
            if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
                return hit[1]
            key_lock = _KEY_LOCKS.setdefault(key, threading.Lock())
        with key_lock:
            with _CACHE_LOCK:
                hit = _CACHE.get(key)
                if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
                    return hit[1]
            value = fn(db, user, *args, **kwargs)
            with _CACHE_LOCK:
                _CACHE[key] = (time.monotonic(), value)
            return value

    wrapper.uncached = fn  # type: ignore[attr-defined]
    return wrapper


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def asset_scope(user: User):
    return scope.asset_condition(user)


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


@cached
def trend(db: Session, user: User, weeks: int = 26) -> list[dict]:
    """Weekly average of each finding's latest score in that week (open-portfolio risk)."""
    cutoff = datetime.now(timezone.utc) - timedelta(weeks=weeks)
    query = (
        select(
            RiskScoreHistory.finding_id,
            RiskScoreHistory.calculated_at,
            RiskScoreHistory.score,
        )
        .join(Finding, RiskScoreHistory.finding_id == Finding.id)
        .where(RiskScoreHistory.calculated_at >= cutoff)
    )
    scope = asset_scope(user)
    if scope is not None:
        query = query.join(Asset, Finding.asset_id == Asset.id).where(scope)
    latest: dict[tuple[int, int], dict] = defaultdict(dict)
    labels: dict[tuple[int, int], str] = {}
    for finding_id, timestamp, score in db.execute(query):
        timestamp = as_utc(timestamp)
        year, week, _ = timestamp.isocalendar()
        key = (year, week)
        current = latest[key].get(finding_id)
        if current is None or timestamp >= current[0]:
            latest[key][finding_id] = (timestamp, float(score))
        labels[key] = max(
            labels.get(key, timestamp.date().isoformat()), timestamp.date().isoformat()
        )
    ordered = sorted(latest)[-weeks:]
    return [
        {
            "week": labels[key],
            "average_score": round(
                sum(score for _, score in latest[key].values()) / len(latest[key]), 1
            ),
            "sample_count": len(latest[key]),
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


def overdue_by_owner_and_category(db: Session, user: User) -> list[dict]:
    """Overdue open tasks grouped by owner and SLA category (risk band)."""
    now = datetime.now(timezone.utc)
    query = (
        select(
            User.full_name, RemediationTask.sla_category, func.count(RemediationTask.id)
        )
        .join(User, RemediationTask.assigned_to_user_id == User.id, isouter=True)
        .where(RemediationTask.status != "closed", RemediationTask.sla_due_date < now)
        .group_by(User.full_name, RemediationTask.sla_category)
    )
    condition = asset_scope(user)
    if condition is not None:
        query = query.join(Asset, RemediationTask.asset_id == Asset.id).where(condition)
    return [
        {
            "owner": name or "Unassigned",
            "sla_category": category or "unknown",
            "overdue_tasks": n,
        }
        for name, category, n in db.execute(query)
    ]


def internet_facing_high_risk(db: Session, user: User, limit: int = 10) -> list[dict]:
    query = (
        select(
            Asset.id,
            Asset.name,
            Asset.is_crown_jewel,
            func.count(Finding.id),
            func.max(Finding.risk_score),
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .where(
            Asset.internet_exposed.is_(True),
            Finding.status == "open",
            Finding.risk_band.in_(["critical", "high"]),
        )
        .group_by(Asset.id, Asset.name, Asset.is_crown_jewel)
        .order_by(func.max(Finding.risk_score).desc())
    )
    condition = asset_scope(user)
    if condition is not None:
        query = query.where(condition)
    return [
        {
            "asset_id": str(i),
            "asset": n,
            "crown_jewel": bool(c),
            "high_risk_findings": count,
            "max_risk": float(m or 0),
        }
        for i, n, c, count, m in db.execute(query.limit(limit))
    ]


def crown_jewel_paths(db: Session, user: User, limit: int = 8) -> list[dict]:
    targets = select(Asset.id).where(Asset.is_crown_jewel.is_(True))
    condition = asset_scope(user)
    if condition is not None:
        targets = targets.where(condition)
    query = (
        select(AttackPath)
        .where(AttackPath.target_asset_id.in_(targets))
        .order_by(AttackPath.path_risk_score.desc())
    )
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "path_risk_score": p.path_risk_score,
            "hops": len(p.path_asset_ids or []),
        }
        for p in db.scalars(query.limit(limit))
    ]


@cached
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
    # Compliant = closed on/before the SLA date, or still open and not yet due.
    late_closed = 0
    for closed_at, due in db.execute(
        task_base.with_only_columns(
            RemediationTask.closed_at, RemediationTask.sla_due_date
        ).where(
            RemediationTask.status == "closed",
            RemediationTask.closed_at.is_not(None),
            RemediationTask.sla_due_date.is_not(None),
        )
    ):
        if as_utc(closed_at) > as_utc(due):
            late_closed += 1
    compliant = max(0, total_tasks - overdue - late_closed)
    raw_count = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.total_records), 0))) or 0
    )
    duplicates = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.duplicate_count), 0))) or 0
    )
    failed_rows = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.failed_count), 0))) or 0
    )
    # Distinct records after correlation: every duplicate row merged is triage avoided.
    distinct_actions = max(0, int(raw_count) - int(duplicates) - int(failed_rows))
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
        "duplicates_merged": int(duplicates),
        "effort_saved_minutes": int(duplicates) * MINUTES_PER_RAW_RECORD,
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
        "overdue_by_owner_and_category": overdue_by_owner_and_category(db, user),
        "internet_facing_high_risk": internet_facing_high_risk(db, user),
        "crown_jewel_paths": crown_jewel_paths(db, user),
    }

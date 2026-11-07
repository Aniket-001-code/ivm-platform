"""Predictive analytics from historical remediation data (bonus items in SPEC section 17).

* SLA breach likelihood per open task, learned from closed-task history: typical
  time-to-close per risk band and each owner's on-time rate (Beta-smoothed toward the
  portfolio rate). The model is deliberately transparent: every probability comes with the
  factors that produced it.
* Risk trend forecast: least-squares linear fit over the weekly average risk score.
"""

import math
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.models.entities import RemediationTask
from app.services.remediation import DEFAULT_SLA_DAYS

STATUS_FACTOR = {
    "open": 1.0,
    "in_progress": 0.75,
    "pending_verification": 0.35,
    "blocked": 1.35,
}


@dataclass
class History:
    median_days_by_band: dict[str, float]
    owner_on_time: dict[str, tuple[int, int]]  # owner id -> (on_time, total)
    portfolio_on_time_rate: float


def learn_history(db: Session) -> History:
    durations: dict[str, list[float]] = {}
    owners: dict[str, list[int]] = {}
    on_time_total = [0, 0]
    for task in db.scalars(
        select(RemediationTask).where(RemediationTask.closed_at.is_not(None))
    ):
        if task.closed_at is None:
            continue
        created = as_utc(task.created_at) if task.created_at else None
        closed = as_utc(task.closed_at)
        if created:
            durations.setdefault(task.priority, []).append(
                max(0.0, (closed - created).total_seconds() / 86400)
            )
        if task.sla_due_date:
            on_time = int(closed <= as_utc(task.sla_due_date))
            key = str(task.assigned_to_user_id)
            owners.setdefault(key, [0, 0])
            owners[key][0] += on_time
            owners[key][1] += 1
            on_time_total[0] += on_time
            on_time_total[1] += 1
    rate = (on_time_total[0] + 4) / (on_time_total[1] + 5)  # prior: mostly on time
    return History(
        median_days_by_band={
            band: statistics.median(v) for band, v in durations.items() if v
        },
        owner_on_time={k: (v[0], v[1]) for k, v in owners.items()},
        portfolio_on_time_rate=rate,
    )


def breach_likelihood(
    task: RemediationTask, history: History, now: datetime | None = None
):
    """Return (probability 0..1, level, factors) that the task misses its SLA."""
    now = now or datetime.now(timezone.utc)
    if task.status == "closed" or not task.sla_due_date:
        return 0.0, "none", []
    due = as_utc(task.sla_due_date)
    remaining = (due - now).total_seconds() / 86400
    if remaining <= 0:
        return 1.0, "breached", [f"SLA passed {abs(remaining):.0f} days ago"]
    created = as_utc(task.created_at) if task.created_at else now
    elapsed = max(0.0, (now - created).total_seconds() / 86400)
    sla_days = DEFAULT_SLA_DAYS.get(task.priority, 30)
    typical = history.median_days_by_band.get(task.priority, sla_days * 0.6)
    expected_remaining = max(0.5, typical - elapsed)
    # Positive gap: the task is expected to need more time than it has left.
    gap = (expected_remaining - remaining) / max(1.0, sla_days * 0.25)
    base = 1 / (1 + math.exp(-gap * 2.2))
    on_time, total = history.owner_on_time.get(str(task.assigned_to_user_id), (0, 0))
    prior_strength = 4
    owner_rate = (on_time + prior_strength * history.portfolio_on_time_rate) / (
        total + prior_strength
    )
    owner_factor = 0.6 + (1 - owner_rate) * 1.6  # 0.6 (reliable) .. 2.2 (always late)
    status_factor = STATUS_FACTOR.get(task.status, 1.0)
    probability = max(0.01, min(0.99, base * owner_factor * status_factor))
    level = "high" if probability >= 0.6 else "medium" if probability >= 0.3 else "low"
    factors = [
        f"{remaining:.1f} days left of {sla_days}-day SLA",
        f"typical {task.priority} fix takes {typical:.1f} days",
        f"owner on-time rate {owner_rate:.0%} ({total} closed tasks)",
        f"status {task.status.replace('_', ' ')}",
    ]
    return round(probability, 3), level, factors


def breach_forecast(db: Session, tasks, horizon_days: int = 14) -> dict:
    history = learn_history(db)
    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=horizon_days)
    rows = []
    for task in tasks:
        probability, level, factors = breach_likelihood(task, history, now)
        if level == "none":
            continue
        rows.append(
            {
                "task_id": str(task.id),
                "finding_id": str(task.finding_id),
                "priority": task.priority,
                "status": task.status,
                "sla_due_date": task.sla_due_date,
                "probability": probability,
                "level": level,
                "factors": factors,
                "due_within_horizon": bool(
                    task.sla_due_date and as_utc(task.sla_due_date) <= horizon
                ),
            }
        )
    rows.sort(key=lambda r: r["probability"], reverse=True)
    upcoming = [r for r in rows if r["level"] != "breached" and r["due_within_horizon"]]
    return {
        "horizon_days": horizon_days,
        "already_breached": sum(r["level"] == "breached" for r in rows),
        "expected_new_breaches": round(sum(r["probability"] for r in upcoming), 1),
        "high_risk_tasks": sum(r["level"] == "high" for r in rows),
        "model": {
            "median_days_to_close": {
                k: round(v, 1) for k, v in history.median_days_by_band.items()
            },
            "portfolio_on_time_rate": round(history.portfolio_on_time_rate, 3),
            "closed_tasks_learned_from": sum(
                t for _, t in history.owner_on_time.values()
            ),
        },
        "tasks": rows[:50],
    }


def linear_forecast(points: list[float], periods: int = 4) -> dict:
    """Least-squares trend over equally spaced points, projected ``periods`` steps ahead."""
    n = len(points)
    if n < 2:
        return {
            "slope_per_period": 0.0,
            "projection": points[-1:] * periods,
            "r_squared": 0.0,
        }
    xs = list(range(n))
    mean_x, mean_y = sum(xs) / n, sum(points) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, points))
    slope = sxy / sxx if sxx else 0.0
    intercept = mean_y - slope * mean_x
    fitted = [intercept + slope * x for x in xs]
    ss_res = sum((y - f) ** 2 for y, f in zip(points, fitted))
    ss_tot = sum((y - mean_y) ** 2 for y in points)
    projection = [
        round(max(0.0, min(100.0, intercept + slope * (n + i))), 2)
        for i in range(periods)
    ]
    return {
        "slope_per_period": round(slope, 3),
        "projection": projection,
        "r_squared": round(1 - ss_res / ss_tot, 3) if ss_tot else 1.0,
    }

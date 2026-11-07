from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.forecasting import History, breach_likelihood, linear_forecast


def test_linear_forecast_recovers_slope_and_projects():
    fit = linear_forecast([10, 12, 14, 16], periods=2)
    assert fit["slope_per_period"] == 2.0
    assert fit["projection"] == [18.0, 20.0]
    assert fit["r_squared"] == 1.0


def test_linear_forecast_handles_short_series():
    assert linear_forecast([42.0], periods=3)["slope_per_period"] == 0.0


def _task(**kw):
    now = datetime.now(timezone.utc)
    base = dict(
        status="open",
        priority="critical",
        created_at=now - timedelta(days=5),
        sla_due_date=now + timedelta(days=2),
        assigned_to_user_id="owner",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_breach_likelihood_is_explainable_and_ordered():
    history = History({"critical": 6.0}, {"owner": (1, 4)}, 0.8)
    tight, _, factors = breach_likelihood(_task(), history)
    roomy, _, _ = breach_likelihood(
        _task(sla_due_date=datetime.now(timezone.utc) + timedelta(days=30)), history
    )
    verifying, _, _ = breach_likelihood(_task(status="pending_verification"), history)
    assert 0 < roomy < tight < 1
    assert verifying < tight
    assert any("owner on-time rate" in f for f in factors)


def test_breached_and_closed_tasks():
    history = History({}, {}, 0.8)
    late = _task(sla_due_date=datetime.now(timezone.utc) - timedelta(days=1))
    assert breach_likelihood(late, history)[:2] == (1.0, "breached")
    assert breach_likelihood(_task(status="closed"), history)[:2] == (0.0, "none")

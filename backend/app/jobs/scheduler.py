import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.db.session import SessionLocal
from app.services.exceptions import expire_exceptions
from app.services.sla import check_overdue_tasks

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler(timezone="UTC")


def _run_sla() -> None:
    with SessionLocal() as db:
        logger.info(
            "SLA check created escalations", extra={"count": check_overdue_tasks(db)}
        )


def _run_expiry() -> None:
    with SessionLocal() as db:
        logger.info(
            "Exception expiry job completed", extra={"count": expire_exceptions(db)}
        )


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(
        _run_sla, "interval", minutes=15, id="sla-check", replace_existing=True
    )
    scheduler.add_job(
        _run_expiry, "interval", hours=1, id="exception-expiry", replace_existing=True
    )
    scheduler.start()


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)

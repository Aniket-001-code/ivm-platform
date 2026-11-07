"""Aggregate API router; route modules are included in their original registration order."""

from fastapi import APIRouter

from app.api.v1.routes import (
    ai,
    assets,
    attack_paths,
    audit,
    auth,
    config,
    dashboards,
    exceptions,
    findings,
    imports,
    reports,
    risk,
    system,
    tasks,
    ticketing,
    users,
)

router = APIRouter()
for _module in (
    auth,
    users,
    assets,
    findings,
    imports,
    risk,
    attack_paths,
    tasks,
    exceptions,
    dashboards,
    ai,
    ticketing,
    audit,
    config,
    system,
    reports,
):
    router.include_router(_module.router)

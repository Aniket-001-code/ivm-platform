"""Default-deny, permission-based access control for the API."""

from enum import StrEnum

from fastapi import Depends, HTTPException, Request, status

from app.core.deps import get_current_user
from app.models.entities import User


class Permission(StrEnum):
    AUTHENTICATED = "authenticated"
    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    ASSET_READ = "asset:read"
    ASSET_MANAGE = "asset:manage"
    FINDING_READ = "finding:read"
    FINDING_TRIAGE = "finding:triage"
    IMPORT = "import:run"
    RISK_READ = "risk:read"
    RISK_MANAGE = "risk:manage"
    RISK_WHAT_IF = "risk:what_if"
    ATTACK_PATH_READ = "attack_path:read"
    TASK_READ = "task:read"
    TASK_MANAGE = "task:manage"
    TASK_ASSIGNED = "task:assigned"
    EXCEPTION_READ = "exception:read"
    EXCEPTION_REQUEST = "exception:request"
    EXCEPTION_APPROVE_TEMP = "exception:approve_temporary"
    EXCEPTION_APPROVE_ALL = "exception:approve_all"
    AUDIT_READ = "audit:read"
    AI_USE = "ai:use"
    AI_EXECUTIVE = "ai:executive_summary"
    TICKET_CREATE = "ticket:create"
    CONFIG_READ = "config:read"
    CONFIG_MANAGE = "config:manage"
    SCHEDULER_RUN = "scheduler:run"
    REPORT_READ = "report:read"
    NOTIFICATION_READ = "notification:read"


_ANALYST = {
    Permission.ASSET_READ,
    Permission.FINDING_READ,
    Permission.FINDING_TRIAGE,
    Permission.IMPORT,
    Permission.RISK_READ,
    Permission.ATTACK_PATH_READ,
    Permission.TASK_READ,
    Permission.EXCEPTION_READ,
    Permission.EXCEPTION_REQUEST,
    Permission.AI_USE,
    Permission.TICKET_CREATE,
    Permission.REPORT_READ,
}

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "platform_admin": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.USER_READ,
            Permission.USER_MANAGE,
            Permission.ASSET_READ,
            Permission.ASSET_MANAGE,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.IMPORT,
            Permission.RISK_READ,
            Permission.RISK_MANAGE,
            Permission.RISK_WHAT_IF,
            Permission.ATTACK_PATH_READ,
            Permission.TASK_READ,
            Permission.TASK_MANAGE,
            Permission.EXCEPTION_READ,
            Permission.EXCEPTION_REQUEST,
            Permission.AUDIT_READ,
            Permission.AI_USE,
            Permission.AI_EXECUTIVE,
            Permission.TICKET_CREATE,
            Permission.CONFIG_READ,
            Permission.CONFIG_MANAGE,
            Permission.SCHEDULER_RUN,
            Permission.REPORT_READ,
            Permission.NOTIFICATION_READ,
        }
    ),
    "security_analyst": frozenset(
        _ANALYST
        | {
            Permission.AUTHENTICATED,
            Permission.USER_READ,
            Permission.CONFIG_READ,
            Permission.AUDIT_READ,
        }
    ),
    "vulnerability_manager": frozenset(
        _ANALYST
        | {
            Permission.AUTHENTICATED,
            Permission.USER_READ,
            Permission.TASK_MANAGE,
            Permission.ASSET_MANAGE,
            Permission.RISK_MANAGE,
            Permission.RISK_WHAT_IF,
            Permission.EXCEPTION_APPROVE_TEMP,
            Permission.CONFIG_READ,
            Permission.SCHEDULER_RUN,
            Permission.NOTIFICATION_READ,
        }
    ),
    "security_architect": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.ASSET_READ,
            Permission.FINDING_READ,
            Permission.RISK_READ,
            Permission.RISK_WHAT_IF,
            Permission.RISK_MANAGE,
            Permission.ATTACK_PATH_READ,
            Permission.EXCEPTION_READ,
            Permission.EXCEPTION_REQUEST,
            Permission.EXCEPTION_APPROVE_ALL,
            Permission.EXCEPTION_APPROVE_TEMP,
            Permission.AUDIT_READ,
            Permission.AI_USE,
            Permission.AI_EXECUTIVE,
            Permission.REPORT_READ,
        }
    ),
    "it_asset_owner": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.ASSET_READ,
            Permission.FINDING_READ,
            Permission.RISK_READ,
            Permission.REPORT_READ,
            Permission.TASK_READ,
            Permission.TASK_ASSIGNED,
            Permission.EXCEPTION_READ,
            Permission.EXCEPTION_REQUEST,
            Permission.TICKET_CREATE,
        }
    ),
    "system_administrator": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.ASSET_READ,
            Permission.RISK_READ,
            Permission.REPORT_READ,
            Permission.TASK_READ,
            Permission.TASK_ASSIGNED,
            Permission.TICKET_CREATE,
        }
    ),
    "business_unit_manager": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.ASSET_READ,
            Permission.FINDING_READ,
            Permission.RISK_READ,
            Permission.TASK_READ,
            Permission.EXCEPTION_READ,
            Permission.REPORT_READ,
            Permission.NOTIFICATION_READ,
        }
    ),
    "executive_ciso": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.RISK_READ,
            Permission.AI_EXECUTIVE,
            Permission.REPORT_READ,
        }
    ),
    "auditor": frozenset(
        {
            Permission.AUTHENTICATED,
            Permission.EXCEPTION_READ,
            Permission.AUDIT_READ,
            Permission.RISK_READ,
            Permission.REPORT_READ,
        }
    ),
}

ROLE_ALIASES = {
    "analyst": "security_analyst",
    "manager": "vulnerability_manager",
    "approver": "vulnerability_manager",
    "remediation_owner": "it_asset_owner",
    "executive": "executive_ciso",
}


def canonical_role(role: str) -> str:
    return ROLE_ALIASES.get(role, role)


def permissions_for(role: str) -> list[str]:
    """Sorted permission names for a role, sent to the browser to drive menus and guards."""
    return sorted(
        p.value for p in ROLE_PERMISSIONS.get(canonical_role(role), frozenset())
    )


def has_permission(role: str, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(canonical_role(role), frozenset())


def permission_for_request(request: Request) -> Permission:
    """Map every protected HTTP route to its least-privilege capability."""
    method = request.method.upper()
    path = request.url.path.removeprefix("/api/v1")
    if path.startswith("/auth/"):
        return Permission.AUTHENTICATED
    if path == "/users" or path.startswith("/users/"):
        return Permission.USER_MANAGE if method != "GET" else Permission.USER_READ
    if path.startswith("/config/"):
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return Permission.CONFIG_MANAGE
        return Permission.CONFIG_READ
    if path.startswith("/audit"):
        return Permission.AUDIT_READ
    if path.startswith("/exceptions"):
        if path.endswith("/approve") or path.endswith("/reject"):
            return Permission.EXCEPTION_APPROVE_TEMP
        if path.endswith("/export") or path.endswith("/expiring"):
            return Permission.EXCEPTION_READ
        return (
            Permission.EXCEPTION_REQUEST
            if method == "POST"
            else Permission.EXCEPTION_READ
        )
    if path.startswith("/imports") or path.startswith("/threat-intel/import"):
        return (
            Permission.IMPORT
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            else Permission.FINDING_READ
        )
    if path.startswith("/assets"):
        return (
            Permission.ASSET_MANAGE
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            else Permission.ASSET_READ
        )
    if path.startswith("/findings"):
        return (
            Permission.FINDING_TRIAGE
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            else Permission.FINDING_READ
        )
    if path.startswith("/risk/what-if"):
        return Permission.RISK_WHAT_IF
    if path.startswith("/risk/recalculate") or path.startswith("/risk/config"):
        return Permission.RISK_MANAGE if method != "GET" else Permission.RISK_READ
    if path.startswith("/reports"):
        return Permission.REPORT_READ
    if path.startswith("/analytics"):
        return Permission.RISK_READ
    if path.startswith("/risk") or path.startswith("/dashboards"):
        return Permission.RISK_READ
    if path.startswith("/attack-paths"):
        return (
            Permission.ATTACK_PATH_READ if method == "GET" else Permission.RISK_MANAGE
        )
    if path.startswith("/tasks"):
        return (
            Permission.TASK_ASSIGNED
            if method in {"PATCH", "PUT", "POST", "DELETE"}
            else Permission.TASK_READ
        )
    if path.startswith("/escalations") and path.endswith("/acknowledge"):
        return (
            Permission.AUTHENTICATED
        )  # the route itself restricts this to the recipient
    if path.startswith("/escalations"):
        return Permission.NOTIFICATION_READ
    if path.startswith("/jobs/run"):
        return Permission.SCHEDULER_RUN
    if path.startswith("/ai/executive-summary"):
        return Permission.AI_EXECUTIVE
    if path.startswith("/ai"):
        return Permission.AI_USE
    if path.startswith("/ticketing"):
        return Permission.TICKET_CREATE
    if path.startswith("/metrics") or path.startswith("/threat-intel"):
        return (
            Permission.REPORT_READ
            if path.startswith("/metrics")
            else Permission.FINDING_READ
        )
    return Permission.AUTHENTICATED


def require_permission(permission: Permission):
    def check(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission.value}",
            )
        return user

    return check

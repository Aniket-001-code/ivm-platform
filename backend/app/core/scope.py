"""Single source of truth for which assets (and so findings/tasks) a user may see.

API routes, dashboard analytics and the AI assistant all use this module so that a
user never sees different numbers on different screens.
"""

from sqlalchemy import or_, select

from app.core.rbac import canonical_role
from app.models.entities import Asset, RemediationTask, User

# Portfolio-wide read access. Write access is still governed by permissions in rbac.py.
GLOBAL_ROLES = frozenset(
    {
        "platform_admin",
        "security_analyst",
        "vulnerability_manager",
        "executive_ciso",
        "auditor",
    }
)


def is_global(user: User) -> bool:
    return canonical_role(user.role) in GLOBAL_ROLES


def asset_condition(user: User):
    """Return a SQL condition on Asset, or None when the user sees every asset."""
    role = canonical_role(user.role)
    if role in GLOBAL_ROLES:
        return None
    if role == "business_unit_manager":
        return Asset.business_unit_id == user.business_unit_id
    if role in {"it_asset_owner", "security_architect"}:
        return or_(
            Asset.owner_user_id == user.id,
            Asset.business_unit_id == user.business_unit_id,
        )
    if role == "system_administrator":
        return Asset.id.in_(
            select(RemediationTask.asset_id).where(
                RemediationTask.assigned_to_user_id == user.id
            )
        )
    return Asset.id.is_(None)  # unknown roles see nothing

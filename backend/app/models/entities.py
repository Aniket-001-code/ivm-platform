"""Compatibility re-export of every ORM entity; prefer the domain modules for new code."""

from app.models.audit import AiQueryLog, AuditLog
from app.models.inventory import Asset, AssetConnection
from app.models.mixins import TimestampMixin
from app.models.organization import BusinessService, BusinessUnit, User
from app.models.remediation import (
    Escalation,
    OwnershipRule,
    RemediationTask,
    RiskException,
    SlaPolicy,
    TaskUpdate,
    TicketRecord,
)
from app.models.vulnerabilities import (
    AttackPath,
    Finding,
    FindingSource,
    ImportBatch,
    RawFinding,
    RiskScoreHistory,
    ScoringConfig,
    VulnerabilityCatalog,
)

__all__ = [
    "AiQueryLog",
    "Asset",
    "AssetConnection",
    "AttackPath",
    "AuditLog",
    "BusinessService",
    "BusinessUnit",
    "Escalation",
    "Finding",
    "FindingSource",
    "ImportBatch",
    "OwnershipRule",
    "RawFinding",
    "RemediationTask",
    "RiskException",
    "RiskScoreHistory",
    "ScoringConfig",
    "SlaPolicy",
    "TaskUpdate",
    "TicketRecord",
    "TimestampMixin",
    "User",
    "VulnerabilityCatalog",
]

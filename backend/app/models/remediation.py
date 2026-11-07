"""Remediation tasks, SLAs, escalations, exceptions, ownership and tickets."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin


class RemediationTask(TimestampMixin, Base):
    __tablename__ = "remediation_tasks"
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"))
    assigned_to_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_by_rule: Mapped[str | None] = mapped_column(String(120), nullable=True)
    assigned_group: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open")
    priority: Mapped[str] = mapped_column(String(20), default="medium")
    sla_due_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    sla_category: Mapped[str | None] = mapped_column(String(30), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    evidence_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    ticket_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)


class TaskUpdate(TimestampMixin, Base):
    __tablename__ = "task_updates"
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_tasks.id"), index=True
    )
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    old_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    new_status: Mapped[str] = mapped_column(String(30))
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)


class SlaPolicy(TimestampMixin, Base):
    __tablename__ = "sla_policies"
    risk_band: Mapped[str] = mapped_column(String(20), unique=True)
    sla_days: Mapped[int] = mapped_column(Integer)
    escalation_level_1_days: Mapped[int] = mapped_column(Integer)
    escalation_level_2_days: Mapped[int] = mapped_column(Integer)


class Escalation(TimestampMixin, Base):
    __tablename__ = "escalations"
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_tasks.id"), index=True
    )
    level: Mapped[int] = mapped_column(Integer)
    escalated_to_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    reason: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )


class RiskException(TimestampMixin, Base):
    __tablename__ = "risk_exceptions"
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    requested_by: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    justification: Mapped[str] = mapped_column(Text)
    compensating_controls: Mapped[str] = mapped_column(Text)
    exception_type: Mapped[str] = mapped_column(String(20))
    requested_expiry_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    reviewed_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class OwnershipRule(TimestampMixin, Base):
    __tablename__ = "ownership_rules"
    priority_order: Mapped[int] = mapped_column(Integer, index=True)
    match_field: Mapped[str] = mapped_column(String(40))
    match_value: Mapped[str] = mapped_column(String(200))
    assign_to_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assign_to_group: Mapped[str | None] = mapped_column(String(120), nullable=True)


class TicketRecord(TimestampMixin, Base):
    __tablename__ = "ticket_records"
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("remediation_tasks.id"), index=True
    )
    system: Mapped[str] = mapped_column(String(30))
    ticket_key: Mapped[str] = mapped_column(String(100), unique=True)
    status: Mapped[str] = mapped_column(String(30))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

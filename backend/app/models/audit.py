"""Audit trail and AI query log."""

from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_logs"
    actor_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    old_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # Hash chain (see app/services/audit.py): rows written before the chain existed are null.
    sequence: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True, unique=True
    )
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AiQueryLog(TimestampMixin, Base):
    __tablename__ = "ai_query_logs"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    question: Mapped[str] = mapped_column(Text)
    detected_intent: Mapped[str] = mapped_column(String(80))
    answer_summary: Mapped[str] = mapped_column(Text)
    used_llm: Mapped[bool] = mapped_column(Boolean, default=False)

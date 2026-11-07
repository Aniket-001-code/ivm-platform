"""Business units, services and platform users."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin


class BusinessUnit(TimestampMixin, Base):
    __tablename__ = "business_units"
    name: Mapped[str] = mapped_column(String(120), unique=True)
    head_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )


class BusinessService(TimestampMixin, Base):
    __tablename__ = "business_services"
    name: Mapped[str] = mapped_column(String(120))
    business_unit_id: Mapped[UUID] = mapped_column(ForeignKey("business_units.id"))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class User(TimestampMixin, Base):
    __tablename__ = "users"
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(160))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(40), default="analyst")
    business_unit_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("business_units.id"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(512), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    refresh_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

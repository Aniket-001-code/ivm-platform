"""Assets and their network connections."""

from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"
    name: Mapped[str] = mapped_column(String(200), index=True)
    asset_type: Mapped[str] = mapped_column(String(40))
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    environment: Mapped[str] = mapped_column(String(20), default="dev")
    business_unit_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("business_units.id"), nullable=True, index=True
    )
    business_service_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("business_services.id"), nullable=True
    )
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    criticality_tier: Mapped[int] = mapped_column(Integer, default=3)
    is_customer_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    is_crown_jewel: Mapped[bool] = mapped_column(Boolean, default=False)
    has_sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    regulatory_tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    os_or_platform: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="active")


class AssetConnection(TimestampMixin, Base):
    __tablename__ = "asset_connections"
    source_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"), index=True)
    target_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"), index=True)
    connection_type: Mapped[str] = mapped_column(String(30))
    port_or_protocol: Mapped[str | None] = mapped_column(String(80), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

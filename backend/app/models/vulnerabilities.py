"""Vulnerability catalog, findings, imports, scoring and attack paths."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.mixins import TimestampMixin


class VulnerabilityCatalog(TimestampMixin, Base):
    __tablename__ = "vulnerability_catalog"
    cve_id: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_base_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(160), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(40), nullable=True)
    published_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[str] = mapped_column(String(20), default="none")
    epss_score: Mapped[float] = mapped_column(Float, default=0)
    in_kev_list: Mapped[bool] = mapped_column(Boolean, default=False)
    ransomware_used: Mapped[bool] = mapped_column(Boolean, default=False)
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False)


class ImportBatch(TimestampMixin, Base):
    __tablename__ = "import_batches"
    source_name: Mapped[str] = mapped_column(String(100))
    file_name: Mapped[str] = mapped_column(String(255))
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    errors: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class RawFinding(TimestampMixin, Base):
    __tablename__ = "raw_findings"
    source_name: Mapped[str] = mapped_column(String(100))
    source_type: Mapped[str] = mapped_column(String(40))
    import_batch_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    raw_payload: Mapped[dict] = mapped_column(JSON)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    status: Mapped[str] = mapped_column(String(20), default="new")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True), nullable=True
    )
    finding_type: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(String(30), default="open", index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0, index=True)
    risk_band: Mapped[str] = mapped_column(String(20), default="low")
    risk_breakdown: Mapped[list] = mapped_column(JSON, default=list)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)


class FindingSource(TimestampMixin, Base):
    __tablename__ = "finding_sources"
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    raw_finding_id: Mapped[UUID] = mapped_column(
        ForeignKey("raw_findings.id"), index=True
    )
    source_name: Mapped[str] = mapped_column(String(100))


class RiskScoreHistory(TimestampMixin, Base):
    __tablename__ = "risk_score_history"
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    score: Mapped[float] = mapped_column(Float)
    band: Mapped[str] = mapped_column(String(20))
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    config_version: Mapped[int] = mapped_column(Integer)


class ScoringConfig(TimestampMixin, Base):
    __tablename__ = "scoring_config"
    version: Mapped[int] = mapped_column(Integer, unique=True)
    weights: Mapped[dict] = mapped_column(JSON)
    band_thresholds: Mapped[dict] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )


class AttackPath(TimestampMixin, Base):
    __tablename__ = "attack_paths"
    name: Mapped[str] = mapped_column(String(200))
    entry_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"))
    target_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"))
    path_asset_ids: Mapped[list] = mapped_column(JSON, default=list)
    path_finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    path_risk_score: Mapped[float] = mapped_column(Float, default=0)
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

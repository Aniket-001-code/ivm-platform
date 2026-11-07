from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TimestampMixin:
    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


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


class AssetConnection(TimestampMixin, Base):
    __tablename__ = "asset_connections"
    source_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"), index=True)
    target_asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"), index=True)
    connection_type: Mapped[str] = mapped_column(String(30))
    port_or_protocol: Mapped[str | None] = mapped_column(String(80), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


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


class RemediationTask(TimestampMixin, Base):
    __tablename__ = "remediation_tasks"
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), index=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id"))
    assigned_to_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    assigned_by_rule: Mapped[str | None] = mapped_column(String(120), nullable=True)
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


class AiQueryLog(TimestampMixin, Base):
    __tablename__ = "ai_query_logs"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    question: Mapped[str] = mapped_column(Text)
    detected_intent: Mapped[str] = mapped_column(String(80))
    answer_summary: Mapped[str] = mapped_column(Text)
    used_llm: Mapped[bool] = mapped_column(Boolean, default=False)

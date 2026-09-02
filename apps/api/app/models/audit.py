import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, ForeignKey, JSON, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class AuditEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_org_created", "organization_id", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), default="user", nullable=False)  # "user", "service_identity", "api_key", "system"

    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)  # "secret.read", "secret.reveal", "kms.encrypt", "pki.issue"
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "secret", "certificate", "managed_key", "access_request"
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    result: Mapped[str] = mapped_column(String(32), default="success", nullable=False)  # "success", "denied", "failure"
    
    request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Sanitized context metadata (never containing plaintext secrets)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Tamper-evident SHA-256 hash chaining
    prev_event_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

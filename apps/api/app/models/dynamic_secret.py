import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class DynamicSecretProvider(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "dynamic_secret_providers"

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "postgres", "mysql", "aws_sts", "ssh"
    default_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)  # 1 hour
    max_ttl_seconds: Mapped[int] = mapped_column(Integer, default=86400, nullable=False)  # 24 hours
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)  # Provider connection and credential config
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    leases: Mapped[List["DynamicCredentialLease"]] = relationship("DynamicCredentialLease", back_populates="provider", cascade="all, delete-orphan")


class DynamicCredentialLease(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "dynamic_credential_leases"

    provider_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("dynamic_secret_providers.id", ondelete="CASCADE"), nullable=False, index=True)
    issued_identity: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "aegis_tmp_usr_9f8a2e"
    credential_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False, index=True)  # "active", "expired", "revoked"
    requester_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)

    provider: Mapped["DynamicSecretProvider"] = relationship("DynamicSecretProvider", back_populates="leases")

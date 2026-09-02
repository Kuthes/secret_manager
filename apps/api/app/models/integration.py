import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class IntegrationConnection(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "integration_connections"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "github", "vercel", "aws", "kubernetes"
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    credentials_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="healthy", nullable=False)  # "healthy", "warning", "error"
    last_health_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    syncs: Mapped[List["SecretSync"]] = relationship("SecretSync", back_populates="connection", cascade="all, delete-orphan")


class SecretSync(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_syncs"

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True)
    connection_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("integration_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    target_path: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "acme/payments-api", "prod-cluster/payments"
    sync_status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # "active", "paused", "error"
    last_sync_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    connection: Mapped["IntegrationConnection"] = relationship("IntegrationConnection", back_populates="syncs")
    runs: Mapped[List["SecretSyncRun"]] = relationship("SecretSyncRun", back_populates="sync", cascade="all, delete-orphan", order_by="desc(SecretSyncRun.created_at)")


class SecretSyncRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_sync_runs"

    sync_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("secret_syncs.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # "success", "failed", "in_progress"
    synced_keys_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message_redacted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    sync: Mapped["SecretSync"] = relationship("SecretSync", back_populates="runs")

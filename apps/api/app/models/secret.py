import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, JSON, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin


class SecretFolder(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_folders"

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("secret_folders.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(String(500), default="/", nullable=False, index=True)

    secrets: Mapped[List["Secret"]] = relationship("Secret", back_populates="folder", cascade="all, delete-orphan")


class Secret(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "secrets"
    __table_args__ = (
        UniqueConstraint("project_id", "environment_id", "folder_id", "key", "is_deleted", name="uq_secret_scope_key"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True)
    folder_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("secret_folders.id", ondelete="SET NULL"), nullable=True, index=True)
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    current_version_num: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    folder: Mapped[Optional["SecretFolder"]] = relationship("SecretFolder", back_populates="secrets")
    versions: Mapped[List["SecretVersion"]] = relationship("SecretVersion", back_populates="secret", cascade="all, delete-orphan", order_by="desc(SecretVersion.version)")
    rotation: Mapped[Optional["SecretRotation"]] = relationship("SecretRotation", back_populates="secret", uselist=False, cascade="all, delete-orphan")


class SecretVersion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_versions"
    __table_args__ = (
        UniqueConstraint("secret_id", "version", name="uq_secret_version"),
    )

    secret_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Envelope Encrypted Payload
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_data_key: Mapped[str] = mapped_column(Text, nullable=False)
    dek_nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    mek_id: Mapped[str] = mapped_column(String(64), nullable=False)
    mek_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM", nullable=False)

    # Version Audit Telemetry
    change_type: Mapped[str] = mapped_column(String(32), default="create", nullable=False)  # "create", "update", "rollback", "rotation"
    change_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    secret: Mapped["Secret"] = relationship("Secret", back_populates="versions")


class SecretRotation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_rotations"

    secret_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), unique=True, nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "postgres_user", "mysql_user", "api_key", "webhook"
    interval_seconds: Mapped[int] = mapped_column(Integer, default=2592000, nullable=False)  # 30 days default
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # "active", "paused", "failed"
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)  # Envelope-encrypted credentials to perform rotation

    secret: Mapped["Secret"] = relationship("Secret", back_populates="rotation")

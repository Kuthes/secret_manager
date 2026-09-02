import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin


class ManagedKey(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "managed_keys"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM", nullable=False)  # "AES-256-GCM", "RSA-4096", "Ed25519"
    key_usage: Mapped[str] = mapped_column(String(32), default="ENCRYPT_DECRYPT", nullable=False)  # "ENCRYPT_ONLY", "ENCRYPT_DECRYPT", "SIGN_VERIFY", "VERIFY_ONLY"
    encrypted_key_material: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="enabled", nullable=False)  # "enabled", "disabled", "pending_deletion"
    deletion_scheduled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    versions: Mapped[List["ManagedKeyVersion"]] = relationship("ManagedKeyVersion", back_populates="key", cascade="all, delete-orphan", order_by="desc(ManagedKeyVersion.version)")


class ManagedKeyVersion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "managed_key_versions"
    __table_args__ = (
        UniqueConstraint("key_id", "version", name="uq_managed_key_version"),
    )

    key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("managed_keys.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_key_material: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="enabled", nullable=False)

    key: Mapped["ManagedKey"] = relationship("ManagedKey", back_populates="versions")


class EncryptionOperation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "encryption_operations"

    key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("managed_keys.id", ondelete="CASCADE"), nullable=False, index=True)
    operation_type: Mapped[str] = mapped_column(String(32), nullable=False)  # "encrypt", "decrypt", "sign", "verify"
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    payload_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

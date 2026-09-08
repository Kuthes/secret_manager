import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.db.session import Base
from apps.api.app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class AccessResource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_resources"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "secret_path", "database", "kubernetes", "ssh", "console"
    resource_identifier: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "/backend", "prod-cluster"
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=7200, nullable=False)  # 2 hours default
    approval_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    requests: Mapped[list["AccessRequest"]] = relationship("AccessRequest", back_populates="resource", cascade="all, delete-orphan")


class AccessRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_requests"

    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_resources.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)  # "pending", "approved", "rejected", "expired", "revoked"
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    resource: Mapped["AccessResource"] = relationship("AccessResource", back_populates="requests")
    approvals: Mapped[list["AccessApproval"]] = relationship("AccessApproval", back_populates="request", cascade="all, delete-orphan")


class AccessApproval(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_approvals"

    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    approver_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)  # "approved", "rejected"
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    request: Mapped["AccessRequest"] = relationship("AccessRequest", back_populates="approvals")

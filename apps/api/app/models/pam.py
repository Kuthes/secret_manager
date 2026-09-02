import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class AccessResource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_resources"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)  # "secret_path", "database", "kubernetes", "ssh", "console"
    resource_identifier: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "/backend", "prod-cluster"
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=7200, nullable=False)  # 2 hours default
    approval_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    requests: Mapped[List["AccessRequest"]] = relationship("AccessRequest", back_populates="resource", cascade="all, delete-orphan")


class AccessRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_requests"

    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_resources.id", ondelete="CASCADE"), nullable=False, index=True)
    requester_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False, index=True)  # "pending", "approved", "rejected", "expired", "revoked"
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    resource: Mapped["AccessResource"] = relationship("AccessResource", back_populates="requests")
    approvals: Mapped[List["AccessApproval"]] = relationship("AccessApproval", back_populates="request", cascade="all, delete-orphan")


class AccessApproval(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "access_approvals"

    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("access_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    approver_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)  # "approved", "rejected"
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    request: Mapped["AccessRequest"] = relationship("AccessRequest", back_populates="approvals")

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.db.session import Base
from apps.api.app.models.base import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from apps.api.app.models.secret import Secret
    from apps.api.app.models.user import Environment, Project, User


class SecretChangeRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "secret_change_requests"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    environment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    secret_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("secrets.id", ondelete="CASCADE"), nullable=True, index=True
    )

    change_type: Mapped[str] = mapped_column(String(32), nullable=False)  # "create", "update", "delete", "rollback"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)  # Justification

    # Encrypted candidate secret attributes
    proposed_key: Mapped[str] = mapped_column(String(255), nullable=False)
    proposed_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # Envelope encrypted payload
    proposed_description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Actor Telemetry & Review Status
    requester_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requester_name: Mapped[str] = mapped_column(String(255), nullable=False)

    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    reviewer_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False, index=True
    )  # "pending", "approved", "rejected", "applied", "cancelled"

    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    project: Mapped["Project"] = relationship("Project", lazy="selectin")
    environment: Mapped["Environment"] = relationship("Environment", lazy="selectin")
    secret: Mapped["Secret | None"] = relationship("Secret", lazy="selectin")
    requester: Mapped["User"] = relationship("User", foreign_keys=[requester_id], lazy="selectin")
    reviewer: Mapped["User | None"] = relationship("User", foreign_keys=[reviewer_id], lazy="selectin")

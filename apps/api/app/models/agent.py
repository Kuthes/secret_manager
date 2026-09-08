import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.db.session import Base
from apps.api.app.models.base import (
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class AgentIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """Represents an autonomous AI agent identity scoped to an environment."""
    __tablename__ = "agent_identities"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("environments.id", ondelete="CASCADE"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)  # 1 hour default session limit

    # Relationships
    policy: Mapped[Optional["AgentPolicy"]] = relationship("AgentPolicy", back_populates="agent", uselist=False, cascade="all, delete-orphan")
    sessions: Mapped[list["AgentSession"]] = relationship("AgentSession", back_populates="agent", cascade="all, delete-orphan")


class AgentPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Enforces fine-grained tool and outbound URL allowlists for an agent."""
    __tablename__ = "agent_policies"

    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agent_identities.id", ondelete="CASCADE"), unique=True, nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)  # e.g. ["stripe.charge", "github.create_issue"]
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)  # e.g. ["api.stripe.com", "api.github.com"]
    max_requests_per_minute: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    require_justification: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    agent: Mapped["AgentIdentity"] = relationship("AgentIdentity", back_populates="policy")


class AgentSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Represents an active, ephemeral session token issued to an agent."""
    __tablename__ = "agent_sessions"

    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agent_identities.id", ondelete="CASCADE"), nullable=False, index=True)
    session_token_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # "active", "revoked", "expired"
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    agent: Mapped["AgentIdentity"] = relationship("AgentIdentity", back_populates="sessions")

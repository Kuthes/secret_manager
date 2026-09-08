import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.app.db.session import Base
from apps.api.app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class ScannerRepository(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scanner_repositories"

    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_url: Mapped[str] = mapped_column(String(500), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(100), default="main", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="protected", nullable=False)  # "protected", "scanning", "error"
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan_jobs: Mapped[list["ScanJob"]] = relationship("ScanJob", back_populates="repository", cascade="all, delete-orphan", order_by="desc(ScanJob.created_at)")


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_jobs"

    repository_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scanner_repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)  # "running", "completed", "failed"
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    repository: Mapped["ScannerRepository"] = relationship("ScannerRepository", back_populates="scan_jobs")
    findings: Mapped[list["ScanFinding"]] = relationship("ScanFinding", back_populates="job", cascade="all, delete-orphan")


class ScanFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_findings"

    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "stripe-api-key", "aws-secret-access-key"
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    secret_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # SHA-256 hash of leaked secret
    redacted_preview: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "sk_live_••••••••7Xk"
    severity: Mapped[str] = mapped_column(String(32), default="high", nullable=False)  # "critical", "high", "medium", "low"
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)  # "open", "resolved", "false_positive"
    resolution_comment: Mapped[str | None] = mapped_column(Text, nullable=True)

    job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="findings")

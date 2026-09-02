import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Integer, ForeignKey, Text, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from apps.api.app.db.session import Base
from apps.api.app.models.base import UUIDPrimaryKeyMixin, TimestampMixin


class CertificateAuthority(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "certificate_authorities"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_ca_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    ca_type: Mapped[str] = mapped_column(String(32), default="root", nullable=False)  # "root", "intermediate"
    subject_dn: Mapped[str] = mapped_column(String(255), nullable=False)
    key_algorithm: Mapped[str] = mapped_column(String(32), default="RSA-4096", nullable=False)  # "RSA-4096", "ECDSA-P256", "ECDSA-P384"
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_private_key: Mapped[str] = mapped_column(Text, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    crl_number: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # "active", "revoked", "expired"

    certificates: Mapped[List["Certificate"]] = relationship("Certificate", back_populates="ca", cascade="all, delete-orphan")


class CertificateProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "certificate_profiles"

    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    max_validity_days: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    key_usages: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)
    extended_key_usages: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)
    allowed_domains: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)


class Certificate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "certificates"

    ca_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("certificate_authorities.id", ondelete="CASCADE"), nullable=False, index=True)
    profile_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("certificate_profiles.id", ondelete="SET NULL"), nullable=True)
    serial_number: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    common_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    san_dns_names: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)
    cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Optional (if generated server-side)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)  # "active", "revoked", "expired"
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    ca: Mapped["CertificateAuthority"] = relationship("CertificateAuthority", back_populates="certificates")

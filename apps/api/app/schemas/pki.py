import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class CACreateRequest(BaseModel):
    name: str = Field(..., min_length=2)
    common_name: str = Field(..., min_length=2)
    ca_type: str = "root"  # "root" or "intermediate"
    key_algorithm: str = "RSA-4096"
    validity_days: int = 3650
    parent_ca_id: Optional[uuid.UUID] = None


class CAResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    ca_type: str
    subject_dn: str
    key_algorithm: str
    cert_pem: str
    valid_from: datetime
    valid_to: datetime
    status: str


class CertIssueRequest(BaseModel):
    ca_id: uuid.UUID
    common_name: str
    san_dns_names: List[str] = []
    validity_days: int = 90
    key_algorithm: str = "RSA-2048"


class CertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ca_id: uuid.UUID
    serial_number: str
    common_name: str
    san_dns_names: List[str]
    cert_pem: str
    private_key_pem: Optional[str] = None
    valid_from: datetime
    valid_to: datetime
    status: str
    revoked_at: Optional[datetime] = None


class CertRevokeRequest(BaseModel):
    reason: str = Field(default="unspecified")

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DynamicProviderCreate(BaseModel):
    name: str = Field(..., min_length=2)
    provider_type: str = Field(..., description="postgres, mysql, aws_sts, ssh")
    project_id: uuid.UUID
    environment_id: uuid.UUID
    default_ttl_seconds: int = 3600
    max_ttl_seconds: int = 86400
    config: dict[str, Any]


class DynamicProviderResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    provider_type: str
    project_id: uuid.UUID
    environment_id: uuid.UUID
    default_ttl_seconds: int
    max_ttl_seconds: int
    is_active: bool


class LeaseIssueRequest(BaseModel):
    ttl_seconds: int | None = None


class LeaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider_id: uuid.UUID
    issued_identity: str
    credentials: dict[str, Any] | None = None
    ttl_seconds: int
    expires_at: datetime
    status: str

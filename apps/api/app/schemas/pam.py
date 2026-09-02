import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class AccessResourceCreate(BaseModel):
    name: str = Field(..., min_length=2)
    resource_type: str = Field(..., description="secret_path, database, kubernetes, ssh")
    resource_identifier: str = Field(...)
    max_duration_seconds: int = 7200


class AccessResourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    resource_type: str
    resource_identifier: str
    max_duration_seconds: int


class AccessRequestCreate(BaseModel):
    resource_id: uuid.UUID
    justification: str = Field(..., min_length=10)
    duration_seconds: int = Field(default=3600, ge=300, le=86400)


class AccessRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    resource_id: uuid.UUID
    resource_name: Optional[str] = None
    requester_id: uuid.UUID
    requester_name: Optional[str] = None
    justification: str
    duration_seconds: int
    status: str
    expires_at: Optional[datetime] = None
    created_at: datetime


class ApprovalRequest(BaseModel):
    decision: str = Field(..., pattern="^(approved|rejected)$")
    comment: Optional[str] = None

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=2)
    provider_type: str = Field(..., description="github, vercel, aws, kubernetes")
    credentials: dict[str, Any] = Field(...)


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    provider_type: str
    status: str
    last_health_check: datetime | None = None
    created_at: datetime


class SyncCreate(BaseModel):
    project_id: uuid.UUID
    environment_id: uuid.UUID
    connection_id: uuid.UUID
    target_path: str


class SyncResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    connection_id: uuid.UUID
    target_path: str
    sync_status: str
    last_sync_at: datetime | None = None

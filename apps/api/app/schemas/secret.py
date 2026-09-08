import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SecretCreate(BaseModel):
    key: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1)
    path: str = Field(default="/", max_length=500)
    comment: str | None = None
    rotation_interval_days: int | None = None


class SecretUpdate(BaseModel):
    value: str = Field(..., min_length=1)
    comment: str | None = None
    change_message: str | None = None


class SecretResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    key: str
    path: str
    comment: str | None = None
    current_version: int
    updated_at: datetime
    last_actor_name: str | None = None
    rotation_interval: str | None = None


class SecretRevealResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    value: str  # Plaintext returned ONLY on dedicated reveal API
    version: int
    updated_at: datetime


class SecretVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version: int
    change_type: str
    change_message: str | None = None
    actor_name: str | None = None
    created_at: datetime


class RollbackRequest(BaseModel):
    target_version: int = Field(..., ge=1)
    reason: str | None = None


class RotationCreate(BaseModel):
    provider_type: str
    interval_seconds: int = 2592000  # 30 days
    config: dict


class RotationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    secret_id: uuid.UUID
    provider_type: str
    interval_seconds: int
    next_run_at: datetime
    last_run_at: datetime | None = None
    status: str

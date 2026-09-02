import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class SecretCreate(BaseModel):
    key: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1)
    path: str = Field(default="/", max_length=500)
    comment: Optional[str] = None
    rotation_interval_days: Optional[int] = None


class SecretUpdate(BaseModel):
    value: str = Field(..., min_length=1)
    comment: Optional[str] = None
    change_message: Optional[str] = None


class SecretResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    key: str
    path: str
    comment: Optional[str] = None
    current_version: int
    updated_at: datetime
    last_actor_name: Optional[str] = None
    rotation_interval: Optional[str] = None


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
    change_message: Optional[str] = None
    actor_name: Optional[str] = None
    created_at: datetime


class RollbackRequest(BaseModel):
    target_version: int = Field(..., ge=1)
    reason: Optional[str] = None


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
    last_run_at: Optional[datetime] = None
    status: str

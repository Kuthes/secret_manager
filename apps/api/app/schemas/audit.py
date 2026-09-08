import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID | None = None
    actor_id: uuid.UUID | None = None
    actor_name: str
    actor_type: str
    action: str
    resource_type: str
    resource_id: str | None = None
    result: str
    source_ip: str | None = None
    user_agent: str | None = None
    metadata_json: dict[str, Any] = {}
    event_hash: str
    created_at: datetime

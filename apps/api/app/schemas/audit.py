import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    actor_id: Optional[uuid.UUID] = None
    actor_name: str
    actor_type: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    result: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    metadata_json: Dict[str, Any] = {}
    event_hash: str
    created_at: datetime

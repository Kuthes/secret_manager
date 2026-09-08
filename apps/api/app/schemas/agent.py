import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentPolicySchema(BaseModel):
    allowed_tools: list[str] = Field(default_factory=list, description="List of authorized tool names e.g. ['stripe.charge', 'github.issue']")
    allowed_domains: list[str] = Field(default_factory=list, description="List of authorized destination hostnames/domains e.g. ['api.stripe.com']")
    max_requests_per_minute: int = Field(60, ge=1, le=1000)
    require_justification: bool = False


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=255)
    description: str | None = None
    project_id: uuid.UUID
    environment_id: uuid.UUID
    max_ttl_seconds: int = Field(3600, ge=60, le=86400)
    policy: AgentPolicySchema = Field(default_factory=AgentPolicySchema)


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    name: str
    slug: str
    description: str | None = None
    is_active: bool
    max_ttl_seconds: int
    policy: AgentPolicySchema | None = None
    created_at: datetime


class AgentSessionCreate(BaseModel):
    ttl_seconds: int | None = Field(None, ge=60, le=86400)


class AgentSessionResponse(BaseModel):
    session_id: uuid.UUID
    agent_id: uuid.UUID
    token: str
    expires_at: datetime
    status: str


class AgentProxyRequest(BaseModel):
    tool_name: str | None = Field(None, description="Optional logical tool identifier for policy matching")
    url: str = Field(..., description="Target destination HTTP/HTTPS endpoint")
    method: str = Field("POST", pattern="^(GET|POST|PUT|PATCH|DELETE)$")
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any | None = None
    justification: str | None = None


class AgentProxyResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    data: Any
    latency_ms: float
    request_id: str

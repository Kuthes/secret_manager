import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChangeRequestCreate(BaseModel):
    project_id: uuid.UUID
    environment_id: uuid.UUID
    secret_id: uuid.UUID | None = None
    change_type: Literal["create", "update", "delete", "rollback"] = "update"
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5, description="Business justification for the secret change")
    proposed_key: str = Field(..., min_length=1, max_length=255)
    proposed_value: str | None = Field(None, description="Plaintext value to be encrypted into change request payload")
    proposed_description: str | None = None


class ChangeRequestReview(BaseModel):
    decision: Literal["approved", "rejected"]
    comment: str | None = Field(None, max_length=1000)


class ChangeRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    secret_id: uuid.UUID | None
    change_type: str
    title: str
    description: str
    proposed_key: str
    proposed_description: str | None
    requester_id: uuid.UUID
    requester_name: str
    reviewer_id: uuid.UUID | None
    reviewer_name: str | None
    review_comment: str | None
    status: str
    created_at: datetime
    reviewed_at: datetime | None
    applied_at: datetime | None

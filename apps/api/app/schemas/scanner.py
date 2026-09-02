import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class ScannerRepoCreate(BaseModel):
    project_id: uuid.UUID
    repo_url: str = Field(..., min_length=5)
    default_branch: str = "main"


class ScannerRepoResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    repo_url: str
    default_branch: str
    status: str
    last_scan_at: Optional[datetime] = None


class ScanFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    file_path: str
    line_number: int
    secret_fingerprint: str
    redacted_preview: str
    severity: str
    status: str
    resolution_comment: Optional[str] = None
    created_at: datetime

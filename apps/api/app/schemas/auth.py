import uuid
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2)
    org_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str
    mfa_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: uuid.UUID
    email: str
    full_name: str
    org_id: Optional[uuid.UUID] = None
    org_name: Optional[str] = None
    role: Optional[str] = None
    mfa_required: bool = False


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool


class MFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    recovery_codes: List[str]


class MFAVerifyRequest(BaseModel):
    code: str


class UniversalAuthRequest(BaseModel):
    client_id: str
    client_secret: str


class KubernetesAuthRequest(BaseModel):
    jwt: str = Field(..., description="Kubernetes service account projected volume token")
    role: Optional[str] = Field(default="developer")


class MachineTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    identity_type: str
    identity_name: str
    org_id: uuid.UUID

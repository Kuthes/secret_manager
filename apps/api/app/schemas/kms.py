import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class KeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2)
    algorithm: str = "AES-256-GCM"  # "AES-256-GCM", "RSA-4096", "Ed25519"
    key_usage: str = "ENCRYPT_DECRYPT"  # "ENCRYPT_ONLY", "ENCRYPT_DECRYPT", "SIGN_VERIFY", "VERIFY_ONLY"
    project_id: Optional[uuid.UUID] = None


class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    algorithm: str
    key_usage: str
    version: int
    status: str
    public_key_pem: Optional[str] = None
    created_at: datetime


class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="UTF-8 plaintext payload")


class EncryptResponse(BaseModel):
    key_id: uuid.UUID
    key_version: int
    ciphertext: str
    nonce: Optional[str] = None


class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: Optional[str] = None
    version: Optional[int] = None


class DecryptResponse(BaseModel):
    key_id: uuid.UUID
    plaintext: str


class SignRequest(BaseModel):
    message: str = Field(..., description="Plaintext message to sign")


class SignResponse(BaseModel):
    key_id: uuid.UUID
    key_version: int
    signature: str


class VerifyRequest(BaseModel):
    message: str = Field(..., description="Plaintext message that was signed")
    signature: str = Field(..., description="Base64 encoded signature")
    version: Optional[int] = None


class VerifyResponse(BaseModel):
    key_id: uuid.UUID
    valid: bool

import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PROJECT_NAME: str = "AegisVault"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    DEMO_MODE: bool = False

    # Security & Cryptography
    SECRET_KEY: str = "TESTONLY_insecure-dev-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    MASTER_ENCRYPTION_KEY: str = "TESTONLY_QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
    MEK_ID: str = "mek-local-v1"
    KMS_PROVIDER_TYPE: str = "local"  # "local", "aws", "azure", "gcp", "pkcs11"
    AWS_KMS_KEY_ID: Optional[str] = None
    AWS_REGION: Optional[str] = "us-east-1"

    # Database & Cache
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/aegisvault"
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    @model_validator(mode="after")
    def validate_production_safeguards(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            if (
                "TESTONLY_" in self.SECRET_KEY
                or "insecure-dev" in self.SECRET_KEY
                or len(self.SECRET_KEY) < 32
            ):
                raise ValueError("Production mode refused: Insecure or short SECRET_KEY is configured.")
            if (
                "TESTONLY_" in self.MASTER_ENCRYPTION_KEY
                or len(self.MASTER_ENCRYPTION_KEY) < 32
            ):
                raise ValueError("Production mode refused: Insecure or short MASTER_ENCRYPTION_KEY is configured.")
        return self


settings = Settings()

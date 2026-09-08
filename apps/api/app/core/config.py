from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    AWS_KMS_KEY_ID: str | None = None
    AWS_REGION: str | None = "us-east-1"

    # Database & Cache
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/aegisvault"
    REDIS_URL: str = "redis://localhost:6379/0"

    # SSRF & Outbound Connectors (SEC-06)
    ALLOW_PRIVATE_INTEGRATION_TARGETS: bool = False

    # Cookie Security Settings (SEC-07)
    COOKIE_SECURE: bool | None = None  # Auto-inferred to True in production if None
    COOKIE_SAMESITE: str = "lax"
    COOKIE_HTTPONLY: bool = True
    COOKIE_MAX_AGE_SECONDS: int = 86400

    # Secret Reveal Rate Limiting (SEC-08)
    SECRET_REVEAL_RATE_LIMIT_USER_PER_MINUTE: int = 30
    SECRET_REVEAL_RATE_LIMIT_ORG_PER_MINUTE: int = 100

    # CORS
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    @property
    def is_cookie_secure(self) -> bool:
        """Resolve whether cookies must be marked Secure."""
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return self.ENVIRONMENT == "production"

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
            if self.COOKIE_SECURE is False:
                raise ValueError("Production mode refused: Insecure cookie configuration (COOKIE_SECURE=False) is forbidden in production.")
            if self.DEMO_MODE:
                raise ValueError("Production mode refused: DEMO_MODE must not be true in production.")
        return self


settings = Settings()

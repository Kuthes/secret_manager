"""AegisVault Python Client SDK."""

from aegisvault.client import AegisVault, AsyncAegisVault
from aegisvault.exceptions import (
    AegisVaultError,
    AuthenticationError,
    AuthorizationError,
    SecretNotFoundError,
    VaultUnavailableError,
)

__version__ = "0.1.0"

__all__ = [
    "AegisVault",
    "AsyncAegisVault",
    "AegisVaultError",
    "AuthenticationError",
    "AuthorizationError",
    "SecretNotFoundError",
    "VaultUnavailableError",
]

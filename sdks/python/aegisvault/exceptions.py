"""AegisVault Python SDK Exceptions.

Security Invariant: No exception in this module will ever include or format
the plaintext value of any secret in its error message or representation.
"""

class AegisVaultError(Exception):
    """Base exception for all AegisVault SDK errors."""
    pass


class AuthenticationError(AegisVaultError):
    """Raised when authentication with AegisVault fails (e.g., invalid or expired token)."""
    pass


class AuthorizationError(AegisVaultError):
    """Raised when the provided token lacks permission for the requested action."""
    pass


class SecretNotFoundError(AegisVaultError):
    """Raised when the specified secret key or path is not found in the environment."""
    def __init__(self, key: str, project_id: str, environment_id: str):
        self.key = key
        self.project_id = project_id
        self.environment_id = environment_id
        super().__init__(f"Secret '{key}' not found in project '{project_id}' (environment '{environment_id}').")


class VaultUnavailableError(AegisVaultError):
    """Raised when the AegisVault server is unreachable or returned a 5xx error."""
    pass

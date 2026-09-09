"""Official AegisVault Python Client SDK.

Provides synchronous and asynchronous clients for retrieving secrets,
dynamic credentials, and encryption services with in-memory caching.
"""

import os
import time
import threading
from typing import Optional, Dict, Any
import httpx

from aegisvault.exceptions import (
    AegisVaultError,
    AuthenticationError,
    AuthorizationError,
    SecretNotFoundError,
    VaultUnavailableError,
)


class AegisVault:
    """
    Synchronous AegisVault Client.

    Example usage:
        ```python
        from aegisvault import AegisVault

        vault = AegisVault(
            api_url="http://localhost:8000",
            token="av_live_...",
            project_id="c0a80123-...",
            environment_id="c0a80124-...",
            cache_ttl_seconds=300,
        )

        db_password = vault.get("DATABASE_PASSWORD")
        ```
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        project_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        cache_ttl_seconds: int = 300,
        timeout: float = 10.0,
    ):
        self.api_url = (api_url or os.environ.get("AEGIS_API_URL") or "http://localhost:8000").rstrip("/")
        self.token = token or os.environ.get("AEGIS_TOKEN")
        self.project_id = project_id or os.environ.get("AEGIS_PROJECT_ID")
        self.environment_id = environment_id or os.environ.get("AEGIS_ENVIRONMENT_ID")
        self.cache_ttl_seconds = max(0, cache_ttl_seconds)
        self.timeout = timeout

        if not self.token:
            raise AuthenticationError("AegisVault token is required. Pass 'token' or set 'AEGIS_TOKEN' env variable.")

        self._cache: Dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._client = httpx.Client(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "aegisvault-python-sdk/0.1.0",
            },
            timeout=self.timeout,
        )

    def _get_project_and_env(
        self, project_id: Optional[str], environment_id: Optional[str]
    ) -> tuple[str, str]:
        p = project_id or self.project_id
        e = environment_id or self.environment_id
        if not p or not e:
            raise AegisVaultError(
                "Both 'project_id' and 'environment_id' are required. Set them on client initialization or pass as arguments."
            )
        return str(p), str(e)

    def get(
        self,
        key: str,
        default: Optional[str] = None,
        project_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        justification: Optional[str] = None,
        bypass_cache: bool = False,
    ) -> Optional[str]:
        """
        Retrieve a decrypted secret value by key name.

        Args:
            key: Name of the secret (e.g., 'DATABASE_PASSWORD').
            default: Fallback value if the secret is not found.
            project_id: Override project ID if different from client default.
            environment_id: Override environment ID if different from client default.
            justification: Optional reason/ticket number for audit logging.
            bypass_cache: If True, forces a fresh network call to AegisVault.

        Returns:
            Decrypted secret string.
        """
        proj_id, env_id = self._get_project_and_env(project_id, environment_id)
        cache_key = f"{proj_id}:{env_id}:{key.strip().upper()}"

        # 1. Check in-memory cache
        if not bypass_cache and self.cache_ttl_seconds > 0:
            with self._lock:
                if cache_key in self._cache:
                    val, expiry = self._cache[cache_key]
                    if time.time() < expiry:
                        return val

        # 2. Network call to AegisVault API
        params: Dict[str, Any] = {
            "project_id": proj_id,
            "environment_id": env_id,
            "key": key.strip().upper(),
        }
        if justification:
            params["justification"] = justification

        try:
            resp = self._client.get("/api/v1/secrets/value", params=params)
        except httpx.RequestError as exc:
            raise VaultUnavailableError(f"Failed to connect to AegisVault at '{self.api_url}': {exc}") from exc

        if resp.status_code == 200:
            data = resp.json()
            secret_value = str(data.get("value", ""))

            # Update cache
            if self.cache_ttl_seconds > 0:
                with self._lock:
                    self._cache[cache_key] = (secret_value, time.time() + self.cache_ttl_seconds)

            return secret_value
        elif resp.status_code == 404:
            if default is not None:
                return default
            raise SecretNotFoundError(key, proj_id, env_id)
        elif resp.status_code == 401:
            raise AuthenticationError("AegisVault authentication failed: Invalid or expired token.")
        elif resp.status_code == 403:
            raise AuthorizationError(f"AegisVault permission denied: Token lacks 'secret:reveal' permission for key '{key}'.")
        else:
            raise VaultUnavailableError(f"AegisVault returned unexpected status code {resp.status_code}.")

    def invalidate_cache(self, key: Optional[str] = None) -> None:
        """Clear cached secrets from memory."""
        with self._lock:
            if key is None:
                self._cache.clear()
            else:
                formatted_key = key.strip().upper()
                keys_to_delete = [k for k in self._cache if k.endswith(f":{formatted_key}")]
                for k in keys_to_delete:
                    del self._cache[k]

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> "AegisVault":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class AsyncAegisVault:
    """
    Asynchronous AegisVault Client for asyncio, FastAPI, and async workers.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        project_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        cache_ttl_seconds: int = 300,
        timeout: float = 10.0,
    ):
        self.api_url = (api_url or os.environ.get("AEGIS_API_URL") or "http://localhost:8000").rstrip("/")
        self.token = token or os.environ.get("AEGIS_TOKEN")
        self.project_id = project_id or os.environ.get("AEGIS_PROJECT_ID")
        self.environment_id = environment_id or os.environ.get("AEGIS_ENVIRONMENT_ID")
        self.cache_ttl_seconds = max(0, cache_ttl_seconds)
        self.timeout = timeout

        if not self.token:
            raise AuthenticationError("AegisVault token is required. Pass 'token' or set 'AEGIS_TOKEN' env variable.")

        self._cache: Dict[str, tuple[str, float]] = {}
        self._client = httpx.AsyncClient(
            base_url=self.api_url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "aegisvault-python-sdk/0.1.0 (async)",
            },
            timeout=self.timeout,
        )

    def _get_project_and_env(
        self, project_id: Optional[str], environment_id: Optional[str]
    ) -> tuple[str, str]:
        p = project_id or self.project_id
        e = environment_id or self.environment_id
        if not p or not e:
            raise AegisVaultError("Both 'project_id' and 'environment_id' are required.")
        return str(p), str(e)

    async def get(
        self,
        key: str,
        default: Optional[str] = None,
        project_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        justification: Optional[str] = None,
        bypass_cache: bool = False,
    ) -> Optional[str]:
        proj_id, env_id = self._get_project_and_env(project_id, environment_id)
        cache_key = f"{proj_id}:{env_id}:{key.strip().upper()}"

        if not bypass_cache and self.cache_ttl_seconds > 0:
            if cache_key in self._cache:
                val, expiry = self._cache[cache_key]
                if time.time() < expiry:
                    return val

        params: Dict[str, Any] = {
            "project_id": proj_id,
            "environment_id": env_id,
            "key": key.strip().upper(),
        }
        if justification:
            params["justification"] = justification

        try:
            resp = await self._client.get("/api/v1/secrets/value", params=params)
        except httpx.RequestError as exc:
            raise VaultUnavailableError(f"Failed to connect to AegisVault: {exc}") from exc

        if resp.status_code == 200:
            data = resp.json()
            secret_value = str(data.get("value", ""))

            if self.cache_ttl_seconds > 0:
                self._cache[cache_key] = (secret_value, time.time() + self.cache_ttl_seconds)

            return secret_value
        elif resp.status_code == 404:
            if default is not None:
                return default
            raise SecretNotFoundError(key, proj_id, env_id)
        elif resp.status_code == 401:
            raise AuthenticationError("AegisVault authentication failed: Invalid or expired token.")
        elif resp.status_code == 403:
            raise AuthorizationError(f"AegisVault permission denied for key '{key}'.")
        else:
            raise VaultUnavailableError(f"AegisVault returned unexpected status code {resp.status_code}.")

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncAegisVault":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

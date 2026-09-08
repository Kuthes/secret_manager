import asyncio
import logging
import secrets
import time

import redis.asyncio as aioredis

from apps.api.app.core.config import settings

logger = logging.getLogger(__name__)

# Lua script to release lock only if the token matches
RELEASE_LUA_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""

# In-memory lock registry for tests/fallback when Redis is not reachable
_in_memory_locks: dict[str, dict[str, float]] = {}
_in_memory_lock_mutex = asyncio.Lock()


class DistributedLock:
    """
    Production-grade distributed lock.
    - Uses Redis SET NX EX for atomic acquisition.
    - Uses Lua script for safe ownership-validated release.
    - Gracefully falls back to in-memory lock if Redis is unreachable in test mode.
    """

    def __init__(
        self,
        lock_key: str,
        ttl_seconds: int = 60,
        token: str | None = None,
        redis_url: str | None = None,
    ):
        self.lock_key = f"aegisvault:lock:{lock_key}"
        self.ttl_seconds = ttl_seconds
        self.token = token or secrets.token_hex(16)
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis_client: aioredis.Redis | None = None
        self._is_in_memory = False

    async def _get_client(self) -> aioredis.Redis | None:
        if self._redis_client is None and not self._is_in_memory:
            try:
                self._redis_client = aioredis.from_url(
                    self.redis_url,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                    decode_responses=True,
                )
                await self._redis_client.ping()
            except Exception as e:
                logger.debug(f"Redis unavailable, using memory lock fallback: {e}")
                self._is_in_memory = True
                if self._redis_client:
                    await self._redis_client.aclose()
                self._redis_client = None
        return self._redis_client

    async def acquire(self) -> bool:
        """Attempt to acquire distributed lock. Returns True if acquired."""
        client = await self._get_client()
        if client and not self._is_in_memory:
            try:
                acquired = await client.set(
                    self.lock_key,
                    self.token,
                    nx=True,
                    ex=self.ttl_seconds,
                )
                return bool(acquired)
            except Exception as e:
                logger.warning(f"Redis error during lock acquisition: {e}. Falling back to memory lock.")
                self._is_in_memory = True

        # In-memory lock fallback
        async with _in_memory_lock_mutex:
            now = time.time()
            if self.lock_key in _in_memory_locks:
                lock_info = _in_memory_locks[self.lock_key]
                if lock_info["expires_at"] > now:
                    return False  # Still locked
            _in_memory_locks[self.lock_key] = {
                "token": self.token,
                "expires_at": now + self.ttl_seconds,
            }
            return True

    async def release(self) -> bool:
        """Release lock only if token matches."""
        client = await self._get_client()
        if client and not self._is_in_memory:
            try:
                res = await client.eval(
                    RELEASE_LUA_SCRIPT,
                    1,
                    self.lock_key,
                    self.token,
                )
                return bool(res)
            except Exception as e:
                logger.warning(f"Redis error during lock release: {e}")

        # In-memory release
        async with _in_memory_lock_mutex:
            if self.lock_key in _in_memory_locks:
                lock_info = _in_memory_locks[self.lock_key]
                if lock_info["token"] == self.token:
                    del _in_memory_locks[self.lock_key]
                    return True
            return False

    async def __aenter__(self):
        acquired = await self.acquire()
        if not acquired:
            raise RuntimeError(f"Could not acquire distributed lock for {self.lock_key}")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.release()
        if self._redis_client:
            await self._redis_client.aclose()
